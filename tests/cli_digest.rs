//! `inkseal digest <文件>` 的端到端回归测试：通过真实文件访问验证
//! 命令行约定的路径处理与输出格式。
//!
//! 重点区分两类路径文字：用户传入的真实路径（必须按原样用于打开文件）
//! 与错误提示中显示的路径文字（仅用于展示，可含替换字符与转义）。

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

/// 独立依据：GNU coreutils sha256sum 对相应字节序列的计算结果。
const HELLO_HEX: &str = "6a2785d0b3b2b82f85a94ac0b7b1a9c814da2321245820e43d7fac20419f4d13";
const EMPTY_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const BINARY_HEX: &str = "879e1d6af3829ebad59012630ce80b422b1bf81dbdc2bc0c1ba940f46f2dde3c";
const CONTENT_ONE_HEX: &str =
    "8200a1f75db10da179903afe518dd91d2aaeeec6d3d7828ab2d786bc0b892657";
const CONTENT_TWO_HEX: &str =
    "2af014cc40d9c9830b20c7ac17f2709ea59f7ae4843882e88e807aedd6a22b01";

/// 含零字节、非法 UTF-8 字节和多种换行的二进制内容。
const BINARY_CONTENT: &[u8] =
    b"alpha\nbeta\r\ngamma\rdelta\n\x00\xff\xfe\x80tail-without-newline";

fn inkseal() -> Command {
    Command::new(env!("CARGO_BIN_EXE_inkseal"))
}

struct Run {
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run(cmd: &mut Command) -> Run {
    let Output { status, stdout, stderr } = cmd.output().expect("failed to spawn inkseal");
    Run { code: status.code(), stdout, stderr }
}

fn stderr_text(run: &Run) -> String {
    String::from_utf8(run.stderr.clone()).expect("stderr must be valid UTF-8")
}

/// 每个测试一个独立临时目录，测试结束（或失败 panic 后 unwinding）时清理。
struct TempDir(PathBuf);

impl TempDir {
    fn new(test_name: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = format!(
            "inkseal-cli-test-{}-{}-{}",
            test_name,
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path).expect("create temp dir");
        TempDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, name: &str, content: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, content).expect("write fixture file");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// 成功输出的约定：恰好 64 个小写十六进制字符加一个末尾换行，别无他物。
fn assert_success_output(run: &Run, expected_hex: &str) {
    assert_eq!(run.code, Some(0), "exit code must be 0, stderr: {:?}", stderr_text(run));
    assert_eq!(
        run.stdout,
        format!("{expected_hex}\n").into_bytes(),
        "stdout must be exactly the 64-char hex digest plus a trailing newline"
    );
    assert_eq!(run.stdout.len(), 65);
    assert!(run.stdout[..64]
        .iter()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    assert!(run.stderr.is_empty(), "stderr must be empty on success");
}

#[test]
fn digest_of_regular_file_matches_content_sha256() {
    let dir = TempDir::new("regular");
    let path = dir.write("plain.txt", b"hello inkseal");

    let run = run(inkseal().arg("digest").arg(&path));

    assert_success_output(&run, HELLO_HEX);
}

#[test]
fn empty_file_yields_standard_empty_sha256() {
    let dir = TempDir::new("empty");
    let path = dir.write("empty.bin", b"");

    let run = run(inkseal().arg("digest").arg(&path));

    assert_success_output(&run, EMPTY_HEX);
}

#[test]
fn path_with_spaces_and_non_ascii_characters_reads_the_same_file() {
    let dir = TempDir::new("unicode");
    // 目录名和文件名都含空格与非 ASCII 字符。
    let nested = dir.path().join("空 白 dir");
    fs::create_dir_all(&nested).unwrap();
    let path = nested.join("文件 名.txt");
    fs::write(&path, b"hello inkseal").unwrap();

    let run = run(inkseal().arg("digest").arg(&path));

    // 与普通路径一样成功读取，输出同一内容的摘要。
    assert_success_output(&run, HELLO_HEX);
}

#[test]
fn same_content_under_different_names_and_locations_gives_same_digest() {
    let dir = TempDir::new("same-content");
    let first = dir.write("first.txt", b"hello inkseal");
    let sub = dir.path().join("elsewhere");
    fs::create_dir_all(&sub).unwrap();
    let second = sub.join("第二份.bin");
    fs::write(&second, b"hello inkseal").unwrap();

    let run_first = run(inkseal().arg("digest").arg(&first));
    let run_second = run(inkseal().arg("digest").arg(&second));

    // 路径文字不参与计算：内容相同则摘要相同。
    assert_success_output(&run_first, HELLO_HEX);
    assert_success_output(&run_second, HELLO_HEX);
    assert_eq!(run_first.stdout, run_second.stdout);
}

#[test]
fn zero_bytes_and_non_utf8_content_hashed_verbatim() {
    let dir = TempDir::new("binary");
    let path = dir.write("raw.bin", BINARY_CONTENT);

    let run = run(inkseal().arg("digest").arg(&path));

    // 任何文本解码、换行转换或零字节截断都会改变该值。
    assert_success_output(&run, BINARY_HEX);
}

#[test]
fn missing_file_reports_path_and_exits_1() {
    let dir = TempDir::new("missing");
    let path = dir.path().join("nope.txt");

    let run = run(inkseal().arg("digest").arg(&path));

    assert_eq!(run.code, Some(1));
    assert!(run.stdout.is_empty(), "stdout must stay empty on failure");
    let stderr = stderr_text(&run);
    assert!(stderr.contains("cannot open"), "stderr should state the cause: {stderr:?}");
    assert!(
        stderr.contains("nope.txt"),
        "stderr should name the failing path: {stderr:?}"
    );
    // 失败提示必须与成功摘要可区分：64 位十六进制不会出现在失败输出里。
    assert!(!run.stdout.windows(64).any(|w| w == HELLO_HEX.as_bytes()));
}

#[test]
fn directory_path_is_an_error_not_a_digest() {
    let dir = TempDir::new("directory");
    let sub = dir.path().join("a-directory");
    fs::create_dir_all(&sub).unwrap();

    let run = run(inkseal().arg("digest").arg(&sub));

    assert_eq!(run.code, Some(1));
    assert!(run.stdout.is_empty());
    let stderr = stderr_text(&run);
    assert!(stderr.contains("a-directory"), "stderr should name the path: {stderr:?}");
}

#[test]
fn control_characters_in_error_path_are_visibly_escaped() {
    let dir = TempDir::new("control");
    // 不存在的文件，名字里含换行与制表符。
    let path = dir.path().join("weird\nname\ttab");

    let run = run(inkseal().arg("digest").arg(&path));

    assert_eq!(run.code, Some(1));
    assert!(run.stdout.is_empty());
    let stderr = stderr_text(&run);
    // 控制字符以可见转义形式出现……
    assert!(stderr.contains("weird\\nname\\ttab"), "escaped path expected: {stderr:?}");
    // ……且提示仍是一行：原始换行/制表符不得改变行结构。
    assert!(stderr.ends_with('\n'));
    let body = &stderr[..stderr.len() - 1];
    assert!(!body.contains('\n'), "message must be a single line: {stderr:?}");
    assert!(!body.contains('\t'), "no raw tab in message: {stderr:?}");
    assert!(!body.contains('\r'), "no raw carriage return: {stderr:?}");
}

#[test]
fn usage_errors_exit_2_with_usage_only_on_stderr() {
    let dir = TempDir::new("usage");
    let existing = dir.write("a.txt", b"hello inkseal");

    let cases: Vec<Vec<OsString>> = vec![
        // 缺少子命令。
        vec![],
        // digest 缺少路径。
        vec!["digest".into()],
        // digest 多给路径。
        vec!["digest".into(), existing.clone().into_os_string(), "extra".into()],
        // 未知子命令。
        vec!["frobnicate".into()],
    ];

    for args in cases {
        let run = run(inkseal().args(&args));
        assert_eq!(run.code, Some(2), "args {args:?} must exit 2");
        assert!(run.stdout.is_empty(), "args {args:?}: stdout must be empty");
        let stderr = stderr_text(&run);
        assert!(stderr.contains("Usage"), "args {args:?}: usage hint expected: {stderr:?}");
    }
}

/// 以下测试依赖允许非 UTF-8 文件名的系统（Unix）：文件名是原始字节序列。
#[cfg(unix)]
mod non_utf8_paths {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    fn os(bytes: &[u8]) -> OsString {
        OsStr::from_bytes(bytes).to_os_string()
    }

    /// 两个真实路径只在不可解码字节上不同（`x_\xff` 与 `x_\xfe`），
    /// 损失性显示都会变成 `x_�`——显示文字相同，路径不同。
    fn confusing_pair(dir: &Path, stem: u8) -> (PathBuf, PathBuf) {
        let mut a = b"x_".to_vec();
        a.push(stem);
        let mut b = b"x_".to_vec();
        b.push(if stem == 0xff { 0xfe } else { 0xff });
        (dir.join(os(&a)), dir.join(os(&b)))
    }

    #[test]
    fn paths_differing_only_in_undecodable_bytes_open_their_own_files() {
        let dir = TempDir::new("non-utf8-pair");
        let (path_ff, path_fe) = confusing_pair(dir.path(), 0xff);
        // 显示文字相同，但两个文件内容不同。
        assert_eq!(
            path_ff.as_os_str().to_string_lossy(),
            path_fe.as_os_str().to_string_lossy(),
            "fixture requires both paths to display identically"
        );
        fs::write(&path_ff, b"content-one").unwrap();
        fs::write(&path_fe, b"content-two").unwrap();

        let run_ff = run(inkseal().arg("digest").arg(&path_ff));
        let run_fe = run(inkseal().arg("digest").arg(&path_fe));

        // 各自得到对应内容的摘要：既没有读错文件，也没有把合法路径当作用法错误。
        assert_success_output(&run_ff, CONTENT_ONE_HEX);
        assert_success_output(&run_fe, CONTENT_TWO_HEX);
    }

    #[test]
    fn missing_non_utf8_sibling_is_not_confused_with_existing_file() {
        let dir = TempDir::new("non-utf8-missing");
        let (path_ff, path_fe) = confusing_pair(dir.path(), 0xff);
        // 只有 x_\xff 存在；访问 x_\xfe 必须报不存在，不能误读已有文件。
        fs::write(&path_ff, b"content-one").unwrap();

        let run = run(inkseal().arg("digest").arg(&path_fe));

        assert_eq!(run.code, Some(1));
        assert!(run.stdout.is_empty(), "must not emit the sibling's digest");
        let stderr = stderr_text(&run);
        assert!(stderr.contains("cannot open"), "stderr: {stderr:?}");
        // 提示中的替换字符只影响显示：路径以 `x_�` 形式呈现。
        assert!(
            stderr.contains("x_\u{FFFD}"),
            "undecodable byte shown as replacement char: {stderr:?}"
        );
    }

    #[test]
    fn non_utf8_existing_file_still_digests_normally() {
        let dir = TempDir::new("non-utf8-ok");
        let path = dir.path().join(os(b"\xff\xfe\x80.dat"));
        fs::write(&path, BINARY_CONTENT).unwrap();

        let run = run(inkseal().arg("digest").arg(&path));

        // 路径中的不可解码字节不参与摘要，文件按原始字节读取。
        assert_success_output(&run, BINARY_HEX);
    }

    #[test]
    fn non_utf8_missing_path_error_is_single_line_with_replacement_char() {
        let dir = TempDir::new("non-utf8-err");
        let path = dir.path().join(os(b"gone_\xff"));

        let run = run(inkseal().arg("digest").arg(&path));

        assert_eq!(run.code, Some(1));
        assert!(run.stdout.is_empty());
        let stderr = stderr_text(&run);
        assert!(stderr.contains("gone_\u{FFFD}"), "stderr: {stderr:?}");
        assert!(stderr.ends_with('\n'));
        assert!(!stderr[..stderr.len() - 1].contains('\n'));
    }
}
