//! `inkseal digest <文件>` 的端到端回归测试：以真实子进程运行编译出的命令，
//! 在临时目录中创建真实文件，验证命令确实按用户给出的路径访问文件，
//! 且输出、退出码、错误提示遵循 README 约定的行为。
//!
//! 重点保障：用户传入的真实路径（操作系统原始字节）与错误提示中显示的
//! 路径文字（损失性转换、控制字符转义）之间的区别——显示文本绝不参与
//! 文件访问，路径文字也不参与摘要计算。

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// 待测试的命令行程序（Cargo 为集成测试提供编译好的二进制路径）。
fn inkseal() -> Command {
    Command::new(env!("CARGO_BIN_EXE_inkseal"))
}

fn run_digest(path: &OsStr) -> Output {
    inkseal()
        .arg("digest")
        .arg(path)
        .output()
        .expect("failed to run inkseal")
}

fn run_args(args: &[&OsStr]) -> Output {
    inkseal()
        .args(args)
        .output()
        .expect("failed to run inkseal")
}

/// 每个测试独立的临时目录，退出作用域时清理。
struct TestDir(PathBuf);

impl TestDir {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "inkseal-cli-test-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        TestDir(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    /// 在目录下创建指定名字（可以是任意 OsStr，包括非 UTF-8 字节）的文件。
    fn write_file(&self, name: &OsStr, contents: &[u8]) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, contents).expect("write test file");
        path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// 成功摘要的标准输出形态：恰好 64 个小写十六进制字符加一个末尾换行。
fn assert_hex_stdout(stdout: &[u8]) -> &str {
    let text = std::str::from_utf8(stdout).expect("stdout must be UTF-8 hex");
    assert!(
        text.ends_with('\n'),
        "stdout must end with a newline: {text:?}"
    );
    let hex = &text[..text.len() - 1];
    assert_eq!(hex.len(), 64, "digest line must be 64 chars: {text:?}");
    assert!(
        hex.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "digest must be lowercase hex only: {hex:?}"
    );
    hex
}

/// 成功路径的完整约定：退出码 0、标准输出只有摘要行、标准错误为空。
fn assert_success(output: &Output) -> String {
    assert_eq!(output.status.code(), Some(0), "exit code: {output:?}");
    assert!(
        output.stderr.is_empty(),
        "stderr must be empty on success: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_hex_stdout(&output.stdout).to_owned()
}

/// 打开/读取失败的完整约定：退出码 1、标准输出为空、标准错误单行说明。
fn assert_failure(output: &Output) -> String {
    assert_eq!(output.status.code(), Some(1), "exit code: {output:?}");
    assert!(
        output.stdout.is_empty(),
        "stdout must be empty on failure: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8(output.stderr.clone()).expect("stderr must be UTF-8");
    assert!(
        stderr.ends_with('\n') && !stderr[..stderr.len() - 1].contains('\n'),
        "error message must be a single line: {stderr:?}"
    );
    assert!(
        stderr.starts_with("inkseal: cannot "),
        "error message must state the failure: {stderr:?}"
    );
    stderr
}

/// 与库无关的独立依据：python3 hashlib.sha256(b"abc")。
const ABC_HEX: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

/// 与库测试相同的独立依据：python3 hashlib.sha256 对 bytes(range(256)) + b"\\x00\\xff\\xfe\\x80"。
const BINARY_HEX: &str = "ae1754116b130744d081ccc09988962b3e875ec0e0d6194f2c950e8fe7e27a3d";

fn binary_content() -> Vec<u8> {
    (0u8..=255).chain([0x00, 0xff, 0xfe, 0x80]).collect()
}

#[test]
fn digest_of_plain_file_matches_content() {
    let dir = TestDir::new("plain");
    let path = dir.write_file(OsStr::new("hello.txt"), b"abc");

    let output = run_digest(path.as_os_str());

    let hex = assert_success(&output);
    assert_eq!(hex, ABC_HEX);
}

#[test]
fn filename_with_spaces_and_non_ascii_characters_is_read() {
    let dir = TestDir::new("unicode-names");
    // 空格、中文、其他非 ASCII 字符都应与普通路径一样成功读取。
    for name in ["my file.txt", "报告 最终版.txt", "données été.bin"] {
        let path = dir.write_file(OsStr::new(name), b"abc");
        let output = run_digest(path.as_os_str());
        let hex = assert_success(&output);
        assert_eq!(hex, ABC_HEX, "digest for file named {name:?}");
    }
}

#[test]
fn same_content_in_different_names_and_locations_gives_same_digest() {
    let dir = TestDir::new("same-content");
    let sub = dir.path().join("nested").join("deeper");
    fs::create_dir_all(&sub).unwrap();

    // 相同内容放在不同名称、不同位置：摘要必须相同，路径文字不得参与计算。
    let first = dir.write_file(OsStr::new("alpha.bin"), b"shared content");
    let second = dir.write_file(OsStr::new("完全 不同 的名字.bin"), b"shared content");
    let third = sub.join("alpha.bin");
    fs::write(&third, b"shared content").unwrap();

    let expected = inkseal::digest_reader(&b"shared content"[..])
        .unwrap()
        .to_hex();
    for path in [&first, &second, &third] {
        let output = run_digest(path.as_os_str());
        let hex = assert_success(&output);
        assert_eq!(hex, expected, "digest must not depend on path {path:?}");
    }
}

#[test]
fn zero_bytes_and_non_utf8_content_hashed_verbatim() {
    let dir = TestDir::new("binary-content");
    let path = dir.write_file(OsStr::new("blob.bin"), &binary_content());

    let output = run_digest(path.as_os_str());

    // 任何文本解码、换行转换或编码规范化都会改变这些字节，从而改变摘要。
    let hex = assert_success(&output);
    assert_eq!(hex, BINARY_HEX);
}

#[test]
fn success_stdout_is_exactly_64_lowercase_hex_and_newline() {
    let dir = TestDir::new("output-shape");
    let path = dir.write_file(OsStr::new("f"), b"abc");

    let output = run_digest(path.as_os_str());

    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    // 逐字节核对：不多不少，方便把结果直接交给其他工具。
    assert_eq!(output.stdout, format!("{ABC_HEX}\n").as_bytes());
}

#[test]
fn missing_file_reports_error_with_path() {
    let dir = TestDir::new("missing");
    let path = dir.path().join("nope.txt");

    let output = run_digest(path.as_os_str());

    let stderr = assert_failure(&output);
    assert!(
        stderr.contains("cannot open"),
        "should report open failure: {stderr:?}"
    );
    assert!(
        stderr.contains("nope.txt"),
        "error must name the failing path: {stderr:?}"
    );
    // 用户必须能区分成功摘要和失败提示：失败时标准输出没有任何摘要。
    assert!(output.stdout.is_empty());
}

#[test]
fn directory_path_reports_error_with_path() {
    let dir = TestDir::new("directory");
    let sub = dir.path().join("a-directory");
    fs::create_dir_all(&sub).unwrap();

    let output = run_digest(sub.as_os_str());

    let stderr = assert_failure(&output);
    assert!(
        stderr.contains("a-directory"),
        "error must name the failing path: {stderr:?}"
    );
}

#[test]
fn control_characters_in_error_path_are_escaped_visibly() {
    let dir = TestDir::new("control-chars");
    // 不存在的路径，名字含换行、制表符和响铃符。
    let path = dir.path().join("bad\nname\ttab\u{7}bell.txt");

    let output = run_digest(path.as_os_str());

    let stderr = assert_failure(&output);
    // 控制字符必须以可见转义形式出现，不得改变提示的行结构。
    assert!(stderr.contains("bad\\nname\\ttab\\u{7}bell.txt"), "{stderr:?}");
    assert!(!stderr.contains("bad\nname"), "{stderr:?}");
    assert!(!stderr.contains('\t'), "{stderr:?}");
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    fn os(bytes: &[u8]) -> OsString {
        OsString::from(OsStr::from_bytes(bytes))
    }

    #[test]
    fn non_utf8_filename_is_read_like_any_other_path() {
        let dir = TestDir::new("non-utf8");
        let path = dir.write_file(&os(b"raw \xff\xfe name.bin"), b"abc");

        let output = run_digest(path.as_os_str());

        let hex = assert_success(&output);
        assert_eq!(hex, ABC_HEX);
    }

    #[test]
    fn paths_differing_only_in_undecodable_bytes_reach_their_own_files() {
        let dir = TestDir::new("undecodable-pair");
        // 两个真实路径只在不可解码字节上不同，损失性显示文字相同。
        let first = dir.write_file(&os(b"data_\xff.bin"), b"content of first");
        let second = dir.write_file(&os(b"data_\xfe.bin"), b"content of second");

        // 测试前提：两个路径的显示文字确实相同（都含替换字符）。
        let display_first = first.as_os_str().to_string_lossy().into_owned();
        let display_second = second.as_os_str().to_string_lossy().into_owned();
        assert_eq!(display_first, display_second);
        assert!(display_first.contains('\u{fffd}'));

        // 各自得到对应内容的摘要，不能读到另一个文件。
        let hex_first = assert_success(&run_digest(first.as_os_str()));
        let hex_second = assert_success(&run_digest(second.as_os_str()));
        assert_eq!(
            hex_first,
            inkseal::digest_reader(&b"content of first"[..])
                .unwrap()
                .to_hex()
        );
        assert_eq!(
            hex_second,
            inkseal::digest_reader(&b"content of second"[..])
                .unwrap()
                .to_hex()
        );
        assert_ne!(hex_first, hex_second);
    }

    #[test]
    fn missing_undecodable_path_reports_not_found_without_reading_sibling() {
        let dir = TestDir::new("undecodable-missing");
        // 只创建 \xff 版本；访问 \xfe 版本必须报文件不存在，
        // 不能因显示文字相同而误读已有文件。
        let existing = dir.write_file(&os(b"data_\xff.bin"), b"existing content");
        let missing = dir.path().join(os(b"data_\xfe.bin"));

        let output = run_digest(missing.as_os_str());

        let stderr = assert_failure(&output);
        // 提示中的替换字符只影响显示：两个路径显示文字相同，但行为不同。
        assert!(stderr.contains('\u{fffd}'), "{stderr:?}");
        assert!(stderr.contains("cannot open"), "{stderr:?}");
        // 绝不能输出已有文件的摘要。
        let existing_hex = inkseal::digest_reader(&b"existing content"[..])
            .unwrap()
            .to_hex();
        assert!(!output.stdout.windows(64).any(|w| w == existing_hex.as_bytes()));
        // 对照：已有文件本身可以正常摘要。
        let hex = assert_success(&run_digest(existing.as_os_str()));
        assert_eq!(hex, existing_hex);
    }

    #[test]
    fn undecodable_bytes_in_error_path_shown_as_replacement_char() {
        let dir = TestDir::new("undecodable-error");
        // 不存在的路径，同时含不可解码字节和控制字符。
        let path = dir.path().join(os(b"bad\xff\nname"));

        let output = run_digest(path.as_os_str());

        let stderr = assert_failure(&output);
        // 不可解码字节以替换字符呈现，换行以可见转义呈现，提示仍是单行。
        assert!(stderr.contains('\u{fffd}'), "{stderr:?}");
        assert!(stderr.contains("\\n"), "{stderr:?}");
        assert!(!stderr[..stderr.len() - 1].contains('\n'), "{stderr:?}");
    }
}

#[test]
fn missing_path_argument_is_usage_error() {
    let output = run_args(&[OsStr::new("digest")]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage:"), "{stderr:?}");
}

#[test]
fn extra_path_argument_is_usage_error_even_when_file_exists() {
    let dir = TestDir::new("extra-arg");
    let path = dir.write_file(OsStr::new("real.txt"), b"abc");

    let output = run_args(&[
        OsStr::new("digest"),
        path.as_os_str(),
        OsStr::new("extra"),
    ]);

    // 每次只处理一个文件：多给路径是用法错误，不得输出任何摘要。
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage:"), "{stderr:?}");
}

#[test]
fn no_arguments_and_unknown_subcommand_are_usage_errors() {
    for args in [&[][..], &[OsStr::new("frobnicate")][..]] {
        let output = run_args(args);
        assert_eq!(output.status.code(), Some(2), "args: {args:?}");
        assert!(output.stdout.is_empty(), "args: {args:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Usage:"), "args: {args:?}: {stderr:?}");
    }
}

// ── check-digest ────────────────────────────────────────────────────────────

fn run_check(path: &OsStr, expected: &OsStr) -> Output {
    inkseal()
        .arg("check-digest")
        .arg(path)
        .arg(expected)
        .output()
        .expect("failed to run inkseal")
}

/// 匹配的完整约定：退出码 0、标准输出只有 `OK\n`、标准错误为空。
fn assert_check_ok(output: &Output) {
    assert_eq!(output.status.code(), Some(0), "exit code: {output:?}");
    assert_eq!(output.stdout, b"OK\n", "stdout must be exactly OK\\n: {output:?}");
    assert!(
        output.stderr.is_empty(),
        "stderr must be empty on match: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// 内容不匹配的完整约定：退出码 1、标准输出为空、标准错误说明不匹配
/// 并列出预期与实际两个 64 位小写十六进制摘要。
fn assert_mismatch(output: &Output, expected_hex: &str, actual_hex: &str) -> String {
    assert_eq!(output.status.code(), Some(1), "exit code: {output:?}");
    assert!(
        output.stdout.is_empty(),
        "stdout must be empty on mismatch: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8(output.stderr.clone()).expect("stderr must be UTF-8");
    assert!(
        stderr.to_lowercase().contains("mismatch"),
        "must state content mismatch, not an I/O error: {stderr:?}"
    );
    assert!(
        stderr.contains(expected_hex),
        "must list expected digest: {stderr:?}"
    );
    assert!(
        stderr.contains(actual_hex),
        "must list actual digest: {stderr:?}"
    );
    // 两者都必须以 64 个小写十六进制字符出现。
    for line in stderr.lines() {
        if let Some(hex) = line.split_whitespace().find(|w| w.len() == 64) {
            assert!(
                hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
                "digest in message must be lowercase hex: {hex:?}"
            );
        }
    }
    stderr
}

/// 用法错误的完整约定：退出码 2、标准输出为空、标准错误说明问题并给出用法。
fn assert_usage_error(output: &Output) -> String {
    assert_eq!(output.status.code(), Some(2), "exit code: {output:?}");
    assert!(
        output.stdout.is_empty(),
        "stdout must be empty on usage error: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Usage:"), "usage must be shown: {stderr:?}");
    stderr.into_owned()
}

#[test]
fn check_digest_matches_when_content_unchanged() {
    let dir = TestDir::new("check-ok");
    let path = dir.write_file(OsStr::new("hello.txt"), b"abc");

    let output = run_check(path.as_os_str(), OsStr::new(ABC_HEX));

    assert_check_ok(&output);
}

#[test]
fn check_digest_accepts_uppercase_and_mixed_case_hex() {
    let dir = TestDir::new("check-case");
    let path = dir.write_file(OsStr::new("hello.txt"), b"abc");

    let upper: String = ABC_HEX.to_uppercase();
    let mixed: String = ABC_HEX
        .chars()
        .enumerate()
        .map(|(i, c)| if i % 2 == 0 { c.to_ascii_uppercase() } else { c })
        .collect();

    assert_check_ok(&run_check(path.as_os_str(), OsStr::new(&upper)));
    assert_check_ok(&run_check(path.as_os_str(), OsStr::new(&mixed)));
}

#[test]
fn check_digest_mismatch_lists_both_digests_lowercase() {
    let dir = TestDir::new("check-mismatch");
    let path = dir.write_file(OsStr::new("hello.txt"), b"abc");

    // 文件是 "abc"，却给出空文件的摘要作为预期值。
    let empty_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let output = run_check(path.as_os_str(), OsStr::new(empty_hex));

    let stderr = assert_mismatch(&output, empty_hex, ABC_HEX);
    // 预期值在提示中保持小写呈现，即使输入本身是大写。
    let output_upper = run_check(path.as_os_str(), OsStr::new(&empty_hex.to_uppercase()));
    let stderr_upper = assert_mismatch(&output_upper, empty_hex, ABC_HEX);
    assert!(stderr_upper.contains(empty_hex));
    assert!(!stderr_upper.contains(&empty_hex.to_uppercase()));
    // 不能伪装成文件访问问题。
    assert!(!stderr.contains("cannot open"));
    assert!(!stderr.contains("cannot read"));
}

#[test]
fn check_digest_works_for_empty_and_binary_files() {
    let dir = TestDir::new("check-empty-binary");

    let empty = dir.write_file(OsStr::new("empty"), b"");
    let empty_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert_check_ok(&run_check(empty.as_os_str(), OsStr::new(empty_hex)));

    let binary = dir.write_file(OsStr::new("blob.bin"), &binary_content());
    assert_check_ok(&run_check(binary.as_os_str(), OsStr::new(BINARY_HEX)));
}

#[test]
fn check_digest_reads_large_file_with_constant_sized_buffering() {
    let dir = TestDir::new("check-large");
    let data: Vec<u8> = (0..(5 * 64 * 1024 + 777))
        .map(|i| ((i * 31 + 7) % 256) as u8)
        .collect();
    let path = dir.write_file(OsStr::new("large.bin"), &data);
    let expected = inkseal::digest_reader(&data[..]).unwrap().to_hex();

    assert_check_ok(&run_check(path.as_os_str(), OsStr::new(&expected)));
}

#[test]
fn check_digest_missing_file_is_io_failure_not_mismatch() {
    let dir = TestDir::new("check-missing");
    let path = dir.path().join("nope.txt");

    let output = run_check(path.as_os_str(), OsStr::new(ABC_HEX));

    let stderr = assert_failure(&output);
    assert!(stderr.contains("cannot open"), "{stderr:?}");
    assert!(stderr.contains("nope.txt"), "{stderr:?}");
    // 不能把访问失败说成内容不匹配，也不能给出任何摘要。
    assert!(!stderr.to_lowercase().contains("mismatch"), "{stderr:?}");
    assert!(!stderr.contains(ABC_HEX), "{stderr:?}");
}

#[test]
fn check_digest_directory_is_io_failure_not_mismatch() {
    let dir = TestDir::new("check-directory");
    let sub = dir.path().join("a-directory");
    fs::create_dir_all(&sub).unwrap();

    let output = run_check(sub.as_os_str(), OsStr::new(ABC_HEX));

    let stderr = assert_failure(&output);
    assert!(stderr.contains("a-directory"), "{stderr:?}");
    assert!(!stderr.to_lowercase().contains("mismatch"), "{stderr:?}");
}

#[test]
fn check_digest_invalid_hex_is_usage_error_without_opening_file() {
    let dir = TestDir::new("check-bad-digest");
    let missing = dir.path().join("does-not-exist");
    let valid_but_other = dir.write_file(OsStr::new("other.txt"), b"other");

    // 长度不对、非十六进制字符、空格、前缀、尾随换行——即便路径不存在，
    // 报告的也必须是摘要格式问题（退出码 2），而不是文件错误（退出码 1）。
    let cases: &[&[u8]] = &[
        b"abc",                                                              // 太短
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015a",  // 63
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad0",// 65
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015az", // 非 hex
        b"ba7816bf8f01cfea414140de5dae2223b00361a39 6177a9cb410ff61f20015ad",// 夹空格
        b"  ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", // 前导空格
        b"0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", // 前缀
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n", // 尾随换行
    ];

    for bad in cases {
        let bad_os = OsStr::new(std::str::from_utf8(bad).expect("cases are ASCII"));
        let stderr = assert_usage_error(&run_check(missing.as_os_str(), bad_os));
        assert!(
            !stderr.contains("cannot open") && !stderr.contains("cannot read"),
            "digest format must be validated before opening the file (case {bad:?}): {stderr:?}"
        );
        // 即便文件存在也一样：格式错误优先。
        assert_usage_error(&run_check(valid_but_other.as_os_str(), bad_os));
    }
}

#[test]
fn check_digest_missing_and_extra_arguments_are_usage_errors() {
    let dir = TestDir::new("check-arity");
    let path = dir.write_file(OsStr::new("f"), b"abc");

    let none = run_args(&[OsStr::new("check-digest")]);
    assert_usage_error(&none);

    let one = run_args(&[OsStr::new("check-digest"), path.as_os_str()]);
    assert_usage_error(&one);

    let three = inkseal()
        .args(["check-digest"])
        .arg(&path)
        .arg(ABC_HEX)
        .arg("extra")
        .output()
        .unwrap();
    assert_usage_error(&three);
}

#[test]
fn check_digest_does_not_modify_the_file() {
    let dir = TestDir::new("check-readonly");
    let path = dir.write_file(OsStr::new("f"), b"abc");
    let before = fs::read(&path).unwrap();

    assert_check_ok(&run_check(path.as_os_str(), OsStr::new(ABC_HEX)));

    let after = fs::read(&path).unwrap();
    assert_eq!(before, after, "file bytes must be untouched");
    // 也不产生任何结果文件。
    let entries: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(entries.len(), 1, "no result files may be created");
}

#[cfg(unix)]
#[test]
fn check_digest_accepts_non_utf8_filename() {
    use std::os::unix::ffi::OsStrExt;
    let dir = TestDir::new("check-non-utf8");
    let path = dir.write_file(OsStr::from_bytes(b"raw \xff\xfe name.bin"), b"abc");

    assert_check_ok(&run_check(path.as_os_str(), OsStr::new(ABC_HEX)));
}

#[cfg(unix)]
#[test]
fn check_digest_non_utf8_digest_argument_is_usage_error_without_opening_file() {
    use std::os::unix::ffi::OsStrExt;
    let dir = TestDir::new("check-non-utf8-digest");
    let missing = dir.path().join("does-not-exist");

    // 长度恰好 64 字节，但含无法解码为合法文字的字节：属于用法错误，
    // 且在打开文件之前判定。
    let mut bad = [b'0'; 64];
    bad[63] = 0xff;
    let output = run_check(missing.as_os_str(), OsStr::from_bytes(&bad));

    let stderr = assert_usage_error(&output);
    assert!(!stderr.contains("cannot open"), "{stderr:?}");
}

// ── 标准输出写入失败 ─────────────────────────────────────────────────────────

#[cfg(unix)]
mod output_failures {
    use super::*;
    use std::fs::OpenOptions;
    use std::os::unix::io::{FromRawFd, RawFd};
    use std::process::Stdio;

    unsafe extern "C" {
        fn pipe(pipefd: *mut RawFd) -> std::os::raw::c_int;
    }

    /// 构造一个读端已经关闭的管道写端：子进程一写标准输出就收到 EPIPE，
    /// 模拟“结果交给管道而接收方已提前关闭”。
    fn closed_pipe_stdout() -> Stdio {
        let mut fds: [RawFd; 2] = [-1, -1];
        assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
        // 读端立即关闭（File 析构关闭该 fd）。
        drop(unsafe { std::fs::File::from_raw_fd(fds[0]) });
        Stdio::from(unsafe { std::fs::File::from_raw_fd(fds[1]) })
    }

    /// 以读不开写方式打开一个普通文件得到的 fd：对它写入会被内核拒绝，
    /// 模拟“标准输出被重定向到拒绝写入的位置”。
    fn read_only_stdout(path: &Path) -> Stdio {
        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(path)
            .expect("open read-only fd");
        Stdio::from(file)
    }

    fn run_with_stdout(stdout: Stdio, args: &[&OsStr]) -> Output {
        inkseal()
            .args(args)
            .stdout(stdout)
            .output()
            .expect("failed to run inkseal")
    }

    /// 输出失败的完整约定：退出码 1、标准输出为空、标准错误只有一条
    /// inkseal: 的写入失败提示（保留系统原因），没有任何崩溃信息。
    fn assert_output_failure(output: &Output) -> String {
        assert_eq!(output.status.code(), Some(1), "exit code: {output:?}");
        assert!(
            output.stdout.is_empty(),
            "captured stdout must be empty: {:?}",
            String::from_utf8_lossy(&output.stdout)
        );
        let stderr = String::from_utf8(output.stderr.clone()).expect("stderr must be UTF-8");
        assert!(
            stderr.starts_with("inkseal: unable to write to standard output"),
            "must report an output failure, not another error: {stderr:?}"
        );
        assert!(
            stderr.ends_with('\n') && !stderr[..stderr.len() - 1].contains('\n'),
            "hint must be a single line: {stderr:?}"
        );
        // 系统给出的具体原因必须保留，且不能是 Rust 崩溃信息。
        assert!(!stderr.contains("panicked"), "must not crash: {stderr:?}");
        stderr
    }

    #[test]
    fn version_write_failure_exits_1_without_panic() {
        let output = run_with_stdout(closed_pipe_stdout(), &[OsStr::new("--version")]);

        let stderr = assert_output_failure(&output);
        assert!(stderr.to_lowercase().contains("pipe"), "keep OS reason: {stderr:?}");
    }

    #[test]
    fn digest_computed_but_not_delivered_is_still_a_failure() {
        let dir = TestDir::new("digest-dead-pipe");
        let path = dir.write_file(OsStr::new("hello.txt"), b"abc");

        let output = run_with_stdout(
            closed_pipe_stdout(),
            &[OsStr::new("digest"), path.as_os_str()],
        );

        let stderr = assert_output_failure(&output);
        // 不能把输出问题误报成读文件问题，也不能把摘要写到标准错误。
        assert!(!stderr.contains("cannot read"), "{stderr:?}");
        assert!(!stderr.contains(ABC_HEX), "digest must not move to stderr: {stderr:?}");
    }

    #[test]
    fn check_digest_match_but_not_delivered_is_still_a_failure() {
        let dir = TestDir::new("check-dead-pipe");
        let path = dir.write_file(OsStr::new("hello.txt"), b"abc");

        let output = run_with_stdout(
            closed_pipe_stdout(),
            &[
                OsStr::new("check-digest"),
                path.as_os_str(),
                OsStr::new(ABC_HEX),
            ],
        );

        let stderr = assert_output_failure(&output);
        // 不能补写成功标记，也不能误报为不匹配。
        assert!(!stderr.to_lowercase().contains("mismatch"), "{stderr:?}");
        assert!(!stderr.contains("OK"), "must not echo success marker to stderr: {stderr:?}");
    }

    #[test]
    fn redirect_to_unwritable_destination_is_output_failure() {
        let dir = TestDir::new("stdout-readonly");
        let target = dir.write_file(OsStr::new("sink"), b"");

        let output = run_with_stdout(
            read_only_stdout(&target),
            &[OsStr::new("--version")],
        );

        // 只读 fd 上的写入同样是输出失败，而非崩溃或成功。
        assert_output_failure(&output);
    }

    #[test]
    fn failure_branches_are_not_reported_as_output_errors_when_stdout_dead() {
        let dir = TestDir::new("dead-stdout-failures");
        let file = dir.write_file(OsStr::new("hello.txt"), b"abc");
        let missing = dir.path().join("nope.txt");
        let empty_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        // 参数错误仍是退出码 2 与用法提示。
        let usage = run_with_stdout(closed_pipe_stdout(), &[OsStr::new("digest")]);
        assert_eq!(usage.status.code(), Some(2), "{usage:?}");
        let stderr = String::from_utf8_lossy(&usage.stderr);
        assert!(stderr.contains("Usage:"), "{stderr:?}");
        assert!(!stderr.contains("unable to write to standard output"), "{stderr:?}");

        // 摘要格式错误仍是退出码 2，且不访问文件。
        let bad_digest = run_with_stdout(
            closed_pipe_stdout(),
            &[
                OsStr::new("check-digest"),
                missing.as_os_str(),
                OsStr::new("abc"),
            ],
        );
        assert_eq!(bad_digest.status.code(), Some(2), "{bad_digest:?}");
        let stderr = String::from_utf8_lossy(&bad_digest.stderr);
        assert!(stderr.contains("Usage:"), "{stderr:?}");
        assert!(!stderr.contains("unable to write to standard output"), "{stderr:?}");

        // 文件打不开仍是退出码 1 与 cannot open，不是输出错误。
        let open_fail = run_with_stdout(
            closed_pipe_stdout(),
            &[OsStr::new("digest"), missing.as_os_str()],
        );
        assert_eq!(open_fail.status.code(), Some(1), "{open_fail:?}");
        let stderr = assert_failure(&open_fail);
        assert!(stderr.contains("cannot open"), "{stderr:?}");
        assert!(!stderr.contains("unable to write to standard output"), "{stderr:?}");

        // 内容不匹配仍按不匹配报告：没有成功结果需要写出，
        // 不应仅因标准输出不可用而变成输出错误。
        let mismatch = run_with_stdout(
            closed_pipe_stdout(),
            &[
                OsStr::new("check-digest"),
                file.as_os_str(),
                OsStr::new(empty_hex),
            ],
        );
        assert_mismatch(&mismatch, empty_hex, ABC_HEX);
        let stderr = String::from_utf8_lossy(&mismatch.stderr);
        assert!(!stderr.contains("unable to write to standard output"), "{stderr:?}");
    }
}

// ── 标准错误写入失败 ─────────────────────────────────────────────────────────
//
// 用户把标准错误接到另一个程序，而接收方提前关闭管道时，失败提示本身可能
// 写不出去。提示说明的是已经发生的失败：无论标准错误是否还可读，命令对
// 本次操作的判断（退出码 1 或 2）都不能改变，更不能因 eprintln! 在
// EPIPE/EBADF 上 panic 而以 101 崩溃。
#[cfg(unix)]
mod stderr_failures {
    use super::*;
    use std::fs::OpenOptions;
    use std::io;
    use std::os::raw::{c_int, c_void};
    use std::os::unix::io::{FromRawFd, RawFd};
    use std::process::Stdio;

    unsafe extern "C" {
        fn pipe(pipefd: *mut RawFd) -> c_int;
        fn pipe2(pipefd: *mut RawFd, flags: c_int) -> c_int;
        fn read(fd: RawFd, buf: *mut c_void, count: usize) -> isize;
        fn close(fd: RawFd) -> c_int;
        fn fcntl(fd: RawFd, cmd: c_int, arg: c_int) -> c_int;
    }

    /// 构造一个读端已经关闭的管道写端：子进程一写标准错误就收到 EPIPE，
    /// 模拟“错误提示交给管道而接收方已提前关闭”，且一个字节都送不出去。
    fn closed_pipe_stderr() -> Stdio {
        let mut fds: [RawFd; 2] = [-1, -1];
        assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0);
        // 读端立即关闭（File 析构关闭该 fd）。
        drop(unsafe { std::fs::File::from_raw_fd(fds[0]) });
        Stdio::from(unsafe { std::fs::File::from_raw_fd(fds[1]) })
    }

    /// 以只读方式打开一个普通文件得到的 fd：对它写入会被内核拒绝，
    /// 模拟“标准错误从一开始就被定向到拒绝写入的位置”。
    fn read_only_stderr(path: &Path) -> Stdio {
        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(path)
            .expect("open read-only fd");
        Stdio::from(file)
    }

    fn run_with_stderr(stderr: Stdio, args: &[&OsStr]) -> Output {
        inkseal()
            .args(args)
            .stdout(Stdio::piped())
            .stderr(stderr)
            .output()
            .expect("failed to run inkseal")
    }

    /// 标准错误从第一个字节起就不可写时，所有用法错误仍以退出码 2
    /// 正常结束：不崩溃、不改报成功、不把用法说明挪到标准输出。
    #[test]
    fn usage_errors_with_dead_stderr_keep_exit_code_2() {
        let dir = TestDir::new("stderr-usage");
        let file = dir.write_file(OsStr::new("real.txt"), b"abc");
        let missing = dir.path().join("does-not-exist");

        let cases: Vec<Vec<&OsStr>> = vec![
            vec![],                                              // 无参数
            vec![OsStr::new("frobnicate")],                     // 未知子命令
            vec![OsStr::new("digest")],                         // 缺少文件参数
            vec![
                OsStr::new("digest"),
                file.as_os_str(),
                OsStr::new("extra"),
            ],                                                   // 多给参数
            vec![OsStr::new("check-digest")],                   // 缺少两个参数
            vec![OsStr::new("check-digest"), file.as_os_str()], // 缺少摘要参数
            vec![
                // 非法摘要 + 不存在的文件：格式校验先于文件访问，
                // 即使格式提示无法写出，也必须是 2，且不去打开文件。
                OsStr::new("check-digest"),
                missing.as_os_str(),
                OsStr::new("abc"),
            ],
        ];

        for args in cases {
            let output = run_with_stderr(closed_pipe_stderr(), &args);
            assert_eq!(
                output.status.code(),
                Some(2),
                "usage error must exit 2 even with dead stderr, args={args:?}: {output:?}"
            );
            // 必须是正常退出而非被信号终止（panic 会以 101 或 SIGABRT 结束）。
            assert!(output.status.code().is_some(), "must not be killed: {output:?}");
            assert!(
                output.stdout.is_empty(),
                "usage text must never move to stdout: {output:?}"
            );
            assert!(
                output.stderr.is_empty(),
                "dead pipe cannot carry any bytes: {output:?}"
            );
        }
    }

    /// 文件无法打开、路径为目录和摘要不匹配在标准错误完全不可写时，
    /// 仍以退出码 1 正常结束；读取失败同理（见下方只读 fd 之外的情形）。
    #[test]
    fn io_and_mismatch_failures_with_dead_stderr_keep_exit_code_1() {
        let dir = TestDir::new("stderr-failure");
        let file = dir.write_file(OsStr::new("hello.txt"), b"abc");
        let missing = dir.path().join("nope.txt");
        let subdir = dir.path().join("a-directory");
        fs::create_dir_all(&subdir).unwrap();
        let empty_hex =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let cases: Vec<Vec<&OsStr>> = vec![
            vec![OsStr::new("digest"), missing.as_os_str()],
            vec![OsStr::new("digest"), subdir.as_os_str()],
            vec![
                OsStr::new("check-digest"),
                missing.as_os_str(),
                OsStr::new(ABC_HEX),
            ],
            vec![
                OsStr::new("check-digest"),
                subdir.as_os_str(),
                OsStr::new(ABC_HEX),
            ],
            vec![
                OsStr::new("check-digest"),
                file.as_os_str(),
                OsStr::new(empty_hex),
            ],
        ];

        for args in cases {
            let output = run_with_stderr(closed_pipe_stderr(), &args);
            assert_eq!(
                output.status.code(),
                Some(1),
                "failure must keep exit 1 with dead stderr, args={args:?}: {output:?}"
            );
            assert!(
                output.stdout.is_empty(),
                "no success output may appear, args={args:?}: {output:?}"
            );
            assert!(output.stderr.is_empty(), "dead pipe carries no bytes: {output:?}");
        }
    }

    /// 标准错误从一开始就拒绝写入（fd 以只读方式打开，内核直接拒绝）时，
    /// 同样保留退出码且静默结束。
    #[test]
    fn read_only_stderr_keeps_exit_codes_without_panic() {
        let dir = TestDir::new("stderr-readonly");
        let sink = dir.write_file(OsStr::new("sink"), b"");
        let missing = dir.path().join("nope.txt");

        // 每次运行都需要一个新的只读 fd（Stdio 会消耗它）。
        let usage = run_with_stderr(
            read_only_stderr(&sink),
            &[OsStr::new("digest")],
        );
        assert_eq!(usage.status.code(), Some(2), "{usage:?}");
        assert!(usage.stdout.is_empty(), "{usage:?}");

        let open_fail = run_with_stderr(
            read_only_stderr(&sink),
            &[OsStr::new("digest"), missing.as_os_str()],
        );
        assert_eq!(open_fail.status.code(), Some(1), "{open_fail:?}");
        assert!(open_fail.stdout.is_empty(), "{open_fail:?}");
        assert!(
            !String::from_utf8_lossy(&open_fail.stderr).contains("panicked"),
            "must not crash: {open_fail:?}"
        );
    }

    /// 标准错误不可用本身不能使成功操作失败：版本查询、摘要计算、
    /// 核对通过仍照常把结果写到标准输出并以 0 退出。
    #[test]
    fn success_is_unaffected_when_stderr_is_dead() {
        let dir = TestDir::new("stderr-dead-success");
        let path = dir.write_file(OsStr::new("hello.txt"), b"abc");

        let version = run_with_stderr(closed_pipe_stderr(), &[OsStr::new("--version")]);
        assert_eq!(version.status.code(), Some(0), "{version:?}");
        assert_eq!(version.stdout, b"inkseal 0.1.0\n", "{version:?}");
        assert!(version.stderr.is_empty());

        let digest = run_with_stderr(
            closed_pipe_stderr(),
            &[OsStr::new("digest"), path.as_os_str()],
        );
        assert_eq!(digest.status.code(), Some(0), "{digest:?}");
        assert_eq!(digest.stdout, format!("{ABC_HEX}\n").as_bytes(), "{digest:?}");

        let check = run_with_stderr(
            closed_pipe_stderr(),
            &[
                OsStr::new("check-digest"),
                path.as_os_str(),
                OsStr::new(ABC_HEX),
            ],
        );
        assert_eq!(check.status.code(), Some(0), "{check:?}");
        assert_eq!(check.stdout, b"OK\n", "{check:?}");
    }

    /// 成功结果无法写到标准输出、且连输出失败提示也无法写到标准错误时，
    /// 按既有规则以 1 静默结束：两个流都为空，也没有崩溃信息。
    #[test]
    fn undeliverable_success_with_both_streams_dead_is_silent_exit_1() {
        let dir = TestDir::new("both-dead");
        let path = dir.write_file(OsStr::new("hello.txt"), b"abc");

        let cases: Vec<Vec<&OsStr>> = vec![
            vec![OsStr::new("--version")],
            vec![OsStr::new("digest"), path.as_os_str()],
            vec![
                OsStr::new("check-digest"),
                path.as_os_str(),
                OsStr::new(ABC_HEX),
            ],
        ];
        for args in cases {
            let output = inkseal()
                .args(&args)
                .stdout(closed_pipe_stderr())
                .stderr(closed_pipe_stderr())
                .output()
                .expect("failed to run inkseal");
            assert_eq!(output.status.code(), Some(1), "args={args:?}: {output:?}");
            assert!(output.stdout.is_empty(), "args={args:?}: {output:?}");
            assert!(output.stderr.is_empty(), "args={args:?}: {output:?}");
        }
    }

    /// 管道只接收了提示的前几个字节、接收方便提前关闭时，子进程在后续
    /// 写入上收到 EPIPE：已发出的字节保留，退出码仍为 1，进程正常结束。
    ///
    /// 确定性地制造“部分送达后失败”：把管道容量缩到一个页面（4096），
    /// 再让提示本身远大于该容量（超长路径触发的文件错误）。内核对
    /// 大于 PIPE_BUF 的阻塞写是非原子的——写满容量后子进程阻塞等待，
    /// 此时关闭读端，剩余写入必然以 EPIPE 失败，而提示开头的字节已经
    /// 送达。若提示仍经由 eprintln! 写出，子进程会 panic（101/信号）。
    #[cfg(target_os = "linux")]
    #[test]
    fn partial_stderr_write_failure_keeps_exit_code_without_panic() {
        const F_SETPIPE_SZ: c_int = 1024 + 7;
        // arm64/x86-64 Linux 上 O_CLOEXEC 均为 02000000（八进制）。
        const O_CLOEXEC: c_int = 0o2000000;

        let dir = TestDir::new("stderr-partial");
        // 单条错误提示远超 PIPE_BUF（4096）：含约 10000 字节的路径名。
        // 该路径无法打开（ENAMETOOLONG），属于退出码 1 的文件访问失败。
        let path = dir.path().join("A".repeat(10_000));

        // pipe2(…, O_CLOEXEC) 至关重要：读端不能被子进程继承，否则测试
        // 关闭自己的读端副本后子进程仍持有读端，会无限阻塞地写给自己。
        let mut fds: [RawFd; 2] = [-1, -1];
        assert_eq!(
            unsafe { pipe2(fds.as_mut_ptr(), O_CLOEXEC) },
            0,
            "{}",
            io::Error::last_os_error()
        );
        let set = unsafe { fcntl(fds[1], F_SETPIPE_SZ, 4096) };
        assert!(set >= 0, "shrink pipe: {}", io::Error::last_os_error());

        let write_end = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        let child = inkseal()
            .args(["digest"])
            .arg(path.as_os_str())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(write_end))
            .spawn()
            .expect("failed to run inkseal");

        // 子进程的首次写入已填满 4096 字节容量后阻塞；一次性取出这段
        // 连续的提示前缀（在子进程补入更多字节之前读完）。
        let mut prefix = vec![0u8; 4096];
        read_full(fds[0], &mut prefix);
        assert!(
            prefix.starts_with(b"inkseal: cannot open '"),
            "delivered prefix must be the real hint: {:?}",
            String::from_utf8_lossy(&prefix[..40.min(prefix.len())])
        );

        // 接收方提前关闭：管道中已送达的提示前缀无需也无法补齐，
        // 子进程剩余写入立即失败，但必须仍以退出码 1 正常结束。
        assert_eq!(unsafe { close(fds[0]) }, 0);

        let output = child.wait_with_output().expect("failed to wait");
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("panicked"),
            "must not crash: {output:?}"
        );
    }

    /// 阻塞地从 fd 读满 `buf`，EINTR 立即重试。
    #[cfg(target_os = "linux")]
    fn read_full(fd: RawFd, mut buf: &mut [u8]) {
        while !buf.is_empty() {
            let n = unsafe { read(fd, buf.as_mut_ptr().cast::<c_void>(), buf.len()) };
            assert!(n > 0, "read pipe: {}", io::Error::last_os_error());
            let len = n as usize;
            buf = &mut buf[len..];
        }
    }
}

// ── 临时中断与短写之后的完整交付（Linux）────────────────────────────────────
//
// 既有测试覆盖了管道提前关闭、拒绝写入、部分送达后失败；本模块保障另一侧：
// 只要接收方恢复接收，临时中断（EINTR）与一次只接收部分字节（短写）都不能
// 造成结果缺失、重复或误报失败——最终交付的字节流与无中断时逐字节相同。
//
// 确定性注入靠 LD_PRELOAD shim（见 SHIM_SOURCE）：拦截子进程对 fd 1/2 的
// write()，按脚本返回 EINTR、短写、零进展或不可恢复错误。真实管道无法
// 制造这些条件（≤PIPE_BUF 的写是原子的，且子进程不装信号处理器时不会
// 产生 EINTR），因此 shim 在测试运行时用 rustc 现场编译。
#[cfg(target_os = "linux")]
mod resumed_delivery {
    use super::*;
    use std::io;
    use std::io::Read as _;
    use std::os::raw::{c_int, c_void};
    use std::os::unix::io::{FromRawFd, RawFd};
    use std::process::Stdio;
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    unsafe extern "C" {
        fn pipe2(pipefd: *mut RawFd, flags: c_int) -> c_int;
        fn read(fd: RawFd, buf: *mut c_void, count: usize) -> isize;
        fn close(fd: RawFd) -> c_int;
        fn fcntl(fd: RawFd, cmd: c_int, arg: c_int) -> c_int;
    }

    /// LD_PRELOAD shim 的源码：按环境变量脚本驱动子进程对 fd 1/2 的 write()。
    ///
    /// 脚本经 INKSEAL_SHIM_SCRIPT_OUT / INKSEAL_SHIM_SCRIPT_ERR 传入，逗号
    /// 分隔，每次 write 调用消耗一个记号：
    ///   E    返回 -1，errno = EINTR（临时中断，之后仍可继续写入）
    ///   s<N> 短写：只写入 N 字节并返回 N（一次只接收部分字节）
    ///   Z    返回 0（尚有内容待写却毫无进展）
    ///   B    返回 -1，errno = EIO（不可恢复的写入错误）
    ///   N    原样透传（完整写入）
    /// 脚本用完后一律透传。子进程是单线程的，静态计数器无需同步。
    const SHIM_SOURCE: &str = r#"
use std::ffi::{c_char, c_int, c_void};

type WriteFn = unsafe extern "C" fn(c_int, *const c_void, usize) -> isize;

const EINTR: c_int = 4;
const EIO: c_int = 5;
const RTLD_NEXT: *mut c_void = -1isize as *mut c_void;

extern "C" {
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn getenv(name: *const c_char) -> *mut c_char;
    fn __errno_location() -> *mut c_int;
}

static mut REAL_WRITE: Option<WriteFn> = None;
static mut SCRIPT_OUT: Option<Vec<u8>> = None;
static mut SCRIPT_ERR: Option<Vec<u8>> = None;
static mut IDX_OUT: usize = 0;
static mut IDX_ERR: usize = 0;

unsafe fn real_write() -> WriteFn {
    if REAL_WRITE.is_none() {
        let sym = dlsym(RTLD_NEXT, b"write\0".as_ptr().cast());
        assert!(!sym.is_null(), "shim: cannot resolve real write");
        REAL_WRITE = Some(std::mem::transmute::<*mut c_void, WriteFn>(sym));
    }
    REAL_WRITE.unwrap()
}

fn set_errno(value: c_int) {
    unsafe { *__errno_location() = value }
}

unsafe fn script_for(fd: c_int) -> &'static [u8] {
    let slot: *mut Option<Vec<u8>> = if fd == 1 { &mut SCRIPT_OUT } else { &mut SCRIPT_ERR };
    if (*slot).is_none() {
        let name: &[u8] = if fd == 1 {
            b"INKSEAL_SHIM_SCRIPT_OUT\0"
        } else {
            b"INKSEAL_SHIM_SCRIPT_ERR\0"
        };
        let p = getenv(name.as_ptr().cast());
        let mut script = Vec::new();
        if !p.is_null() {
            let mut len = 0;
            while *p.add(len) != 0 {
                len += 1;
            }
            script = std::slice::from_raw_parts(p.cast::<u8>(), len).to_vec();
        }
        *slot = Some(script);
    }
    (*slot).as_deref().unwrap()
}

unsafe fn next_token(fd: c_int) -> Option<String> {
    let idx: &mut usize = if fd == 1 { &mut IDX_OUT } else { &mut IDX_ERR };
    let script = script_for(fd);
    if *idx >= script.len() {
        return None;
    }
    let rest = &script[*idx..];
    let take = rest.iter().position(|&b| b == b',').unwrap_or(rest.len());
    let token = String::from_utf8_lossy(&rest[..take]).into_owned();
    // 越过分隔逗号；末尾无逗号时越过结尾，下次调用返回 None。
    *idx += take + 1;
    Some(token)
}

#[no_mangle]
pub unsafe extern "C" fn write(fd: c_int, buf: *const c_void, count: usize) -> isize {
    let real = real_write();
    if fd == 1 || fd == 2 {
        if let Some(token) = next_token(fd) {
            let token = token.trim();
            if token == "E" {
                set_errno(EINTR);
                return -1;
            }
            if token == "Z" {
                return 0;
            }
            if token == "B" {
                set_errno(EIO);
                return -1;
            }
            if let Some(n) = token.strip_prefix('s').and_then(|rest| rest.parse::<usize>().ok()) {
                return real(fd, buf, n.min(count));
            }
            // "N" 或未识别记号：原样透传。
        }
    }
    real(fd, buf, count)
}
"#;

    /// 编译（每个测试进程一次）并返回 shim 共享库的路径。
    fn shim_path() -> &'static Path {
        static SHIM: OnceLock<PathBuf> = OnceLock::new();
        SHIM.get_or_init(|| {
            let dir = option_env!("CARGO_TARGET_TMPDIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    std::env::temp_dir().join(format!("inkseal-shim-{}", std::process::id()))
                });
            fs::create_dir_all(&dir).expect("create shim dir");
            let src = dir.join("write_shim.rs");
            let so = dir.join("libinkseal_write_shim.so");
            fs::write(&src, SHIM_SOURCE).expect("write shim source");
            let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
            let build = Command::new(rustc)
                .args(["--edition", "2021", "--crate-type", "cdylib", "-O"])
                .arg(&src)
                .arg("-o")
                .arg(&so)
                .output()
                .expect("run rustc to build the LD_PRELOAD shim");
            assert!(
                build.status.success(),
                "shim build failed: {}",
                String::from_utf8_lossy(&build.stderr)
            );
            so
        })
    }

    /// 以 shim 脚本运行命令并等待结束。超过时限视为实现陷入空转（例如对
    /// 零进展写入无限重试）：杀掉子进程并让测试失败，而不是挂住整个套件。
    fn run_scripted(script_out: Option<&str>, script_err: Option<&str>, args: &[&OsStr]) -> Output {
        let mut cmd = inkseal();
        cmd.args(args).env("LD_PRELOAD", shim_path());
        if let Some(script) = script_out {
            cmd.env("INKSEAL_SHIM_SCRIPT_OUT", script);
        }
        if let Some(script) = script_err {
            cmd.env("INKSEAL_SHIM_SCRIPT_ERR", script);
        }
        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to run inkseal");
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = child.try_wait().expect("try_wait") {
                // 进程已结束：收齐两个流的全部字节。
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                child.stdout.take().unwrap().read_to_end(&mut stdout).unwrap();
                child.stderr.take().unwrap().read_to_end(&mut stderr).unwrap();
                return Output { status, stdout, stderr };
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("child did not exit within 30s (endless retry?), args={args:?}");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// 与 src/main.rs 中 USAGE 加末尾换行一致的完整用法文本。
    const USAGE_TEXT: &str = "Usage: inkseal --version\n       inkseal digest <file>\n       inkseal check-digest <file> <digest>\n";

    #[test]
    fn digest_line_intact_after_interleaved_interrupts_and_short_writes() {
        let dir = TestDir::new("resume-digest");
        let path = dir.write_file(OsStr::new("hello.txt"), b"abc");

        // 连续中断、中断夹在短写之间、逐字节短写、脚本耗尽后透传：
        // 最终交付必须与无中断时逐字节相同——每个字节恰好一次，
        // 顺序不变，末尾换行不丢。
        let output = run_scripted(
            Some("E,s1,E,E,s7,s1,E,s13,s40"),
            None,
            &[OsStr::new("digest"), path.as_os_str()],
        );

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_eq!(output.stdout, format!("{ABC_HEX}\n").as_bytes(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
    }

    #[test]
    fn ok_line_intact_after_interrupts_before_first_byte() {
        let dir = TestDir::new("resume-ok");
        let path = dir.write_file(OsStr::new("hello.txt"), b"abc");

        // 第一个字节送出之前连续中断：中断不是输出结束。
        let output = run_scripted(
            Some("E,E,E,E"),
            None,
            &[
                OsStr::new("check-digest"),
                path.as_os_str(),
                OsStr::new(ABC_HEX),
            ],
        );

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_eq!(output.stdout, b"OK\n", "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
    }

    #[test]
    fn version_line_intact_after_short_writes_and_interrupt() {
        let output = run_scripted(Some("s1,s2,E,s3"), None, &[OsStr::new("--version")]);

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_eq!(output.stdout, b"inkseal 0.1.0\n", "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
    }

    #[test]
    fn usage_error_intact_after_interleaved_interrupts_and_short_writes() {
        let output = run_scripted(None, Some("E,s5,E,E,s9,s1,E"), &[OsStr::new("digest")]);

        // 用法提示完整交付后仍是退出码 2，标准输出为空。
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert_eq!(output.stderr, USAGE_TEXT.as_bytes(), "{output:?}");
    }

    #[test]
    fn invalid_digest_hint_intact_after_interleaved_interrupts_and_short_writes() {
        let dir = TestDir::new("resume-bad-digest");
        let missing = dir.path().join("does-not-exist");

        let output = run_scripted(
            None,
            Some("s2,E,s11,E,s5"),
            &[
                OsStr::new("check-digest"),
                missing.as_os_str(),
                OsStr::new("abc"),
            ],
        );

        let expected = format!(
            "inkseal: invalid expected digest: \
             expected digest must be exactly 64 ASCII hexadecimal characters, got 3\n\
             {USAGE_TEXT}"
        );
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert_eq!(output.stderr, expected.as_bytes(), "{output:?}");
    }

    #[test]
    fn cannot_open_hint_intact_after_interleaved_interrupts_and_short_writes() {
        let dir = TestDir::new("resume-open");
        let missing = dir.path().join("nope.txt");

        let output = run_scripted(
            None,
            Some("s3,E,s8,E,E,s17"),
            &[OsStr::new("digest"), missing.as_os_str()],
        );

        // 与无中断时完全一致的提示：同样的行结构、路径与系统原因。
        let expected = format!(
            "inkseal: cannot open '{}': {}\n",
            missing.to_string_lossy(),
            fs::File::open(&missing).unwrap_err()
        );
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert_eq!(output.stderr, expected.as_bytes(), "{output:?}");
    }

    #[test]
    fn mismatch_hint_lists_each_digest_exactly_once_after_resume() {
        let dir = TestDir::new("resume-mismatch");
        let path = dir.write_file(OsStr::new("hello.txt"), b"abc");
        let empty_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let output = run_scripted(
            None,
            Some("E,s4,E,s6,E,s2,s100"),
            &[
                OsStr::new("check-digest"),
                path.as_os_str(),
                OsStr::new(empty_hex),
            ],
        );

        // 多行提示完整交付：行结构、预期值与实际值都与无中断时一致。
        let expected = format!(
            "inkseal: digest mismatch for '{}'\nexpected: {empty_hex}\nactual:   {ABC_HEX}\n",
            path.to_string_lossy()
        );
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert_eq!(output.stderr, expected.as_bytes(), "{output:?}");
        // 预期值与实际值各出现恰好一次：续写不能重复已交付的开头。
        let stderr = String::from_utf8(output.stderr.clone()).unwrap();
        assert_eq!(stderr.matches(empty_hex).count(), 1, "{stderr:?}");
        assert_eq!(stderr.matches(ABC_HEX).count(), 1, "{stderr:?}");
    }

    #[test]
    fn unrecoverable_error_after_partial_success_prefix_exits_1() {
        let dir = TestDir::new("resume-then-dead");
        let path = dir.write_file(OsStr::new("hello.txt"), b"abc");
        let line = format!("{ABC_HEX}\n");

        // 前 10 个字节已交付，随后写入彻底失败：守住临时受阻与无法
        // 继续之间的边界——已送出的前缀保留，不补发整行，结果不转移
        // 到标准错误，退出码为 1。
        let output = run_scripted(
            Some("s10,B"),
            None,
            &[OsStr::new("digest"), path.as_os_str()],
        );

        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert_eq!(output.stdout, line.as_bytes()[..10], "{output:?}");
        let stderr = String::from_utf8(output.stderr.clone()).expect("stderr must be UTF-8");
        assert!(
            stderr.starts_with("inkseal: unable to write to standard output"),
            "{stderr:?}"
        );
        assert!(
            stderr.ends_with('\n') && !stderr[..stderr.len() - 1].contains('\n'),
            "hint must be a single line: {stderr:?}"
        );
        assert!(!stderr.contains(ABC_HEX), "digest must not move to stderr: {stderr:?}");
        assert!(!stderr.contains("panicked"), "must not crash: {stderr:?}");
    }

    #[test]
    fn zero_progress_write_is_output_failure_not_endless_retry() {
        let dir = TestDir::new("zero-progress");
        let path = dir.write_file(OsStr::new("hello.txt"), b"abc");

        // 尚有内容待写却返回零字节：按输出失败结束，不能无限等待。
        // （若实现在此空转，run_scripted 的时限会让本测试失败而非挂住。）
        let output = run_scripted(
            Some("Z"),
            None,
            &[OsStr::new("digest"), path.as_os_str()],
        );

        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let stderr = String::from_utf8(output.stderr.clone()).expect("stderr must be UTF-8");
        assert!(
            stderr.starts_with("inkseal: unable to write to standard output"),
            "{stderr:?}"
        );
        assert!(!stderr.contains("panicked"), "must not crash: {stderr:?}");
    }

    #[test]
    fn zero_progress_on_usage_hint_keeps_exit_code_2() {
        // 用法错误的提示自身写不出任何进展：仍以退出码 2 正常结束，
        // 不崩溃、不改报、不把提示挪到标准输出。
        let output = run_scripted(None, Some("Z"), &[OsStr::new("digest")]);

        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
    }

    #[test]
    fn unrecoverable_error_mid_hint_keeps_partial_hint_and_exit_code() {
        let dir = TestDir::new("hint-then-dead");
        let missing = dir.path().join("nope.txt");

        // 提示送出 6 个字节后写入彻底失败：已送出的前缀保留，不补齐、
        // 不重试，退出码仍是原操作的 1，进程正常结束。
        let output = run_scripted(
            None,
            Some("s6,B"),
            &[OsStr::new("digest"), missing.as_os_str()],
        );

        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert_eq!(output.stderr, b"inksea", "{output:?}");
    }

    /// 不借助 shim 的真实管道场景：提示远超管道容量，接收方缓慢但持续地
    /// 读取——子进程写满容量后阻塞，接收方每取走一段，子进程续写一段，
    /// 最终交付的提示必须与无阻塞时逐字节相同。
    #[test]
    fn long_hint_fully_delivered_through_slowly_drained_pipe() {
        const F_SETPIPE_SZ: c_int = 1024 + 7;
        // arm64/x86-64 Linux 上 O_CLOEXEC 均为 02000000（八进制）。
        const O_CLOEXEC: c_int = 0o2000000;

        let dir = TestDir::new("resume-long-hint");
        // 单条错误提示远超 PIPE_BUF（4096）：含约 10000 字节的路径名。
        let path = dir.path().join("A".repeat(10_000));

        // pipe2(…, O_CLOEXEC)：读端不能被子进程继承（同既有部分送达测试）。
        let mut fds: [RawFd; 2] = [-1, -1];
        assert_eq!(
            unsafe { pipe2(fds.as_mut_ptr(), O_CLOEXEC) },
            0,
            "{}",
            io::Error::last_os_error()
        );
        let set = unsafe { fcntl(fds[1], F_SETPIPE_SZ, 4096) };
        assert!(set >= 0, "shrink pipe: {}", io::Error::last_os_error());

        let write_end = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        let child = inkseal()
            .args(["digest"])
            .arg(path.as_os_str())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(write_end))
            .spawn()
            .expect("failed to run inkseal");

        // 缓慢但持续地读到 EOF：每次只取一小段，让子进程反复阻塞-续写。
        let mut delivered = Vec::new();
        let mut buf = [0u8; 997];
        loop {
            let n = unsafe { read(fds[0], buf.as_mut_ptr().cast::<c_void>(), buf.len()) };
            assert!(n >= 0, "read pipe: {}", io::Error::last_os_error());
            if n == 0 {
                break;
            }
            delivered.extend_from_slice(&buf[..n as usize]);
        }
        assert_eq!(unsafe { close(fds[0]) }, 0);

        let output = child.wait_with_output().expect("failed to wait");
        let expected = format!(
            "inkseal: cannot open '{}': {}\n",
            path.to_string_lossy(),
            fs::File::open(&path).unwrap_err()
        );
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert_eq!(delivered, expected.as_bytes());
    }
}
