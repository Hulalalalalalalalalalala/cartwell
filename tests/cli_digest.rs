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
