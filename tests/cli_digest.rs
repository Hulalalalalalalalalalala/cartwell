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

// ── 读取临时受阻后继续（EINTR 与短读）与部分读取后失败 ─────────────────────────
//
// check-digest 打开文件后，读取循环必须持续到明确读到文件结束：一次 read
// 只返回少量字节（短读）不是结束，可恢复的临时中断（EINTR，一个字节都没
// 读到）也不是结束，二者都必须在原位置继续；只有 read 明确返回 0 才是
// 结束。若已读入部分内容后出现真正的读取错误，这是读取失败：退出码 1、
// 标准输出为空、沿用 `cannot read` 提示并给出路径与具体原因，绝不能因为
// “已经读到的前缀摘要恰好等于预期摘要”而报 OK，也不能退化为不匹配。
//
// 与输出侧重试相同，这类读取序列无法从父进程一侧确定性地制造，因此用
// LD_PRELOAD 垫片拦截子进程的 read，按 INKSEAL_READ_SHIM 给出的逗号分隔
// 脚本逐步注入临时中断、短读与不可恢复错误，脚本耗尽后透传真实读取。
#[cfg(target_os = "linux")]
mod read_retry {
    use super::*;
    use std::sync::OnceLock;

    /// LD_PRELOAD 垫片源码：拦截子进程对已打开输入文件（fd 3 及以上）的
    /// read 调用，按 INKSEAL_READ_SHIM 的逗号分隔脚本逐步执行，脚本耗尽
    /// 后透传真实读取。步骤：`i` = 返回 EINTR（不读到任何字节）；
    /// `sN` = 最多读取 N 字节的短读；`eN` = 返回 errno 为 N 的真实错误。
    ///
    /// 垫片自身读取时直接走 read 系统调用，绕开对 read 符号的拦截，否则
    /// 透传分支会递归进入自己。垫片不引入任何 crate 依赖，测试运行时用
    /// rustc 编译为 cdylib。
    const SHIM_SOURCE: &str = r#"
use std::os::raw::{c_int, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

#[derive(Clone, Copy)]
enum Step {
    Intr,
    Short(usize),
    Errno(c_int),
}

fn steps() -> &'static [Step] {
    static STEPS: OnceLock<Vec<Step>> = OnceLock::new();
    STEPS
        .get_or_init(|| {
            std::env::var("INKSEAL_READ_SHIM")
                .unwrap_or_default()
                .split(',')
                .filter(|token| !token.is_empty())
                .map(|token| {
                    if token == "i" {
                        Step::Intr
                    } else if let Some(n) = token.strip_prefix('s') {
                        Step::Short(n.parse().expect("short-read length"))
                    } else if let Some(e) = token.strip_prefix('e') {
                        Step::Errno(e.parse().expect("errno"))
                    } else {
                        panic!("unknown shim step: {token}");
                    }
                })
                .collect()
        })
        .as_slice()
}

static STEP_INDEX: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    fn syscall(number: isize, ...) -> isize;
    fn __errno_location() -> *mut c_int;
}

#[cfg(target_arch = "x86_64")]
const SYS_READ: isize = 0;
#[cfg(target_arch = "aarch64")]
const SYS_READ: isize = 63;

const EINTR: c_int = 4;

fn fail(errno: c_int) -> isize {
    unsafe { *__errno_location() = errno };
    -1
}

fn real_read(fd: c_int, buf: *mut c_void, count: usize) -> isize {
    // 直接发起 read 系统调用：不能调用 libc 的 read，否则会被本垫片
    // 再次拦截而无限递归。
    unsafe { syscall(SYS_READ, fd, buf, count) }
}

#[no_mangle]
pub unsafe extern "C" fn read(fd: c_int, buf: *mut c_void, count: usize) -> isize {
    // 只驱动被核对的输入文件：子进程的标准描述符固定为 0–2，命令打开
    // 文件后得到 fd 3。脚本耗尽后一律透传，启动阶段即便存在其他读取
    // （已确认本进程没有）也不会受到影响。
    if fd >= 3 {
        let index = STEP_INDEX.fetch_add(1, Ordering::SeqCst);
        match steps().get(index) {
            Some(Step::Intr) => return fail(EINTR),
            Some(Step::Errno(errno)) => return fail(*errno),
            Some(Step::Short(limit)) => return real_read(fd, buf, count.min(*limit)),
            None => {}
        }
    }
    real_read(fd, buf, count)
}
"#;

    /// Linux 上各架构一致的 errno 值。
    const EIO: i32 = 5;
    const EACCES: i32 = 13;

    /// errno 5（EIO）经标准库显示的具体原因。
    const EIO_REASON: &str = "Input/output error (os error 5)";
    /// errno 13（EACCES）经标准库显示的具体原因。
    const EACCES_REASON: &str = "Permission denied (os error 13)";

    /// 每个测试进程只编译一次垫片，产物放在临时目录。
    fn read_shim() -> &'static Path {
        static SHIM: OnceLock<PathBuf> = OnceLock::new();
        SHIM.get_or_init(|| {
            let dir = std::env::temp_dir()
                .join(format!("inkseal-read-shim-{}", std::process::id()));
            fs::create_dir_all(&dir).expect("create shim dir");
            let source = dir.join("read_shim.rs");
            let library = dir.join("libinkseal_read_shim.so");
            fs::write(&source, SHIM_SOURCE).expect("write shim source");
            let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
            let status = Command::new(rustc)
                .arg("--edition=2021")
                .arg("--crate-type=cdylib")
                .arg("-O")
                .arg("-o")
                .arg(&library)
                .arg(&source)
                .status()
                .expect("run rustc for read shim");
            assert!(status.success(), "read shim must compile");
            library
        })
    }

    /// 在读取垫片脚本作用下运行 check-digest，两个流按默认方式捕获。
    fn run_check_with_read_shim(script: &str, path: &Path, expected: &OsStr) -> Output {
        inkseal()
            .arg("check-digest")
            .arg(path)
            .arg(expected)
            .env("LD_PRELOAD", read_shim())
            .env("INKSEAL_READ_SHIM", script)
            .output()
            .expect("failed to run inkseal")
    }

    /// 文件已打开、读到部分内容后读取失败的完整约定：退出码 1（正常结束
    /// 而非被信号杀死）、标准输出为空、标准错误是一条单行
    /// `inkseal: cannot read '<路径>': failed to read input: <原因>`，
    /// 既不是打不开、不匹配或输出失败，也不出现崩溃信息或任何摘要值。
    fn assert_cannot_read(output: &Output, file_name: &str, reason: &str) {
        assert_eq!(output.status.code(), Some(1), "exit code: {output:?}");
        assert!(output.status.code().is_some(), "must end normally, not killed: {output:?}");
        assert!(
            output.stdout.is_empty(),
            "stdout must stay empty on read failure: {:?}",
            String::from_utf8_lossy(&output.stdout)
        );
        let stderr = String::from_utf8(output.stderr.clone()).expect("stderr must be UTF-8");
        assert!(
            stderr.ends_with('\n') && !stderr[..stderr.len() - 1].contains('\n'),
            "hint must be a single line: {stderr:?}"
        );
        assert!(
            stderr.starts_with("inkseal: cannot read '"),
            "must report a read failure: {stderr:?}"
        );
        assert!(
            stderr.contains(file_name),
            "must name the failing path: {stderr:?}"
        );
        assert!(
            stderr.contains("failed to read input"),
            "must keep the existing read-failure wording: {stderr:?}"
        );
        assert!(
            stderr.contains(reason),
            "must keep the specific OS cause {reason:?}: {stderr:?}"
        );
        for forbidden in [
            "cannot open",
            "mismatch",
            "unable to write",
            "panicked",
            "expected:",
            "actual:",
            "OK",
        ] {
            assert!(
                !stderr.contains(forbidden),
                "{forbidden:?} must not appear in a read-failure hint: {stderr:?}"
            );
        }
        // 绝不输出任何 64 位十六进制摘要——已读前缀的摘要也不能出现。
        let leaks_digest = stderr
            .split(|c: char| !c.is_ascii_hexdigit())
            .any(|token| token.len() == 64);
        assert!(!leaks_digest, "no digest value may appear in the hint: {stderr:?}");
    }

    /// 含零字节、非法 UTF-8 与 LF/CRLF/CR 三种换行、且无末尾换行的内容。
    /// 独立依据：python3 hashlib.sha256(下面这 48 个字节)（与库常量一致）。
    const SPECIAL_HEX: &str =
        "879e1d6af3829ebad59012630ce80b422b1bf81dbdc2bc0c1ba940f46f2dde3c";

    fn special_content() -> Vec<u8> {
        b"alpha\nbeta\r\ngamma\rdelta\n\x00\xff\xfe\x80tail-without-newline".to_vec()
    }

    /// 独立依据：python3 对 (i*31+7)%256、长度 3*64KiB+1234 的序列计算结果
    /// （与库内长内容常量一致）。
    const LONG_HEX: &str =
        "8ca02b16ce35f9fca993a0fdf5a537fc72a62a77b2e6fa852a371f18b8e3fcc4";

    fn long_content() -> Vec<u8> {
        (0..(3 * 64 * 1024 + 1234))
            .map(|i| ((i * 31 + 7) % 256) as u8)
            .collect()
    }

    /// 已读前缀（32 字节）与其后尚未读取的后缀（44 字节）；预期摘要故意
    /// 可以指向前缀，制造“已读部分恰好匹配”的误判陷阱。
    const PREFIX: &[u8] = b"partial bytes before the failure";
    const SUFFIX: &[u8] = b"::remaining bytes that must also be digested";
    /// 独立依据：python3 hashlib.sha256(PREFIX)（亦与库测试注释交叉一致）。
    const PREFIX_HEX: &str =
        "2b7e878471b3ebc8ea1c831f07bb3adc450e78ca01c751e760b7de84a6ed3df1";
    /// 独立依据：python3 hashlib.sha256(PREFIX ++ SUFFIX)。
    const FULL_HEX: &str =
        "adaae83de72a3240a7edf4b2bacf187ab0d4c76a6c1648ebd0667ef881f98603";

    fn trap_content() -> Vec<u8> {
        let mut data = PREFIX.to_vec();
        data.extend_from_slice(SUFFIX);
        data
    }

    #[test]
    fn interruptions_before_first_byte_between_bytes_and_before_eof_still_check_whole_file() {
        let dir = TestDir::new("read-intr-special");
        let content = special_content();
        assert_eq!(content.len(), 48, "test fixture length");
        let path = dir.write_file(OsStr::new("special.bin"), &content);

        // 第一个字节之前中断；随后每次只读 1 字节（短读不代表结束）；
        // 最后一段内容之后、确认 EOF 之前再中断一次。脚本耗尽后透传，
        // 由一次真实的 read 返回 0 明确结束。
        let mut steps = vec!["i".to_string()];
        steps.extend((0..content.len()).map(|_| "s1".to_string()));
        steps.push("i".to_string());

        let output = run_check_with_read_shim(&steps.join(","), &path, OsStr::new(SPECIAL_HEX));

        // 结果必须对应整份原始字节：零字节、非 UTF-8 与各种换行都保留，
        // 后续内容不遗漏，已读字节不重复——任何偏差都会让摘要不同。
        assert_check_ok(&output);
    }

    #[test]
    fn one_byte_reads_are_not_treated_as_end_of_file() {
        let dir = TestDir::new("read-one-byte");
        let content = special_content();
        let path = dir.write_file(OsStr::new("special.bin"), &content);

        // 全程每次只读到 1 个字节；循环必须持续到 read 明确返回 0，
        // 绝不能把“这次只拿到少量字节”当作文件结束。
        let script = vec!["s1"; content.len()].join(",");
        let output = run_check_with_read_shim(&script, &path, OsStr::new(SPECIAL_HEX));

        assert_check_ok(&output);
    }

    #[test]
    fn interruption_after_final_chunk_before_eof_does_not_end_check_early() {
        let dir = TestDir::new("read-intr-long");
        let content = long_content();
        let path = dir.write_file(OsStr::new("long.bin"), &content);

        // 独立常量与库计算交叉一致，避免库与命令共享同一缺陷却通过测试。
        assert_eq!(
            inkseal::digest_reader(&content[..]).unwrap().to_hex(),
            LONG_HEX
        );

        // 跨越多次内部读取，末段不整齐；最后一段内容读完后、确认结束前
        // 发生中断（甚至连续多次），核对都必须继续到明确的 EOF 再比较。
        let chunks = vec!["s60000"; 4].join(",");
        let one_intr = format!("{chunks},i");
        let repeated_intr = format!("{chunks},i,i,i");
        for script in [one_intr, repeated_intr] {
            let output =
                run_check_with_read_shim(&script, &path, OsStr::new(LONG_HEX));
            assert_check_ok(&output);
        }
    }

    #[test]
    fn interrupted_read_of_empty_file_reaches_explicit_eof() {
        let dir = TestDir::new("read-intr-empty");
        let path = dir.write_file(OsStr::new("empty"), b"");
        let empty_hex =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        // 唯一一次读取先被中断：重试后必须由真实 read 返回 0 确认空文件，
        // 中断本身既不是结束也不是失败。
        let output = run_check_with_read_shim("i", &path, OsStr::new(empty_hex));

        assert_check_ok(&output);
    }

    #[test]
    fn real_read_error_after_partial_content_is_cannot_read_without_any_digest() {
        let dir = TestDir::new("read-fail-partial");
        let path = dir.write_file(OsStr::new("trap.bin"), &trap_content());

        // 先成功读到部分内容（两次短读，至多 32 字节），随后出现真正的
        // 读取错误 EIO；即便给出的预期摘要与整份文件相符，也不能报 OK。
        let output = run_check_with_read_shim(
            &format!("s16,s16,e{EIO}"),
            &path,
            OsStr::new(FULL_HEX),
        );

        assert_cannot_read(&output, "trap.bin", EIO_REASON);
        // 既不能给出整份文件的摘要，也不能给出已读前缀的摘要。
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains(FULL_HEX), "{stderr:?}");
        assert!(!stderr.contains(PREFIX_HEX), "{stderr:?}");
    }

    #[test]
    fn digest_matching_read_prefix_with_unread_bytes_then_error_is_still_read_failure() {
        let dir = TestDir::new("read-prefix-trap");
        let data = trap_content();
        let path = dir.write_file(OsStr::new("trap.bin"), &data);

        // 关键误判条件：预期摘要合法，且恰好等于“已经读到的那 32 字节
        // 前缀”的摘要，但文件还有 44 字节尚未读取，紧接着读取失败。
        // s1 强制逐字节读取，精确定位于前缀读完之后再注入 EIO。
        let mut steps = vec!["s1".to_string(); PREFIX.len()];
        steps.push(format!("e{EIO}"));
        let output =
            run_check_with_read_shim(&steps.join(","), &path, OsStr::new(PREFIX_HEX));

        // 这仍然是读取失败：不能输出 OK，不能按前缀摘要生成不匹配，
        // 也不能把部分摘要标为整个文件的实际摘要。
        assert_cannot_read(&output, "trap.bin", EIO_REASON);
        assert_ne!(output.stdout, b"OK\n", "must not succeed: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.to_lowercase().contains("mismatch"), "{stderr:?}");
        assert!(!stderr.contains(PREFIX_HEX), "partial digest must not appear: {stderr:?}");
        assert!(!stderr.contains(FULL_HEX), "{stderr:?}");
    }

    #[test]
    fn real_error_after_interruptions_reports_the_later_error_cause() {
        let dir = TestDir::new("read-intr-then-fail");
        let path = dir.write_file(OsStr::new("trap.bin"), &trap_content());

        // 先经历可恢复的临时中断（且读到部分内容），之后才出现真正的
        // 读取错误 EACCES：提示必须反映后一次失败的具体原因，而不是之前
        // 的中断。
        let output = run_check_with_read_shim(
            &format!("i,s16,i,s16,e{EACCES}"),
            &path,
            OsStr::new(FULL_HEX),
        );
        assert_cannot_read(&output, "trap.bin", EACCES_REASON);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("Interrupted"), "earlier EINTR must not be reported: {stderr:?}");
        assert!(!stderr.contains("os error 4"), "{stderr:?}");
        assert!(!stderr.contains(EIO_REASON), "{stderr:?}");

        // 交换最后一步的 errno（改用 EIO），提示中的原因随之改变：
        // 证明原因取自最后一次真实失败，而非任何写死的措辞。
        let output = run_check_with_read_shim(
            &format!("i,s8,e{EIO}"),
            &path,
            OsStr::new(FULL_HEX),
        );
        assert_cannot_read(&output, "trap.bin", EIO_REASON);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains(EACCES_REASON), "{stderr:?}");
    }

    #[test]
    fn after_full_read_recovers_mismatch_still_names_both_full_digests() {
        let dir = TestDir::new("read-recover-mismatch");
        let path = dir.write_file(OsStr::new("trap.bin"), &trap_content());

        // 与前缀陷阱同一文件、同一预期摘要（前缀摘要），但这次读取在中断
        // 与短读后最终完整成功：应报内容不匹配，且实际摘要是整份文件的
        // 摘要，不是已读前缀的摘要。
        let output = run_check_with_read_shim(
            "i,s16,i,s16",
            &path,
            OsStr::new(PREFIX_HEX),
        );

        assert_mismatch(&output, PREFIX_HEX, FULL_HEX);
    }

    #[test]
    fn read_failure_does_not_modify_input_or_create_result_files() {
        let dir = TestDir::new("read-fail-sideeffects");
        let path = dir.write_file(OsStr::new("trap.bin"), &trap_content());
        let before = fs::read(&path).unwrap();

        let output = run_check_with_read_shim(
            &format!("s1,s1,e{EIO}"),
            &path,
            OsStr::new(FULL_HEX),
        );
        assert_eq!(output.status.code(), Some(1), "{output:?}");

        // 输入文件字节保持不变，也不产生任何结果文件。
        let after = fs::read(&path).unwrap();
        assert_eq!(before, after, "input file must be untouched");
        let entries = fs::read_dir(dir.path()).unwrap().count();
        assert_eq!(entries, 1, "no result files may be created");
    }
}

// ── 临时受阻后完整交付（EINTR 与短写）─────────────────────────────────────────
//
// 接收方仍可继续写入时，对输出端的 write 可能因信号临时中断（EINTR，一个
// 字节都没送出），也可能一次只接收部分字节（短写）。命令必须原地重试中断、
// 续写剩余部分，最终交付的内容与无中断时完全相同：每个字节恰好一次、顺序
// 不变、末尾换行不丢失。这类“临时受阻后恢复”的序列无法从父进程一侧确定
// 性地制造（阻塞写会写满才返回，EINTR 需要子进程安装信号处理器），因此
// 用 LD_PRELOAD 垫片拦截子进程的 write，按脚本逐步注入中断、短写、零进展
// 与不可恢复错误，再核对交付内容与退出状态。
#[cfg(target_os = "linux")]
mod write_retry {
    use super::*;
    use std::sync::OnceLock;

    /// LD_PRELOAD 垫片源码：拦截子进程对标准输出（fd 1）与标准错误（fd 2）
    /// 的 write 调用，按 INKSEAL_WRITE_SHIM 环境变量给出的逗号分隔脚本
    /// 逐步执行，脚本耗尽后按真实 write 透传。步骤：
    /// `i` = 返回 EINTR（不送出任何字节）；`sN` = 最多写 N 字节的短写；
    /// `z` = 尚有内容待写却返回 0（毫无进展）；`eN` = 返回 errno 为 N 的错误。
    ///
    /// 垫片自身发起写时直接走 write 系统调用，绕开对 write 符号的拦截，
    /// 否则透传分支会递归进入自己。垫片不引入任何 crate 依赖，测试运行时
    /// 用 rustc 编译为 cdylib。
    const SHIM_SOURCE: &str = r#"
use std::os::raw::{c_int, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

#[derive(Clone, Copy)]
enum Step {
    Intr,
    Short(usize),
    Zero,
    Errno(c_int),
}

fn steps() -> &'static [Step] {
    static STEPS: OnceLock<Vec<Step>> = OnceLock::new();
    STEPS
        .get_or_init(|| {
            std::env::var("INKSEAL_WRITE_SHIM")
                .unwrap_or_default()
                .split(',')
                .filter(|token| !token.is_empty())
                .map(|token| {
                    if token == "i" {
                        Step::Intr
                    } else if token == "z" {
                        Step::Zero
                    } else if let Some(n) = token.strip_prefix('s') {
                        Step::Short(n.parse().expect("short-write length"))
                    } else if let Some(e) = token.strip_prefix('e') {
                        Step::Errno(e.parse().expect("errno"))
                    } else {
                        panic!("unknown shim step: {token}");
                    }
                })
                .collect()
        })
        .as_slice()
}

static STEP_INDEX: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    fn syscall(number: isize, ...) -> isize;
    fn __errno_location() -> *mut c_int;
}

#[cfg(target_arch = "x86_64")]
const SYS_WRITE: isize = 1;
#[cfg(target_arch = "aarch64")]
const SYS_WRITE: isize = 64;

const EINTR: c_int = 4;

fn fail(errno: c_int) -> isize {
    unsafe { *__errno_location() = errno };
    -1
}

fn real_write(fd: c_int, buf: *const c_void, count: usize) -> isize {
    // 直接发起 write 系统调用：不能调用 libc 的 write，否则会被本垫片
    // 再次拦截而无限递归。
    unsafe { syscall(SYS_WRITE, fd, buf, count) }
}

#[no_mangle]
pub unsafe extern "C" fn write(fd: c_int, buf: *const c_void, count: usize) -> isize {
    if fd == 1 || fd == 2 {
        let index = STEP_INDEX.fetch_add(1, Ordering::SeqCst);
        match steps().get(index) {
            Some(Step::Intr) => return fail(EINTR),
            Some(Step::Zero) => return 0,
            Some(Step::Errno(errno)) => return fail(*errno),
            Some(Step::Short(limit)) => return real_write(fd, buf, count.min(*limit)),
            None => {}
        }
    }
    real_write(fd, buf, count)
}
"#;

    /// Linux 上各架构一致的 errno 值。
    const EPIPE: i32 = 32;

    /// 每个测试进程只编译一次垫片，产物放在临时目录。
    fn write_shim() -> &'static Path {
        static SHIM: OnceLock<PathBuf> = OnceLock::new();
        SHIM.get_or_init(|| {
            let dir = std::env::temp_dir()
                .join(format!("inkseal-write-shim-{}", std::process::id()));
            fs::create_dir_all(&dir).expect("create shim dir");
            let source = dir.join("write_shim.rs");
            let library = dir.join("libinkseal_write_shim.so");
            fs::write(&source, SHIM_SOURCE).expect("write shim source");
            let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
            let status = Command::new(rustc)
                .arg("--edition=2021")
                .arg("--crate-type=cdylib")
                .arg("-O")
                .arg("-o")
                .arg(&library)
                .arg(&source)
                .status()
                .expect("run rustc for write shim");
            assert!(status.success(), "write shim must compile");
            library
        })
    }

    /// 在垫片脚本作用下运行命令，两个流都按默认方式捕获。
    fn run_with_shim(script: &str, args: &[&OsStr]) -> Output {
        inkseal()
            .args(args)
            .env("LD_PRELOAD", write_shim())
            .env("INKSEAL_WRITE_SHIM", script)
            .output()
            .expect("failed to run inkseal")
    }

    /// 用法提示的完整文本（与命令实现中的 USAGE 常量加末尾换行一致）。
    const USAGE_TEXT: &str = "Usage: inkseal --version\n       inkseal digest <file>\n       inkseal check-digest <file> <digest>\n";

    #[test]
    fn digest_line_fully_delivered_through_interruptions_and_short_writes() {
        let dir = TestDir::new("retry-digest");
        let path = dir.write_file(OsStr::new("hello.txt"), b"abc");

        // 第一个字节送出前连续中断，之后短写与中断交错；脚本耗尽后透传。
        let output = run_with_shim(
            "i,i,i,s7,i,s1,s1,i,s40",
            &[OsStr::new("digest"), path.as_os_str()],
        );

        // 交付内容与无中断时逐字节相同：64 个小写十六进制字符加末尾换行。
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_eq!(output.stdout, format!("{ABC_HEX}\n").as_bytes(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
    }

    #[test]
    fn digest_line_byte_by_byte_with_interruption_before_each_byte() {
        let dir = TestDir::new("retry-digest-storm");
        let path = dir.write_file(OsStr::new("hello.txt"), b"abc");

        // 每个字节送出前都先中断一次：连续中断与短写交错的最重情形。
        // 40 步短写覆盖行前 40 字节，其余字节由透传补足。
        let script: Vec<&str> = (0..40).flat_map(|_| ["i", "s1"]).collect();
        let output = run_with_shim(
            &script.join(","),
            &[OsStr::new("digest"), path.as_os_str()],
        );

        // 逐字节相等本身即保证：没有字节丢失、没有字节重复、顺序不变。
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_eq!(output.stdout, format!("{ABC_HEX}\n").as_bytes(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
    }

    #[test]
    fn ok_line_fully_delivered_through_interruptions_and_short_writes() {
        let dir = TestDir::new("retry-check-ok");
        let path = dir.write_file(OsStr::new("hello.txt"), b"abc");

        // “OK\n” 三个字节逐一短写送出，每次写之前都先中断。
        let output = run_with_shim(
            "i,s1,i,s1,i,s1,i",
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
    fn version_line_fully_delivered_through_interruptions_and_short_writes() {
        let output = run_with_shim("i,i,s3,i,s5", &[OsStr::new("--version")]);

        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_eq!(output.stdout, b"inkseal 0.1.0\n", "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
    }

    /// 已交付部分成功结果后遇到不可恢复的写入错误：退出码 1，已送出的
    /// 前缀原样保留，不补发整行，也不把结果转移到标准错误。
    #[test]
    fn unrecoverable_error_after_partial_delivery_keeps_prefix_and_exits_1() {
        let dir = TestDir::new("retry-partial-then-dead");
        let path = dir.write_file(OsStr::new("hello.txt"), b"abc");

        // 摘要行先送出 10 个字节，随后写入彻底失败（EPIPE）。
        let output = run_with_shim(
            &format!("s10,e{EPIPE}"),
            &[OsStr::new("digest"), path.as_os_str()],
        );

        assert_eq!(output.status.code(), Some(1), "{output:?}");
        // 已交付的前缀保留，不多不少：没有重发开头，也没有补发整行。
        assert_eq!(output.stdout, ABC_HEX[..10].as_bytes(), "{output:?}");
        let stderr = String::from_utf8(output.stderr.clone()).expect("stderr must be UTF-8");
        assert!(
            stderr.starts_with("inkseal: unable to write to standard output"),
            "{stderr:?}"
        );
        assert!(stderr.contains("Broken pipe"), "keep OS reason: {stderr:?}");
        assert!(!stderr.contains("panicked"), "must not crash: {stderr:?}");
        // 结果不转移到标准错误。
        assert!(!stderr.contains(ABC_HEX), "{stderr:?}");

        // 核对通过同样如此：“OK\n”送出 2 个字节后写入彻底失败。
        let output = run_with_shim(
            &format!("s2,e{EPIPE}"),
            &[
                OsStr::new("check-digest"),
                path.as_os_str(),
                OsStr::new(ABC_HEX),
            ],
        );
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert_eq!(output.stdout, b"OK", "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.starts_with("inkseal: unable to write to standard output"), "{stderr:?}");
    }

    /// 尚有内容待写却一次返回零字节：按输出失败结束（退出码 1），
    /// 而不是无限等待。测试能结束本身即证明没有空转。
    #[test]
    fn zero_byte_write_progress_is_output_failure_not_hang() {
        let dir = TestDir::new("retry-zero-progress");
        let path = dir.write_file(OsStr::new("hello.txt"), b"abc");

        // 第一个字节之前就毫无进展。
        let output = run_with_shim("z", &[OsStr::new("digest"), path.as_os_str()]);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.starts_with("inkseal: unable to write to standard output"),
            "{stderr:?}"
        );
        assert!(stderr.contains("no progress"), "{stderr:?}");
        assert!(!stderr.contains("panicked"), "{stderr:?}");

        // 中断与短写之后、行未写完时毫无进展：已送出的前缀保留。
        let output = run_with_shim("i,s6,z", &[OsStr::new("digest"), path.as_os_str()]);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert_eq!(output.stdout, ABC_HEX[..6].as_bytes(), "{output:?}");

        // 核对通过的结果同样适用。
        let output = run_with_shim(
            "z",
            &[
                OsStr::new("check-digest"),
                path.as_os_str(),
                OsStr::new(ABC_HEX),
            ],
        );
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
    }

    /// 用法错误的完整提示在短写与临时中断后仍逐字节交付，退出码保持 2。
    #[test]
    fn usage_message_fully_delivered_through_interruptions() {
        let output = run_with_shim("i,s3,i,s20,i,s1", &[]);

        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert_eq!(output.stderr, USAGE_TEXT.as_bytes(), "{output:?}");
    }

    /// 文件访问失败的提示在短写与临时中断后仍完整交付：行结构、路径与
    /// 系统原因都与无中断时一致，退出码保持 1。
    #[test]
    fn cannot_open_message_fully_delivered_through_interruptions() {
        let dir = TestDir::new("retry-cannot-open");
        let path = dir.path().join("nope.txt");

        let output = run_with_shim(
            "i,i,s4,i,s9,s2",
            &[OsStr::new("digest"), path.as_os_str()],
        );

        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let expected = format!(
            "inkseal: cannot open '{}': No such file or directory (os error 2)\n",
            path.display()
        );
        assert_eq!(output.stderr, expected.as_bytes(), "{output:?}");
    }

    /// 摘要不匹配的提示在短写与临时中断后仍完整交付：预期值与实际值
    /// 各出现恰好一次，退出码保持 1。
    #[test]
    fn mismatch_message_fully_delivered_through_interruptions() {
        let dir = TestDir::new("retry-mismatch");
        let path = dir.write_file(OsStr::new("hello.txt"), b"abc");
        let empty_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let output = run_with_shim(
            "i,s1,i,s64,s2,i,s13",
            &[
                OsStr::new("check-digest"),
                path.as_os_str(),
                OsStr::new(empty_hex),
            ],
        );

        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let expected = format!(
            "inkseal: digest mismatch for '{}'\nexpected: {empty_hex}\nactual:   {ABC_HEX}\n",
            path.display()
        );
        assert_eq!(output.stderr, expected.as_bytes(), "{output:?}");
        let stderr = String::from_utf8(output.stderr.clone()).unwrap();
        assert_eq!(stderr.matches(empty_hex).count(), 1, "{stderr:?}");
        assert_eq!(stderr.matches(ABC_HEX).count(), 1, "{stderr:?}");
    }

    /// 错误提示自身遇到零进展：保留原操作的退出码并正常结束，不崩溃。
    #[test]
    fn error_hint_zero_progress_keeps_original_exit_code() {
        let dir = TestDir::new("retry-hint-zero");
        let file = dir.write_file(OsStr::new("hello.txt"), b"abc");
        let missing = dir.path().join("nope.txt");
        let empty_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let cases: Vec<(Vec<&OsStr>, i32)> = vec![
            (vec![], 2), // 用法错误
            (vec![OsStr::new("digest"), missing.as_os_str()], 1),
            (
                vec![
                    OsStr::new("check-digest"),
                    file.as_os_str(),
                    OsStr::new(empty_hex),
                ],
                1,
            ),
        ];
        for (args, code) in cases {
            let output = run_with_shim("z", &args);
            // 正常退出（不是被信号终止，也不是 panic 的 101），退出码不变。
            assert_eq!(output.status.code(), Some(code), "args={args:?}: {output:?}");
            assert!(output.stdout.is_empty(), "args={args:?}: {output:?}");
            assert!(output.stderr.is_empty(), "args={args:?}: {output:?}");
        }
    }

    /// 错误提示送出一段前缀后遇到不可恢复的写入错误：前缀保留，不补发、
    /// 不重试，保留原操作的退出码并正常结束，不出现崩溃信息。
    #[test]
    fn error_hint_partial_then_unrecoverable_keeps_exit_code() {
        let dir = TestDir::new("retry-hint-partial");
        let missing = dir.path().join("nope.txt");
        let script = format!("s8,e{EPIPE}");

        // 用法错误：提示前缀保留，退出码仍为 2。
        let output = run_with_shim(&script, &[]);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert_eq!(output.stderr, USAGE_TEXT[..8].as_bytes(), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");

        // 文件访问失败：提示前缀保留，退出码仍为 1。
        let output = run_with_shim(&script, &[OsStr::new("digest"), missing.as_os_str()]);
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let expected_prefix =
            format!("inkseal: cannot open '{}': No such file or directory (os error 2)\n",
                    missing.display());
        assert_eq!(output.stderr, expected_prefix[..8].as_bytes(), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("panicked"),
            "must not crash: {output:?}"
        );
    }
}
