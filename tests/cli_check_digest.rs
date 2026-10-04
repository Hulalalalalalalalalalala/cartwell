//! `inkseal check-digest <文件> <预期摘要>` 的端到端回归测试：
//! 以真实子进程运行编译出的命令，验证匹配 / 不匹配 / 文件错误 / 用法错误
//! 四类结果的退出码、标准输出、标准错误均遵循 README 约定。
//!
//! 重点保障：
//! - 摘要格式先于文件校验（摘要不合法时绝不打开文件，即使路径不存在）；
//! - 不自动去掉空白（前缀、空格、换行、长度不对、非十六进制字符一律拒绝）；
//! - 文件错误不能被说成内容不匹配，也不能给出部分摘要；
//! - 路径仍按操作系统原始字节访问，显示文本只用于错误提示。

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// 待测试的命令行程序（Cargo 为集成测试提供编译好的二进制路径）。
fn inkseal() -> Command {
    Command::new(env!("CARGO_BIN_EXE_inkseal"))
}

fn run_check(path: &OsStr, expected: &OsStr) -> Output {
    inkseal()
        .arg("check-digest")
        .arg(path)
        .arg(expected)
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
            "inkseal-check-test-{}-{name}",
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

/// 匹配的完整约定：退出码 0、标准输出恰好是 `OK\n`、标准错误为空。
fn assert_match(output: &Output) {
    assert_eq!(output.status.code(), Some(0), "exit code: {output:?}");
    assert_eq!(output.stdout, b"OK\n", "match stdout must be exactly OK\\n");
    assert!(
        output.stderr.is_empty(),
        "stderr must be empty on match: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// 用法错误的完整约定：退出码 2、标准输出为空、标准错误说明问题并给出用法。
fn assert_usage_error(output: &Output) -> String {
    assert_eq!(output.status.code(), Some(2), "exit code: {output:?}");
    assert!(
        output.stdout.is_empty(),
        "stdout must be empty on usage error: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8(output.stderr.clone()).expect("stderr must be UTF-8");
    assert!(stderr.contains("Usage:"), "usage errors show usage: {stderr:?}");
    stderr
}

/// 独立依据：python3 hashlib.sha256(b"abc") 与空输入的标准值。
const ABC_HEX: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const EMPTY_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[test]
fn matching_digest_prints_only_ok() {
    let dir = TestDir::new("match");
    let path = dir.write_file(OsStr::new("f"), b"abc");

    let output = run_check(path.as_os_str(), OsStr::new(ABC_HEX));

    assert_match(&output);
}

#[test]
fn uppercase_and_mixed_case_digests_compare_by_value() {
    let dir = TestDir::new("case");
    let path = dir.write_file(OsStr::new("f"), b"abc");

    // 全大写、大小写混合都表示同一个 32 字节值，必须匹配。
    assert_match(&run_check(path.as_os_str(), OsStr::new(&ABC_HEX.to_uppercase())));
    assert_match(&run_check(
        path.as_os_str(),
        OsStr::new("Ba7816BF8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ));
}

#[test]
fn empty_file_can_be_checked() {
    let dir = TestDir::new("empty");
    let path = dir.write_file(OsStr::new("empty"), b"");

    assert_match(&run_check(path.as_os_str(), OsStr::new(EMPTY_HEX)));
}

#[test]
fn mismatch_lists_both_digests_lowercase_on_stderr() {
    let dir = TestDir::new("mismatch");
    let path = dir.write_file(OsStr::new("f"), b"abc");

    // 预期给空文件的摘要，与内容 b"abc" 不匹配。
    let output = run_check(path.as_os_str(), OsStr::new(EMPTY_HEX));

    assert_eq!(output.status.code(), Some(1), "exit code: {output:?}");
    assert!(output.stdout.is_empty(), "mismatch stdout must be empty");
    let stderr = String::from_utf8(output.stderr.clone()).expect("stderr UTF-8");
    assert!(
        stderr.contains("digest mismatch") || stderr.contains("does not match"),
        "must clearly state content mismatch: {stderr:?}"
    );
    // 两个摘要都要出现，且以 64 个小写十六进制字符显示（即使预期原本是大写）。
    assert!(stderr.contains(ABC_HEX), "actual digest listed: {stderr:?}");
    assert!(stderr.contains(EMPTY_HEX), "expected digest listed: {stderr:?}");

    // 大写预期值时，错误信息里仍以小写呈现。
    let output_upper = run_check(path.as_os_str(), OsStr::new(&EMPTY_HEX.to_uppercase()));
    assert_eq!(output_upper.status.code(), Some(1));
    let stderr_upper = String::from_utf8_lossy(&output_upper.stderr);
    assert!(stderr_upper.contains(EMPTY_HEX), "expected shown lowercase: {stderr_upper:?}");
    assert!(
        !stderr_upper.contains(&EMPTY_HEX.to_uppercase()),
        "uppercase spelling must not appear: {stderr_upper:?}"
    );
}

#[test]
fn missing_file_is_file_error_not_mismatch() {
    let dir = TestDir::new("missing");
    let path = dir.path().join("nope.txt");

    let output = run_check(path.as_os_str(), OsStr::new(ABC_HEX));

    assert_eq!(output.status.code(), Some(1), "exit code: {output:?}");
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot open"), "must report open failure: {stderr:?}");
    assert!(stderr.contains("nope.txt"), "must name the path: {stderr:?}");
    assert!(
        !stderr.to_lowercase().contains("mismatch"),
        "file errors must not be called a mismatch: {stderr:?}"
    );
    // 不能给出任何摘要值。
    assert!(!stderr.contains(ABC_HEX), "no digest on file error: {stderr:?}");
}

#[test]
fn directory_path_is_file_error_not_mismatch() {
    let dir = TestDir::new("directory");
    let sub = dir.path().join("a-directory");
    fs::create_dir_all(&sub).unwrap();

    let output = run_check(sub.as_os_str(), OsStr::new(ABC_HEX));

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("a-directory"), "must name the path: {stderr:?}");
    assert!(
        stderr.contains("cannot open") || stderr.contains("cannot read"),
        "must report the file problem: {stderr:?}"
    );
    assert!(!stderr.contains(ABC_HEX), "no partial/digest value: {stderr:?}");
}

#[test]
fn invalid_digest_reported_even_when_file_does_not_exist() {
    let dir = TestDir::new("invalid-digest-missing-file");
    let missing = dir.path().join("nope.txt");

    // 摘要格式问题优先于文件访问：路径不存在也不影响结论，且退出码是 2。
    for bad in ["", "abc", "z".repeat(64).as_str(), &format!("sha256:{ABC_HEX}"),
                &format!("{ABC_HEX} "), &format!(" {ABC_HEX}"),
                &format!("{ABC_HEX}\n"), &ABC_HEX[..63], &format!("{ABC_HEX}0")]
    {
        let output = run_check(missing.as_os_str(), OsStr::new(bad));
        let stderr = assert_usage_error(&output);
        assert!(
            stderr.to_lowercase().contains("digest"),
            "must describe the digest problem ({bad:?}): {stderr:?}"
        );
        // 绝不报告文件错误，证明文件没有被访问。
        assert!(
            !stderr.contains("cannot open"),
            "invalid digest must be reported without opening the file ({bad:?}): {stderr:?}"
        );
    }
}

#[test]
fn whitespace_and_prefix_in_digest_are_not_trimmed() {
    let dir = TestDir::new("whitespace");
    let path = dir.write_file(OsStr::new("f"), b"abc");

    // 夹空格、制表符等同样拒绝（长度已不是 64，且含非十六进制字符）。
    let split = format!("{} {}", &ABC_HEX[..10], &ABC_HEX[10..]);
    for bad in [format!("sha256:{ABC_HEX}"), format!("{ABC_HEX}\t"), split] {
        let output = run_check(path.as_os_str(), OsStr::new(&bad));
        assert_usage_error(&output);
    }
}

#[test]
fn missing_and_extra_arguments_are_usage_errors() {
    let dir = TestDir::new("argc");
    let path = dir.write_file(OsStr::new("f"), b"abc");

    // 无参数。
    assert_usage_error(&run_args(&[OsStr::new("check-digest")]));
    // 只有文件，缺摘要。
    assert_usage_error(&run_args(&[OsStr::new("check-digest"), path.as_os_str()]));
    // 多给参数（即使文件和摘要都正确）。
    assert_usage_error(&run_args(&[
        OsStr::new("check-digest"),
        path.as_os_str(),
        OsStr::new(ABC_HEX),
        OsStr::new("extra"),
    ]));
}

#[test]
fn non_matching_digest_value_is_mismatch_but_same_hex_after_reparse() {
    // 同长度、合法但值不同的摘要是内容不匹配（退出码 1），不是用法错误。
    let dir = TestDir::new("wrong-value");
    let path = dir.write_file(OsStr::new("f"), b"abc");
    let wrong = "0".repeat(64);

    let output = run_check(path.as_os_str(), OsStr::new(&wrong));
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&wrong), "expected value listed: {stderr:?}");
    assert!(stderr.contains(ABC_HEX), "actual value listed: {stderr:?}");
}

#[test]
fn check_digest_uses_only_raw_bytes_not_text_or_newlines() {
    let dir = TestDir::new("raw-bytes");
    // 含零字节、非 UTF-8 字节和多种换行；摘要由库按原始字节独立计算。
    let data: &[u8] = b"alpha\nbeta\r\ngamma\r\x00\xff\xfe\x80";
    let path = dir.write_file(OsStr::new("blob.bin"), data);
    let expected = inkseal::digest_reader(data).unwrap().to_hex();

    assert_match(&run_check(path.as_os_str(), OsStr::new(&expected)));

    // 末尾多一个字节就必须不匹配，且给出实际摘要而非部分摘要。
    let mut changed = data.to_vec();
    changed.push(b'\n');
    let path2 = dir.write_file(OsStr::new("blob2.bin"), &changed);
    let output = run_check(path2.as_os_str(), OsStr::new(&expected));
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let actual = inkseal::digest_reader(changed.as_slice()).unwrap().to_hex();
    assert!(stderr.contains(&actual), "full actual digest listed: {stderr:?}");
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::ffi::OsStrExt;

    fn os(bytes: &[u8]) -> OsString {
        OsString::from(OsStr::from_bytes(bytes))
    }

    #[test]
    fn non_utf8_filename_is_checked_like_any_other_path() {
        let dir = TestDir::new("non-utf8-name");
        let path = dir.write_file(&os(b"raw \xff\xfe name.bin"), b"abc");

        assert_match(&run_check(path.as_os_str(), OsStr::new(ABC_HEX)));
    }

    #[test]
    fn non_utf8_digest_argument_is_usage_error() {
        let dir = TestDir::new("non-utf8-digest");
        let path = dir.write_file(OsStr::new("f"), b"abc");

        // 摘要参数无法解码为合法文字：用法错误，且不打开文件。
        let mut bad = vec![b'a'; 63];
        bad.push(0xff);
        let output = run_check(path.as_os_str(), &os(&bad));
        let stderr = assert_usage_error(&output);
        assert!(
            stderr.to_lowercase().contains("digest"),
            "must explain the digest argument: {stderr:?}"
        );
    }

    #[test]
    fn missing_undecodable_path_reports_file_error_not_mismatch() {
        let dir = TestDir::new("undecodable-missing");
        let missing = dir.path().join(os(b"data_\xfe.bin"));

        let output = run_check(missing.as_os_str(), OsStr::new(ABC_HEX));
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("cannot open"), "{stderr:?}");
        assert!(stderr.contains('\u{fffd}'), "path shown with replacement char: {stderr:?}");
        assert!(!stderr.contains(ABC_HEX), "no digest value: {stderr:?}");
    }
}
