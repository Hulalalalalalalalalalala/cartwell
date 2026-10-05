use inkseal::{ParseDigestError, Sha256Digest};
use std::env;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "Usage: inkseal --version\n       inkseal digest <file>\n       inkseal check-digest <file> <digest>";

/// 把一行成功结果完整写到标准输出（含末尾换行），并确保数据真正送出。
///
/// 成功意味着整行结果已经完整交付，而不只是内容已经计算完毕：写入或
/// 刷新失败（例如标准输出被重定向到拒绝写入的位置，或管道接收方提前
/// 关闭）都视为失败。调用方随后通过 [report_stdout_error] 报告错误。
fn write_stdout_line(line: &str) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    handle.write_all(line.as_bytes())?;
    handle.write_all(b"\n")?;
    // BufWriter 等缓冲层可能把最后的写入错误延迟到 flush；这里用的是
    // 未缓冲的 Stdout，但 flush 也会触发底层最终交付，必须检查其结果。
    handle.flush()
}

/// 报告“无法写入标准输出”。
///
/// 只在标准错误给出一条以 `inkseal:` 开头的提示，并保留系统提供的具体
/// 原因；不把它说成文件读取或内容问题，也不追加用法说明。此前可能已经
/// 有结果的前几个字节送达标准输出，既不撤回也不再补写整行或成功标记。
/// 若连这条提示也无法写出（例如标准错误同样关闭），静默处理——调用方
/// 仍以退出码 1 结束，报告错误本身绝不能再次导致崩溃。
fn report_stdout_error(err: &io::Error) {
    let result = (|| -> io::Result<()> {
        let stderr = io::stderr();
        let mut handle = stderr.lock();
        writeln!(handle, "inkseal: failed to write to standard output: {err}")?;
        handle.flush()
    })();
    let _ = result;
}

fn main() -> ExitCode {
    // 使用 args_os 而非 args：命令行参数是操作系统给出的原始字节，
    // 在允许非 UTF-8 文件名的系统上这类路径是合法路径，必须原样保留。
    let mut args = env::args_os().skip(1);
    match args.next() {
        Some(ref cmd) if cmd.as_encoded_bytes() == b"--version" && args.next().is_none() => {
            if let Err(err) = write_stdout_line("inkseal 0.1.0") {
                report_stdout_error(&err);
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Some(ref cmd) if cmd.as_encoded_bytes() == b"digest" => {
            let (Some(path), None) = (args.next(), args.next()) else {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            };
            run_digest(Path::new(&path))
        }
        Some(ref cmd) if cmd.as_encoded_bytes() == b"check-digest" => {
            let (Some(path), Some(expected), None) = (args.next(), args.next(), args.next()) else {
                eprintln!("inkseal: check-digest requires exactly two arguments: <file> <digest>");
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            };
            run_check_digest(Path::new(&path), &expected)
        }
        _ => {
            // 未知子命令（即便含有非 UTF-8 字节）等用法错误统一走这里。
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run_digest(path: &Path) -> ExitCode {
    // 仅在输出错误信息时做损失性转换；打开文件始终使用原始路径，
    // 绝不把用于显示的文字当作实际路径访问。
    let display = path_display(path);
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("inkseal: cannot open '{display}': {err}");
            return ExitCode::FAILURE;
        }
    };
    match inkseal::digest_reader(file) {
        Ok(digest) => {
            if let Err(err) = write_stdout_line(&digest.to_hex()) {
                report_stdout_error(&err);
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("inkseal: cannot read '{display}': {err}");
            ExitCode::FAILURE
        }
    }
}

/// 解析用户给出的预期摘要。
///
/// 解析规则完全来自库（[`Sha256Digest::from_hex_bytes`]），与库的
/// `FromStr` 以及摘要的再次显示共用同一套实现：必须恰好是 64 个 ASCII
/// 十六进制字符（大小写均可），按其表示的 32 字节摘要值比较，不做任何
/// 空白裁剪——前缀、空格、末尾换行、长度不对或含非十六进制字符都视为
/// 格式错误；参数无法解码为合法文字时，直接按其原始字节校验，同样视为
/// 格式错误。这里只负责把库的类型化错误映射为本命令既有的提示文字。
fn parse_expected_digest(arg: &OsStr) -> Result<Sha256Digest, String> {
    Sha256Digest::from_hex_bytes(arg.as_encoded_bytes()).map_err(|err| match err {
        ParseDigestError::InvalidLength(len) => format!(
            "expected digest must be exactly 64 ASCII hexadecimal characters, got {len}"
        ),
        ParseDigestError::InvalidHexChar(_) => {
            "expected digest contains a non-hexadecimal character".to_string()
        }
    })
}

fn run_check_digest(path: &Path, expected_arg: &OsStr) -> ExitCode {
    // 先校验摘要格式；格式不合法时绝不打开文件——即使路径本身也不存在，
    // 仍报告摘要格式问题。
    let expected = match parse_expected_digest(expected_arg) {
        Ok(digest) => digest,
        Err(reason) => {
            eprintln!("inkseal: invalid expected digest: {reason}");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    // 仅在输出错误信息时做损失性转换；打开文件始终使用原始路径，
    // 绝不把用于显示的文字当作实际路径访问。
    let display = path_display(path);
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("inkseal: cannot open '{display}': {err}");
            return ExitCode::FAILURE;
        }
    };
    let actual = match inkseal::digest_reader(file) {
        Ok(digest) => digest,
        Err(err) => {
            eprintln!("inkseal: cannot read '{display}': {err}");
            return ExitCode::FAILURE;
        }
    };

    if actual == expected {
        if let Err(err) = write_stdout_line("OK") {
            report_stdout_error(&err);
            return ExitCode::FAILURE;
        }
        ExitCode::SUCCESS
    } else {
        // 内容不匹配：预期与实际都用库的同一显示规则呈现为
        // 64 个小写十六进制字符（大小写混用的输入也规范为小写）。
        eprintln!("inkseal: digest mismatch for '{display}'");
        eprintln!("expected: {}", expected.to_hex());
        eprintln!("actual:   {}", actual.to_hex());
        ExitCode::FAILURE
    }
}

/// 生成可安全输出到标准错误的路径文本：不可解码的字节以替换字符
/// （U+FFFD）呈现，控制字符转义为可见写法。该文本只用于显示。
fn path_display(path: &Path) -> String {
    let lossy = path.to_string_lossy();
    if !lossy.contains(char::is_control) {
        return lossy.into_owned();
    }
    let mut out = String::with_capacity(lossy.len());
    for ch in lossy.chars() {
        match ch {
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}
