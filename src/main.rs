use std::env;
use std::ffi::OsStr;
use std::fs::File;
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "Usage: inkseal --version\n       inkseal digest <file>\n       inkseal check-digest <file> <digest>";

fn main() -> ExitCode {
    // 使用 args_os 而非 args：命令行参数是操作系统给出的原始字节，
    // 在允许非 UTF-8 文件名的系统上这类路径是合法路径，必须原样保留。
    let mut args = env::args_os().skip(1);
    match args.next() {
        Some(ref cmd) if cmd.as_encoded_bytes() == b"--version" && args.next().is_none() => {
            println!("inkseal 0.1.0");
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
            println!("{}", digest.to_hex());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("inkseal: cannot read '{display}': {err}");
            ExitCode::FAILURE
        }
    }
}

/// 解析用户给出的预期摘要：必须恰好是 64 个 ASCII 十六进制字符（大小写
/// 均可），按其表示的 32 字节摘要值比较。不做任何空白裁剪——前缀、空格、
/// 末尾换行、长度不对或含非十六进制字符都视为格式错误。参数无法解码为
/// 合法文字同样视为格式错误。
fn parse_expected_digest(arg: &OsStr) -> Result<[u8; 32], String> {
    let bytes = arg.as_encoded_bytes();
    if bytes.len() != 64 {
        return Err(format!(
            "expected digest must be exactly 64 ASCII hexadecimal characters, got {}",
            bytes.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, pair) in bytes.chunks(2).enumerate() {
        let hi = hex_nibble(pair[0])
            .ok_or_else(|| "expected digest contains a non-hexadecimal character".to_string())?;
        let lo = hex_nibble(pair[1])
            .ok_or_else(|| "expected digest contains a non-hexadecimal character".to_string())?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn run_check_digest(path: &Path, expected_arg: &OsStr) -> ExitCode {
    // 先校验摘要格式；格式不合法时绝不打开文件——即使路径本身也不存在，
    // 仍报告摘要格式问题。
    let expected = match parse_expected_digest(expected_arg) {
        Ok(bytes) => bytes,
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

    if actual.as_bytes() == &expected {
        println!("OK");
        ExitCode::SUCCESS
    } else {
        // 内容不匹配：预期与实际都以 64 个小写十六进制字符呈现。
        let mut expected_hex = String::with_capacity(64);
        for byte in expected {
            use std::fmt::Write as _;
            let _ = write!(expected_hex, "{byte:02x}");
        }
        eprintln!("inkseal: digest mismatch for '{display}'");
        eprintln!("expected: {expected_hex}");
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
