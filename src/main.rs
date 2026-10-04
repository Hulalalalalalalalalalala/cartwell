use std::env;
use std::ffi::OsStr;
use std::fs::File;
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "Usage: inkseal --version\n       inkseal digest <file>\n       inkseal check-digest <file> <expected-sha256>";

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
            // 每次只接收一个文件和一个摘要：参数数量必须恰好为两个。
            let (Some(path), Some(expected), None) = (args.next(), args.next(), args.next())
            else {
                eprintln!(
                    "inkseal: check-digest requires exactly two arguments: <file> and <expected-sha256>"
                );
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

fn run_check_digest(path: &Path, expected_arg: &OsStr) -> ExitCode {
    // 摘要参数必须能解码为合法文字：无法解码为 UTF-8 属于用法错误。
    let expected_text = match expected_arg.to_str() {
        Some(text) => text,
        None => {
            eprintln!("inkseal: invalid expected digest: argument is not valid UTF-8 text");
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    // 先校验摘要格式，再打开文件：摘要不合法时绝不触碰文件，
    // 即使给定路径也不存在，报告的仍是摘要格式问题。
    // 不自动去掉任何空白：带前缀、夹空格、末尾换行等一律拒绝。
    let Some(expected) = parse_digest_hex(expected_text) else {
        eprintln!(
            "inkseal: invalid expected digest: must be exactly 64 ASCII hexadecimal \
             characters (0-9, a-f, A-F), with no whitespace or prefix"
        );
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };

    // 仅在输出错误信息时做损失性转换；打开文件始终使用原始路径，
    // 绝不把用于显示的文字当作实际路径访问。
    let display = path_display(path);
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) => {
            // 这是文件访问问题，不是内容不匹配：不得给出任何摘要值。
            eprintln!("inkseal: cannot open '{display}': {err}");
            return ExitCode::FAILURE;
        }
    };
    // 复用流式摘要计算：内存占用不随文件大小增长；读取中途失败时
    // digest_reader 返回错误而不是部分内容的摘要。
    match inkseal::digest_reader(file) {
        Ok(actual) if actual.as_bytes() == &expected => {
            println!("OK");
            ExitCode::SUCCESS
        }
        Ok(actual) => {
            // 预期值与实际值都以 64 个小写十六进制字符显示，比较按字节值进行。
            eprintln!(
                "inkseal: digest mismatch: content of '{display}' does not match the expected digest \
                 (expected {expected_hex}, actual {actual_hex})",
                expected_hex = lower_hex(&expected),
                actual_hex = actual.to_hex(),
            );
            ExitCode::FAILURE
        }
        Err(err) => {
            // 读取失败属于文件错误，不能把它说成内容不匹配，也不能给出部分摘要。
            eprintln!("inkseal: cannot read '{display}': {err}");
            ExitCode::FAILURE
        }
    }
}

/// 解析恰好 64 个 ASCII 十六进制字符（大小写均可）表示的 32 字节摘要。
///
/// 长度不对或出现任何非十六进制字符（包括空白、前缀、换行）都返回 `None`，
/// 绝不替调用方去掉空白。
fn parse_digest_hex(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (chunk, slot) in bytes.chunks_exact(2).zip(&mut out) {
        *slot = (hex_nibble(chunk[0])? << 4) | hex_nibble(chunk[1])?;
    }
    Some(out)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// 把字节编码为小写十六进制文本（每个字节两位）。
fn lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    use std::fmt::Write as _;
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
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
