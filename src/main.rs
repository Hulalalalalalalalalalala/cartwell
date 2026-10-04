use std::env;
use std::fs::File;
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "Usage: inkseal --version\n       inkseal digest <file>";

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
