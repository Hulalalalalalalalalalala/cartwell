use std::env;
use std::fs::File;
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "Usage: inkseal --version
       inkseal digest <file>";

fn main() -> ExitCode {
    // 使用 args_os 而非 args：命令行参数在允许非 UTF-8 文件名的系统上
    // 可能包含无法解码的字节，args() 遇到这类参数会在访问文件前恐慌。
    let mut args = env::args_os().skip(1);
    match args.next() {
        Some(subcommand) if subcommand.as_os_str() == "--version" && args.next().is_none() => {
            println!("inkseal 0.1.0");
            ExitCode::SUCCESS
        }
        Some(subcommand) if subcommand.as_os_str() == "digest" => {
            let (Some(path), None) = (args.next(), args.next()) else {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            };
            run_digest(Path::new(&path))
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run_digest(path: &Path) -> ExitCode {
    // 直接以系统提供的真实路径打开文件：显示用的 lossy 文本绝不参与访问。
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("inkseal: cannot open '{}': {err}", path.display());
            return ExitCode::FAILURE;
        }
    };
    match inkseal::digest_reader(file) {
        Ok(digest) => {
            println!("{}", digest.to_hex());
            ExitCode::SUCCESS
        }
        Err(err) => {
            // Path::display 对不可解码字节以替换字符输出，不会恐慌。
            eprintln!("inkseal: cannot read '{}': {err}", path.display());
            ExitCode::FAILURE
        }
    }
}
