use inkseal::digest_reader;
use std::env;
use std::fs::File;
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "\
Usage: inkseal --version
       inkseal digest <file path>";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();

    match args.get(0).map(String::as_str) {
        Some("--version") if args.len() == 1 => {
            println!("inkseal 0.1.0");
            ExitCode::SUCCESS
        }
        Some("digest") => match args.as_slice() {
            [_, path] => run_digest(Path::new(path)),
            _ => {
                eprintln!("{USAGE}");
                ExitCode::from(2)
            }
        },
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run_digest(path: &Path) -> ExitCode {
    let display = path.display();

    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("inkseal digest: failed to open '{display}': {err}");
            return ExitCode::FAILURE;
        }
    };

    match digest_reader(file) {
        Ok(digest) => {
            println!("{}", digest.to_hex());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("inkseal digest: failed to read '{display}': {}", err.io_error());
            ExitCode::FAILURE
        }
    }
}
