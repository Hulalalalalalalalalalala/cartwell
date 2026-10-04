use std::env;
use std::fs::File;
use std::process::ExitCode;

const USAGE: &str = "Usage: inkseal --version\n       inkseal digest <file>";

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("--version") if args.next().is_none() => {
            println!("inkseal 0.1.0");
            ExitCode::SUCCESS
        }
        Some("digest") => {
            let (Some(path), None) = (args.next(), args.next()) else {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            };
            run_digest(&path)
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run_digest(path: &str) -> ExitCode {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("inkseal: cannot open '{path}': {err}");
            return ExitCode::FAILURE;
        }
    };
    match inkseal::digest_reader(file) {
        Ok(digest) => {
            println!("{}", digest.to_hex());
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("inkseal: cannot read '{path}': {err}");
            ExitCode::FAILURE
        }
    }
}
