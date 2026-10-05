use inkseal::{ParseDigestError, Sha256Digest};
use std::env;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "Usage: inkseal --version\n       inkseal digest <file>\n       inkseal check-digest <file> <digest>";

fn main() -> ExitCode {
    // 使用 args_os 而非 args：命令行参数是操作系统给出的原始字节，
    // 在允许非 UTF-8 文件名的系统上这类路径是合法路径，必须原样保留。
    let mut args = env::args_os().skip(1);
    match args.next() {
        Some(ref cmd) if cmd.as_encoded_bytes() == b"--version" && args.next().is_none() => {
            emit_success(b"inkseal 0.1.0\n")
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
            let mut line = digest.to_hex();
            line.push('\n');
            emit_success(line.as_bytes())
        }
        Err(err) => {
            eprintln!("inkseal: cannot read '{display}': {err}");
            ExitCode::FAILURE
        }
    }
}

/// 把成功结果一次性完整写到标准输出并立即刷出，返回进程退出码。
///
/// 成功的含义是**整行结果（含末尾换行）已经真正交到输出端**：仅算出
/// 摘要或通过比较并不构成成功，写中途失败或最后的刷新失败（例如标准
/// 输出被重定向到只读位置，或管道接收方提前关闭）都必须以退出码 1
/// 结束，而不是让 `println!` 的 panic 打印崩溃信息，也不能照常报成功。
///
/// 输出失败时只在标准错误给出一条以 `inkseal:` 开头的单行提示，保留
/// 系统给出的具体原因；不补充用法说明，不把摘要改写到标准错误，也不
/// 重试整行输出。标准输出此前可能已经收到结果的前几个字节，这些字节
/// 无法也不必撤回。若连这条提示都写不出去，同样静默地以退出码 1
/// 结束——报告输出失败的过程自身绝不能再崩溃。
fn emit_success(line: &[u8]) -> ExitCode {
    match write_stdout_all(line) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // 直接走 Write trait 写原始字节，不经过会因写失败而 panic 的宏；
            // 提示本身写不出去也忽略，只需保证退出码为 1。
            let stderr = io::stderr();
            let mut err_handle = stderr.lock();
            let _ = writeln!(
                err_handle,
                "inkseal: unable to write to standard output: {err}"
            );
            let _ = err_handle.flush();
            ExitCode::FAILURE
        }
    }
}

/// 直接对标准输出的原始文件描述符发起 `write`，绕过标准库 `Stdout`
/// 对“输出端不存在/拒绝写入”这类失败的特殊处理——它在某些情况下会把
/// 失败（如 fd 以只读方式打开时内核返回的 EBADF）静默报告为成功，导致
/// 调用方误以为结果已交付。短写照常续写到同一 fd；EINTR 立即重试。
#[cfg(unix)]
fn write_stdout_all(mut line: &[u8]) -> io::Result<()> {
    use std::os::raw::c_void;
    use std::os::fd::RawFd;

    unsafe extern "C" {
        fn write(fd: RawFd, buf: *const c_void, count: usize) -> isize;
    }

    const STDOUT_FD: RawFd = 1;
    while !line.is_empty() {
        let written = unsafe { write(STDOUT_FD, line.as_ptr().cast::<c_void>(), line.len()) };
        if written < 0 {
            let err = io::Error::last_os_error();
            // 临时中断不代表任何字节的命运，原地重试。
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        let n = written as usize;
        if n == 0 {
            // 对正数计数的 write 返回 0 没有可恢复的含义，按写出失败处理，
            // 避免在此空转。
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "write to standard output returned no progress",
            ));
        }
        line = &line[n..];
    }
    Ok(())
}

/// 非 Unix 目标：标准库句柄不存在上述特殊处理，沿用加锁写入并显式刷新。
#[cfg(not(unix))]
fn write_stdout_all(line: &[u8]) -> io::Result<()> {
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    handle.write_all(line)?;
    handle.flush()
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
        emit_success(b"OK\n")
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
