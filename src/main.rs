use inkseal::{ParseDigestError, Sha256Digest};
use std::env;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "Usage: inkseal --version\n       inkseal digest <file>\n       inkseal check-digest <file> <digest>\n       inkseal check-digest-file <file> <digest-file>";

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
                return emit_error(2, format!("{USAGE}\n").as_bytes());
            };
            run_digest(Path::new(&path))
        }
        Some(ref cmd) if cmd.as_encoded_bytes() == b"check-digest" => {
            let (Some(path), Some(expected), None) = (args.next(), args.next(), args.next()) else {
                return emit_error(
                    2,
                    format!(
                        "inkseal: check-digest requires exactly two arguments: <file> <digest>\n\
                         {USAGE}\n"
                    )
                    .as_bytes(),
                );
            };
            run_check_digest(Path::new(&path), &expected)
        }
        Some(ref cmd) if cmd.as_encoded_bytes() == b"check-digest-file" => {
            let (Some(path), Some(digest_path), None) = (args.next(), args.next(), args.next())
            else {
                return emit_error(
                    2,
                    format!(
                        "inkseal: check-digest-file requires exactly two arguments: \
                         <file> <digest-file>\n\
                         {USAGE}\n"
                    )
                    .as_bytes(),
                );
            };
            run_check_digest_file(Path::new(&path), Path::new(&digest_path))
        }
        _ => {
            // 未知子命令（即便含有非 UTF-8 字节）等用法错误统一走这里。
            emit_error(2, format!("{USAGE}\n").as_bytes())
        }
    }
}

/// 打开 `path` 并以流式方式读取其全部内容，返回完整摘要。
///
/// 这是 `digest` 与 `check-digest` 共用的唯一文件访问规则：始终以操作
/// 系统给出的原始路径打开文件（用于显示的文字绝不参与访问），以原始
/// 字节流式计算摘要——空文件、二进制内容与各种换行形式都按同一条规则
/// 处理，内存占用与文件大小无关。文件打不开与读取中途失败是两类不同的
/// 失败（见 [`FileAccessError`]）；即使已读入一部分内容，读取失败也绝不
/// 返回部分摘要。
fn digest_file(path: &Path) -> Result<Sha256Digest, FileAccessError> {
    let file = File::open(path)
        .map_err(|err| FileAccessError::Open(path.to_path_buf(), err))?;
    inkseal::digest_reader(file)
        .map_err(|err| FileAccessError::Read(path.to_path_buf(), err))
}

/// 读取单个文件计算完整摘要时的失败，区分“打不开”与“读取中途失败”,
/// 以便两条命令共用同一套提示规则。
enum FileAccessError {
    /// 文件无法打开；携带原始路径与系统给出的原因。
    Open(PathBuf, io::Error),
    /// 文件已打开但读取中途失败；已读入的部分内容不产生任何摘要。
    Read(PathBuf, inkseal::DigestError),
}

impl FileAccessError {
    /// 渲染为既有的单行错误提示（含末尾换行）：仅在此时把路径做损失性
    /// 转换并转义控制字符，显示文字不影响也不回溯到实际访问对象。
    fn message(&self) -> String {
        match self {
            FileAccessError::Open(path, err) => {
                format!("inkseal: cannot open '{}': {err}\n", path_display(path))
            }
            FileAccessError::Read(path, err) => {
                format!("inkseal: cannot read '{}': {err}\n", path_display(path))
            }
        }
    }
}

fn run_digest(path: &Path) -> ExitCode {
    match digest_file(path) {
        Ok(digest) => {
            let mut line = digest.to_hex();
            line.push('\n');
            emit_success(line.as_bytes())
        }
        Err(err) => emit_error(1, err.message().as_bytes()),
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
            // 与失败路径同一条规则：提示本身写不出去也忽略，只需保证
            // 退出码为 1，绝不经过会因写失败而 panic 的宏。
            let hint = format!("inkseal: unable to write to standard output: {err}\n");
            let _ = write_stderr_all(hint.as_bytes());
            ExitCode::FAILURE
        }
    }
}

/// 失败路径的统一出口：把既有的错误提示（原始字节，含其行结构）尽力
/// 写到标准错误，然后以约定的退出码（用法错误 `2`、其余失败 `1`）结束。
///
/// 提示说明的是**已经发生的失败**：接收方是否还读得到提示，不能改变
/// 命令对本次操作的判断。标准错误被接到另一个程序而接收方提前关闭管道、
/// 或从一开始就拒绝写入时，`eprintln!` 会在 EPIPE/EBADF 上 panic，使
/// 进程以崩溃退出码（101）结束并打出崩溃信息，丢掉原本约定的退出码。
/// 这里与 [emit_success] 一样直接走 `write` 系统调用并忽略写失败：
/// 已经送出的字节保留，写不出去的部分不补齐、不重试、不改写到标准输出，
/// 只保证静默地以 `code` 正常结束。
fn emit_error(code: u8, message: &[u8]) -> ExitCode {
    let _ = write_stderr_all(message);
    ExitCode::from(code)
}

/// 把 `data` 完整写到给定输出端：成功结果与失败提示共用的唯一交付规则。
///
/// 只要输出端仍可继续接收，临时中断（EINTR）原地重试、一次只接收部分
/// 字节（短写）就续写剩余部分，直到全部字节交付完毕——最终内容完整、
/// 顺序不变且没有重复。真正的写入错误结束本次交付并返回该错误；对正数
/// 计数的 write 返回 0 没有任何进展，按失败处理而不是空转。`target`
/// 只用于“毫无进展”这条合成错误的文字，系统给出的真实错误原样返回。
#[cfg(unix)]
fn write_fd_all(fd: std::os::fd::RawFd, mut data: &[u8], target: &'static str) -> io::Result<()> {
    use std::os::raw::c_void;

    unsafe extern "C" {
        fn write(fd: std::os::fd::RawFd, buf: *const c_void, count: usize) -> isize;
    }

    while !data.is_empty() {
        let written = unsafe { write(fd, data.as_ptr().cast::<c_void>(), data.len()) };
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
            // 对正数计数的 write 返回 0 没有可恢复的含义，停止续写，
            // 避免在此空转。
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("write to {target} returned no progress"),
            ));
        }
        data = &data[n..];
    }
    Ok(())
}

/// 非 Unix 目标：标准库句柄不存在上述特殊处理，沿用加锁写入并显式刷新。
/// `write_all` 内部已处理短写与 EINTR，语义与 Unix 路径一致。
#[cfg(not(unix))]
fn write_locked_all(mut handle: impl std::io::Write, data: &[u8]) -> io::Result<()> {
    use std::io::Write;

    handle.write_all(data)?;
    handle.flush()
}

/// 直接对标准输出的原始文件描述符发起 `write`，绕过标准库 `Stdout`
/// 对“输出端不存在/拒绝写入”这类失败的特殊处理——它在某些情况下会把
/// 失败（如 fd 以只读方式打开时内核返回的 EBADF）静默报告为成功，导致
/// 调用方误以为结果已交付。
#[cfg(unix)]
fn write_stdout_all(line: &[u8]) -> io::Result<()> {
    const STDOUT_FD: std::os::fd::RawFd = 1;
    write_fd_all(STDOUT_FD, line, "standard output")
}

/// 非 Unix 目标：标准库句柄不存在上述特殊处理，沿用加锁写入并显式刷新。
#[cfg(not(unix))]
fn write_stdout_all(line: &[u8]) -> io::Result<()> {
    write_locked_all(io::stdout().lock(), line)
}

/// 直接对标准错误的原始文件描述符发起 `write`，绕过标准库 `Stderr`
/// 的行缓冲以及 `eprintln!`/`writeln!` 在写失败时的 panic（宏内部
/// `unwrap`）。任何无法继续写入的错误都返回，由调用方决定忽略——
/// 失败提示本身绝不能再崩溃。
#[cfg(unix)]
fn write_stderr_all(message: &[u8]) -> io::Result<()> {
    const STDERR_FD: std::os::fd::RawFd = 2;
    write_fd_all(STDERR_FD, message, "standard error")
}

/// 非 Unix 目标：沿用加锁写入并显式刷新；写失败同样由调用方忽略。
#[cfg(not(unix))]
fn write_stderr_all(message: &[u8]) -> io::Result<()> {
    write_locked_all(io::stderr().lock(), message)
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
            return emit_error(
                2,
                format!("inkseal: invalid expected digest: {reason}\n{USAGE}\n").as_bytes(),
            );
        }
    };

    finish_digest_check(path, expected)
}

/// 预期摘要已确认合法后，核对 `path` 的实际内容并按既有的唯一一套规则
/// 输出：匹配写 `OK\n`（完整交付后以 0 退出）；访问失败报告文件原因；
/// 不匹配列出小写的预期与实际摘要。`check-digest` 与
/// `check-digest-file` 在拿到合法摘要之后共用本函数，因此两者对待核对
/// 文件的原始字节、流式读取、比较与输出规则完全一致。
fn finish_digest_check(path: &Path, expected: Sha256Digest) -> ExitCode {
    // 与 digest 共用同一条文件访问规则；访问失败是文件问题，
    // 绝不能被解释成内容不匹配。
    let actual = match digest_file(path) {
        Ok(digest) => digest,
        Err(err) => return emit_error(1, err.message().as_bytes()),
    };

    if actual == expected {
        emit_success(b"OK\n")
    } else {
        // 内容不匹配：预期与实际都用库的同一显示规则呈现为
        // 64 个小写十六进制字符（大小写混用的输入也规范为小写）。
        emit_error(
            1,
            format!(
                "inkseal: digest mismatch for '{}'\n\
                 expected: {}\n\
                 actual:   {}\n",
                path_display(path),
                expected.to_hex(),
                actual.to_hex()
            )
            .as_bytes(),
        )
    }
}

/// 读取并解析摘要文件时的失败。
///
/// 前两类是摘要文件本身的访问问题（以 `1` 退出）；[`Malformed`](Self::Malformed)
/// 是内容不符合“恰好一份摘要”的格式约定（以 `2` 退出）。三类都必须在
/// 待核对文件被访问之前判定，且提示里都要带上摘要文件自己的路径，绝不
/// 能把摘要文件的问题改报成待核对文件的访问错误。
enum DigestFileError {
    /// 摘要文件无法打开（不存在、权限不足等）。
    Open(PathBuf, io::Error),
    /// 摘要文件已打开但读取中途失败（含路径指向目录时的读取错误）。
    Read(PathBuf, io::Error),
    /// 摘要文件内容不符合格式约定。
    Malformed(PathBuf, DigestFileProblem),
}

/// 摘要文件内容的具体格式问题，用于给出精确的错误原因。
enum DigestFileProblem {
    /// 空文件：连一个摘要字符都没有。
    Empty,
    /// 内容超过“64 个十六进制字符 + 单个 CRLF”的 66 字节上限：
    /// 多余字节可能是第二份摘要、文件名或任何附加内容，一律拒绝。
    TooLong,
    /// 去掉唯一允许的末尾换行后，摘要正文未通过库的严格十六进制解析。
    InvalidDigest(ParseDigestError),
}

impl DigestFileProblem {
    /// 渲染为人类可读的具体格式原因（不含路径，路径由调用方添加）。
    fn description(&self) -> String {
        const RULE: &str = concat!(
            "the digest file must contain exactly one digest of 64 ASCII ",
            "hexadecimal characters, optionally followed by one LF or CRLF"
        );
        match self {
            DigestFileProblem::Empty => {
                format!("{RULE}, but the file is empty")
            }
            DigestFileProblem::TooLong => {
                format!("{RULE}, but the file contains extra bytes beyond that single line")
            }
            DigestFileProblem::InvalidDigest(ParseDigestError::InvalidLength(len)) => {
                format!(
                    "{RULE}; the digest text is {len} bytes long (before any trailing newline)"
                )
            }
            DigestFileProblem::InvalidDigest(ParseDigestError::InvalidHexChar(pos)) => {
                format!(
                    "{RULE}; the digest text contains a non-hexadecimal byte at offset {pos} \
                    (only 0-9, a-f and A-F are allowed)"
                )
            }
        }
    }
}

/// 打开摘要文件、读取其（被严格限长的）全部内容并解析为摘要值。
///
/// 合法文件至多 66 字节：64 个十六进制字符，末尾可带一个 LF 或 CRLF。
/// 这里最多读入 67 字节——多出的第 67 字节是“内容超长”的确定性哨兵，
/// 因此内存占用恒定，也不必把可能很大的非法文件（例如误指向二进制或
/// 第二份摘要）整个读完就能判定格式错误。读取本身失败与内容格式不合法
/// 是两类不同的失败，分别映射到 [`DigestFileError`] 的不同变体。
fn load_expected_digest_file(path: &Path) -> Result<Sha256Digest, DigestFileError> {
    use std::io::Read as _;

    let file = File::open(path)
        .map_err(|err| DigestFileError::Open(path.to_path_buf(), err))?;

    let mut content = Vec::with_capacity(67);
    file.take(67)
        .read_to_end(&mut content)
        .map_err(|err| DigestFileError::Read(path.to_path_buf(), err))?;

    parse_digest_file_content(&content)
        .map_err(|problem| DigestFileError::Malformed(path.to_path_buf(), problem))
}

/// 摘要文件内容的唯一解析规则。
///
/// 与 `check-digest` 的摘要参数不同，摘要文件允许结尾带一个换行：内容
/// 要么恰好是 64 个十六进制字符，要么在其后紧跟一个 LF 或 CRLF。除此之外
/// 不做任何裁剪或修正——空文件、首尾空格、单独的 CR、额外空行、第二份
/// 摘要、附带的文件名、`0x` 前缀或非 ASCII 字节都属于格式错误。剥离唯一
/// 允许的行结束后，正文仍必须通过库的严格解析
/// （[`Sha256Digest::from_hex_bytes`]），其严格格式不在此放宽。
fn parse_digest_file_content(content: &[u8]) -> Result<Sha256Digest, DigestFileProblem> {
    if content.is_empty() {
        return Err(DigestFileProblem::Empty);
    }
    if content.len() > 66 {
        return Err(DigestFileProblem::TooLong);
    }

    // 仅当 LF 是最后一个字节时剥离它；剥到 LF 后，再仅当 CR 紧接在它
    // 前面（即结尾确为 CRLF）时剥离该 CR。顺序保证：单独的 CR、CRLF
    // 之外的任何尾随字节都不会被裁掉——例如 "\n\r" 的末字节是 CR，
    // 第一步就不匹配，整体按长度错误拒绝。
    let mut hex: &[u8] = content;
    if let Some(rest) = hex.strip_suffix(b"\n") {
        hex = rest;
        if let Some(rest) = hex.strip_suffix(b"\r") {
            hex = rest;
        }
    }

    Sha256Digest::from_hex_bytes(hex).map_err(DigestFileProblem::InvalidDigest)
}

fn run_check_digest_file(path: &Path, digest_path: &Path) -> ExitCode {
    // 先完整处理摘要文件：在它被成功打开、读取并确认格式合法之前，
    // 绝不访问待核对文件——即使待核对文件不存在，也不得改报它的错误。
    let expected = match load_expected_digest_file(digest_path) {
        Ok(digest) => digest,
        Err(DigestFileError::Open(p, err)) => {
            return emit_error(
                1,
                format!(
                    "inkseal: cannot open digest file '{}': {err}\n",
                    path_display(&p)
                )
                .as_bytes(),
            );
        }
        Err(DigestFileError::Read(p, err)) => {
            return emit_error(
                1,
                format!(
                    "inkseal: cannot read digest file '{}': {err}\n",
                    path_display(&p)
                )
                .as_bytes(),
            );
        }
        Err(DigestFileError::Malformed(p, problem)) => {
            return emit_error(
                2,
                format!(
                    "inkseal: malformed digest file '{}': {}\n{USAGE}\n",
                    path_display(&p),
                    problem.description()
                )
                .as_bytes(),
            );
        }
    };

    // 摘要文件合法后才打开待核对文件；其后的访问、比较与输出规则与
    // check-digest 完全一致（共用 finish_digest_check）。
    finish_digest_check(path, expected)
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
