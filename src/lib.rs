//! inkseal 的公开库接口。
//!
//! 当前提供对任意 [`std::io::Read`] 输入计算 SHA-256 摘要的能力。
//! 摘要只取决于读取到的原始字节：不做文本解码、不转换换行符，
//! 也不包含文件名、路径或时间信息。

use sha2::{Digest as _, Sha256};
use std::error::Error;
use std::fmt;
use std::io;
use std::io::Read;

/// 读取缓冲区大小，使内存占用不随输入大小增长。
const BUFFER_SIZE: usize = 8 * 1024;

/// SHA-256 摘要失败时返回的类型化错误。
///
/// 读取输入过程中发生任何 I/O 错误都会返回该类型，而不会产生摘要。
#[derive(Debug)]
pub struct DigestError {
    source: io::Error,
}

impl DigestError {
    /// 返回导致摘要失败的底层 I/O 错误。
    pub fn io_error(&self) -> &io::Error {
        &self.source
    }
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to read input while computing SHA-256 digest: {}", self.source)
    }
}

impl Error for DigestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

impl From<io::Error> for DigestError {
    fn from(source: io::Error) -> Self {
        Self { source }
    }
}

/// 一个 SHA-256 摘要，即 32 字节的结果。
///
/// 使用 [`Digest::to_hex`] 或 [`fmt::Display`] 可得到 64 个小写
/// 十六进制字符，与命令行 `inkseal digest` 的输出格式一致。
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest([u8; 32]);

impl Digest {
    /// 以大端字节序返回摘要的 32 个原始字节。
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 返回 64 个小写十六进制字符组成的文本表示。
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in &self.0 {
            out.push(HEX_DIGITS[(byte >> 4) as usize]);
            out.push(HEX_DIGITS[(byte & 0x0f) as usize]);
        }
        out
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Digest").field(&self.to_hex()).finish()
    }
}

const HEX_DIGITS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// 以流式方式计算 `reader` 全部内容的 SHA-256 摘要。
///
/// 输入按原始字节参与计算，不做文本解码或换行转换；空输入产生标准的
/// 空字节序列摘要。读取使用固定大小的缓冲区，内存占用不随输入大小增长。
///
/// 读取中途失败时返回 [`DigestError`]，不会返回部分内容的摘要。
pub fn digest_reader<R: Read>(mut reader: R) -> Result<Digest, DigestError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    Ok(Digest(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, ErrorKind, Read};

    /// 先吐出部分字节、随后在读取中途失败的 Reader，
    /// 用于确认读取失败不会被当作成功摘要。
    struct FailAfterStart {
        remaining: usize,
    }

    impl Read for FailAfterStart {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::new(ErrorKind::Other, "simulated read failure"));
            }
            let n = self.remaining.min(buf.len());
            buf[..n].fill(b'a');
            self.remaining -= n;
            Ok(n)
        }
    }

    #[test]
    fn empty_input_matches_standard_sha256() {
        let digest = digest_reader(io::empty()).unwrap();
        assert_eq!(
            digest.to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn abc_matches_standard_sha256() {
        let digest = digest_reader(&b"abc"[..]).unwrap();
        assert_eq!(
            digest.to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn digest_covers_multiple_buffer_fills() {
        // 输入跨越多个固定大小的读取缓冲块。
        let data = vec![0x5au8; BUFFER_SIZE * 3 + 17];
        let digest = digest_reader(data.as_slice()).unwrap();

        // 独立计算一次期望值。
        let mut hasher = Sha256::new();
        sha2::Digest::update(&mut hasher, &data);
        let expected: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(digest.to_hex(), expected);
    }

    #[test]
    fn read_error_after_partial_data_is_typed_failure() {
        let reader = FailAfterStart { remaining: 100 };
        let err = digest_reader(reader).unwrap_err();
        assert_eq!(err.io_error().kind(), ErrorKind::Other);
        assert!(err.to_string().contains("simulated read failure"));
    }
}
