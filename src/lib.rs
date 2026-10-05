//! inkseal 的库接口：对任意实现 [`std::io::Read`] 的输入计算 SHA-256 摘要。
//!
//! 摘要只取决于输入的原始字节，与命令行 `inkseal digest <文件>` 遵循同一内容规则。

use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use std::io::{self, Read};

/// SHA-256 摘要结果，可表示为 64 个小写十六进制字符。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    /// 返回摘要的原始 32 字节。
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 返回 64 个小写十六进制字符，与命令行输出一致（不含换行）。
    pub fn to_hex(&self) -> String {
        let mut hex = String::with_capacity(64);
        for byte in self.0 {
            hex.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
            hex.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
        }
        hex
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256Digest({self})")
    }
}

/// 计算摘要过程中读取输入失败时返回的类型化错误。
#[derive(Debug)]
pub struct DigestError(io::Error);

impl DigestError {
    /// 取出底层的 I/O 错误。
    pub fn into_inner(self) -> io::Error {
        self.0
    }
}

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "failed to read input: {}", self.0)
    }
}

impl Error for DigestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

impl From<io::Error> for DigestError {
    fn from(err: io::Error) -> Self {
        DigestError(err)
    }
}

/// 以流式方式读取 `reader` 的全部字节并计算 SHA-256 摘要。
///
/// 内存占用与输入大小无关。读取失败时返回 [`DigestError`]，绝不返回部分内容的摘要。
///
/// [`io::ErrorKind::Interrupted`] 是临时中断而非输入结束：本次读取没有
/// 消费任何字节，直接重试同一位置，摘要与未发生中断时完全一致。其他
/// 错误（权限不足、数据损坏等）仍然立即失败。
pub fn digest_reader<R: Read>(mut reader: R) -> Result<Sha256Digest, DigestError> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(ref err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(DigestError(err)),
        }
    }
    Ok(Sha256Digest(hasher.finalize().into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn empty_input_matches_standard_sha256() {
        let digest = digest_reader(io::empty()).unwrap();
        assert_eq!(
            digest.to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn known_vector_abc() {
        let digest = digest_reader(&b"abc"[..]).unwrap();
        assert_eq!(
            digest.to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn binary_and_non_utf8_bytes_hashed_verbatim() {
        let data: Vec<u8> = (0u8..=255).chain([0x00, 0xff, 0xfe, 0x80]).collect();
        let digest = digest_reader(&data[..]).unwrap();
        // 独立依据：python3 hashlib.sha256 对同样 260 字节的计算结果。
        assert_eq!(
            digest.to_hex(),
            "ae1754116b130744d081ccc09988962b3e875ec0e0d6194f2c950e8fe7e27a3d"
        );
        assert_eq!(digest.to_hex().len(), 64);
        assert!(digest.to_hex().chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn read_failure_is_typed_error_not_digest() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::Other, "boom"))
            }
        }
        let err = digest_reader(FailingReader).unwrap_err();
        assert!(err.to_string().contains("boom"));
    }

    /// 按给定片段长度序列依次返回输入字节的读取器；序列为空时每次读满。
    /// 用于模拟不同分块方式，验证摘要只取决于字节内容而非读取方式。
    struct ChunkedReader<'a> {
        data: &'a [u8],
        pos: usize,
        chunk_sizes: &'a [usize],
        chunk_index: usize,
    }

    impl<'a> ChunkedReader<'a> {
        fn new(data: &'a [u8], chunk_sizes: &'a [usize]) -> Self {
            ChunkedReader { data, pos: 0, chunk_sizes, chunk_index: 0 }
        }
    }

    impl Read for ChunkedReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pos == self.data.len() {
                return Ok(0);
            }
            let mut limit = buf.len();
            if !self.chunk_sizes.is_empty() {
                limit = limit.min(self.chunk_sizes[self.chunk_index % self.chunk_sizes.len()]);
                self.chunk_index += 1;
            }
            let n = limit.min(self.data.len() - self.pos);
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    /// 确定性长输入：长度 3*64KiB + 1234，保证跨越多次内部读取且末尾留有不整段的尾巴。
    fn long_input() -> Vec<u8> {
        (0..(3 * 64 * 1024 + 1234))
            .map(|i| ((i * 31 + 7) % 256) as u8)
            .collect()
    }

    /// 独立依据：python3 hashlib.sha256 对 long_input() 全部字节的计算结果。
    const LONG_INPUT_HEX: &str =
        "8ca02b16ce35f9fca993a0fdf5a537fc72a62a77b2e6fa852a371f18b8e3fcc4";

    #[test]
    fn long_input_digest_covers_all_bytes_including_tail() {
        let digest = digest_reader(&long_input()[..]).unwrap();
        assert_eq!(digest.to_hex(), LONG_INPUT_HEX);
    }

    #[test]
    fn chunking_strategy_does_not_change_digest() {
        let data = long_input();
        let expected = digest_reader(&data[..]).unwrap();

        // 每次只给少量字节（1 字节），读取器必须被持续读取直到报告结束。
        let one_byte = digest_reader(ChunkedReader::new(&data, &[1])).unwrap();
        // 每次少量但不等的字节数。
        let small_uneven = digest_reader(ChunkedReader::new(&data, &[1, 2, 3, 5, 7])).unwrap();
        // 较大片段。
        let large = digest_reader(ChunkedReader::new(&data, &[64 * 1024])).unwrap();
        // 连续不等长片段，且片段边界与内部缓冲区边界错开。
        let uneven = digest_reader(ChunkedReader::new(&data, &[3, 1000, 65537, 17, 4096])).unwrap();

        for digest in [one_byte, small_uneven, large, uneven] {
            assert_eq!(digest, expected);
        }
        // 并且结果对应整份原始字节，而非某次读取或前半段。
        assert_eq!(expected.to_hex(), LONG_INPUT_HEX);
    }

    #[test]
    fn zero_bytes_non_utf8_and_mixed_newlines_hashed_verbatim() {
        // 含零字节、非法 UTF-8 字节和 LF / CRLF / CR 三种换行；
        // 任何文本解码、换行转换或尾部遗漏都会改变这些字节，从而改变摘要。
        let data: &[u8] = b"alpha\nbeta\r\ngamma\rdelta\n\x00\xff\xfe\x80tail-without-newline";
        let digest = digest_reader(data).unwrap();
        // 独立依据：python3 hashlib.sha256 对同样 48 字节的计算结果。
        assert_eq!(
            digest.to_hex(),
            "879e1d6af3829ebad59012630ce80b422b1bf81dbdc2bc0c1ba940f46f2dde3c"
        );
    }

    /// 按脚本驱动的读取器：每个步骤要么返回下一段内容（长度可短于缓冲区），
    /// 要么返回一个错误。脚本用完后继续返回剩余内容，内容耗尽后返回 Ok(0)。
    /// 用于精确模拟“中断出现在任意位置”的读取序列。
    enum Step {
        /// 返回下一段内容（可为空切片以外的任意长度）。
        Data,
        /// 返回指定错误。
        Fail(io::ErrorKind, &'static str),
    }

    struct ScriptedReader<'a> {
        data: &'a [u8],
        pos: usize,
        steps: &'a [Step],
        step_index: usize,
    }

    impl<'a> ScriptedReader<'a> {
        fn new(data: &'a [u8], steps: &'a [Step]) -> Self {
            ScriptedReader { data, pos: 0, steps, step_index: 0 }
        }
    }

    impl Read for ScriptedReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.steps.get(self.step_index) {
                Some(Step::Data) => {
                    self.step_index += 1;
                    // 每段最多给剩余内容的一半，保证一段脚本可能对应多次内容返回，
                    // 且片段长度通常短于缓冲区容量。
                    let remaining = self.data.len() - self.pos;
                    let n = (remaining / 2).max(1).min(remaining).min(buf.len());
                    buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                    self.pos += n;
                    Ok(n)
                }
                Some(Step::Fail(kind, msg)) => {
                    self.step_index += 1;
                    Err(io::Error::new(*kind, *msg))
                }
                None => {
                    let remaining = self.data.len() - self.pos;
                    let n = remaining.min(buf.len());
                    buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                    self.pos += n;
                    Ok(n)
                }
            }
        }
    }

    use Step::{Data, Fail};

    #[test]
    fn interrupted_reads_are_retried_not_treated_as_eof_or_error() {
        let data = long_input();
        let expected = digest_reader(&data[..]).unwrap();

        // 第一个字节之前中断。
        let before_first = digest_reader(ScriptedReader::new(
            &data,
            &[Fail(io::ErrorKind::Interrupted, "EINTR"), Data, Data, Data, Data, Data, Data],
        ))
        .unwrap();
        // 中断夹在两段有效内容之间。
        let between = digest_reader(ScriptedReader::new(
            &data,
            &[Data, Fail(io::ErrorKind::Interrupted, "EINTR"), Data, Data, Data],
        ))
        .unwrap();
        // 最后一段内容之后、输入正式结束之前中断。
        let before_eof = digest_reader(ScriptedReader::new(
            &data,
            &[Data, Data, Data, Data, Data, Data, Fail(io::ErrorKind::Interrupted, "EINTR")],
        ))
        .unwrap();
        // 连续多次中断。
        let repeated = digest_reader(ScriptedReader::new(
            &data,
            &[
                Fail(io::ErrorKind::Interrupted, "EINTR"),
                Fail(io::ErrorKind::Interrupted, "EINTR"),
                Data,
                Fail(io::ErrorKind::Interrupted, "EINTR"),
                Fail(io::ErrorKind::Interrupted, "EINTR"),
                Data,
                Data,
                Data,
                Data,
                Fail(io::ErrorKind::Interrupted, "EINTR"),
                Fail(io::ErrorKind::Interrupted, "EINTR"),
            ],
        ))
        .unwrap();

        for digest in [before_first, between, before_eof, repeated] {
            assert_eq!(digest, expected);
        }
        // 结果仍对应整份原始字节。
        assert_eq!(expected.to_hex(), LONG_INPUT_HEX);
    }

    #[test]
    fn interrupted_empty_input_still_yields_empty_digest() {
        // 只有中断、没有任何内容：与无中断的空输入摘要一致。
        let digest = digest_reader(ScriptedReader::new(
            b"",
            &[Fail(io::ErrorKind::Interrupted, "EINTR"), Fail(io::ErrorKind::Interrupted, "EINTR")],
        ))
        .unwrap();
        assert_eq!(digest, digest_reader(io::empty()).unwrap());
    }

    #[test]
    fn non_interrupted_error_after_interrupt_still_fails() {
        const PREFIX: &[u8] = b"partial bytes before the failure";
        // 先发生可恢复的临时中断，随后出现真正的读取错误：
        // 本次调用必须失败，且报告的是后来的真实错误，不是之前的中断。
        let err = digest_reader(ScriptedReader::new(
            PREFIX,
            &[
                Fail(io::ErrorKind::Interrupted, "EINTR"),
                Data,
                Fail(io::ErrorKind::PermissionDenied, "disk vanished"),
            ],
        ))
        .unwrap_err();

        let inner = err.into_inner();
        assert_eq!(inner.kind(), io::ErrorKind::PermissionDenied);
        assert!(inner.to_string().contains("disk vanished"));
    }

    #[test]
    fn error_after_partial_read_is_typed_error_not_partial_digest() {
        const PREFIX: &[u8] = b"partial bytes before the failure";
        struct PartialThenFail {
            pos: usize,
        }
        impl Read for PartialThenFail {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.pos < PREFIX.len() {
                    let n = (PREFIX.len() - self.pos).min(buf.len());
                    buf[..n].copy_from_slice(&PREFIX[self.pos..self.pos + n]);
                    self.pos += n;
                    Ok(n)
                } else {
                    Err(io::Error::new(io::ErrorKind::PermissionDenied, "disk vanished"))
                }
            }
        }

        let err = digest_reader(PartialThenFail { pos: 0 }).unwrap_err();

        // 错误不能被当作输入结束：即使已读前缀本身有合法摘要，也不能返回它。
        // （前缀的 SHA-256 为 2b7e8784…，与本次调用无关——调用必须失败。）
        let inner = err.into_inner();
        assert_eq!(inner.kind(), io::ErrorKind::PermissionDenied);
        assert!(inner.to_string().contains("disk vanished"));
    }

    #[test]
    fn typed_error_display_and_source_preserve_original_cause() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::InvalidData, "corrupt sector 7"))
            }
        }
        let err = digest_reader(FailingReader).unwrap_err();
        assert!(err.to_string().contains("corrupt sector 7"));
        let source = std::error::Error::source(&err).expect("typed error keeps its cause");
        assert!(source.to_string().contains("corrupt sector 7"));
    }

    #[test]
    fn digest_representations_express_the_same_value() {
        let digest = digest_reader(&b"abc"[..]).unwrap();
        let hex = digest.to_hex();

        // 原始字节与十六进制文本表达同一个值。
        let mut from_bytes = String::with_capacity(64);
        for byte in digest.as_bytes() {
            use std::fmt::Write as _;
            let _ = write!(from_bytes, "{byte:02x}");
        }
        assert_eq!(from_bytes, hex);

        // Display 与 to_hex 一致。
        assert_eq!(format!("{digest}"), hex);

        // 恰好 64 个小写十六进制字符，无文件名、标签、空白或换行。
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert!(!hex.chars().any(char::is_whitespace));
    }
}
