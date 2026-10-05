//! inkseal 的库接口：对任意实现 [`std::io::Read`] 的输入计算 SHA-256 摘要。
//!
//! 摘要只取决于输入的原始字节，与命令行 `inkseal digest <文件>` 遵循同一内容规则。

use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use std::io::{self, Read};
use std::str::FromStr;

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

impl FromStr for Sha256Digest {
    type Err = ParseDigestError;

    /// 把先前保存的十六进制摘要文本还原为 [`Sha256Digest`]。
    ///
    /// 输入必须恰好是 64 个 ASCII 十六进制字符（`0-9`、`a-f`、`A-F`，
    /// 大小写混用表示同一个摘要）。不做任何裁剪或修正：前后空白、末尾
    /// 换行、`0x` 前缀、分隔符、长度不符或含非 ASCII 内容都是格式错误。
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes = text.as_bytes();
        if bytes.len() != 64 {
            return Err(ParseDigestError::InvalidLength(bytes.len()));
        }
        let mut out = [0u8; 32];
        for (i, pair) in bytes.chunks_exact(2).enumerate() {
            let hi = hex_nibble(pair[0])
                .ok_or(ParseDigestError::InvalidCharacter(2 * i))?;
            let lo = hex_nibble(pair[1])
                .ok_or(ParseDigestError::InvalidCharacter(2 * i + 1))?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Sha256Digest(out))
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// 从十六进制文本解析 [`Sha256Digest`] 失败时返回的类型化错误。
///
/// 两类失败可以按变体区分：长度不符时取得输入的实际 UTF-8 字节长度；
/// 长度符合但含非法字符时取得首个非法字节从零开始的字节偏移（按原始
/// 文本的字节计算，不按字符个数）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseDigestError {
    /// 输入的 UTF-8 字节长度不是 64；字段为实际字节长度。
    InvalidLength(usize),
    /// 长度符合但含有非十六进制字符；字段为首个非法字节的字节偏移。
    InvalidCharacter(usize),
}

impl ParseDigestError {
    /// 长度不符时返回输入的实际字节长度，否则返回 `None`。
    pub fn actual_len(&self) -> Option<usize> {
        match self {
            ParseDigestError::InvalidLength(len) => Some(*len),
            ParseDigestError::InvalidCharacter(_) => None,
        }
    }

    /// 含非法字符时返回首个非法字节的字节偏移，否则返回 `None`。
    pub fn invalid_position(&self) -> Option<usize> {
        match self {
            ParseDigestError::InvalidCharacter(pos) => Some(*pos),
            ParseDigestError::InvalidLength(_) => None,
        }
    }
}

impl fmt::Display for ParseDigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseDigestError::InvalidLength(len) => write!(
                f,
                "digest must be exactly 64 ASCII hexadecimal characters, got {len} bytes"
            ),
            ParseDigestError::InvalidCharacter(pos) => {
                write!(f, "digest contains a non-hexadecimal byte at offset {pos}")
            }
        }
    }
}

impl Error for ParseDigestError {}

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

    #[test]
    fn parsed_digest_equals_computed_digest_of_same_content() {
        let computed = digest_reader(&b"abc"[..]).unwrap();
        let parsed: Sha256Digest = computed.to_hex().parse().unwrap();
        assert_eq!(parsed, computed);
        // 既有的字节访问与显示功能可直接用于解析结果。
        assert_eq!(parsed.as_bytes(), computed.as_bytes());
        assert_eq!(parsed.to_hex(), computed.to_hex());
        assert_eq!(format!("{parsed}"), computed.to_hex());
    }

    #[test]
    fn parse_accepts_mixed_case_as_same_digest() {
        let lower = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let upper = lower.to_uppercase();
        let mut mixed = String::with_capacity(64);
        for (i, c) in lower.chars().enumerate() {
            if i % 2 == 0 { mixed.push(c.to_ascii_uppercase()) } else { mixed.push(c) }
        }
        let lower: Sha256Digest = lower.parse().unwrap();
        assert_eq!(upper.parse::<Sha256Digest>().unwrap(), lower);
        assert_eq!(mixed.parse::<Sha256Digest>().unwrap(), lower);
    }

    #[test]
    fn parsed_bytes_match_text_value_byte_for_byte() {
        // 逐字节构造期望：0x00, 0x11, 0x22, …, 0xff 的重复序列，
        // 覆盖高位/低位半字节与开头为零的情况。
        let mut expected = [0u8; 32];
        let mut hex = String::with_capacity(64);
        for (i, byte) in expected.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(0x11);
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}", byte = *byte);
        }
        let parsed: Sha256Digest = hex.parse().unwrap();
        assert_eq!(parsed.as_bytes(), &expected);
        // 输出仍统一为 64 个小写十六进制字符，保留开头的零。
        assert_eq!(parsed.to_hex(), hex);
        assert!(hex.starts_with("00"));
    }

    #[test]
    fn parse_rejects_wrong_length_and_reports_actual_len() {
        for (input, len) in [
            ("", 0usize),
            (&"a".repeat(63)[..], 63),
            (&"a".repeat(65)[..], 65),
            ("0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 66),
        ] {
            let err = input.parse::<Sha256Digest>().unwrap_err();
            assert_eq!(err, ParseDigestError::InvalidLength(len));
            assert_eq!(err.actual_len(), Some(len));
            assert_eq!(err.invalid_position(), None);
        }
        // 空字符串不能变成空文件的摘要。
        assert!("".parse::<Sha256Digest>().is_err());
    }

    #[test]
    fn parse_rejects_invalid_character_and_reports_byte_offset() {
        // 第 10 个字节是 'g'。
        let mut text = "a".repeat(64);
        text.replace_range(10..11, "g");
        let err = text.parse::<Sha256Digest>().unwrap_err();
        assert_eq!(err, ParseDigestError::InvalidCharacter(10));
        assert_eq!(err.invalid_position(), Some(10));
        assert_eq!(err.actual_len(), None);

        // 首字符非法时偏移为 0；末字符非法时偏移为 63。
        let mut first = "a".repeat(64);
        first.replace_range(0..1, "z");
        assert_eq!(
            first.parse::<Sha256Digest>().unwrap_err(),
            ParseDigestError::InvalidCharacter(0)
        );
        let mut last = "a".repeat(64);
        last.replace_range(63..64, " ");
        assert_eq!(
            last.parse::<Sha256Digest>().unwrap_err(),
            ParseDigestError::InvalidCharacter(63)
        );
    }

    #[test]
    fn parse_rejects_non_ascii_and_reports_byte_offset_not_char_index() {
        // 全角数字“０”占 3 个 UTF-8 字节：61 个 ASCII 十六进制字符 + “０”
        // 恰好 64 字节，长度检查通过，非法位置按字节偏移 61 报告（而非字符
        // 索引或字符个数）。
        let text = format!("{}{}", "a".repeat(61), '０');
        assert_eq!(text.len(), 64);
        let err = text.parse::<Sha256Digest>().unwrap_err();
        assert_eq!(err, ParseDigestError::InvalidCharacter(61));
    }

    #[test]
    fn parse_does_not_trim_or_fix_input() {
        let valid = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        // 复制时带入的空白、末尾换行、0x 前缀和分隔符都是格式错误。
        for bad in [
            format!(" {valid}"),
            format!("{valid} "),
            format!("{valid}\n"),
            format!("{valid}\r\n"),
            format!("0x{valid}"),
            format!("{valid}\t"),
        ] {
            assert!(bad.parse::<Sha256Digest>().is_err(), "accepted {bad:?}");
        }
        // 长度符合但中间夹空格：按非法字符报告其字节位置。
        let mut spaced = valid.to_string();
        spaced.replace_range(20..21, " ");
        assert_eq!(
            spaced.parse::<Sha256Digest>().unwrap_err(),
            ParseDigestError::InvalidCharacter(20)
        );
    }

    #[test]
    fn parse_error_supports_display_and_error_trait() {
        let len_err = "abc".parse::<Sha256Digest>().unwrap_err();
        let msg = len_err.to_string();
        assert!(msg.contains("64"), "message should state expected length: {msg}");
        assert!(msg.contains('3'), "message should state actual length: {msg}");

        let mut text = "a".repeat(64);
        text.replace_range(5..6, "!");
        let char_err = text.parse::<Sha256Digest>().unwrap_err();
        assert!(char_err.to_string().contains('5'));

        // 两类错误都实现 std::error::Error，可放入常规错误传递链路。
        fn assert_error<T: std::error::Error>(_: &T) {}
        assert_error(&len_err);
        assert_error(&char_err);
        let _: Box<dyn std::error::Error> = Box::new(len_err);
        let _: Box<dyn std::error::Error> = Box::new(char_err);
    }
}
