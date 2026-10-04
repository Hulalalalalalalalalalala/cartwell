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
pub fn digest_reader<R: Read>(mut reader: R) -> Result<Sha256Digest, DigestError> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(Sha256Digest(hasher.finalize().into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    // 预期摘要全部由库外的独立 SHA-256 实现计算、并经两套工具交叉核对：
    // Python hashlib（底层 OpenSSL）与 GNU coreutils 的 sha256sum 结果一致。
    // 不能只拿两次调用本库的结果互相比，也不能只确认输出“看起来像十六进制”。
    const EMPTY_HEX: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ABC_HEX: &str =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; // NIST FIPS 180-4
    const BINARY_256_HEX: &str =
        "ae1754116b130744d081ccc09988962b3e875ec0e0d6194f2c950e8fe7e27a3d";
    const MIXED_HEX: &str =
        "143a88852e27e77f6ff3ad294f95d12cc86f01e2d6adfe16a68a146aaa7329f5";
    const LONG_HEX: &str =
        "9616ca04e2bfe2a36e50c5bdc37821f66a01f636101903dff8f79fe97d30d444";
    const LONG_DROP_LAST_HEX: &str =
        "5096be65f555412bf83ff11931c5b08d3597cd83adddd72f5cb056c374d91b5b";

    /// 混合内容：NUL、非法 UTF-8 起始字节（0xff/0xfe/0x80）、LF、CRLF、
    /// 孤立 CR、tab，以及一个合法的多字节 UTF-8 字符（é = c3 a9）。
    /// 整体不是合法 UTF-8，长度 47 字节，适合做精确值与变异对照。
    /// 在运行时构造，避免字节串字面量被静态地当作“必然非法 UTF-8”。
    fn mixed_input() -> Vec<u8> {
        let mut v = vec![0x00, 0xff, 0xfe, 0x80];
        v.extend_from_slice(b"line one\nline two\r\nline three\rtab\t\xc3\xa9 ");
        v.push(0xff);
        v.extend_from_slice(b" end");
        v.push(0x00);
        v
    }

    // ---- 测试用读取器：模拟各种交付字节的方式 ----

    /// 每次读取至多 `limit` 字节，即使调用方给了更大的缓冲区。
    struct LimitedReader<'a> {
        data: &'a [u8],
        limit: usize,
        reads: usize,
    }

    impl<'a> LimitedReader<'a> {
        fn new(data: &'a [u8], limit: usize) -> Self {
            Self { data, limit, reads: 0 }
        }
    }

    impl Read for LimitedReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.data.is_empty() {
                return Ok(0);
            }
            let n = self.limit.min(buf.len()).min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            self.reads += 1;
            Ok(n)
        }
    }

    /// 按固定脚本循环地交付不等长片段（长度和为 197），其中包含只给
    /// 1 字节的读取；输入耗尽前始终返回非零字节数，耗尽时才报告 EOF。
    struct ScriptedReader<'a> {
        data: &'a [u8],
        next_chunk: usize,
        reads: usize,
    }

    const SCRIPT_CHUNKS: [usize; 9] = [1, 2, 5, 13, 64, 3, 100, 2, 7];

    impl<'a> ScriptedReader<'a> {
        fn new(data: &'a [u8]) -> Self {
            Self { data, next_chunk: 0, reads: 0 }
        }
    }

    impl Read for ScriptedReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.data.is_empty() {
                return Ok(0);
            }
            let want = SCRIPT_CHUNKS[self.next_chunk % SCRIPT_CHUNKS.len()].min(buf.len());
            self.next_chunk += 1;
            let n = want.min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            self.reads += 1;
            Ok(n)
        }
    }

    /// 第一次读取交付前缀的全部字节，之后的每次读取都报 I/O 错误。
    /// 用于覆盖“已经拿到部分内容，后续读取才失败”的中途失败场景。
    struct PartialThenFailReader<'a> {
        data: &'a [u8],
        delivered: bool,
    }

    impl Read for PartialThenFailReader<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.delivered {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "disk exploded mid-read",
                ));
            }
            let n = self.data.len().min(buf.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            self.delivered = true;
            Ok(n)
        }
    }

    /// 确定性长输入，200_003 字节：超过三次 64 KiB 整块读取，整块读取
    /// 三次后还余 3_395 字节短尾。每 1000 字节开头散布 NUL/0xff/0xfe/
    /// CR/LF/0x80 等特殊字节，其余字节由位置确定性推出，整体非法 UTF-8。
    fn long_input() -> Vec<u8> {
        const SPECIAL: [u8; 9] = [0x00, 0xff, 0xfe, 0x0a, 0x0d, 0x0a, 0x0d, 0x80, 0xc3];
        (0..200_003u64)
            .map(|i| match (i % 1000) as usize {
                r @ 0..9 => SPECIAL[r],
                _ => (i.wrapping_mul(2654435761) & 0xff) as u8,
            })
            .collect()
    }

    #[test]
    fn empty_input_matches_standard_sha256() {
        let digest = digest_reader(io::empty()).unwrap();
        assert_eq!(digest.to_hex(), EMPTY_HEX);
    }

    #[test]
    fn known_vector_abc() {
        let digest = digest_reader(&b"abc"[..]).unwrap();
        assert_eq!(digest.to_hex(), ABC_HEX);
    }

    #[test]
    fn all_byte_values_plus_sentinels_match_independent_digest() {
        let data: Vec<u8> = (0u8..=255).chain([0x00, 0xff, 0xfe, 0x80]).collect();
        let digest = digest_reader(&data[..]).unwrap();
        assert_eq!(digest.to_hex(), BINARY_256_HEX);
    }

    #[test]
    fn mixed_binary_content_hashed_without_decode_or_newline_conversion() {
        let mixed = mixed_input();
        // 前置条件：内容确实包含要保护的各种字节，且整体不是合法 UTF-8。
        assert!(std::str::from_utf8(&mixed).is_err());
        assert!(mixed.contains(&0));
        assert!(mixed.windows(2).any(|w| w == b"\r\n"));
        assert!(mixed.contains(&b'\r'));
        assert!(mixed.contains(&b'\n'));

        assert_eq!(digest_reader(&mixed[..]).unwrap().to_hex(), MIXED_HEX);

        // 任何错误的“文本化”处理都会改变原始字节，从而无法对上独立预期值：
        // 1) 损失性 UTF-8 解码后再编码（非法字节变成 U+FFFD）；
        let lossy = String::from_utf8_lossy(&mixed).into_owned();
        assert_ne!(digest_reader(lossy.as_bytes()).unwrap().to_hex(), MIXED_HEX);
        // 2) 类文本模式的 CRLF -> LF 换行转换；
        let mut crlf_stripped = Vec::with_capacity(mixed.len());
        let mut i = 0;
        while i < mixed.len() {
            if mixed[i..].starts_with(b"\r\n") {
                crlf_stripped.push(b'\n');
                i += 2;
            } else {
                crlf_stripped.push(mixed[i]);
                i += 1;
            }
        }
        assert_ne!(digest_reader(&crlf_stripped[..]).unwrap().to_hex(), MIXED_HEX);
        // 3) 遗漏尾部数据（少最后一个字节）。
        assert_ne!(
            digest_reader(&mixed[..mixed.len() - 1]).unwrap().to_hex(),
            MIXED_HEX
        );
    }

    #[test]
    fn digest_is_independent_of_read_chunking_and_includes_tail() {
        const READ_BUF: usize = 64 * 1024;
        const LONG_LEN: usize = 200_003;

        let data = long_input();
        assert_eq!(data.len(), LONG_LEN);
        // 三种读取方式末尾都留有一段较短数据：
        assert!(LONG_LEN > 3 * READ_BUF);
        assert_eq!(LONG_LEN - 3 * READ_BUF, 3_395); // 大片段：三次整块后余 3_395
        assert_eq!(LONG_LEN % 7, 6); // 每次 7 字节：最后一次只读到 6 字节
        assert_eq!(LONG_LEN % 197, 48); // 不等长脚本（长度和 197）：末尾 48 字节
        // 内容同样覆盖特殊与非法 UTF-8 字节：
        assert!(std::str::from_utf8(&data).is_err());
        assert!(data.contains(&0) && data.contains(&0xff) && data.contains(&0xfe));

        // 方式一：较大片段（给多大缓冲区就尽量填满，等同文件读取）。
        let via_big_chunks = digest_reader(&data[..]).unwrap();
        // 方式二：每次只读少量（7 个）字节。
        let mut small = LimitedReader::new(&data, 7);
        let via_small_reads = digest_reader(&mut small).unwrap();
        // 方式三：连续不等长片段，其中多次读取只返回 1~2 个字节。
        let mut scripted = ScriptedReader::new(&data);
        let via_scripted_chunks = digest_reader(&mut scripted).unwrap();

        // 三者必须等于同一个由库外工具核对出的摘要，即整份原始字节的摘要：
        assert_eq!(via_big_chunks.to_hex(), LONG_HEX);
        assert_eq!(via_small_reads.to_hex(), LONG_HEX);
        assert_eq!(via_scripted_chunks.to_hex(), LONG_HEX);

        // 确认确实经历了多次读取并把输入耗尽，而非一次性读完或提前结束：
        assert_eq!(small.reads, (LONG_LEN + 6) / 7);
        assert!(small.data.is_empty());
        assert!(scripted.reads > 1);
        assert!(scripted.data.is_empty());

        // 末尾短尾确实参与了计算：少最后一个字节得到的是另一个独立已知值，
        // 任何遗漏尾部的实现都会算出它而不是 LONG_HEX，从而被本测试抓住。
        let missing_tail = digest_reader(&data[..LONG_LEN - 1]).unwrap();
        assert_eq!(missing_tail.to_hex(), LONG_DROP_LAST_HEX);
        assert_ne!(LONG_DROP_LAST_HEX, LONG_HEX);
    }

    #[test]
    fn short_non_final_reads_keep_being_accumulated_until_eof() {
        // 输入每次只交付 1 个字节；尚未 EOF 时必须继续累积，直到读到 0。
        let mut reader = LimitedReader::new(b"abc", 1);
        let digest = digest_reader(&mut reader).unwrap();
        assert_eq!(digest.to_hex(), ABC_HEX);
        assert_eq!(reader.reads, 3);
        assert!(reader.data.is_empty());
    }

    #[test]
    fn read_failure_before_any_data_is_typed_error_not_digest() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::Other, "boom"))
            }
        }
        let err = digest_reader(FailingReader).unwrap_err();
        assert!(err.to_string().contains("boom"));
        assert_eq!(err.into_inner().kind(), io::ErrorKind::Other);
    }

    #[test]
    fn failure_after_partial_data_returns_typed_error_never_partial_digest() {
        // 第一次读取成功交付 "abc"，随后的读取报告 BrokenPipe。
        let mut reader = PartialThenFailReader { data: b"abc", delivered: false };
        let err = digest_reader(&mut reader)
            .expect_err("an error after partial data must not become a digest");

        // 与“什么都没读到就失败”区分：错误发生前确实已交付部分字节。
        assert!(reader.delivered);
        assert!(reader.data.is_empty());

        // 错误说明保留包装语义与原始原因，source 链也能找回底层错误。
        let text = err.to_string();
        assert!(text.contains("failed to read input"), "{text}");
        assert!(text.contains("disk exploded mid-read"), "{text}");
        let source = err.source().expect("DigestError exposes a source").to_string();
        assert!(source.contains("disk exploded mid-read"));

        // 调用方仍能取得底层 io::Error 并辨认其种类。
        assert_eq!(err.into_inner().kind(), io::ErrorKind::BrokenPipe);

        // 对照：同样的 "abc" 被正常读完时是成功的已知摘要；而上面的调用
        // 即使在错误发生前读到的字节本身能形成合法摘要，也绝不能成功。
        assert_eq!(digest_reader(&b"abc"[..]).unwrap().to_hex(), ABC_HEX);
    }

    #[test]
    fn bytes_hex_and_display_express_one_value_with_plain_hex_text() {
        let mixed = mixed_input();
        let digest = digest_reader(&mixed[..]).unwrap();
        assert_eq!(digest.to_hex(), MIXED_HEX);

        // 原始字节、十六进制文本、Display 三种表达必须是同一个 SHA-256 值。
        assert_eq!(digest.as_bytes().len(), 32);
        let rebuilt: String = digest.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(rebuilt, digest.to_hex());
        assert_eq!(digest.to_string(), digest.to_hex());

        // 文本形式：恰好 64 个小写十六进制字符，不含换行、空白、文件名或标签。
        let hex = digest.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(hex.bytes().all(|b| !b.is_ascii_uppercase()));
        assert_eq!(hex, hex.trim());
        for forbidden in ['\n', '\r', '\t', ' ', ':'] {
            assert!(!hex.contains(forbidden), "hex text must not contain {forbidden:?}");
        }
    }
}
