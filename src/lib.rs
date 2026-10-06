//! inkseal 的库接口：
//!
//! - 对任意实现 [`std::io::Read`] 的输入计算 SHA-256 摘要
//!   （[`digest_reader`] / [`Sha256Digest`]）；
//! - 从 DER 编码的 SubjectPublicKeyInfo 导入 RFC 8410 的 Ed25519 公钥
//!   （[`import_ed25519_public_key`] / [`Ed25519PublicKey`]）。
//!
//! 摘要只取决于输入的原始字节，与命令行 `inkseal digest <文件>` 遵循同一内容规则。
//! 公钥是与摘要相互独立的类型：公钥不会被当作摘要解析，其十六进制文本表示的是
//! 公钥本身，而非公钥的 SHA-256 摘要。

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
        bytes_to_lower_hex(&self.0)
    }

    /// 从十六进制文本的原始字节解析摘要。
    ///
    /// 这是摘要文字还原的唯一规则：[`FromStr`] 只是在 `&str` 上委托给本
    /// 方法，命令行核对摘要时也直接使用它，因此从文本解析、按值比较与再次
    /// 显示永远遵循同一套规则。接受 `0-9`、`a-f` 和 `A-F`，大小写混用表示
    /// 同一个 32 字节值；解析结果可与 [`digest_reader`] 的结果直接比较，
    /// 再经 [`to_hex`](Self::to_hex) 显示时始终是完整的 64 个小写十六进制
    /// 字符，前导零不会丢失。
    ///
    /// 入参按原始字节处理，不要求是合法 UTF-8（例如操作系统给出的命令行
    /// 参数可能无法解码）：长度先按字节数判断，必须恰好为 64；长度正确时
    /// 报告首个非法字节从零开始的字节偏移。不做任何裁剪或修正，空白、末尾
    /// 换行、`0x` 前缀以及非 ASCII 字节都属于格式错误。
    pub fn from_hex_bytes(bytes: &[u8]) -> Result<Sha256Digest, ParseDigestError> {
        if bytes.len() != 64 {
            return Err(ParseDigestError::InvalidLength(bytes.len()));
        }
        let mut out = [0u8; 32];
        for (i, pair) in bytes.chunks_exact(2).enumerate() {
            let hi = hex_nibble(pair[0])
                .ok_or(ParseDigestError::InvalidHexChar(2 * i))?;
            let lo = hex_nibble(pair[1])
                .ok_or(ParseDigestError::InvalidHexChar(2 * i + 1))?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Sha256Digest(out))
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

/// 从十六进制文本解析 [`Sha256Digest`] 失败时返回的类型化错误。
///
/// 两类失败可以按变体区分：长度不符时携带输入的实际 UTF-8 字节长度；
/// 长度正确但含非法字符时携带首个非法字节从零开始的字节偏移。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseDigestError {
    /// 输入的 UTF-8 字节长度不是 64；携带实际字节长度。
    InvalidLength(usize),
    /// 长度为 64 但含有非十六进制字符；携带首个非法字节的字节偏移
    /// （按原始文本的字节计算，不按字符个数）。
    InvalidHexChar(usize),
}

impl ParseDigestError {
    /// 长度不符时返回输入的实际字节长度，否则返回 `None`。
    pub fn actual_length(&self) -> Option<usize> {
        match self {
            ParseDigestError::InvalidLength(len) => Some(*len),
            ParseDigestError::InvalidHexChar(_) => None,
        }
    }

    /// 含非法字符时返回首个非法字节的字节偏移，否则返回 `None`。
    pub fn invalid_position(&self) -> Option<usize> {
        match self {
            ParseDigestError::InvalidLength(_) => None,
            ParseDigestError::InvalidHexChar(pos) => Some(*pos),
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
            ParseDigestError::InvalidHexChar(pos) => {
                write!(f, "digest contains a non-hexadecimal byte at offset {pos}")
            }
        }
    }
}

impl Error for ParseDigestError {}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

impl std::str::FromStr for Sha256Digest {
    type Err = ParseDigestError;

    /// 从 64 个 ASCII 十六进制字符解析摘要。
    ///
    /// 接受 `0-9`、`a-f` 和 `A-F`，大小写混用表示同一个摘要。输入必须
    /// 恰好是 64 个字符：不做任何裁剪或修正，空白、末尾换行、`0x` 前缀、
    /// 分隔符以及全角数字等非 ASCII 内容都属于格式错误。长度按输入的
    /// UTF-8 字节数判断，非法字符的位置也按字节偏移报告。
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Sha256Digest::from_hex_bytes(s.as_bytes())
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

// ── Ed25519 公钥导入 ─────────────────────────────────────────────────────────
//
// 入口只接受一种形态：DER 编码的 SubjectPublicKeyInfo（RFC 5280），且算法
// 标识为 RFC 8410 规定的 Ed25519（OID 1.3.101.112）。公钥因此是与
// [`Sha256Digest`] 完全独立的类型——二者底层都只是 32 字节，但语义、解析
// 入口与文本表示都不可互换，公钥不会被当作摘要解析，摘要也不会被当作公钥。
//
// 解析器手写且零依赖：只实现 SPKI 所需的 DER 子集，并对长度编码与边界做
// 完整、规范（strict DER）校验。任何截断、声明长度与实际内容不符、非规范
// 长度编码、容器中的多余字段或对象之后的多余字节都属于编码损坏，绝不忽略
// 剩余内容或自动补齐。

/// 从 DER 编码的 SubjectPublicKeyInfo 导入的 Ed25519 公钥。
///
/// 该类型与 [`Sha256Digest`] 明确区分：它只由
/// [`import_ed25519_public_key`] 产生，不能从十六进制文本构造，也不会被
/// 当作摘要解析。它持有的是公钥本身的 32 个原始字节（RFC 8032 编码点），
/// **不是**公钥或任何内容的 SHA-256 摘要。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ed25519PublicKey([u8; 32]);

impl Ed25519PublicKey {
    /// 返回公钥原样的 32 字节（RFC 8032 的公钥编码点）。
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 返回 64 个小写十六进制字符，表示公钥本身。
    ///
    /// 与 [`Sha256Digest::to_hex`] 形状相同（32 字节的十六进制展开），
    /// 但二者语义不同：这里是公钥字节的文本表示，前导零保留，不含标签、
    /// 空白或换行，也不是公钥的 SHA-256 摘要。
    pub fn to_hex(&self) -> String {
        bytes_to_lower_hex(&self.0)
    }
}

impl fmt::Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519PublicKey({self})")
    }
}

/// SubjectPublicKeyInfo 中出现的算法标识，按内容节点（OID）的原始 DER
/// 内容字节逐字节比较。
///
/// 目前唯一可比较的具名值是 Ed25519（`1.3.101.112`，RFC 8410）；
/// 其他标识以 [`Other`](Self::Other) 原样保留其 DER 内容字节，调用方可
/// 自行解码展示，库不会为不支持的算法猜测文本名称。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublicKeyAlgorithm {
    /// Ed25519：OID 1.3.101.112（RFC 8410）。
    Ed25519,
    /// 其他算法标识：`oid` 的前 `len` 字节是 OID 的原始 DER 内容字节
    /// （弧段值的压缩编码，不含 OBJECT IDENTIFIER 的标签与长度），
    /// 其余字节为零。调用方可自行解码展示，库不会为不支持的算法猜测
    /// 文本名称。
    Other {
        /// OID 内容字节（前 `len` 个字节有效）。
        oid: [u8; OID_CAPACITY],
        /// OID 内容的实际字节数。
        len: usize,
    },
}

/// 未知 OID 最多保留的内容字节数。
///
/// 合法的 OID 内容是一串 7 位基数字（base-128）弧段；前导 `0x80` 延续
/// 字节是非规范编码，属于整体编码损坏，不会走到算法比较，因此这里只需
/// 容纳实际可能出现的合法 OID。任意实际算法 OID 都远短于此上限；超出
/// 同样按编码损坏处理，而不是静默截断。
const OID_CAPACITY: usize = 64;

impl PublicKeyAlgorithm {
    /// 未知 OID 最多保留的内容字节数（见 [`OID_CAPACITY`]）。
    pub const OTHER_CAPACITY: usize = OID_CAPACITY;

    /// 按 OID 的内容字节判定：恰好是 Ed25519（1.3.101.112）的编码。
    fn from_oid_content(content: &[u8]) -> Result<PublicKeyAlgorithm, KeyImportError> {
        const ED25519_OID: &[u8] = &[0x2b, 0x65, 0x70]; // 1.3.101.112
        if content == ED25519_OID {
            Ok(PublicKeyAlgorithm::Ed25519)
        } else {
            if content.is_empty() || content.len() > OID_CAPACITY {
                return Err(KeyImportError::Malformed);
            }
            // 合法 OID 内容由一串 base-128 弧段组成：除每段最后一个字节
            // 的高位为 0 外，其余延续字节高位为 1。任何前导 0x80（非规范
            // 延续）或末字节仍带高位（截断的弧段）都是损坏编码。
            let mut cont = false;
            for &b in content {
                if !cont && b == 0x80 {
                    return Err(KeyImportError::Malformed);
                }
                cont = b & 0x80 != 0;
            }
            if cont {
                return Err(KeyImportError::Malformed);
            }
            let mut oid = [0u8; OID_CAPACITY];
            oid[..content.len()].copy_from_slice(content);
            Ok(PublicKeyAlgorithm::Other { oid, len: content.len() })
        }
    }

    /// 是否为受支持的 Ed25519 算法标识。
    pub fn is_ed25519(&self) -> bool {
        matches!(self, PublicKeyAlgorithm::Ed25519)
    }

    /// 其他算法标识的原始 OID 内容字节；Ed25519 返回 `None`。
    ///
    /// 返回的是 OBJECT IDENTIFIER 内容节点的原始 DER 字节（不含标签与
    /// 长度），可供调用方按点分十进制自行解码展示；库不替调用方猜测其
    /// 文本名称。
    pub fn oid_bytes(&self) -> Option<&[u8]> {
        match self {
            PublicKeyAlgorithm::Ed25519 => None,
            PublicKeyAlgorithm::Other { oid, len } => Some(&oid[..*len]),
        }
    }
}

impl fmt::Debug for PublicKeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublicKeyAlgorithm::Ed25519 => f.write_str("Ed25519(1.3.101.112)"),
            PublicKeyAlgorithm::Other { oid, len } => {
                write!(f, "Other({})", bytes_to_lower_hex(&oid[..*len]))
            }
        }
    }
}

/// 导入 Ed25519 公钥失败时返回的类型化错误。
///
/// 调用方无需解析提示字符串即可区分两类失败：
///
/// - [`Malformed`](Self::Malformed)：输入不是一份完整、规范的 DER
///   SubjectPublicKeyInfo，或其内部结构不符合 Ed25519 公钥的规定——截断、
///   长度不符、非规范长度编码、多余字段、尾随字节、参数写成 `NULL`、
///   位串有未使用位、公钥不是恰好 32 字节等都属于这一类。裸公钥、
///   十六进制文本与 PEM 文本同样不被这个入口接受。
/// - [`UnsupportedAlgorithm`](Self::UnsupportedAlgorithm)：整体 DER 结构
///   完整合法，但算法标识不是 Ed25519。实际标识随错误保留，可直接展示。
///
/// 只有“结构完整、DER 合法”时才可能出现算法不支持；编码已损坏时一律是
/// [`Malformed`](Self::Malformed)，不会因为损坏数据中局部出现某个其他
/// 算法的 OID 字节就改报算法不支持。任何失败都不会产生可继续使用的公钥。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyImportError {
    /// DER 编码或公钥结构不合法（含输入为空、被截断、非规范编码、多余
    /// 字段、尾随字节、参数非缺省、位串未使用位非零、公钥长度不符）。
    Malformed,
    /// SubjectPublicKeyInfo 结构合法，但算法标识不是 Ed25519；携带实际
    /// 算法标识。
    UnsupportedAlgorithm(PublicKeyAlgorithm),
}

impl KeyImportError {
    /// 是否为编码或公钥结构不合法（而非算法不支持）。
    pub fn is_malformed(&self) -> bool {
        matches!(self, KeyImportError::Malformed)
    }

    /// 结构合法但算法不被支持时，返回其中保留的实际算法标识；
    /// 编码损坏时返回 `None`。
    pub fn unsupported_algorithm(&self) -> Option<&PublicKeyAlgorithm> {
        match self {
            KeyImportError::Malformed => None,
            KeyImportError::UnsupportedAlgorithm(algo) => Some(algo),
        }
    }
}

impl fmt::Display for KeyImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyImportError::Malformed => f.write_str(
                "malformed Ed25519 public key: expected one complete DER SubjectPublicKeyInfo \
(RFC 8410), but the encoding is invalid or truncated",
            ),
            KeyImportError::UnsupportedAlgorithm(PublicKeyAlgorithm::Ed25519) => {
                // 不会发生：Ed25519 是受支持算法，保留分支以保证匹配穷尽。
                f.write_str("unexpected Ed25519 algorithm identifier")
            }
            KeyImportError::UnsupportedAlgorithm(PublicKeyAlgorithm::Other { oid, len }) => {
                write!(
                    f,
                    "unsupported public key algorithm with OID content {}; only Ed25519 \
                     (1.3.101.112, RFC 8410) is accepted",
                    bytes_to_lower_hex(&oid[..*len])
                )
            }
        }
    }
}

impl Error for KeyImportError {}

/// DER 通用标签中本解析器用到的值：BIT STRING、OBJECT IDENTIFIER、
/// SEQUENCE。参数 TLV 的标签不做白名单：parameters 是否允许取决于算法
/// 标识——Ed25519 要求参数缺省，任何参数（含显式 NULL `05 00`）都在
/// 算法判定之后按公钥结构不合法拒绝；其他算法的参数只要求本身是一个
/// 完整 TLV。
const DER_TAG_BIT_STRING: u8 = 0x03;
const DER_TAG_OID: u8 = 0x06;
const DER_TAG_SEQUENCE: u8 = 0x30;

/// 读取一个 DER TLV，返回 `(标签, 值字节, 标签后剩余的全部字节)`。
///
/// 严格校验：标识符必须是单字节通用标签（首字节 `0x1f` 的多字节标签
/// 形式直接拒绝）；长度必须是规范 DER——短形式或最短必要的长形式，
/// `0x81 0x00` 之类非最小编码与长形式前导零都拒绝；声明长度必须与实际
/// 内容相符，截断与对象后的多余字节由调用方按“剩余必须恰好用尽”处理。
fn der_read_tlv(data: &[u8]) -> Result<(u8, &[u8], &[u8]), KeyImportError> {
    let (&tag, rest) = data.split_first().ok_or(KeyImportError::Malformed)?;
    // 多字节标签号（tag number 0x1f..=0x3e 的低位全 1）不用于 SPKI 的
    // 任何规定节点，一律拒绝。
    if tag & 0x1f == 0x1f {
        return Err(KeyImportError::Malformed);
    }
    let (&first_len, mut rest) = rest.split_first().ok_or(KeyImportError::Malformed)?;

    let length = match first_len {
        // 短形式：0..=127。
        0..=0x7f => first_len as usize,
        // 长形式：低 7 位是后续长度字节数；0x80（不确定长度）不是 DER，
        0x80 => return Err(KeyImportError::Malformed),
        0x81.. => {
            let n = (first_len & 0x7f) as usize;
            // 长度字节数本身有界：超过指针宽度或剩余数据都属于损坏。
            if n == 0 || n > rest.len() || n > size_of::<usize>() {
                return Err(KeyImportError::Malformed);
            }
            let (len_bytes, after) = rest.split_at(n);
            // 首字节为零说明可用更短的长形式甚至短形式表示，非最小编码。
            if len_bytes[0] == 0 {
                return Err(KeyImportError::Malformed);
            }
            let mut length: usize = 0;
            for &b in len_bytes {
                length = (length << 8) | b as usize;
            }
            // 一个长度字节（n == 1）只能表示 >= 128；若值更小，短形式
            // 才是规范编码。
            if n == 1 && length < 0x80 {
                return Err(KeyImportError::Malformed);
            }
            // 多个长度字节时，首位为零已在上面拒绝，这里无需再判下界。
            rest = after;
            length
        }
    };

    let (value, remainder) = rest.split_at_checked(length).ok_or(KeyImportError::Malformed)?;
    Ok((tag, value, remainder))
}

/// 要求 `data` 是恰好一个带给定标签的 TLV，且其值之后没有任何剩余字节。
fn der_exact_one(tag: u8, data: &[u8]) -> Result<&[u8], KeyImportError> {
    let (found, value, rest) = der_read_tlv(data)?;
    if found != tag || !rest.is_empty() {
        return Err(KeyImportError::Malformed);
    }
    Ok(value)
}

/// 导入一份 DER 编码的 SubjectPublicKeyInfo 公钥，仅接受 RFC 8410 的
/// Ed25519 公钥。
///
/// 入参是二进制公钥容器的原始字节，不是十六进制文本、PEM 文本，也不是
/// 去掉容器后的裸 32 字节公钥；本入口不做任何格式猜测或文本转换。
///
/// 接受的结构（RFC 5280 SubjectPublicKeyInfo，RFC 8410 对 Ed25519 的
/// 规定）：
///
/// ```text
/// SubjectPublicKeyInfo ::= SEQUENCE {
///   algorithm        AlgorithmIdentifier,  -- 恰好 OID 1.3.101.112，参数缺省
///   subjectPublicKey BIT STRING            -- 未使用位为 0，内容恰好 32 字节
/// }
/// AlgorithmIdentifier ::= SEQUENCE {
///   algorithm  OBJECT IDENTIFIER,          -- 1.3.101.112
///   parameters ANY OPTIONAL ABSENT         -- Ed25519 必须缺省，写成 NULL 也拒绝
/// }
/// ```
///
/// 输入必须是一份完整、规范的 DER 对象：截断、声明长度与实际内容不符、
/// 非规范长度编码、容器中出现多余字段（AlgorithmIdentifier 的任何参数、
/// 外层 SEQUENCE 的第三个成员等）或对象之后还有字节都一律拒绝，剩余
/// 内容不会被忽略，缺失字段也不会自动补齐。
///
/// 成功只表示编码被接受：它不验证任何文件签名，也不确认公钥持有者的
/// 身份；调用方需要另行进行签名验证与带外的身份确认。
///
/// 失败时返回 [`KeyImportError`]：结构完整、DER 合法但算法标识不是
/// Ed25519 时为
/// [`UnsupportedAlgorithm`](KeyImportError::UnsupportedAlgorithm)，并保留
/// 实际标识供展示；整体编码损坏时为 [`Malformed`](KeyImportError::Malformed)。
///
/// # 示例
///
/// 传入的是一份**二进制公钥容器**（DER 字节），通常整个读自 `.der`
/// 文件或网络消息；它不是十六进制文本，也不是 PEM 文本：
///
/// ```
/// use inkseal::import_ed25519_public_key;
///
/// // 一份 RFC 8410 Ed25519 公钥的 DER SubjectPublicKeyInfo。
/// // 302a300506032b6570 是固定的容器与算法标识（OID 1.3.101.112，
/// // 参数缺省），032100 引出未使用位为 0 的位串，其后是 32 字节公钥。
/// let spki_hex = concat!(
///     "302a300506032b6570032100",
///     "1111111111111111111111111111111111111111111111111111111111111111",
/// );
/// let spki: Vec<u8> = spki_hex
///     .as_bytes()
///     .chunks_exact(2)
///     .map(|pair| {
///         let digit = |b: u8| match b {
///             b'0'..=b'9' => b - b'0',
///             b'a'..=b'f' => b - b'a' + 10,
///             _ => panic!("test fixture hex"),
///         };
///         (digit(pair[0]) << 4) | digit(pair[1])
///     })
///     .collect();
///
/// let public_key = import_ed25519_public_key(&spki).unwrap();
/// assert_eq!(public_key.as_bytes(), &[0x11u8; 32]);
///
/// // 文本表示固定为 64 个小写十六进制字符（保留前导零，无标签或换行），
/// // 表示公钥本身。
/// assert_eq!(
///     public_key.to_hex(),
///     "1111111111111111111111111111111111111111111111111111111111111111"
/// );
/// ```
///
/// **导入成功只表示这份编码被接受**：它不验证任何文件签名，也不确认
/// 公钥持有者的身份。确认身份需要带外的信任渠道，验证签名需要另行使用
/// 签名验证机制，二者都不在本入口的职责范围内。
pub fn import_ed25519_public_key(der: &[u8]) -> Result<Ed25519PublicKey, KeyImportError> {
    // 外层：恰好一个 SEQUENCE，之后不得有任何字节。
    let spki = der_exact_one(DER_TAG_SEQUENCE, der)?;

    // 第一个成员：AlgorithmIdentifier SEQUENCE。
    let (tag, alg_content, rest) = der_read_tlv(spki)?;
    if tag != DER_TAG_SEQUENCE {
        return Err(KeyImportError::Malformed);
    }

    // AlgorithmIdentifier 的第一个成员：OBJECT IDENTIFIER。
    let (tag, oid_content, after_oid) = der_read_tlv(alg_content)?;
    if tag != DER_TAG_OID {
        return Err(KeyImportError::Malformed);
    }
    // parameters 是可选的单个成员：OID 之后若还有字节，必须恰好能解析为
    // 一个完整 TLV，否则 AlgorithmIdentifier 本身就是损坏结构。这里只做
    // 结构校验——是否允许参数存在取决于算法（见下）：Ed25519 要求参数
    // 缺省，其他算法的合法 SPKI 可能带参数（如 RSA 的显式 NULL）。
    let has_parameters = if after_oid.is_empty() {
        false
    } else {
        let (_, _, after_params) = der_read_tlv(after_oid)?;
        if !after_params.is_empty() {
            return Err(KeyImportError::Malformed);
        }
        true
    };

    // 第二个成员：subjectPublicKey BIT STRING。
    let (tag, bit_string, after_bitstring) = der_read_tlv(rest)?;
    if tag != DER_TAG_BIT_STRING {
        return Err(KeyImportError::Malformed);
    }
    // 外层 SEQUENCE 中 BIT STRING 之后不得再有第三个成员或任何多余字节。
    if !after_bitstring.is_empty() {
        return Err(KeyImportError::Malformed);
    }

    // 至此整体结构完整：外层恰为一个含 AlgorithmIdentifier 与 BIT STRING
    // 的 SEQUENCE。OID 自身的内容编码不合法（空内容、非规范弧段等）属于
    // 整体编码损坏，而不是“其他算法”。
    let algorithm = PublicKeyAlgorithm::from_oid_content(oid_content)?;

    // 只有结构完整、DER 合法时才可能是算法不支持；损坏编码不会因为局部
    // 恰好出现某个 OID 就改报到这里。其他算法的 BIT STRING 内容是否进一步
    // 合法不在本入口的判断范围内——保留实际标识即可返回。
    if algorithm != PublicKeyAlgorithm::Ed25519 {
        return Err(KeyImportError::UnsupportedAlgorithm(algorithm));
    }

    // Ed25519（RFC 8410）：parameters 必须缺省——显式 NULL（05 00）或
    // 任何其他参数都不按缺省处理，一律拒绝。
    if has_parameters {
        return Err(KeyImportError::Malformed);
    }

    // BIT STRING 的第一个内容字节是“未使用位数”，Ed25519 公钥必须为零，
    // 其后恰好是 32 字节公钥。空位串（连未使用位数字节都没有）、非零
    // 未使用位、公钥长度不是 32 都拒绝。
    let (&unused_bits, key_bytes) =
        bit_string.split_first().ok_or(KeyImportError::Malformed)?;
    if unused_bits != 0 {
        return Err(KeyImportError::Malformed);
    }
    let key: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| KeyImportError::Malformed)?;

    Ok(Ed25519PublicKey(key))
}

/// 把字节展开为小写十六进制字符串（摘要与公钥共用同一规则，长度为
/// 输入字节数的两倍）。
fn bytes_to_lower_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        hex.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
    }
    hex
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
    fn from_hex_bytes_shares_the_from_str_rule_and_accepts_non_utf8_source() {
        use std::str::FromStr;
        let hex = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";

        // 字节级解析与 FromStr 是同一条规则：相同字节得到相同摘要，
        // 命令行参数（可能不是合法 UTF-8）也可直接走这里。
        let from_bytes = Sha256Digest::from_hex_bytes(hex.as_bytes()).unwrap();
        assert_eq!(from_bytes, Sha256Digest::from_str(hex).unwrap());
        assert_eq!(from_bytes.to_hex(), hex);

        // 字节级入口不要求合法 UTF-8：长度先按原始字节判断，
        // 非 ASCII 字节在长度为 64 时按字节偏移报非法字符。
        let mut raw = hex.as_bytes().to_vec();
        raw[63] = b'G';
        assert_eq!(
            Sha256Digest::from_hex_bytes(&raw).unwrap_err(),
            ParseDigestError::InvalidHexChar(63)
        );
        raw[63] = 0xff; // 64 个原始字节，但无法整体解码为 UTF-8
        assert_eq!(
            Sha256Digest::from_hex_bytes(&raw).unwrap_err(),
            ParseDigestError::InvalidHexChar(63)
        );
        assert_eq!(
            Sha256Digest::from_hex_bytes(b"").unwrap_err(),
            ParseDigestError::InvalidLength(0)
        );
    }

    #[test]
    fn digest_parses_back_from_its_own_hex() {
        use std::str::FromStr;
        let digest = digest_reader(&b"abc"[..]).unwrap();

        // 标准字符串解析方式：str::parse 与 FromStr::from_str 等价。
        let parsed: Sha256Digest = digest.to_hex().parse().unwrap();
        assert_eq!(parsed, digest);
        assert_eq!(Sha256Digest::from_str(&digest.to_hex()).unwrap(), digest);

        // 解析结果的 32 字节与文本表示的值逐字节一致，
        // 既有字节访问与显示功能直接可用。
        assert_eq!(parsed.as_bytes(), digest.as_bytes());
        assert_eq!(parsed.to_hex(), digest.to_hex());
        assert_eq!(format!("{parsed}"), digest.to_hex());
    }

    #[test]
    fn parsing_accepts_mixed_case_and_preserves_leading_zeros() {
        use std::str::FromStr;
        // 含前导零与大小写混用的已知摘要（SHA-256 of "The quick brown fox...")。
        let lower = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592";
        let mixed = "D7a8FbB307d7809469CA9abCB0082E4f8D5651E46D3Cdb762D02d0BF37C9E592";
        let from_lower = Sha256Digest::from_str(lower).unwrap();
        let from_mixed: Sha256Digest = mixed.parse().unwrap();

        // 大小写混用表示同一个摘要。
        assert_eq!(from_lower, from_mixed);

        // 前导零保留在字节值中，输出仍是 64 个小写十六进制字符。
        let with_zero: Sha256Digest =
            "00b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .parse()
                .unwrap();
        assert_eq!(with_zero.as_bytes()[0], 0x00);
        assert_eq!(
            with_zero.to_hex(),
            "00b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn parse_rejects_wrong_length_and_reports_actual_length() {
        use std::str::FromStr;
        // 空字符串不能变成空文件的摘要。
        let err = Sha256Digest::from_str("").unwrap_err();
        assert_eq!(err, ParseDigestError::InvalidLength(0));
        assert_eq!(err.actual_length(), Some(0));
        assert_eq!(err.invalid_position(), None);

        // 63 与 65 个字符都不接受。
        assert_eq!(
            Sha256Digest::from_str(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85"
            )
            .unwrap_err(),
            ParseDigestError::InvalidLength(63)
        );
        assert_eq!(
            Sha256Digest::from_str(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550"
            )
            .unwrap_err(),
            ParseDigestError::InvalidLength(65)
        );

        // 长度按 UTF-8 字节数判断：全角数字一个字符占 3 字节。
        let fullwidth = "０".repeat(21); // 21 个字符，63 字节
        let err = Sha256Digest::from_str(&fullwidth).unwrap_err();
        assert_eq!(err, ParseDigestError::InvalidLength(63));
        assert_eq!(err.actual_length(), Some(63));
    }

    #[test]
    fn parse_rejects_non_hex_bytes_and_reports_first_byte_offset() {
        use std::str::FromStr;
        // 非法字符出现在偶数与奇数位置，位置从零开始按字节计。
        let err = Sha256Digest::from_str(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85g",
        )
        .unwrap_err();
        assert_eq!(err, ParseDigestError::InvalidHexChar(63));
        assert_eq!(err.invalid_position(), Some(63));
        assert_eq!(err.actual_length(), None);

        let err = Sha256Digest::from_str(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8z5",
        )
        .unwrap_err();
        assert_eq!(err, ParseDigestError::InvalidHexChar(62));

        // 报告的是首个非法字节：后面的非法字符不影响位置。
        let err = Sha256Digest::from_str(
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        )
        .unwrap_err();
        assert_eq!(err, ParseDigestError::InvalidHexChar(0));

        // 全角数字等非 ASCII 内容不作为十六进制字符接受；
        // 位置按原始文本的字节偏移报告，不按字符个数。
        // "e3" + "３"（3 字节）+ 59 个 '0'，共 64 字节，非法字节从偏移 2 开始。
        let s = format!("e3３{}", "0".repeat(59));
        assert_eq!(s.len(), 64);
        let err = Sha256Digest::from_str(&s).unwrap_err();
        assert_eq!(err, ParseDigestError::InvalidHexChar(2));
    }

    #[test]
    fn parse_does_not_trim_or_fix_input() {
        use std::str::FromStr;
        let valid = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        // 末尾换行、首尾空白、0x 前缀、分隔符都是格式错误（长度不符）。
        for bad in [
            format!("{valid}\n"),
            format!(" {valid}"),
            format!("{valid} "),
            format!("0x{valid}"),
            format!("{valid}\r\n"),
        ] {
            assert!(matches!(
                Sha256Digest::from_str(&bad),
                Err(ParseDigestError::InvalidLength(_))
            ));
        }

        // 长度恰好 64 但含分隔符：按非法字符处理。
        let with_dash = format!("{}-{}", &valid[..31], &valid[32..]);
        assert_eq!(with_dash.len(), 64);
        assert_eq!(
            Sha256Digest::from_str(&with_dash).unwrap_err(),
            ParseDigestError::InvalidHexChar(31)
        );
    }

    #[test]
    fn parse_error_supports_display_and_error_trait() {
        use std::str::FromStr;
        let len_err = Sha256Digest::from_str("abc").unwrap_err();
        let msg = len_err.to_string();
        assert!(msg.contains('3'), "unexpected message: {msg}");
        assert!(msg.contains("64"), "unexpected message: {msg}");

        let char_err = Sha256Digest::from_str(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85g",
        )
        .unwrap_err();
        assert!(char_err.to_string().contains("63"));

        // 两类错误可按类型区分，且都实现 std::error::Error，可常规传递。
        fn assert_error<T: std::error::Error>(_: &T) {}
        assert_error(&len_err);
        assert_error(&char_err);
        assert_ne!(len_err, char_err);
        let boxed: Box<dyn std::error::Error> = Box::new(char_err);
        assert!(boxed.to_string().contains("63"));
    }

    // ── Ed25519 公钥导入 ─────────────────────────────────────────────────────

    /// 构造一个 RFC 8410 Ed25519 公钥的 SPKI：默认无参数，可替换公钥
    /// 字节或在 AlgorithmIdentifier 中注入参数字节。
    fn ed25519_spki_with(key: &[u8], params: &[u8]) -> Vec<u8> {
        // 1.3.101.112 的 DER 内容字节为 2b 65 70。
        let oid = [0x06, 0x03, 0x2b, 0x65, 0x70];
        let mut alg = Vec::new();
        alg.extend_from_slice(&oid);
        alg.extend_from_slice(params);
        let alg_tlv = der(0x30, &alg);

        let mut bit_string_content = vec![0x00]; // 未使用位数为 0
        bit_string_content.extend_from_slice(key);
        let bit_string = der(0x03, &bit_string_content);

        let mut spki_content = alg_tlv;
        spki_content.extend_from_slice(&bit_string);
        der(0x30, &spki_content)
    }

    /// 最简 DER TLV 封装（仅测试辅助，按最小编码输出短/长形式长度）。
    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let mut len_bytes = Vec::new();
            let mut rest = len;
            while rest > 0 {
                len_bytes.push((rest & 0xff) as u8);
                rest >>= 8;
            }
            len_bytes.reverse();
            out.push(0x80 | len_bytes.len() as u8);
            out.extend_from_slice(&len_bytes);
        }
        out.extend_from_slice(content);
        out
    }

    fn valid_ed25519_spki() -> Vec<u8> {
        // RFC 8410 示例风格的 32 字节公钥；值取 0x00..0x1f 以便检查前导零。
        let key: Vec<u8> = (0u8..32).collect();
        ed25519_spki_with(&key, &[])
    }

    #[test]
    fn imports_well_formed_ed25519_spki_and_exposes_raw_bytes() {
        let spki = valid_ed25519_spki();
        let key = import_ed25519_public_key(&spki).expect("canonical Ed25519 SPKI must import");

        // 原样取出 32 字节，与位串内容逐字节一致。
        assert_eq!(key.as_bytes().len(), 32);
        let expected: Vec<u8> = (0u8..32).collect();
        assert_eq!(key.as_bytes(), expected.as_slice());
    }

    #[test]
    fn public_key_hex_is_64_lowercase_chars_preserving_leading_zeros() {
        // 首字节为 0x00：文本必须保留前导零，且表示公钥本身。
        let key_bytes = [0u8; 32];
        let spki = ed25519_spki_with(&key_bytes, &[]);
        let key = import_ed25519_public_key(&spki).unwrap();

        let hex = key.to_hex();
        assert_eq!(hex, "0".repeat(64));
        assert_eq!(hex.len(), 64);
        assert_eq!(format!("{key}"), hex);
        assert!(!hex.chars().any(char::is_whitespace));
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_eq!(format!("{key:?}"), format!("Ed25519PublicKey({hex})"));

        // 非零字节按值展开。
        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        bytes[31] = 0x0f;
        let key = import_ed25519_public_key(&ed25519_spki_with(&bytes, &[])).unwrap();
        let hex = key.to_hex();
        assert!(hex.starts_with("ab"));
        assert!(hex.ends_with("0f"));
        assert_eq!(hex.len(), 64);
    }

    #[test]
    fn equal_public_keys_compare_equal_and_different_keys_do_not() {
        let mut a_bytes = [1u8; 32];
        a_bytes[0] = 0x00; // 含前导零
        let a = import_ed25519_public_key(&ed25519_spki_with(&a_bytes, &[])).unwrap();
        let a_again = import_ed25519_public_key(&ed25519_spki_with(&a_bytes, &[])).unwrap();
        let mut b_bytes = a_bytes;
        b_bytes[31] ^= 0x01;
        let b = import_ed25519_public_key(&ed25519_spki_with(&b_bytes, &[])).unwrap();

        assert_eq!(a, a_again);
        assert_ne!(a, b);
        // Copy/Clone 后仍可独立使用。
        let copied = a;
        assert_eq!(copied, a);
    }

    #[test]
    fn public_key_is_distinct_from_digest_type() {
        // 公钥与摘要底层都是 32 字节，但它们是不同类型：既没有共同的
        // 构造入口，也不能互相比较或赋值。这里用一个包装 trait 在类型
        // 层面固定二者的区别，防止日后被合并或互相转换。
        fn assert_static_type<T: 'static>() {}
        assert_static_type::<Ed25519PublicKey>();
        assert_static_type::<Sha256Digest>();

        let key = import_ed25519_public_key(&valid_ed25519_spki()).unwrap();
        // 即便公钥字节恰好等于某摘要的字节，二者的 hex 也只是形状相同，
        // 类型与语义不同；公钥没有从 hex/FromStr 构造的入口。
        let same_bytes = *key.as_bytes();
        let digest = Sha256Digest(same_bytes);
        assert_eq!(key.to_hex(), digest.to_hex());
        // 公钥只能通过二进制 SPKI 得到，不能通过摘要的严格 hex 入口得到。
        assert!(Sha256Digest::from_hex_bytes(key.to_hex().as_bytes()).is_ok());
    }

    #[test]
    fn rejects_truncated_inputs_at_every_boundary() {
        let valid = valid_ed25519_spki();
        // 在每个非零前缀处截断：任何截断都必须报 Malformed，绝不补齐。
        for cut in 0..valid.len() {
            let result = import_ed25519_public_key(&valid[..cut]);
            assert_eq!(
                result,
                Err(KeyImportError::Malformed),
                "prefix of length {cut} must be rejected"
            );
        }
        // 空输入同样是格式错误。
        assert_eq!(
            import_ed25519_public_key(&[]),
            Err(KeyImportError::Malformed)
        );
    }

    #[test]
    fn rejects_declared_length_longer_and_shorter_than_actual_content() {
        let valid = valid_ed25519_spki();

        // 外层 SEQUENCE 声明长度比实际多 1（不追加字节）：长度不符。
        let mut longer = valid.clone();
        // 30 <len> ...；短形式长度位于偏移 1。
        longer[1] += 1;
        assert_eq!(
            import_ed25519_public_key(&longer),
            Err(KeyImportError::Malformed)
        );

        // 外层声明长度比实际少 1（保留多余字节）：der_exact_one 会因
        // 声明内容之后还有字节而拒绝。
        let mut shorter = valid.clone();
        shorter[1] -= 1;
        assert_eq!(
            import_ed25519_public_key(&shorter),
            Err(KeyImportError::Malformed)
        );
    }

    #[test]
    fn rejects_non_canonical_length_encodings() {
        // 直接构造外层 SEQUENCE 使用长形式但等价于短形式的编码。
        let canonical = valid_ed25519_spki();
        let inner = &canonical[2..]; // 去掉 30 <短长度>
        assert!(inner.len() < 0x80);

        // 0x81 后跟一个字节表示长度；长度 < 128 时非规范。
        let mut noncanon = vec![0x30, 0x81, inner.len() as u8];
        noncanon.extend_from_slice(inner);
        assert_eq!(
            import_ed25519_public_key(&noncanon),
            Err(KeyImportError::Malformed)
        );

        // 长形式前导零：82 00 xx 也必须拒绝。
        let mut leading_zero = vec![0x30, 0x82, 0x00, inner.len() as u8];
        leading_zero.extend_from_slice(inner);
        assert_eq!(
            import_ed25519_public_key(&leading_zero),
            Err(KeyImportError::Malformed)
        );

        // 0x80 是 BER 的不确定长度，不是 DER：拒绝。
        let mut indefinite = vec![0x30, 0x80];
        indefinite.extend_from_slice(inner);
        assert_eq!(
            import_ed25519_public_key(&indefinite),
            Err(KeyImportError::Malformed)
        );
    }

    #[test]
    fn accepts_canonical_long_form_lengths_above_127() {
        // 长形式本身合法：用一个合法的大 BIT STRING 公钥长度不行（公钥
        // 必须恰好 32 字节），因此改用其他算法的大 SPKI 验证解析器能读
        // 规范长形式长度——它应报 UnsupportedAlgorithm 而非 Malformed，
        // 证明长形式长度被正确解析。
        //
        // 结构：SEQUENCE { AlgId { OID 1.2.3.4 }, BIT STRING(200 字节) }，
        // 外层内容超过 127 字节，必须用长形式编码。
        let oid = [0x06, 0x03, 0x2a, 0x03, 0x04]; // 1.2.3.4（非 Ed25519）
        let alg = der(0x30, &oid);
        let mut bs_content = vec![0x00u8; 301]; // 未使用位 0 + 300 字节
        bs_content[0] = 0;
        let bs = der(0x03, &bs_content);
        let mut body = alg;
        body.extend_from_slice(&bs);
        assert!(body.len() >= 256, "two-byte long form must be minimal");
        // 手工规范长形式：82 xx xx，首字节非零（长度 >= 256）。
        let len = body.len();
        let mut spki = vec![0x30, 0x82, (len >> 8) as u8, len as u8];
        spki.extend_from_slice(&body);

        let err = import_ed25519_public_key(&spki).unwrap_err();
        match err {
            KeyImportError::UnsupportedAlgorithm(algo) => {
                assert!(!algo.is_ed25519());
                assert_eq!(algo.oid_bytes(), Some([0x2a, 0x03, 0x04].as_slice()));
            }
            other => panic!("expected unsupported algorithm, got {other:?}"),
        }
    }

    #[test]
    fn rejects_trailing_bytes_after_the_object() {
        let valid = valid_ed25519_spki();
        for extra in [&[0x00][..], &[0x30, 0x00], &[0xff]].iter() {
            let mut data = valid.clone();
            data.extend_from_slice(extra);
            assert_eq!(
                import_ed25519_public_key(&data),
                Err(KeyImportError::Malformed),
                "trailing bytes {extra:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_extra_fields_inside_containers() {
        // 外层 SEQUENCE 多出第三个成员：在合法 BIT STRING 后追加一个 NULL。
        let valid = valid_ed25519_spki();
        let mut body = valid[2..].to_vec();
        body.extend_from_slice(&[0x05, 0x00]);
        let with_third = der(0x30, &body);
        assert_eq!(
            import_ed25519_public_key(&with_third),
            Err(KeyImportError::Malformed)
        );

        // AlgorithmIdentifier 中 OID 之后有两个成员（NULL + NULL），
        // 即使参数解析容错，多出来的部分也必须拒绝。
        let double_params = ed25519_spki_with(&[0u8; 32], &[0x05, 0x00, 0x05, 0x00]);
        assert_eq!(
            import_ed25519_public_key(&double_params),
            Err(KeyImportError::Malformed)
        );
    }

    #[test]
    fn rejects_explicit_null_parameters_for_ed25519() {
        // RFC 8410：Ed25519 的 parameters 必须缺省。写成 NULL（05 00）
        // 不能按“缺省参数”处理。
        let with_null = ed25519_spki_with(&[0u8; 32], &[0x05, 0x00]);
        assert_eq!(
            import_ed25519_public_key(&with_null),
            Err(KeyImportError::Malformed)
        );

        // 其他类型的参数同样拒绝（BOOLEAN FALSE、INTEGER 0、OCTET STRING）。
        for params in [
            &[0x01, 0x01, 0x00][..],
            &[0x02, 0x01, 0x00],
            &[0x04, 0x00],
            &[0x06, 0x00],
        ] {
            let data = ed25519_spki_with(&[0u8; 32], params);
            assert_eq!(
                import_ed25519_public_key(&data),
                Err(KeyImportError::Malformed),
                "params {params:?} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_wrong_bit_string_unused_bits_and_key_length() {
        // 未使用位数非零（即使后面恰好 32 字节）：手工重写 BIT STRING
        // 内容，把首字节置为 1。
        let non_zero_unused = {
            let oid = [0x06, 0x03, 0x2b, 0x65, 0x70];
            let alg = der(0x30, &oid);
            let mut bs_content = vec![0x01u8]; // 未使用位数 = 1
            bs_content.extend_from_slice(&[7u8; 32]);
            let bs = der(0x03, &bs_content);
            let mut body = alg;
            body.extend_from_slice(&bs);
            der(0x30, &body)
        };
        assert_eq!(
            import_ed25519_public_key(&non_zero_unused),
            Err(KeyImportError::Malformed)
        );

        // 空 BIT STRING（缺少未使用位数字节）、31 与 33 字节公钥都拒绝。
        for key_len in [0usize, 1, 31, 33, 64] {
            let key = vec![0xabu8; key_len];
            // key_len == 0 时位串内容只有未使用位数字节，合法但公钥长度不符。
            let data = ed25519_spki_with(&key, &[]);
            assert_eq!(
                import_ed25519_public_key(&data),
                Err(KeyImportError::Malformed),
                "key length {key_len} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_wrong_tags_and_nested_length_mismatches() {
        // 外层不是 SEQUENCE。
        let valid = valid_ed25519_spki();
        let mut not_sequence = valid.clone();
        not_sequence[0] = 0x31; // SET
        assert_eq!(
            import_ed25519_public_key(&not_sequence),
            Err(KeyImportError::Malformed)
        );

        // AlgorithmIdentifier 不是 SEQUENCE（构造同内容的 OCTET STRING）。
        let oid = [0x06, 0x03, 0x2b, 0x65, 0x70];
        let mut body = der(0x04, &oid); // 应为 0x30
        let bs_content = {
            let mut v = vec![0x00];
            v.extend_from_slice(&[1u8; 32]);
            v
        };
        body.extend_from_slice(&der(0x03, &bs_content));
        assert_eq!(
            import_ed25519_public_key(&der(0x30, &body)),
            Err(KeyImportError::Malformed)
        );

        // algorithm 成员不是 OID（放一个 NULL）。
        let mut body = der(0x30, &[0x05, 0x00]);
        body.extend_from_slice(&der(0x03, &bs_content));
        assert_eq!(
            import_ed25519_public_key(&der(0x30, &body)),
            Err(KeyImportError::Malformed)
        );

        // subjectPublicKey 不是 BIT STRING（OCTET STRING 装 32 字节）。
        let mut body = der(0x30, &oid);
        body.extend_from_slice(&der(0x04, &{
            let mut v = vec![0x00];
            v.extend_from_slice(&[1u8; 32]);
            v
        }));
        assert_eq!(
            import_ed25519_public_key(&der(0x30, &body)),
            Err(KeyImportError::Malformed)
        );

        // 内层 OID 声明长度 5 却只有 3 个内容字节：内层长度不符。
        let bad_oid_alg = der(
            0x30,
            &{
                let mut v = der(0x30, &[0x06, 0x05, 0x2b, 0x65, 0x70]);
                v.extend_from_slice(&der(0x03, &{
                    let mut b = vec![0x00];
                    b.extend_from_slice(&[1u8; 32]);
                    b
                }));
                v
            },
        );
        assert_eq!(
            import_ed25519_public_key(&bad_oid_alg),
            Err(KeyImportError::Malformed)
        );
    }

    #[test]
    fn unsupported_algorithm_is_reported_with_its_actual_identifier() {
        // 结构完整合法、只是 OID 不是 Ed25519：rsaEncryption（1.2.840.113549.1.1.1）。
        // DER 内容字节：2a 86 48 86 f7 0d 01 01 01
        let rsa_oid = [
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        ];
        // RSA 的 AlgorithmIdentifier 通常带显式 NULL 参数；这对“其他算法”
        // 是合法结构，不应被误报为 Malformed。
        let alg = {
            let mut content = rsa_oid.to_vec();
            content.extend_from_slice(&[0x05, 0x00]);
            der(0x30, &content)
        };
        let bs = der(0x03, &{
            let mut v = vec![0x00];
            v.extend_from_slice(&[0xaau8; 32]); // 长度无所谓：不走到这一步
            v
        });
        let body = {
            let mut v = alg;
            v.extend_from_slice(&bs);
            v
        };
        let spki = der(0x30, &body);

        let err = import_ed25519_public_key(&spki).unwrap_err();
        assert!(!err.is_malformed());
        let algo = err.unsupported_algorithm().expect("must carry algorithm");
        assert!(!algo.is_ed25519());
        assert_eq!(
            algo.oid_bytes(),
            Some([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01].as_slice())
        );
        // Display/Debug 保留实际标识内容，供调用方展示。
        let shown = err.to_string();
        assert!(shown.contains("2a864886f70d010101"), "{shown}");
        assert!(shown.contains("1.3.101.112"));
        assert!(format!("{algo:?}").contains("2a864886f70d010101"));

        // 不带参数的其他算法同样报 UnsupportedAlgorithm。
        let spki_no_params = ed25519_spki_with_oid(
            &[0x06, 0x03, 0x2a, 0x03, 0x04], // 1.2.3.4
            &[0u8; 32],
            &[],
        );
        match import_ed25519_public_key(&spki_no_params) {
            Err(KeyImportError::UnsupportedAlgorithm(a)) => {
                assert_eq!(a.oid_bytes(), Some([0x2a, 0x03, 0x04].as_slice()));
            }
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
    }

    /// 测试辅助：以任意 OID 的完整 TLV 构造 SPKI。
    fn ed25519_spki_with_oid(oid_tlv: &[u8], key: &[u8], params: &[u8]) -> Vec<u8> {
        let mut alg_content = oid_tlv.to_vec();
        alg_content.extend_from_slice(params);
        let alg = der(0x30, &alg_content);
        let mut bs_content = vec![0x00];
        bs_content.extend_from_slice(key);
        let bs = der(0x03, &bs_content);
        let mut body = alg;
        body.extend_from_slice(&bs);
        der(0x30, &body)
    }

    #[test]
    fn structurally_broken_encoding_never_becomes_unsupported_algorithm() {
        // 损坏数据中即使局部出现 Ed25519 之外的 OID 字节，也必须报
        // Malformed，而不是 UnsupportedAlgorithm：
        // SEQUENCE 声明 16 字节，AlgId(OID 1.2.3.4) 看似完整，
        // BIT STRING 声明 5 字节内容却只给了 2 字节（截断）。
        let broken: Vec<u8> = vec![
            0x30, 0x10, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x03, 0x05, 0x00, 0x01, 0x02,
        ];
        assert_eq!(
            import_ed25519_public_key(&broken),
            Err(KeyImportError::Malformed)
        );

        // OID 内容自身非规范（前导 0x80 延续字节）：整体损坏。
        let bad_oid_spki = ed25519_spki_with_oid(
            &[0x06, 0x03, 0x2b, 0x80, 0x70], // 类似 Ed25519 但含非规范延续
            &[0u8; 32],
            &[],
        );
        assert_eq!(
            import_ed25519_public_key(&bad_oid_spki),
            Err(KeyImportError::Malformed)
        );

        // OID 弧段被截断（末字节仍带高位）：损坏。
        let truncated_arc = ed25519_spki_with_oid(&[0x06, 0x02, 0x2a, 0x86], &[0u8; 32], &[]);
        assert_eq!(
            import_ed25519_public_key(&truncated_arc),
            Err(KeyImportError::Malformed)
        );

        // 空 OID 内容：损坏。
        let empty_oid = ed25519_spki_with_oid(&[0x06, 0x00], &[0u8; 32], &[]);
        assert_eq!(
            import_ed25519_public_key(&empty_oid),
            Err(KeyImportError::Malformed)
        );
    }

    #[test]
    fn bare_key_hex_text_and_pem_are_not_accepted_without_guessing() {
        // 裸 32 字节公钥不是这个入口的格式。
        let bare = [0u8; 32];
        assert_eq!(
            import_ed25519_public_key(&bare),
            Err(KeyImportError::Malformed)
        );

        // 公钥的十六进制文本（64 字符）同样不被当作二进制容器。
        let key = import_ed25519_public_key(&valid_ed25519_spki()).unwrap();
        assert_eq!(
            import_ed25519_public_key(key.to_hex().as_bytes()),
            Err(KeyImportError::Malformed)
        );

        // PEM 文本（即使内容正确）不做文本转换：首字节是 ASCII，必失败。
        let pem = "-----BEGIN PUBLIC KEY-----".as_bytes();
        assert_eq!(
            import_ed25519_public_key(pem),
            Err(KeyImportError::Malformed)
        );
    }

    #[test]
    fn failures_never_panic_on_arbitrary_bytes() {
        // 一组确定性的伪随机输入：长度、标签、长度字节任意组合都只能返回
        // Err，不能 panic（包括 split_at_checked 与 try_into 的所有边界）。
        let mut state: u32 = 0x1234_5678;
        let mut next = || {
            // xorshift32，纯确定性。
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        };
        for _ in 0..20_000 {
            let len = (next() % 80) as usize;
            let data: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
            let _ = import_ed25519_public_key(&data);
        }

        // 专门覆盖“长形式长度字节声称很大”的输入。
        for n in 1..=8u8 {
            let mut data = vec![0x30, 0x80 | n];
            data.extend(std::iter::repeat(0xff).take(n as usize));
            data.extend_from_slice(&[0xaa; 10]);
            assert_eq!(
                import_ed25519_public_key(&data),
                Err(KeyImportError::Malformed)
            );
        }
        // 长度字节数超过 usize 宽度（构造 9 个长度字节）。
        let mut huge = vec![0x30, 0x89];
        huge.extend(std::iter::repeat(0xff).take(9));
        assert_eq!(
            import_ed25519_public_key(&huge),
            Err(KeyImportError::Malformed)
        );
    }

    #[test]
    fn import_error_is_public_typed_error_with_display_and_error_trait() {
        // 两类失败可直接按变体区分，无需分析提示字符串。
        let malformed = import_ed25519_public_key(b"not der").unwrap_err();
        assert!(malformed.is_malformed());
        assert!(malformed.unsupported_algorithm().is_none());
        assert!(malformed.to_string().contains("malformed"));

        let other = ed25519_spki_with_oid(&[0x06, 0x03, 0x2a, 0x03, 0x04], &[0u8; 32], &[]);
        let unsupported = import_ed25519_public_key(&other).unwrap_err();
        assert!(!unsupported.is_malformed());
        assert!(unsupported.unsupported_algorithm().is_some());
        assert_ne!(malformed, unsupported);

        fn assert_error<T: std::error::Error>(_: &T) {}
        assert_error(&malformed);
        assert_error(&unsupported);
        let boxed: Box<dyn std::error::Error> = Box::new(unsupported);
        assert!(boxed.to_string().contains("2a0304"));
    }
}
