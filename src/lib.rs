//! inkseal 的库接口：对任意实现 [`std::io::Read`] 的输入计算 SHA-256 摘要，
//! 以及导入 DER 编码（SubjectPublicKeyInfo）或 PEM 文本形式的 Ed25519 公钥。
//!
//! 摘要只取决于输入的原始字节，与命令行 `inkseal digest <文件>` 遵循同一内容规则。
//! 公钥导入只确认编码被接受，不表示已验证任何签名或确认公钥持有者的身份。

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

/// Ed25519 公钥，由 DER 编码或 PEM 文本形式的 SubjectPublicKeyInfo 导入。
///
/// 与 [`Sha256Digest`] 是两个明确区分的类型：公钥不是摘要，不能把公钥
/// 当作摘要解析，也不能用摘要的十六进制解析入口还原公钥。文本表示固定
/// 为 64 个小写十六进制字符（保留前导零，不含标签或换行），表示公钥
/// 本身的 32 字节，**不是**公钥的 SHA-256 摘要。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ed25519PublicKey([u8; 32]);

impl Ed25519PublicKey {
    /// 从 DER 编码的 SubjectPublicKeyInfo（RFC 8410）原始字节导入公钥。
    ///
    /// 入参是**二进制**的公钥容器：恰好一份完整、规范的 DER 对象。
    /// 裸公钥、十六进制文本和 PEM 文本都不属于本入口接受的格式，不做
    /// 任何格式猜测或文本转换。
    ///
    /// 接受范围遵循 RFC 8410 对 Ed25519 公钥的规定：算法标识为
    /// `1.3.101.112`，算法参数必须缺省（即使写成 NULL 也拒绝），公钥
    /// 所在位串的未使用位数为零，公钥内容恰好 32 字节。截断数据、声明
    /// 长度与实际内容不符、非规范长度编码、容器中出现多余字段或对象
    /// 之后还有字节都返回 [`ImportPublicKeyError::Malformed`]，不忽略
    /// 剩余内容，也不自动补齐。
    ///
    /// 公钥长度是 Ed25519 专属的算法约束，只在算法已确认为 Ed25519
    /// 之后检查。因此一份完整、规范但属于其他算法的容器——例如 RFC 8410
    /// 的 Ed448 公钥（算法标识 `1.3.101.113`，公钥内容 57 字节）——
    /// 不会因为长度不是 32 而被当成格式损坏，而是返回
    /// [`ImportPublicKeyError::UnsupportedAlgorithm`]，携带实际标识
    /// `1.3.101.113` 供调用方展示；调用方需要的是 Ed25519 公钥，应当
    /// 更换公钥，而不是去“修复”这份本来就完整的编码。整体编码已损坏
    /// （截断、长度不符、参数写成 NULL、未使用位数非零、对象之后还有
    /// 字节等）时一律返回 [`ImportPublicKeyError::Malformed`]，即使局部
    /// 能看到 Ed448 等其他算法标识，也不会改报算法不支持。
    ///
    /// 导入成功只表示编码被接受：不表示已验证任何文件签名，也不表示
    /// 确认了公钥持有者的身份。
    pub fn from_spki_der(der: &[u8]) -> Result<Ed25519PublicKey, ImportPublicKeyError> {
        const MALFORMED: ImportPublicKeyError = ImportPublicKeyError::Malformed;

        // 外层：恰好一个 SEQUENCE，对象之后不允许有任何字节。
        let (tag, spki, rest) = read_der_tlv(der).ok_or(MALFORMED)?;
        if tag != TAG_SEQUENCE || !rest.is_empty() {
            return Err(MALFORMED);
        }
        // SubjectPublicKeyInfo 内部：恰好 algorithm 与 subjectPublicKey 两项。
        let (tag, algorithm, rest) = read_der_tlv(spki).ok_or(MALFORMED)?;
        if tag != TAG_SEQUENCE {
            return Err(MALFORMED);
        }
        let (tag, bit_string, rest) = read_der_tlv(rest).ok_or(MALFORMED)?;
        if tag != TAG_BIT_STRING || !rest.is_empty() {
            return Err(MALFORMED);
        }
        // AlgorithmIdentifier 内部：恰好一个 OID，没有任何参数——
        // RFC 8410 要求参数缺省，写成 NULL 同样拒绝。
        let (tag, oid_content, rest) = read_der_tlv(algorithm).ok_or(MALFORMED)?;
        if tag != TAG_OID || !rest.is_empty() {
            return Err(MALFORMED);
        }
        let algorithm_oid = decode_oid(oid_content).ok_or(MALFORMED)?;
        // 位串的未使用位数为零是与算法无关的结构约束：非零就是编码损坏。
        // 公钥长度则是 Ed25519 专属的算法约束，必须在确认算法之后再判断——
        // 否则一份完整的 Ed448（公钥 57 字节）容器会被误报成格式损坏，
        // 调用方无法区分“选错了算法”和“公钥文件真的坏了”。
        let (&unused_bits, key) = bit_string.split_first().ok_or(MALFORMED)?;
        if unused_bits != 0 {
            return Err(MALFORMED);
        }

        // 只有整体结构完整、DER 合法时才判断算法：编码已损坏的输入
        // 一律报格式错误，不因局部看到其他算法标识而改报算法不支持。
        if algorithm_oid.arcs() != [1, 3, 101, 112] {
            return Err(ImportPublicKeyError::UnsupportedAlgorithm(algorithm_oid));
        }

        // 算法确为 Ed25519：公钥内容必须恰好 32 字节，多一个少一个都是
        // 格式错误，绝不截短或补齐后接受。
        let Ok(key32) = <&[u8; 32]>::try_from(key) else {
            return Err(MALFORMED);
        };
        Ok(Ed25519PublicKey(*key32))
    }

    /// 从 PEM 文本（RFC 7468 的 `PUBLIC KEY` 块）的原始字节导入公钥。
    ///
    /// 入参是**文本形式**的公钥容器：文件的原始字节，恰好包含一份
    /// `PUBLIC KEY` 块。块内 Base64 还原出的内容必须是一份完整、规范的
    /// DER 编码 SubjectPublicKeyInfo，其结构、算法与公钥长度约束与
    /// [`from_spki_der`](Self::from_spki_der) 完全相同——同一把公钥从
    /// PEM 或 DER 导入得到相同的 32 字节，按值比较相等。二进制 DER、
    /// 裸公钥和十六进制文本都不属于本入口接受的格式，不做任何格式猜测。
    ///
    /// 外层文本的接受范围：首行是 `-----BEGIN PUBLIC KEY-----`，末行是
    /// `-----END PUBLIC KEY-----`，两个标记各占一行；正文是标准 Base64，
    /// 可写成一行或多行，行结束接受 LF 和 CRLF；尾标记之后允许没有换行
    /// 或只有一个换行。除此之外不做任何裁剪或修正：首标记之前和尾标记
    /// 之后不接受任何其他内容（包括第二个块），正文中不接受空行、行内
    /// 空格或制表符；Base64 的填充必须规范（总长为 4 的倍数、末尾至多
    /// 两个 `=`、末尾未使用位为零），非法字符、缺少或多出填充、填充后
    /// 继续出现编码字符都属于格式错误。私钥、证书等其他标签同样不接受。
    ///
    /// 失败分类与 [`from_spki_der`](Self::from_spki_der) 共用同一套：
    /// PEM 标记或正文损坏，以及还原出的 DER 截断、长度不符或带多余字节，
    /// 都返回 [`ImportPublicKeyError::Malformed`]，不产生公钥对象，也不
    /// 忽略剩余内容；外层文本与 DER 均合法、算法却为 Ed448 或 X25519 等
    /// 其他算法时，返回
    /// [`ImportPublicKeyError::UnsupportedAlgorithm`] 并携带实际算法
    /// 标识。DER 本身已损坏时仍报格式错误，不会因为读到了其他算法标识
    /// 而改报算法不支持。
    ///
    /// 导入成功只表示编码被接受：不表示已验证任何文件签名，也不表示
    /// 确认了公钥持有者的身份。
    pub fn from_spki_pem(pem: &[u8]) -> Result<Ed25519PublicKey, ImportPublicKeyError> {
        let der = decode_public_key_pem(pem).ok_or(ImportPublicKeyError::Malformed)?;
        Ed25519PublicKey::from_spki_der(&der)
    }

    /// 返回公钥的原始 32 字节。
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 返回 64 个小写十六进制字符（保留前导零，不含标签或换行）。
    ///
    /// 这是公钥本身的文本表示，不是公钥的 SHA-256 摘要。
    pub fn to_hex(&self) -> String {
        let mut hex = String::with_capacity(64);
        for byte in self.0 {
            hex.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
            hex.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap());
        }
        hex
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

/// 对象标识符（OID），以各段弧的数值保存，用于向调用方展示实际标识。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectIdentifier(Vec<u64>);

impl ObjectIdentifier {
    /// 返回各段弧的数值，例如 Ed25519 为 `[1, 3, 101, 112]`。
    pub fn arcs(&self) -> &[u64] {
        &self.0
    }
}

impl fmt::Display for ObjectIdentifier {
    /// 点分十进制写法，例如 `1.3.101.112`。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut arcs = self.0.iter();
        if let Some(first) = arcs.next() {
            write!(f, "{first}")?;
            for arc in arcs {
                write!(f, ".{arc}")?;
            }
        }
        Ok(())
    }
}

/// 导入 Ed25519 公钥失败时返回的类型化错误。
///
/// 两个导入入口（[`Ed25519PublicKey::from_spki_der`] 与
/// [`Ed25519PublicKey::from_spki_pem`]）共用本类型，调用方按变体即可区分
/// 两类失败，无需分析提示字符串：外层编码（PEM 文本或 DER 结构）或公钥
/// 结构不合法是 [`Malformed`](Self::Malformed)；外层编码与 DER 都
/// 合法但算法标识不是 Ed25519 是
/// [`UnsupportedAlgorithm`](Self::UnsupportedAlgorithm)。
/// 任何失败都不会产出可继续使用的公钥对象。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportPublicKeyError {
    /// 输入不是一份完整、规范的公钥容器：对 PEM 入口是外层文本不合法
    /// （标记缺失或损坏、标记之外还有其他内容、正文含空行或非法字符、
    /// Base64 填充不规范等）；对两个入口也可能是还原出的 DER 不合法——
    /// 截断、
    /// 声明长度与实际内容不符、非规范长度编码、算法参数未缺省（含写成
    /// NULL）、位串未使用位数非零、容器中出现多余字段或对象之后还有
    /// 字节等；当算法标识确为 Ed25519（`1.3.101.112`）时，公钥长度不是
    /// 32 字节也属于本变体。注意：其他算法容器里的公钥长度（例如
    /// Ed448 的 57 字节）不作为格式问题——那属于
    /// [`UnsupportedAlgorithm`](Self::UnsupportedAlgorithm)。
    Malformed,
    /// 整体编码合法，但算法标识不是 Ed25519（`1.3.101.112`）；携带实际
    /// 标识供调用方展示，例如一份完整的 Ed448（`1.3.101.113`）公钥。
    UnsupportedAlgorithm(ObjectIdentifier),
}

impl fmt::Display for ImportPublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportPublicKeyError::Malformed => write!(
                f,
                "input is not a well-formed DER-encoded Ed25519 SubjectPublicKeyInfo"
            ),
            ImportPublicKeyError::UnsupportedAlgorithm(oid) => write!(
                f,
                "unsupported public key algorithm {oid} (expected Ed25519, 1.3.101.112)"
            ),
        }
    }
}

impl Error for ImportPublicKeyError {}

const TAG_SEQUENCE: u8 = 0x30;
const TAG_OID: u8 = 0x06;
const TAG_BIT_STRING: u8 = 0x03;

/// 读取一个 DER TLV，返回（标签，内容，剩余字节）。
///
/// 只接受规范（最短）定长编码：拒绝不定长形式、长形式的前导零字节，
/// 以及本可以用短形式表示的长度；声明长度超出实际剩余内容同样失败。
/// 本模块只使用单字节通用标签，多字节标签形式一律拒绝。
fn read_der_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first_len, rest) = rest.split_first()?;
    let (len, rest) = if first_len & 0x80 == 0 {
        (first_len as usize, rest)
    } else {
        let n = (first_len & 0x7f) as usize;
        // 0x80 是不定长形式，DER 不允许；长度本身也不允许超过 8 字节。
        if n == 0 || n > 8 || rest.len() < n {
            return None;
        }
        let (len_bytes, rest) = rest.split_at(n);
        // 前导零字节是非规范编码。
        if len_bytes[0] == 0 {
            return None;
        }
        let mut value: u64 = 0;
        for &b in len_bytes {
            value = (value << 8) | u64::from(b);
        }
        // 能用短形式表示的长度却用了长形式，同样是非规范编码。
        if value < 128 {
            return None;
        }
        (usize::try_from(value).ok()?, rest)
    };
    if rest.len() < len {
        return None;
    }
    let (content, rest) = rest.split_at(len);
    Some((tag, content, rest))
}

/// 把 OID 的 DER 内容字节解码为各段弧的数值。
///
/// 只接受规范编码：内容非空，每个子标识符按最短形式编码（不允许
/// 前导的 0x80 字节），最后一个子标识符必须完整结束。各段弧以 u64
/// 保存，因此每段数值都必须落在 u64 范围内；第一个子标识符合并编码
/// 前两段弧（首段为 2 时合并值为 80 + 第二段），最大可到
/// `u64::MAX + 80`，超出该上界的合并值或超出 u64 的后续各段都属于
/// 编码损坏，不得截断、回绕或改写成别的数值。
fn decode_oid(content: &[u8]) -> Option<ObjectIdentifier> {
    // 合法子标识符的最大值：首段为 2、第二段为 u64::MAX 时，合并编码的
    // 第一个子标识符为 u64::MAX + 80。子标识符的数值在编码过程中只会
    // 增大，一旦超过该上界就不可能再对应任何可表示的弧，可立即判定
    // 编码损坏；累加器因此始终远小于 u128::MAX，移位不会溢出。
    const MAX_SUBIDENTIFIER: u128 = u64::MAX as u128 + 80;

    if content.is_empty() {
        return None;
    }
    let mut subidentifiers: Vec<u128> = Vec::new();
    let mut value: u128 = 0;
    let mut in_arc = false;
    for &b in content {
        if !in_arc {
            // 子标识符首字节为 0x80 是前导零的非规范编码。
            if b == 0x80 {
                return None;
            }
            in_arc = true;
        }
        value = (value << 7) | u128::from(b & 0x7f);
        if value > MAX_SUBIDENTIFIER {
            return None;
        }
        if b & 0x80 == 0 {
            subidentifiers.push(value);
            value = 0;
            in_arc = false;
        }
    }
    // 最后一个子标识符的续位未结束：内容被截断。
    if in_arc {
        return None;
    }
    let (&first, rest) = subidentifiers.split_first()?;
    // 第一个子标识符合并编码前两段弧：0..=39 → 0.x，40..=79 → 1.x，
    // 其余 → 2.x。首段为 2 时第二段可以接近 u64::MAX，合并值因此
    // 可能超过 u64，必须先按 u128 拆开再逐段检查范围。
    let (arc0, arc1) = if first < 40 {
        (0, first)
    } else if first < 80 {
        (1, first - 40)
    } else {
        (2, first - 80)
    };
    let mut arcs = Vec::with_capacity(rest.len() + 2);
    arcs.push(u64::try_from(arc0).ok()?);
    arcs.push(u64::try_from(arc1).ok()?);
    for &arc in rest {
        // 后续每段都必须落在 u64 范围内，超出即编码损坏。
        arcs.push(u64::try_from(arc).ok()?);
    }
    Some(ObjectIdentifier(arcs))
}

/// `PUBLIC KEY` 块的首尾标记（RFC 7468）。
const PEM_BEGIN: &[u8] = b"-----BEGIN PUBLIC KEY-----";
const PEM_END: &[u8] = b"-----END PUBLIC KEY-----";

/// 剥离末尾的一个行结束（LF 或 CRLF）；末尾不是 LF 时返回 `None`。
fn strip_line_ending(s: &[u8]) -> Option<&[u8]> {
    let s = s.strip_suffix(b"\n")?;
    Some(s.strip_suffix(b"\r").unwrap_or(s))
}

/// 剥离开头的一个行结束（LF 或 CRLF）；开头不是行结束时返回 `None`。
fn strip_leading_line_ending(s: &[u8]) -> Option<&[u8]> {
    if let Some(rest) = s.strip_prefix(b"\r\n") {
        Some(rest)
    } else {
        s.strip_prefix(b"\n")
    }
}

/// 解析一份 PEM 文本（`PUBLIC KEY` 块）的原始字节，还原出其中的 DER 内容。
///
/// 只接受恰好一份块：首标记之前和尾标记之后（至多一个换行除外）不接受
/// 任何内容；两个标记各占一行；正文是一行或多行标准 Base64，行结束接受
///  LF 和 CRLF，不接受空行、行内空格或制表符；填充必须规范。任何一条不
/// 满足都返回 `None`，由调用方统一报告为格式错误。
fn decode_public_key_pem(pem: &[u8]) -> Option<Vec<u8>> {
    // 尾标记之后允许没有换行或只有一个换行（LF 或 CRLF）。
    let mut text = pem;
    if let Some(rest) = text.strip_suffix(b"\n") {
        text = rest.strip_suffix(b"\r").unwrap_or(rest);
    }
    // 尾标记独占一行：整体以它结束，且它前面是一个行结束。
    let text = text.strip_suffix(PEM_END)?;
    let text = strip_line_ending(text)?;
    // 首标记独占一行：输入以它开始，且它后面紧跟一个行结束。
    let text = text.strip_prefix(PEM_BEGIN)?;
    let body = strip_leading_line_ending(text)?;

    // 正文按行拆分：空行（含完全没有正文的空块）不接受；填充用的 `=`
    // 只能出现在最后一行；每行只允许 Base64 字母表字符与 `=`，行内
    // 空格、制表符和其他任何字节都是格式错误。
    let lines: Vec<&[u8]> = body.split(|&b| b == b'\n').collect();
    let last = lines.len() - 1;
    let mut base64 = Vec::with_capacity(body.len());
    for (i, raw_line) in lines.iter().enumerate() {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            return None;
        }
        if i != last && line.contains(&b'=') {
            return None;
        }
        for &b in line {
            if b != b'=' && base64_value(b).is_none() {
                return None;
            }
        }
        base64.extend_from_slice(line);
    }
    decode_base64_canonical(&base64)
}

/// 标准 Base64 字母表中一个字符对应的 6 位值；非字母表字符返回 `None`。
fn base64_value(b: u8) -> Option<u8> {
    match b {
        b'A'..=b'Z' => Some(b - b'A'),
        b'a'..=b'z' => Some(b - b'a' + 26),
        b'0'..=b'9' => Some(b - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// 把整段 Base64 文本（已按行拼接）解码为原始字节，只接受规范编码：
/// 总长为 4 的倍数且非空；填充只能出现在末尾，至多两个 `=`；数据区不
/// 含 `=`；由填充省去的末尾未使用位必须为零。缺少或多出填充、填充后
/// 继续出现编码字符、未使用位非零都返回 `None`。
fn decode_base64_canonical(text: &[u8]) -> Option<Vec<u8>> {
    if text.is_empty() || text.len() % 4 != 0 {
        return None;
    }
    let padding = text.iter().rev().take_while(|&&b| b == b'=').count();
    if padding > 2 {
        return None;
    }
    let data_len = text.len() - padding;
    let mut values = Vec::with_capacity(data_len);
    for &b in &text[..data_len] {
        values.push(base64_value(b)?);
    }
    // 末尾未使用位必须为零：一个填充字符对应 2 位，两个对应 4 位。
    match padding {
        1 if values.last()? & 0x03 != 0 => return None,
        2 if values.last()? & 0x0f != 0 => return None,
        _ => {}
    }
    // 总长是 4 的倍数且填充至多两个，数据字符数只能是 4n、4n+2 或 4n+3。
    let full = data_len / 4 * 4;
    let mut out = Vec::with_capacity(data_len / 4 * 3 + 2);
    for chunk in values[..full].chunks_exact(4) {
        let n = u32::from(chunk[0]) << 18
            | u32::from(chunk[1]) << 12
            | u32::from(chunk[2]) << 6
            | u32::from(chunk[3]);
        out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]);
    }
    match data_len - full {
        3 => {
            let n = u32::from(values[full]) << 18
                | u32::from(values[full + 1]) << 12
                | u32::from(values[full + 2]) << 6;
            out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8]);
        }
        2 => {
            let n = u32::from(values[full]) << 18 | u32::from(values[full + 1]) << 12;
            out.push((n >> 16) as u8);
        }
        _ => {}
    }
    Some(out)
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

    /// RFC 8410 第 4 节的 Ed25519 公钥示例（SubjectPublicKeyInfo 的 DER 编码）。
    const RFC8410_SPKI: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0xd7, 0x5a,
        0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    /// 同一示例的公钥原文（32 字节）。
    const RFC8410_KEY_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    /// 由算法 OID 内容字节与任意长度公钥拼装一份规范编码的 SPKI：
    /// 算法参数缺省，位串未使用位数为零。这里构造的容器都很小，
    /// 各层长度均以短形式单字节编码。
    fn spki_der(oid_content: &[u8], key: &[u8]) -> Vec<u8> {
        // 外层内容 = 算法序列（2 字节头 + 2 字节 OID 头 + OID 内容）
        //          + 位串（2 字节头 + 1 字节未使用位数 + 公钥）。
        let outer_len = oid_content.len() + 4 + key.len() + 3;
        let mut der = vec![0x30, outer_len as u8, 0x30, (oid_content.len() + 2) as u8, 0x06];
        der.push(oid_content.len() as u8);
        der.extend_from_slice(oid_content);
        der.push(0x03);
        der.push((key.len() + 1) as u8);
        der.push(0x00);
        der.extend_from_slice(key);
        der
    }

    #[test]
    fn imports_rfc8410_example_and_exposes_raw_bytes_and_hex() {
        let key = Ed25519PublicKey::from_spki_der(RFC8410_SPKI).unwrap();

        // 原始 32 字节就是位串里的公钥内容。
        assert_eq!(key.as_bytes(), &RFC8410_SPKI[12..]);
        // 文本表示是公钥本身的 64 个小写十六进制字符，不是公钥的 SHA-256 摘要。
        assert_eq!(key.to_hex(), RFC8410_KEY_HEX);
        assert_eq!(format!("{key}"), RFC8410_KEY_HEX);
        assert_ne!(key.to_hex(), digest_reader(&RFC8410_SPKI[12..]).unwrap().to_hex());
    }

    #[test]
    fn public_key_hex_is_64_lowercase_chars_and_keeps_leading_zeros() {
        let mut raw = [0u8; 32];
        raw[0] = 0x00;
        raw[1] = 0x0a;
        raw[31] = 0xff;
        let key = Ed25519PublicKey::from_spki_der(&spki_der(&[0x2b, 0x65, 0x70], &raw)).unwrap();

        let hex = key.to_hex();
        assert_eq!(hex.len(), 64);
        assert!(hex.starts_with("000a"));
        assert!(hex.ends_with("ff"));
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert!(!hex.chars().any(char::is_whitespace));
    }

    #[test]
    fn public_keys_compare_by_value() {
        let a = Ed25519PublicKey::from_spki_der(RFC8410_SPKI).unwrap();
        let b = Ed25519PublicKey::from_spki_der(RFC8410_SPKI).unwrap();
        let mut other_raw = [0u8; 32];
        other_raw.copy_from_slice(&RFC8410_SPKI[12..]);
        other_raw[31] ^= 0x01;
        let c = Ed25519PublicKey::from_spki_der(&spki_der(&[0x2b, 0x65, 0x70], &other_raw))
            .unwrap();

        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn well_formed_non_ed25519_spki_reports_unsupported_algorithm_with_oid() {
        // X25519（1.3.101.110）：结构完整、DER 合法，只是算法不是 Ed25519。
        let der = spki_der(&[0x2b, 0x65, 0x6e], &[0x42; 32]);
        let err = Ed25519PublicKey::from_spki_der(&der).unwrap_err();
        match &err {
            ImportPublicKeyError::UnsupportedAlgorithm(oid) => {
                assert_eq!(oid.arcs(), &[1, 3, 101, 110]);
                assert_eq!(oid.to_string(), "1.3.101.110");
            }
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
        assert!(err.to_string().contains("1.3.101.110"));
    }

    #[test]
    fn well_formed_ed448_spki_reports_unsupported_algorithm_not_malformed() {
        // RFC 8410 的 Ed448 公钥：算法 1.3.101.113（OID 内容 2b 65 71），
        // 参数缺省，位串未使用位数为零，公钥内容恰好 57 字节。
        let der = spki_der(&[0x2b, 0x65, 0x71], &[0x44; 57]);

        // 独立核对这份构造的字节：一份完整、规范的二进制 SPKI——
        // 外层 SEQUENCE 内容 67(0x43) = 算法序列 7 + 位串 60，
        // 位串内容 58(0x3a) = 1 字节未使用位数 + 57 字节公钥，
        // 全程短形式长度编码，无多余字段、无尾随字节。
        let mut expected = vec![
            0x30, 0x43, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x3a, 0x00,
        ];
        expected.extend_from_slice(&[0x44; 57]);
        assert_eq!(der, expected);

        let err = Ed25519PublicKey::from_spki_der(&der).unwrap_err();
        match &err {
            ImportPublicKeyError::UnsupportedAlgorithm(oid) => {
                assert_eq!(oid.arcs(), &[1, 3, 101, 113]);
                assert_eq!(oid.to_string(), "1.3.101.113");
            }
            other => panic!("expected UnsupportedAlgorithm for a valid Ed448 SPKI, got {other:?}"),
        }
        // 提示文字要显示实际标识，并说明这个入口需要 Ed25519。
        let msg = err.to_string();
        assert!(msg.contains("1.3.101.113"), "message must name Ed448: {msg}");
        assert!(msg.contains("1.3.101.112"), "message must name Ed25519: {msg}");
        assert!(msg.to_lowercase().contains("ed25519"), "message must say Ed25519: {msg}");
    }

    #[test]
    fn foreign_algorithm_key_length_never_drives_classification() {
        // 公钥长度只是 Ed25519 专属约束：Ed448 标识下无论公钥多长，
        // 只要结构完整、DER 规范，都报算法不支持而不是格式错误——
        // 57 字节（真正的 Ed448）如此，58 字节同样如此，调用方都应
        // 理解为“换算法”，而不是“修复编码”。
        for len in [57usize, 58] {
            let der = spki_der(&[0x2b, 0x65, 0x71], &vec![0x44; len]);
            match Ed25519PublicKey::from_spki_der(&der).unwrap_err() {
                ImportPublicKeyError::UnsupportedAlgorithm(oid) => {
                    assert_eq!(oid.arcs(), &[1, 3, 101, 113]);
                }
                other => panic!("key length {len} must not make Ed448 look malformed: {other:?}"),
            }
        }
    }

    #[test]
    fn corrupted_ed448_containers_are_malformed_not_unsupported() {
        // 完整的 Ed448 容器：识别出算法不能掩盖编码损坏。
        let ed448 = spki_der(&[0x2b, 0x65, 0x71], &[0x44; 57]);
        assert_eq!(ed448.len(), 69);

        // 截断：外层声明的内容不完整。
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&ed448[..30]).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 声明长度超过实际内容。
        let mut longer = ed448.clone();
        longer[1] = 0x44;
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&longer).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 声明长度短于实际内容：完整对象之后还有字节，不能忽略。
        let mut trailing = ed448.clone();
        trailing[1] = 0x42;
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&trailing).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 对象之后直接多一个字节。
        let mut extra = ed448.clone();
        extra.push(0x00);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&extra).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 位串声明长度与公钥内容不符（声称 59 字节内容，实际 58）。
        let mut bad_bs_len = ed448.clone();
        bad_bs_len[10] = 0x3b;
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&bad_bs_len).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 非规范 DER 长度编码：67 字节本可用短形式，却用了 0x81 0x43。
        let mut non_canonical = vec![0x30, 0x81, 0x43];
        non_canonical.extend_from_slice(&ed448[2..]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&non_canonical).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 参数写成 NULL（05 00）而不是缺省。
        let mut null_params =
            vec![0x30, 0x45, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x05, 0x00];
        null_params.extend_from_slice(&[0x03, 0x3a, 0x00]);
        null_params.extend_from_slice(&[0x44; 57]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&null_params).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 位串未使用位数非零。
        let mut unused_bits = ed448.clone();
        unused_bits[11] = 0x07;
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&unused_bits).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
    }

    #[test]
    fn null_algorithm_parameters_are_rejected_as_malformed() {
        // 参数写成 NULL（05 00）而不是缺省：RFC 8410 不允许。
        let mut der = vec![0x30, 0x2c, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00];
        der.extend_from_slice(&[0x03, 0x21, 0x00]);
        der.extend_from_slice(&[0x11; 32]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
    }

    #[test]
    fn truncated_and_length_mismatched_inputs_are_malformed() {
        // 整体截断：外层声明的 42 字节内容不完整。
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&RFC8410_SPKI[..30]).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 声明长度超过实际内容。
        let mut der = RFC8410_SPKI.to_vec();
        der[1] = 0x2b;
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 声明长度短于实际内容：对象之后还有字节，不能忽略剩余内容。
        let mut der = RFC8410_SPKI.to_vec();
        der[1] = 0x29;
        der[3] = 0x04;
        der.remove(9); // 同步收缩算法序列，让错误只来自外层长度
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 位串声明长度与公钥内容不符。
        let mut der = RFC8410_SPKI.to_vec();
        der[10] = 0x20;
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
    }

    #[test]
    fn non_canonical_lengths_and_indefinite_form_are_malformed() {
        // 长形式表达本可用短形式的长度（0x81 0x2a）：非规范。
        let mut der = vec![0x30, 0x81, 0x2a];
        der.extend_from_slice(&RFC8410_SPKI[2..]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 长形式带前导零字节：非规范。
        let mut der = vec![0x30, 0x82, 0x00, 0x2a];
        der.extend_from_slice(&RFC8410_SPKI[2..]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 不定长形式：DER 不允许。
        let mut der = vec![0x30, 0x80];
        der.extend_from_slice(&RFC8410_SPKI[2..]);
        der.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
    }

    #[test]
    fn bit_string_and_key_size_rules_are_enforced() {
        // 未使用位数非零。
        let mut der = RFC8410_SPKI.to_vec();
        der[11] = 0x01;
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 公钥只有 31 字节。
        let mut der = spki_der(&[0x2b, 0x65, 0x70], &[0x22; 32]);
        der[1] = 0x29;
        der[10] = 0x20;
        der.truncate(der.len() - 1);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 公钥 33 字节。
        let mut der = spki_der(&[0x2b, 0x65, 0x70], &[0x22; 32]);
        der[1] = 0x2b;
        der[10] = 0x22;
        der.push(0x00);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
    }

    #[test]
    fn extra_fields_and_trailing_bytes_are_malformed() {
        // 对象之后还有字节。
        let mut der = RFC8410_SPKI.to_vec();
        der.push(0x00);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 外层容器中多出字段。
        let mut der = spki_der(&[0x2b, 0x65, 0x70], &[0x33; 32]);
        der[1] = 0x2e;
        der.extend_from_slice(&[0x02, 0x01, 0x01]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
    }

    #[test]
    fn raw_key_hex_text_and_pem_are_not_accepted_formats() {
        // 裸公钥（32 字节本身）。
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&RFC8410_SPKI[12..]).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 十六进制文本。
        assert_eq!(
            Ed25519PublicKey::from_spki_der(RFC8410_KEY_HEX.as_bytes()).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // PEM 文本。
        let pem = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----\n";
        assert_eq!(
            Ed25519PublicKey::from_spki_der(pem).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 空输入。
        assert_eq!(
            Ed25519PublicKey::from_spki_der(b"").unwrap_err(),
            ImportPublicKeyError::Malformed
        );
    }

    #[test]
    fn multi_byte_oid_arc_reports_unsupported_with_original_arcs() {
        // 1.3.101.200：最后一段 200 需要用两个字节（0x81 0x48）编码。
        // 结构完整、DER 规范，只是算法不是 Ed25519。
        let der = spki_der(&[0x2b, 0x65, 0x81, 0x48], &[0x42; 32]);
        let err = Ed25519PublicKey::from_spki_der(&der).unwrap_err();
        match &err {
            ImportPublicKeyError::UnsupportedAlgorithm(oid) => {
                // 多字节的一段必须还原为单个数值 200，不能拆成 1 与 72 两段。
                assert_eq!(oid.arcs(), &[1, 3, 101, 200]);
                assert_eq!(oid.to_string(), "1.3.101.200");
            }
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
        assert!(err.to_string().contains("1.3.101.200"));
    }

    #[test]
    fn multi_byte_first_subidentifier_reports_unsupported_with_original_arcs() {
        // 2.999.3：前两段合并为 2*40+999 = 1079，编码本身占两个字节
        //（0x88 0x37），随后一段 3 为 0x03。
        let der = spki_der(&[0x88, 0x37, 0x03], &[0x42; 32]);
        let err = Ed25519PublicKey::from_spki_der(&der).unwrap_err();
        match &err {
            ImportPublicKeyError::UnsupportedAlgorithm(oid) => {
                // 合并编码必须拆回前两段 2 与 999，不能当作单段或截断。
                assert_eq!(oid.arcs(), &[2, 999, 3]);
                assert_eq!(oid.to_string(), "2.999.3");
            }
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
        assert!(err.to_string().contains("2.999.3"));
    }

    /// 把数值按 base-128 最短形式编码为一个 OID 子标识符，追加到 `out`。
    /// 接受 u128 是为了能构造“合并前两段后超过 u64”的第一个子标识符。
    fn push_subidentifier(out: &mut Vec<u8>, value: u128) {
        let mut groups = [0u8; 19]; // u128 最多需要 ceil(128/7) = 19 组
        let mut start = groups.len();
        let mut v = value;
        loop {
            start -= 1;
            groups[start] = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                break;
            }
        }
        let end = groups.len() - 1;
        for b in &mut groups[start..end] {
            *b |= 0x80;
        }
        out.extend_from_slice(&groups[start..]);
    }

    /// 首段为 2 的 OID 内容字节：第一个子标识符合并编码 2*40 + arc1，
    /// 其余各段依次跟在后面。
    fn oid_content_starting_at_2(arc1: u64, rest: &[u64]) -> Vec<u8> {
        let mut content = Vec::new();
        push_subidentifier(&mut content, 80 + u128::from(arc1));
        for &arc in rest {
            push_subidentifier(&mut content, u128::from(arc));
        }
        content
    }

    #[test]
    fn second_arc_at_u64_max_reports_unsupported_with_original_arcs() {
        // 2.18446744073709551615.3：第二段是 u64::MAX，合并编码的第一个
        // 子标识符为 u64::MAX + 80，超出 u64 但每段弧都在 u64 范围内。
        // 编码本身完整、规范，必须报算法不支持并携带原始标识。
        let der = spki_der(&oid_content_starting_at_2(u64::MAX, &[3]), &[0x42; 32]);
        let err = Ed25519PublicKey::from_spki_der(&der).unwrap_err();
        match &err {
            ImportPublicKeyError::UnsupportedAlgorithm(oid) => {
                assert_eq!(oid.arcs(), &[2, 18446744073709551615, 3]);
                assert_eq!(oid.to_string(), "2.18446744073709551615.3");
            }
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
        assert!(err.to_string().contains("2.18446744073709551615.3"));
    }

    #[test]
    fn second_arc_near_u64_max_reports_unsupported_across_the_whole_range() {
        // 第二段从 18446744073709551536（u64::MAX - 79）到 u64::MAX：
        // 合并编码的第一个子标识符从 u64::MAX + 1 到 u64::MAX + 80，
        // 都超出 u64 但都是合法标识。连同两侧相邻的可表示值一起核对，
        // 不允许截断、回绕或改写成别的标识。
        let near_max = (u64::MAX - 79)..=u64::MAX;
        let adjacent = [u64::MAX - 1000, u64::MAX - 80, 1 << 32];
        for arc1 in near_max.chain(adjacent) {
            let der = spki_der(&oid_content_starting_at_2(arc1, &[3, 7]), &[0x42; 32]);
            let err = Ed25519PublicKey::from_spki_der(&der).unwrap_err();
            match &err {
                ImportPublicKeyError::UnsupportedAlgorithm(oid) => {
                    // 每段数值与先后次序都原样保留，包括后面的合法段。
                    assert_eq!(oid.arcs(), &[2, arc1, 3, 7], "arc1 = {arc1}");
                    assert_eq!(oid.to_string(), format!("2.{arc1}.3.7"));
                }
                other => panic!("arc1 = {arc1}: expected UnsupportedAlgorithm, got {other:?}"),
            }
        }
    }

    #[test]
    fn arc_beyond_u64_is_malformed_not_unsupported_and_does_not_crash() {
        // 第二段超出 u64：第一个子标识符为 u64::MAX + 81，任何一段都
        // 无法表示，按编码损坏处理。
        let mut content = Vec::new();
        push_subidentifier(&mut content, u64::MAX as u128 + 81);
        push_subidentifier(&mut content, 3);
        let der = spki_der(&content, &[0x42; 32]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
            ImportPublicKeyError::Malformed
        );

        // 大得多的合并值同样只是编码损坏，不能溢出或崩溃。
        let mut content = Vec::new();
        push_subidentifier(&mut content, u128::MAX);
        let der = spki_der(&content, &[0x42; 32]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
            ImportPublicKeyError::Malformed
        );

        // 后续段超出 u64（2.5.18446744073709551616）：同样报编码损坏。
        let mut content = Vec::new();
        push_subidentifier(&mut content, 85);
        push_subidentifier(&mut content, u64::MAX as u128 + 1);
        let der = spki_der(&content, &[0x42; 32]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
            ImportPublicKeyError::Malformed
        );

        // 而后续段恰好为 u64::MAX（2.5.18446744073709551615）仍合法。
        let mut content = Vec::new();
        push_subidentifier(&mut content, 85);
        push_subidentifier(&mut content, u64::MAX as u128);
        let der = spki_der(&content, &[0x42; 32]);
        match Ed25519PublicKey::from_spki_der(&der).unwrap_err() {
            ImportPublicKeyError::UnsupportedAlgorithm(oid) => {
                assert_eq!(oid.arcs(), &[2, 5, 18446744073709551615]);
            }
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn huge_arc_oid_still_enforces_strict_der() {
        // 接近上限的标识不改变严格 DER 要求：能识别出其他算法，
        // 也不能把编码损坏改报成算法不支持。
        let valid = spki_der(&oid_content_starting_at_2(u64::MAX, &[3]), &[0x42; 32]);

        // 冗余前导零：第一个子标识符前补一个 0x80 组。
        let mut padded_content = vec![0x80];
        padded_content.extend_from_slice(&oid_content_starting_at_2(u64::MAX, &[3]));
        let der = spki_der(&padded_content, &[0x42; 32]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
            ImportPublicKeyError::Malformed
        );

        // 末段子标识符的续位未结束。
        let mut unterminated = oid_content_starting_at_2(u64::MAX, &[3]);
        *unterminated.last_mut().unwrap() |= 0x80;
        let der = spki_der(&unterminated, &[0x42; 32]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
            ImportPublicKeyError::Malformed
        );

        // 容器截断。
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&valid[..valid.len() - 1]).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 对象之后多出字节。
        let mut trailing = valid.clone();
        trailing.push(0x00);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&trailing).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
    }

    #[test]
    fn oid_longer_than_ed25519_prefix_keeps_every_arc_in_order() {
        // 1.3.101.112.255.300：前缀与 Ed25519 相同但更长，整体仍是另一
        // 个算法；255 编码为 0x81 0x7f，300 编码为 0x82 0x2c。
        let der = spki_der(&[0x2b, 0x65, 0x70, 0x81, 0x7f, 0x82, 0x2c], &[0x42; 32]);
        let err = Ed25519PublicKey::from_spki_der(&der).unwrap_err();
        match &err {
            ImportPublicKeyError::UnsupportedAlgorithm(oid) => {
                // 不能只保留与 Ed25519 相同的前几段：每段数值与次序都保留。
                assert_eq!(oid.arcs(), &[1, 3, 101, 112, 255, 300]);
                assert_eq!(oid.to_string(), "1.3.101.112.255.300");
            }
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn malformed_oid_encodings_are_malformed_not_unsupported() {
        // 算法标识为空：OID 内容长度为零。
        let empty = spki_der(&[], &[0x42; 32]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&empty).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 末段子标识符的续位未结束：0x81 之后没有后续字节。
        let unterminated = spki_der(&[0x2b, 0x81], &[0x42; 32]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&unterminated).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 非规范编码：子标识符以 0x80 开头（冗余前导零）。
        let padded_arc = spki_der(&[0x2b, 0x80, 0x65, 0x70], &[0x42; 32]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&padded_arc).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 非规范编码出现在第一个子标识符（合并前两段处）同样拒绝。
        let padded_first = spki_der(&[0x80, 0x2b, 0x65, 0x70], &[0x42; 32]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&padded_first).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
    }

    #[test]
    fn corrupted_encoding_is_malformed_even_with_foreign_oid_inside() {
        // 结构损坏但局部能看到其他算法标识：必须报格式错误，
        // 不能改报算法不支持。
        let x25519 = spki_der(&[0x2b, 0x65, 0x6e], &[0x42; 32]);

        // 截断的 X25519 SPKI。
        let truncated = &x25519[..20];
        assert_eq!(
            Ed25519PublicKey::from_spki_der(truncated).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 尾部多字节的 X25519 SPKI。
        let mut trailing = x25519.clone();
        trailing.push(0x00);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&trailing).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 位串未使用位数非零的 X25519 SPKI。
        let mut bad_bits = x25519.clone();
        bad_bits[11] = 0x07;
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&bad_bits).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
    }

    // ----- PEM 文本导入（from_spki_pem）-----
    //
    // 这一组测试守住两条边界：外层 PEM 文本的严格格式（标记独占一行、
    // 正文只允许规范 Base64、标记之外没有任何内容），以及 PEM 入口与
    // DER 入口的分类一致性——外层或 DER 损坏一律 Malformed，外层与 DER
    // 都合法但算法不是 Ed25519 才是 UnsupportedAlgorithm。

    /// RFC 8410 第 4 节示例的 PEM 形式（与 RFC8410_SPKI 是同一容器）。
    const RFC8410_PEM: &[u8] = b"-----BEGIN PUBLIC KEY-----\n\
        MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n\
        -----END PUBLIC KEY-----\n";

    /// 标准 Base64 编码（规范填充），测试里用来把任意 DER 包进 PEM。
    fn base64_encode(data: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let n = u32::from(chunk[0]) << 16
                | u32::from(*chunk.get(1).unwrap_or(&0)) << 8
                | u32::from(*chunk.get(2).unwrap_or(&0));
            out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
            out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[(n >> 6) as usize & 0x3f] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                ALPHABET[n as usize & 0x3f] as char
            } else {
                '='
            });
        }
        out
    }

    /// 把一份 DER 包成单行正文的 PEM 文本（末尾带一个 LF）。
    fn pem_of_der(der: &[u8]) -> Vec<u8> {
        format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            base64_encode(der)
        )
        .into_bytes()
    }

    #[test]
    fn pem_import_matches_der_import_for_the_same_key() {
        // 独立核对测试用的编码器：对 RFC 示例的编码结果与文献中的 PEM 一致。
        assert_eq!(pem_of_der(RFC8410_SPKI), RFC8410_PEM);

        let from_pem = Ed25519PublicKey::from_spki_pem(RFC8410_PEM).unwrap();
        let from_der = Ed25519PublicKey::from_spki_der(RFC8410_SPKI).unwrap();

        // 同一把公钥从 PEM 或 DER 导入，得到相同的原始 32 字节，按值相等。
        assert_eq!(from_pem, from_der);
        assert_eq!(from_pem.as_bytes(), &RFC8410_SPKI[12..]);
        // 十六进制显示仍是 64 个小写字符，前导零规则不变。
        assert_eq!(from_pem.to_hex(), RFC8410_KEY_HEX);
        assert_eq!(format!("{from_pem}"), RFC8410_KEY_HEX);
    }

    #[test]
    fn pem_body_may_be_one_or_multiple_lines() {
        let body = "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
        let expected = Ed25519PublicKey::from_spki_der(RFC8410_SPKI).unwrap();

        // 按 16 字符（4 的倍数）分行。
        let aligned = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n{}\n{}\n{}\n-----END PUBLIC KEY-----\n",
            &body[..16],
            &body[16..32],
            &body[32..44],
            &body[44..]
        );
        assert_eq!(Ed25519PublicKey::from_spki_pem(aligned.as_bytes()).unwrap(), expected);

        // 分行位置不对齐 4 的倍数同样可以：拼接后的整体是规范 Base64。
        let unaligned = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n{}\n{}\n-----END PUBLIC KEY-----\n",
            &body[..5],
            &body[5..31],
            &body[31..]
        );
        assert_eq!(Ed25519PublicKey::from_spki_pem(unaligned.as_bytes()).unwrap(), expected);
    }

    #[test]
    fn pem_accepts_lf_or_crlf_and_optional_single_trailing_newline() {
        let body = "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
        let expected = Ed25519PublicKey::from_spki_der(RFC8410_SPKI).unwrap();

        // 全程 CRLF，尾标记后没有换行。
        let crlf = format!(
            "-----BEGIN PUBLIC KEY-----\r\n{}\r\n-----END PUBLIC KEY-----",
            body
        );
        assert_eq!(Ed25519PublicKey::from_spki_pem(crlf.as_bytes()).unwrap(), expected);
        // 全程 CRLF，尾标记后再跟一个 CRLF。
        let crlf_final = format!("{crlf}\r\n");
        assert_eq!(Ed25519PublicKey::from_spki_pem(crlf_final.as_bytes()).unwrap(), expected);
        // LF 行结束，尾标记后没有换行。
        let lf_no_final = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
            body
        );
        assert_eq!(Ed25519PublicKey::from_spki_pem(lf_no_final.as_bytes()).unwrap(), expected);
        // 混合行结束：首标记后 CRLF、正文后 LF，尾标记后一个 LF。
        let mixed = format!(
            "-----BEGIN PUBLIC KEY-----\r\n{}\n-----END PUBLIC KEY-----\n",
            body
        );
        assert_eq!(Ed25519PublicKey::from_spki_pem(mixed.as_bytes()).unwrap(), expected);
    }

    #[test]
    fn pem_rejects_anything_outside_the_single_block() {
        let body = "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
        let block = format!("-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n");

        // 首标记之前的任何内容：空白、BOM、注释、另一行文本。
        for bad in [
            format!(" {block}"),
            format!("\n{block}"),
            format!("\u{feff}{block}"),
            format!("# comment\n{block}"),
        ] {
            assert_eq!(
                Ed25519PublicKey::from_spki_pem(bad.as_bytes()).unwrap_err(),
                ImportPublicKeyError::Malformed
            );
        }
        // 尾标记之后的任何内容：第二个块、多余空行（两个换行）、尾随文本。
        for bad in [
            format!("{block}{block}"),
            format!("{block}\n"),
            format!("{block} "),
            format!("{block}-----BEGIN PUBLIC KEY-----\n"),
        ] {
            assert_eq!(
                Ed25519PublicKey::from_spki_pem(bad.as_bytes()).unwrap_err(),
                ImportPublicKeyError::Malformed
            );
        }
    }

    #[test]
    fn pem_rejects_other_labels_and_damaged_markers() {
        let body = "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
        // 私钥、证书等其他标签不接受，也不猜测裸公钥或十六进制文本。
        for bad in [
            format!("-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"),
            format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n"),
            format!("-----BEGIN PUBLIC KEY-----\n{body}\n-----END PRIVATE KEY-----\n"),
            // 标记没有独占一行。
            format!("-----BEGIN PUBLIC KEY-----{body}\n-----END PUBLIC KEY-----\n"),
            format!("-----BEGIN PUBLIC KEY-----\n{body}-----END PUBLIC KEY-----\n"),
            format!("-----BEGIN PUBLIC KEY----- \n{body}\n-----END PUBLIC KEY-----\n"),
            // 标记拼写不同（大小写、短横线数量）。
            format!("-----BEGIN Public Key-----\n{body}\n-----END Public Key-----\n"),
            format!("----BEGIN PUBLIC KEY----\n{body}\n----END PUBLIC KEY----\n"),
        ] {
            assert_eq!(
                Ed25519PublicKey::from_spki_pem(bad.as_bytes()).unwrap_err(),
                ImportPublicKeyError::Malformed,
                "input must be rejected: {bad:?}"
            );
        }
    }

    #[test]
    fn pem_rejects_body_layout_violations() {
        let body = "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
        let (head, tail) = body.split_at(24);
        for bad in [
            // 空块：BEGIN 之后直接是 END。
            "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----\n".to_string(),
            // 正文中间的空行。
            format!("-----BEGIN PUBLIC KEY-----\n{head}\n\n{tail}\n-----END PUBLIC KEY-----\n"),
            // 正文末尾的空行。
            format!("-----BEGIN PUBLIC KEY-----\n{body}\n\n-----END PUBLIC KEY-----\n"),
            // 行内空格与制表符。
            format!("-----BEGIN PUBLIC KEY-----\n{head} {tail}\n-----END PUBLIC KEY-----\n"),
            format!("-----BEGIN PUBLIC KEY-----\n{head}\t{tail}\n-----END PUBLIC KEY-----\n"),
            // 非法 Base64 字符（含非 ASCII 字节）。
            format!("-----BEGIN PUBLIC KEY-----\n{head}*{tail}\n-----END PUBLIC KEY-----\n"),
            format!("-----BEGIN PUBLIC KEY-----\n{head}\u{ff}{tail}\n-----END PUBLIC KEY-----\n"),
            // 单独的 CR 不是行结束。
            format!("-----BEGIN PUBLIC KEY-----\r{body}\n-----END PUBLIC KEY-----\n"),
            format!("-----BEGIN PUBLIC KEY-----\n{body}\r-----END PUBLIC KEY-----\n"),
        ] {
            assert_eq!(
                Ed25519PublicKey::from_spki_pem(bad.as_bytes()).unwrap_err(),
                ImportPublicKeyError::Malformed,
                "input must be rejected: {bad:?}"
            );
        }
    }

    #[test]
    fn pem_rejects_noncanonical_base64_padding_and_content() {
        // 规范形式：总长 4 的倍数，填充在末尾且未使用位为零。
        let body = "MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
        let (head, tail) = body.split_at(24);
        for bad_body in [
            // 缺少填充：总长不是 4 的倍数。
            body.trim_end_matches('=').to_string(),
            // 多出填充。
            format!("{body}="),
            format!("{body}==="),
            // 填充出现在最后一行中间，其后还有编码字符。
            format!("{head}=AAA{tail}"),
            // 填充出现在非最后一行。
            format!("{head}=\n{tail}"),
            // 末尾未使用位非零：把最后一个编码字符 'o'（40，低 2 位为 0）
            // 换成 'p'（41，低 2 位非零）。
            format!("{}p=", &body[..body.len() - 2]),
        ] {
            let pem =
                format!("-----BEGIN PUBLIC KEY-----\n{bad_body}\n-----END PUBLIC KEY-----\n");
            assert_eq!(
                Ed25519PublicKey::from_spki_pem(pem.as_bytes()).unwrap_err(),
                ImportPublicKeyError::Malformed,
                "body must be rejected: {bad_body:?}"
            );
        }
    }

    #[test]
    fn base64_decoder_enforces_canonical_form_directly() {
        // 直接核对解码器的边界（这些输入经 PEM 入口同样都是格式错误，
        // 但 DER 层也会拒绝它们，无法区分错误来自哪一层）。
        assert_eq!(decode_base64_canonical(b""), None);
        assert_eq!(decode_base64_canonical(b"A"), None);
        assert_eq!(decode_base64_canonical(b"AQI"), None); // 缺填充
        assert_eq!(decode_base64_canonical(b"AQ=="), Some(vec![0x01]));
        assert_eq!(decode_base64_canonical(b"AR=="), None); // 未使用位非零
        assert_eq!(decode_base64_canonical(b"AAE="), Some(vec![0x00, 0x01]));
        assert_eq!(decode_base64_canonical(b"AAF="), None); // 未使用位非零
        assert_eq!(decode_base64_canonical(b"AQ==="), None); // 多出填充
        assert_eq!(decode_base64_canonical(b"===="), None);
        assert_eq!(decode_base64_canonical(b"AQ=A"), None); // 数据区含 '='
        assert_eq!(decode_base64_canonical(b"AAAA"), Some(vec![0x00, 0x00, 0x00]));
        assert_eq!(decode_base64_canonical(b"AAA"), None);
        // 与已知向量互验：RFC 8410 示例正文还原为完整 DER。
        assert_eq!(
            decode_base64_canonical(
                b"MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="
            )
            .as_deref(),
            Some(RFC8410_SPKI)
        );
    }

    #[test]
    fn pem_with_valid_der_of_other_algorithm_reports_unsupported_with_oid() {
        // 外层 PEM 与内部 DER 都合法，算法是 Ed448：保留算法不支持的分类
        // 与实际标识，与 DER 入口一致。
        let ed448 = spki_der(&[0x2b, 0x65, 0x71], &[0x44; 57]);
        let err = Ed25519PublicKey::from_spki_pem(&pem_of_der(&ed448)).unwrap_err();
        match &err {
            ImportPublicKeyError::UnsupportedAlgorithm(oid) => {
                assert_eq!(oid.arcs(), &[1, 3, 101, 113]);
            }
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
        assert!(err.to_string().contains("1.3.101.113"));

        // X25519 同样。
        let x25519 = spki_der(&[0x2b, 0x65, 0x6e], &[0x42; 32]);
        let err = Ed25519PublicKey::from_spki_pem(&pem_of_der(&x25519)).unwrap_err();
        match &err {
            ImportPublicKeyError::UnsupportedAlgorithm(oid) => {
                assert_eq!(oid.arcs(), &[1, 3, 101, 110]);
            }
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn pem_with_corrupted_der_is_malformed_even_with_foreign_oid_inside() {
        // 还原出的 DER 截断、长度不符或带多余字节：一律格式错误，
        // 不因内部能看到 Ed448 标识而改报算法不支持。
        let ed448 = spki_der(&[0x2b, 0x65, 0x71], &[0x44; 57]);
        for der in [
            ed448[..30].to_vec(),
            ed448[..ed448.len() - 1].to_vec(),
            ed448.iter().copied().chain([0x00]).collect(),
        ] {
            assert_eq!(
                Ed25519PublicKey::from_spki_pem(&pem_of_der(&der)).unwrap_err(),
                ImportPublicKeyError::Malformed
            );
        }
        // Ed25519 容器被截断或多了字节同样如此。
        for der in [
            RFC8410_SPKI[..30].to_vec(),
            RFC8410_SPKI.iter().copied().chain([0x00]).collect(),
        ] {
            assert_eq!(
                Ed25519PublicKey::from_spki_pem(&pem_of_der(&der)).unwrap_err(),
                ImportPublicKeyError::Malformed
            );
        }
    }

    #[test]
    fn pem_entry_accepts_only_pem_and_der_entry_accepts_only_der() {
        // PEM 入口不接受二进制 DER、裸公钥、十六进制文本或空输入。
        let not_pem: [&[u8]; 4] = [
            RFC8410_SPKI,
            &RFC8410_SPKI[12..],
            RFC8410_KEY_HEX.as_bytes(),
            b"",
        ];
        for bad in not_pem {
            assert_eq!(
                Ed25519PublicKey::from_spki_pem(bad).unwrap_err(),
                ImportPublicKeyError::Malformed
            );
        }
        // DER 入口继续只接受 DER：PEM 文本仍是格式错误。
        assert_eq!(
            Ed25519PublicKey::from_spki_der(RFC8410_PEM).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
    }

    #[test]
    fn import_error_supports_display_and_error_trait() {
        let malformed = Ed25519PublicKey::from_spki_der(b"\x30").unwrap_err();
        assert!(malformed.to_string().contains("DER"));

        let der = spki_der(&[0x2b, 0x65, 0x6e], &[0x42; 32]);
        let unsupported = Ed25519PublicKey::from_spki_der(&der).unwrap_err();
        let msg = unsupported.to_string();
        assert!(msg.contains("1.3.101.110"));
        assert!(msg.contains("1.3.101.112"));

        // 两类失败可按变体区分，且都实现 std::error::Error，可常规传递。
        fn assert_error<T: std::error::Error>(_: &T) {}
        assert_error(&malformed);
        assert_error(&unsupported);
        assert_ne!(malformed, unsupported);
        let boxed: Box<dyn std::error::Error> = Box::new(unsupported);
        assert!(boxed.to_string().contains("1.3.101.110"));
    }

    // ----- DER 长度编码（短形式/长形式）的回归保障 -----
    //
    // 这一组测试只走公开入口 from_spki_der，守住一条边界：容器内容从 127
    // 字节增到 128 字节、长度字段从短形式变成最短长形式时，“结构合法但
    // 算法不是 Ed25519 → UnsupportedAlgorithm”与“编码损坏 → Malformed”
    // 的区分不能改变。外层 SEQUENCE、算法标识所在 SEQUENCE、公钥位串三个
    // 位置适用同一条规则。

    /// 构造测试输入时某一层 TLV 长度字段的写法。
    #[derive(Clone, Copy)]
    enum LenStyle {
        /// 规范最短形式：127 以内短形式，128 起最短长形式。
        Canonical,
        /// 长度小于 128 也写成长形式——本可用短形式，属于非规范编码。
        ForcedLong,
        /// 长形式数字前再补一个零字节——冗余前导零，属于非规范编码。
        ForcedLongZeroPadded,
    }

    /// 按指定风格生成一个 DER 长度字段的字节。
    fn test_len_bytes(len: usize, style: LenStyle) -> Vec<u8> {
        let mut base256 = Vec::new();
        let mut v = len;
        loop {
            base256.push((v & 0xff) as u8);
            v >>= 8;
            if v == 0 {
                break;
            }
        }
        base256.reverse();
        match style {
            LenStyle::Canonical if len < 128 => vec![len as u8],
            LenStyle::Canonical | LenStyle::ForcedLong => {
                let mut out = vec![0x80 | base256.len() as u8];
                out.extend_from_slice(&base256);
                out
            }
            LenStyle::ForcedLongZeroPadded => {
                let mut out = vec![0x80 | (base256.len() + 1) as u8, 0x00];
                out.extend_from_slice(&base256);
                out
            }
        }
    }

    /// 用指定的长度风格拼一个 TLV；内容本身原样放入。
    fn test_tlv(tag: u8, content: &[u8], style: LenStyle) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend_from_slice(&test_len_bytes(content.len(), style));
        out.extend_from_slice(content);
        out
    }

    /// 拼装一份 SPKI：算法参数缺省、位串未使用位数为零；三层 TLV 的长度
    /// 字段风格可分别指定。OID 自身始终按规范短形式编码（这些用例里 OID
    /// 内容都不超过 127 字节）。
    fn styled_spki(
        oid_content: &[u8],
        key: &[u8],
        outer_style: LenStyle,
        alg_style: LenStyle,
        bs_style: LenStyle,
    ) -> Vec<u8> {
        let oid = test_tlv(TAG_OID, oid_content, LenStyle::Canonical);
        let algorithm = test_tlv(TAG_SEQUENCE, &oid, alg_style);
        let mut bs_content = vec![0x00];
        bs_content.extend_from_slice(key);
        let bit_string = test_tlv(TAG_BIT_STRING, &bs_content, bs_style);
        let mut outer_content = algorithm;
        outer_content.extend_from_slice(&bit_string);
        test_tlv(TAG_SEQUENCE, &outer_content, outer_style)
    }

    /// 断言一份结构完整的容器被归类为“算法不支持”，且 OID 原样保留。
    fn assert_unsupported_oid(der: &[u8], expected_arcs: &[u64]) {
        let err = Ed25519PublicKey::from_spki_der(der).unwrap_err();
        match &err {
            ImportPublicKeyError::UnsupportedAlgorithm(oid) => {
                assert_eq!(oid.arcs(), expected_arcs);
                // 点分显示必须包含完整标识，包括末尾的段。
                let dotted: String = expected_arcs
                    .iter()
                    .map(|arc| arc.to_string())
                    .collect::<Vec<_>>()
                    .join(".");
                assert_eq!(oid.to_string(), dotted);
                assert!(err.to_string().contains(&dotted));
            }
            other => panic!("expected UnsupportedAlgorithm({expected_arcs:?}), got {other:?}"),
        }
    }

    #[test]
    fn canonical_ed25519_small_container_still_imports_unchanged() {
        // 兼容基线：规范的小容器（全程短形式长度）继续接受，原始字节与
        // 64 个小写十六进制字符都和以前一致。
        let key = Ed25519PublicKey::from_spki_der(RFC8410_SPKI).unwrap();
        assert_eq!(key.as_bytes(), &RFC8410_SPKI[12..]);
        assert_eq!(key.to_hex(), RFC8410_KEY_HEX);
        assert_eq!(key.to_hex().len(), 64);
        assert!(key
            .to_hex()
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        // 用本组构造器按全规范风格拼出的同一容器，字节完全相同。
        let rebuilt = styled_spki(
            &[0x2b, 0x65, 0x70],
            &RFC8410_SPKI[12..],
            LenStyle::Canonical,
            LenStyle::Canonical,
            LenStyle::Canonical,
        );
        assert_eq!(rebuilt, RFC8410_SPKI);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&rebuilt).unwrap().as_bytes(),
            &RFC8410_SPKI[12..]
        );
    }

    #[test]
    fn outer_sequence_crossing_127_128_keeps_unsupported_classification() {
        // 外层内容恰为 127（短形式 0x7f）与 128（最短长形式 0x81 0x80）：
        // 算法序列 7 字节 + 位串 TLV，故公钥 117/118 字节时外层内容分别
        // 为 127/128；两种情况下位串本身都仍是短形式。算法为 Ed448。
        let at_127 = styled_spki(
            &[0x2b, 0x65, 0x71],
            &[0x44; 117],
            LenStyle::Canonical,
            LenStyle::Canonical,
            LenStyle::Canonical,
        );
        assert_eq!(&at_127[0..2], &[0x30, 0x7f]);
        assert_eq!(at_127[9], 0x03);
        assert_eq!(at_127[10], 0x76); // 位串内容 118

        let at_128 = styled_spki(
            &[0x2b, 0x65, 0x71],
            &[0x44; 118],
            LenStyle::Canonical,
            LenStyle::Canonical,
            LenStyle::Canonical,
        );
        // 唯一的结构差别就是外层长度从短形式变成最短长形式。
        assert_eq!(&at_128[0..3], &[0x30, 0x81, 0x80]);
        assert_eq!(at_128[10], 0x03);
        assert_eq!(at_128[11], 0x77); // 位串内容 119，仍是短形式

        // 两侧的分类原则必须一致：都是合法的其他算法容器。
        assert_unsupported_oid(&at_127, &[1, 3, 101, 113]);
        assert_unsupported_oid(&at_128, &[1, 3, 101, 113]);
    }

    #[test]
    fn bit_string_crossing_127_128_keeps_unsupported_classification() {
        // 位串内容（未使用位数字节 + 公钥）恰为 127/128：公钥 126/127
        // 字节时位串长度分别是 0x7f 与 0x81 0x80；外层在两侧都已是长形式。
        let at_127 = styled_spki(
            &[0x2b, 0x65, 0x71],
            &[0x44; 126],
            LenStyle::Canonical,
            LenStyle::Canonical,
            LenStyle::Canonical,
        );
        assert_eq!(&at_127[0..3], &[0x30, 0x81, 0x88]); // 外层 136
        assert_eq!(&at_127[10..13], &[0x03, 0x7f, 0x00]);

        let at_128 = styled_spki(
            &[0x2b, 0x65, 0x71],
            &[0x44; 127],
            LenStyle::Canonical,
            LenStyle::Canonical,
            LenStyle::Canonical,
        );
        assert_eq!(&at_128[0..3], &[0x30, 0x81, 0x8a]); // 外层 138
        assert_eq!(&at_128[10..14], &[0x03, 0x81, 0x80, 0x00]);

        assert_unsupported_oid(&at_127, &[1, 3, 101, 113]);
        assert_unsupported_oid(&at_128, &[1, 3, 101, 113]);
    }

    #[test]
    fn algorithm_sequence_crossing_127_128_keeps_unsupported_classification() {
        // 算法序列内容（OID TLV）恰为 127/128：OID 内容 125/126 字节。
        // 每个内容字节 0x01..=0x7e 都是完整的单子标识符，因此得到 OID
        // 0.1.2.…（首字节 1 拆成前两段 0 与 1），是合法但不受支持的标识。
        let oid_125: Vec<u8> = (1..=125).collect();
        let oid_126: Vec<u8> = (1..=126).collect();
        let at_127 = styled_spki(
            &oid_125,
            &[0x42; 32],
            LenStyle::Canonical,
            LenStyle::Canonical,
            LenStyle::Canonical,
        );
        assert_eq!(&at_127[0..3], &[0x30, 0x81, 0xa4]); // 外层 164
        assert_eq!(&at_127[3..5], &[0x30, 0x7f]); // 算法序列 127，短形式
        assert_eq!(&at_127[5..7], &[0x06, 0x7d]); // OID 内容 125

        let at_128 = styled_spki(
            &oid_126,
            &[0x42; 32],
            LenStyle::Canonical,
            LenStyle::Canonical,
            LenStyle::Canonical,
        );
        assert_eq!(&at_128[0..3], &[0x30, 0x81, 0xa6]); // 外层 166
        assert_eq!(&at_128[3..6], &[0x30, 0x81, 0x80]); // 算法序列 128，长形式
        assert_eq!(&at_128[6..8], &[0x06, 0x7e]); // OID 内容 126

        // 两侧都报算法不支持；数值、次序与点分显示的末尾都必须保留。
        let err_127 = Ed25519PublicKey::from_spki_der(&at_127).unwrap_err();
        match &err_127 {
            ImportPublicKeyError::UnsupportedAlgorithm(oid) => {
                assert_eq!(oid.arcs().len(), 126);
                assert_eq!(&oid.arcs()[..2], &[0, 1]);
                assert_eq!(oid.arcs().last(), Some(&125));
                assert_eq!(
                    oid.to_string(),
                    (0..=125u64)
                        .map(|arc| arc.to_string())
                        .collect::<Vec<_>>()
                        .join(".")
                );
                assert!(oid.to_string().ends_with(".124.125"));
            }
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
        let err_128 = Ed25519PublicKey::from_spki_der(&at_128).unwrap_err();
        match &err_128 {
            ImportPublicKeyError::UnsupportedAlgorithm(oid) => {
                assert_eq!(oid.arcs().len(), 127);
                assert_eq!(&oid.arcs()[..2], &[0, 1]);
                assert_eq!(oid.arcs().last(), Some(&126));
                assert!(oid.to_string().ends_with(".125.126"));
            }
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn all_three_layers_in_canonical_long_form_still_report_unsupported() {
        // 同一份容器里三层都因内容达到 128 而采用最短长形式：
        // OID 内容 126（算法序列内容 128）、公钥 127（位串内容 128）、
        // 外层内容 262（0x106）。
        let oid_content: Vec<u8> = (1..=126).collect();
        let der = styled_spki(
            &oid_content,
            &[0x44; 127],
            LenStyle::Canonical,
            LenStyle::Canonical,
            LenStyle::Canonical,
        );
        assert_eq!(&der[0..4], &[0x30, 0x82, 0x01, 0x06]);
        assert_eq!(&der[4..7], &[0x30, 0x81, 0x80]);
        assert_eq!(&der[7..9], &[0x06, 0x7e]);
        assert_eq!(&der[135..139], &[0x03, 0x81, 0x80, 0x00]);
        // 对象恰好结束，没有多余字节。
        assert_eq!(der.len(), 4 + 262);

        let expected_arcs: Vec<u64> = (0..=126).collect();
        assert_eq!(expected_arcs.len(), 127);
        let err = Ed25519PublicKey::from_spki_der(&der).unwrap_err();
        match &err {
            ImportPublicKeyError::UnsupportedAlgorithm(oid) => {
                assert_eq!(oid.arcs(), expected_arcs.as_slice());
                assert!(oid.to_string().ends_with(".125.126"));
            }
            other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
        }
    }

    #[test]
    fn foreign_algorithm_key_size_never_triggers_ed25519_length_rule() {
        // “公钥必须 32 字节”只在算法确为 Ed25519 后才检查：Ed448 标识下
        // 公钥为空、短于 32、恰为 32 或远长于 32（含跨越 128 的长度），
        // 只要结构完整、DER 规范，分类一律是算法不支持。
        for key_len in [0usize, 1, 31, 32, 33, 117, 118, 126, 127, 128, 200] {
            let der = styled_spki(
                &[0x2b, 0x65, 0x71],
                &vec![0x44; key_len],
                LenStyle::Canonical,
                LenStyle::Canonical,
                LenStyle::Canonical,
            );
            assert_unsupported_oid(&der, &[1, 3, 101, 113]);
        }
    }

    #[test]
    fn ed25519_key_must_still_be_exactly_32_bytes_even_in_long_form_container() {
        // 算法确为 Ed25519 时，长度约束照旧：31、33 字节以及位串跨入长
        // 形式的 127 字节公钥都是编码损坏，不截短也不补齐。
        for key_len in [31usize, 33, 127] {
            let der = styled_spki(
                &[0x2b, 0x65, 0x70],
                &vec![0x22; key_len],
                LenStyle::Canonical,
                LenStyle::Canonical,
                LenStyle::Canonical,
            );
            assert_eq!(
                Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
                ImportPublicKeyError::Malformed,
                "Ed25519 key of {key_len} bytes must be Malformed"
            );
        }
        // 恰好 32 字节的规范容器仍然成功。
        let der = styled_spki(
            &[0x2b, 0x65, 0x70],
            &[0x22; 32],
            LenStyle::Canonical,
            LenStyle::Canonical,
            LenStyle::Canonical,
        );
        let key = Ed25519PublicKey::from_spki_der(&der).unwrap();
        assert_eq!(key.as_bytes(), &[0x22; 32]);
        assert_eq!(key.to_hex(), "22".repeat(32));
    }

    #[test]
    fn non_canonical_long_form_lengths_are_malformed_at_every_layer() {
        // 用一份本应全部短形式的 Ed448 小容器（公钥 40 字节），分别在三个
        // 位置单独写入非规范长度：能短却长（0x81 前缀）、冗余前导零
        //（0x82 0x00 前缀）。即使 OID 已可识别为其他算法，也必须报编码
        // 损坏，不能报算法不支持。
        for bad_style in [LenStyle::ForcedLong, LenStyle::ForcedLongZeroPadded] {
            for layer in 0..3 {
                let (outer, alg, bs) = match layer {
                    0 => (bad_style, LenStyle::Canonical, LenStyle::Canonical),
                    1 => (LenStyle::Canonical, bad_style, LenStyle::Canonical),
                    _ => (LenStyle::Canonical, LenStyle::Canonical, bad_style),
                };
                let der = styled_spki(&[0x2b, 0x65, 0x71], &[0x44; 40], outer, alg, bs);
                assert_eq!(
                    Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
                    ImportPublicKeyError::Malformed,
                    "non-canonical length at layer {layer} must be Malformed"
                );
            }
        }

        // 内容确实达到 128、但最短长形式前再补零字节（0x82 0x00 0x80），
        // 在外层与位串两个位置同样拒绝。
        for layer in 0..2 {
            let (outer, bs) = if layer == 0 {
                (LenStyle::ForcedLongZeroPadded, LenStyle::Canonical)
            } else {
                (LenStyle::Canonical, LenStyle::ForcedLongZeroPadded)
            };
            let der = styled_spki(
                &[0x2b, 0x65, 0x71],
                &[0x44; 127],
                outer,
                LenStyle::Canonical,
                bs,
            );
            assert_eq!(
                Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
                ImportPublicKeyError::Malformed
            );
        }
    }

    #[test]
    fn declared_long_form_length_beyond_remaining_is_malformed_with_known_oid() {
        // 各层声明的内容长度超过本容器实际剩余内容：一律 Malformed，
        // 即使 Ed448 标识完整可读，也不能先报算法不支持。

        // 外层用长形式声称 256 字节内容，实际只有一小段。
        let mut outer_over = vec![0x30, 0x82, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71];
        outer_over.extend_from_slice(&[0x03, 0x03, 0x00, 0x44, 0x44]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&outer_over).unwrap_err(),
            ImportPublicKeyError::Malformed
        );

        // 位串用长形式声称 256 字节内容，但外层只给了 10 字节实际内容——
        // 嵌套字段不能借用外层容器之后的字节补足自己声明的长度。
        // 外层内容 = 算法序列 7 + 位串头 4 + 实际位串内容 10 = 21。
        let mut inner_over =
            vec![0x30, 0x15, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x82, 0x01, 0x00];
        inner_over.extend_from_slice(&[0x00, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44]);
        assert_eq!(inner_over.len(), 2 + 21);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&inner_over).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 即使在外层之后再补 245 个“看似可借用”的字节，结果仍只能是
        // 编码损坏（完整对象后带字节先被拒绝），绝不产出算法不支持。
        let mut padded = inner_over.clone();
        padded.extend_from_slice(&[0x00; 245]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&padded).unwrap_err(),
            ImportPublicKeyError::Malformed
        );

        // 算法序列声称 32 字节内容，实际在该序列后只剩 10 字节。
        let alg_over: &[u8] = &[
            0x30, 0x0d, 0x30, 0x81, 0x20, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x04, 0x00, 0x01,
            0x02,
        ];
        assert_eq!(
            Ed25519PublicKey::from_spki_der(alg_over).unwrap_err(),
            ImportPublicKeyError::Malformed
        );

        // OID 声称 32 字节内容，算法序列内实际只有 3 字节。
        let oid_over: &[u8] = &[
            0x30, 0x0e, 0x30, 0x06, 0x06, 0x81, 0x20, 0x2b, 0x65, 0x71, 0x03, 0x04, 0x00, 0x01,
            0x02, 0x03,
        ];
        assert_eq!(
            Ed25519PublicKey::from_spki_der(oid_over).unwrap_err(),
            ImportPublicKeyError::Malformed
        );

        // 极大的声明长度（u64::MAX 与超 8 字节的长度头）也只能安静失败，
        // 不能因长度运算溢出而崩溃。
        let mut huge = vec![0x30, 0x88, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        huge.extend_from_slice(&[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&huge).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
    }

    #[test]
    fn truncated_and_trailing_bytes_around_long_form_are_malformed() {
        // 一份三层中两层（外层、位串）使用规范长形式的完整 Ed448 容器。
        let der = styled_spki(
            &[0x2b, 0x65, 0x71],
            &[0x44; 127],
            LenStyle::Canonical,
            LenStyle::Canonical,
            LenStyle::Canonical,
        );
        assert_eq!(&der[0..3], &[0x30, 0x81, 0x8a]);
        assert_eq!(&der[10..14], &[0x03, 0x81, 0x80, 0x00]);

        // 任何真前缀都不是完整对象：空输入、长度字节被截断（30 81、
        // 30 81 8a）、内容被截断等所有切点都必须报 Malformed——既不能
        // 成功，也不能因为已读到 Ed448 标识就报算法不支持，更不能崩溃。
        for cut in 0..der.len() {
            assert_eq!(
                Ed25519PublicKey::from_spki_der(&der[..cut]).unwrap_err(),
                ImportPublicKeyError::Malformed,
                "prefix of length {cut} must be Malformed"
            );
        }

        // 完整对象之后多一个字节同样拒绝。
        let mut trailing = der.clone();
        trailing.push(0x00);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&trailing).unwrap_err(),
            ImportPublicKeyError::Malformed
        );

        // 长度头声明的字节数本身还没读全。
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&[0x30, 0x82, 0x01]).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&[0x30, 0x84, 0x01, 0x00]).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
    }

    #[test]
    fn indefinite_and_too_long_length_coders_are_malformed_at_every_layer() {
        // 不定长形式（0x80）：出现在哪一层都拒绝。
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&[0x30, 0x80, 0x00, 0x00]).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 算法序列位置：外层完整，内部 30 80。
        let indefinite_alg: &[u8] = &[
            0x30, 0x0c, 0x30, 0x80, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x03, 0x00, 0xaa, 0xbb,
        ];
        assert_eq!(
            Ed25519PublicKey::from_spki_der(indefinite_alg).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 位串位置：03 80。
        let indefinite_bs: &[u8] = &[
            0x30, 0x09, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x71, 0x03, 0x80,
        ];
        assert_eq!(
            Ed25519PublicKey::from_spki_der(indefinite_bs).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
        // 长度字节数超过 8（0x89 表示 9 字节长度）直接拒绝，不崩溃。
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&[0x30, 0x89, 0x01, 0x00, 0x00]).unwrap_err(),
            ImportPublicKeyError::Malformed
        );
    }
}
