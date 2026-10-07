//! DER 长度编码对公钥导入分类的回归保障（只走库的公开入口）。
//!
//! 导入入口把输入分为两类失败：编码损坏是 [`ImportPublicKeyError::Malformed`]，
//! 结构合法但算法不是 Ed25519 是 [`ImportPublicKeyError::UnsupportedAlgorithm`]。
//! 本文件守住的是：容器变大、长度字段从短形式转为长形式（内容达到 128 字节
//! 后采用最短长形式仍是规范 DER）时，这种区分不变——
//!
//! * 外层容器、算法标识序列、公钥位串三个位置都允许规范的长形式；
//!   127 与 128 字节两侧的分类原则一致。
//! * 其他算法的完整容器（参数缺省、未使用位数为零、各层内容完整）报算法
//!   不支持，错误携带的算法标识保留全部数值与次序；公钥内容超过 32 字节
//!   本身不触发 Ed25519 专属的长度限制。
//! * 冗余前导零、能用短形式却写成长形式、声明长度超过所在容器剩余内容，
//!   都是编码损坏；嵌套字段不能借用外层之后的字节。即使已读到其他算法
//!   标识，内部长度不合法、输入截断或完整对象后还有字节，也一律报
//!   编码损坏而不是算法不支持。

use inkseal::{Ed25519PublicKey, ImportPublicKeyError};

/// Ed25519 的算法标识 1.3.101.112 的 OID 内容字节。
const ED25519_OID: &[u8] = &[0x2b, 0x65, 0x70];
/// Ed448 的算法标识 1.3.101.113 的 OID 内容字节。
const ED448_OID: &[u8] = &[0x2b, 0x65, 0x71];

/// RFC 8410 第 4 节的 Ed25519 公钥示例（SubjectPublicKeyInfo 的 DER 编码）。
const RFC8410_SPKI: &[u8] = &[
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0xd7, 0x5a, 0x98,
    0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1,
    0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// 同一示例的公钥原文（32 字节）的十六进制文本。
const RFC8410_KEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// 按规范 DER 编码一个 TLV：内容不足 128 字节用短形式，否则用最短长形式。
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if content.len() < 128 {
        out.push(content.len() as u8);
    } else {
        let len_bytes = content.len().to_be_bytes();
        let first = len_bytes.iter().position(|&b| b != 0).unwrap();
        let significant = &len_bytes[first..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(content);
    out
}

/// 由算法 OID 内容字节与任意长度公钥拼装一份规范编码的 SPKI：
/// 算法参数缺省，位串未使用位数为零，各层长度按内容大小选择
/// 短形式或最短长形式。
fn spki_der(oid_content: &[u8], key: &[u8]) -> Vec<u8> {
    let algorithm = tlv(0x30, &tlv(0x06, oid_content));
    let mut bit_string_content = vec![0x00];
    bit_string_content.extend_from_slice(key);
    let bit_string = tlv(0x03, &bit_string_content);
    let mut spki_content = algorithm;
    spki_content.extend_from_slice(&bit_string);
    tlv(0x30, &spki_content)
}

/// 把数值按 base-128 最短形式编码为一个 OID 子标识符，追加到 `out`。
fn push_subidentifier(out: &mut Vec<u8>, mut value: u64) {
    let mut groups = [0u8; 10]; // u64 最多需要 ceil(64/7) = 10 组
    let mut start = groups.len();
    loop {
        start -= 1;
        groups[start] = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            break;
        }
    }
    let end = groups.len() - 1;
    for b in &mut groups[start..end] {
        *b |= 0x80;
    }
    out.extend_from_slice(&groups[start..]);
}

/// 由各段弧构造 OID 内容字节（第一个子标识符合并编码前两段）。
fn oid_content(arcs: &[u64]) -> Vec<u8> {
    assert!(arcs.len() >= 2);
    let mut content = Vec::new();
    push_subidentifier(&mut content, arcs[0] * 40 + arcs[1]);
    for &arc in &arcs[2..] {
        push_subidentifier(&mut content, arc);
    }
    content
}

/// 断言输入报算法不支持，并返回错误供进一步检查标识。
fn expect_unsupported(der: &[u8]) -> ImportPublicKeyError {
    match Ed25519PublicKey::from_spki_der(der) {
        Err(err @ ImportPublicKeyError::UnsupportedAlgorithm(_)) => err,
        other => panic!("expected UnsupportedAlgorithm, got {other:?}"),
    }
}

/// 断言错误携带的算法标识与预期各段弧完全一致（数值与次序），
/// 且点分显示完整、不丢末尾部分。
fn assert_oid(err: &ImportPublicKeyError, expected_arcs: &[u64]) {
    let ImportPublicKeyError::UnsupportedAlgorithm(oid) = err else {
        panic!("expected UnsupportedAlgorithm, got {err:?}");
    };
    assert_eq!(oid.arcs(), expected_arcs);
    let dotted = expected_arcs
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".");
    assert_eq!(oid.to_string(), dotted);
    assert!(err.to_string().contains(&dotted));
}

#[test]
fn canonical_small_ed25519_container_still_imports() {
    // 既有接受格式保持兼容：规范的 Ed25519 小容器（全程短形式长度）。
    let key = Ed25519PublicKey::from_spki_der(RFC8410_SPKI).unwrap();
    assert_eq!(key.as_bytes(), &RFC8410_SPKI[12..]);
    assert_eq!(key.to_hex(), RFC8410_KEY_HEX);
    assert_eq!(key.to_hex().len(), 64);
    assert!(key
        .to_hex()
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
}

#[test]
fn long_form_container_with_foreign_algorithm_is_unsupported_not_malformed() {
    // 公钥 200 字节的其他算法容器：位串内容 201 字节、外层内容 211 字节，
    // 两层都以最短长形式编码——这仍是规范 DER。
    let der = spki_der(ED448_OID, &[0x44; 200]);

    // 独立核对构造的字节：外层 30 81 d3，算法序列短形式，位串 03 81 c9。
    assert_eq!(der[1], 0x81, "outer length must use long form: {der:02x?}");
    assert_eq!(der[2], 0xd3);
    assert_eq!(der[3], 0x30);
    assert_eq!(der[4], 0x05, "algorithm sequence stays short form");
    assert_eq!(&der[10..13], &[0x03, 0x81, 0xc9]);

    // 容器变大、长度转为长形式不改变分类：合法的其他算法容器报算法
    // 不支持，而不是把合法的长形式说成编码损坏；公钥内容超过 32 字节
    // 本身不触发 Ed25519 专属的长度限制。
    let err = expect_unsupported(&der);
    assert_oid(&err, &[1, 3, 101, 113]);
}

#[test]
fn long_form_is_accepted_at_outer_algorithm_and_bit_string_positions() {
    // 仅外层长形式：位串内容 127 字节仍是短形式，外层内容 136 字节是长形式。
    let der = spki_der(ED448_OID, &[0x44; 126]);
    assert_eq!(&der[..3], &[0x30, 0x81, 0x88]);
    assert_eq!(&der[10..12], &[0x03, 0x7f], "bit string stays short form");
    assert_oid(&expect_unsupported(&der), &[1, 3, 101, 113]);

    // 位串长形式：位串内容 128 字节（1 字节未使用位数 + 127 字节公钥）。
    let der = spki_der(ED448_OID, &[0x44; 127]);
    assert_eq!(&der[10..13], &[0x03, 0x81, 0x80]);
    assert_oid(&expect_unsupported(&der), &[1, 3, 101, 113]);

    // 算法标识序列长形式：OID 内容 126 字节，算法序列内容恰好 128 字节。
    // 标识本身很长（2.999.3.7.7…），用来同时核对错误携带的标识完整。
    let mut arcs = vec![2, 999, 3];
    arcs.extend_from_slice(&[7; 123]);
    let oid = oid_content(&arcs);
    assert_eq!(oid.len(), 126);
    let der = spki_der(&oid, &[0x42; 32]);
    assert_eq!(&der[3..6], &[0x30, 0x81, 0x80], "algorithm sequence long form");
    assert_eq!(der[6], 0x06);
    assert_eq!(der[7], 0x7e, "OID content is 126 bytes, short form");

    // 错误携带的算法标识保留全部数值与次序，点分显示不丢末尾部分。
    let err = expect_unsupported(&der);
    assert_oid(&err, &arcs);
    let dotted = arcs.iter().map(u64::to_string).collect::<Vec<_>>().join(".");
    assert!(dotted.ends_with(".7"));
    assert!(err.to_string().contains(&dotted));
}

#[test]
fn boundary_127_and_128_bytes_classify_consistently() {
    // 位串内容 127（短形式）与 128（长形式）两侧：同一分类原则。
    for key_len in [126usize, 127] {
        let der = spki_der(ED448_OID, &vec![0x44; key_len]);
        assert_oid(&expect_unsupported(&der), &[1, 3, 101, 113]);
    }

    // 外层内容 127（短形式）与 128（长形式）两侧：同一分类原则。
    // 外层内容 = 算法序列 7 字节 + 位串（2 字节头 + 1 字节未使用位数 + 公钥）。
    let der127 = spki_der(ED448_OID, &[0x44; 117]);
    assert_eq!(der127[1], 0x7f, "outer content is exactly 127, short form");
    assert_oid(&expect_unsupported(&der127), &[1, 3, 101, 113]);

    let der128 = spki_der(ED448_OID, &[0x44; 118]);
    assert_eq!(&der128[..3], &[0x30, 0x81, 0x80], "outer content 128, long form");
    assert_oid(&expect_unsupported(&der128), &[1, 3, 101, 113]);
}

#[test]
fn ed25519_key_length_rule_applies_only_after_algorithm_is_confirmed() {
    // 算法确为 Ed25519：公钥内容不足或超过 32 字节都是编码损坏，
    // 即使容器其余部分的规范长形式完全合法，也不截短或补齐。
    for key_len in [31usize, 33, 200] {
        let der = spki_der(ED25519_OID, &vec![0x22; key_len]);
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&der).unwrap_err(),
            ImportPublicKeyError::Malformed,
            "Ed25519 key of {key_len} bytes must be Malformed"
        );
    }
    // 同样的公钥长度放在其他算法标识下：只是算法不支持。
    for key_len in [31usize, 33, 200] {
        let der = spki_der(ED448_OID, &vec![0x44; key_len]);
        assert_oid(&expect_unsupported(&der), &[1, 3, 101, 113]);
    }
}

#[test]
fn non_canonical_long_form_lengths_are_malformed() {
    let valid = spki_der(ED448_OID, &[0x44; 200]);
    assert_eq!(&valid[..3], &[0x30, 0x81, 0xd3]);

    // 长形式带冗余前导零字节：0x82 0x00 0xd3。
    let mut leading_zero = vec![0x30, 0x82, 0x00, 0xd3];
    leading_zero.extend_from_slice(&valid[3..]);
    assert_eq!(
        Ed25519PublicKey::from_spki_der(&leading_zero).unwrap_err(),
        ImportPublicKeyError::Malformed
    );

    // 能用短形式却写成长形式：位串内容 64 字节写成 0x81 0x40。
    let mut long_for_short = tlv(0x30, &tlv(0x30, &tlv(0x06, ED448_OID)));
    let mut bs = vec![0x03, 0x81, 0x40, 0x00];
    bs.extend_from_slice(&[0x44; 63]);
    let bs_len = bs.len();
    long_for_short.extend_from_slice(&bs);
    // 修正外层长度（外层内容 = 算法序列 7 + 位串全部字节）。
    long_for_short[1] = (7 + bs_len) as u8;
    assert_eq!(
        Ed25519PublicKey::from_spki_der(&long_for_short).unwrap_err(),
        ImportPublicKeyError::Malformed
    );

    // 边界：127 字节本可用短形式（0x7f），写成 0x81 0x7f 同样非规范。
    // 外层内容 = 算法序列 7 字节 + 位串 TLV（3 字节头 + 127 字节内容）。
    let mut boundary = vec![0x30, 0x81, 0x89];
    boundary.extend_from_slice(&valid[3..10]); // 算法序列原样（短形式）
    boundary.extend_from_slice(&[0x03, 0x81, 0x7f, 0x00]);
    boundary.extend_from_slice(&[0x44; 126]);
    assert_eq!(
        Ed25519PublicKey::from_spki_der(&boundary).unwrap_err(),
        ImportPublicKeyError::Malformed
    );

    // 声明的内容长度超过所在容器实际剩余内容：外层多报 1 字节。
    let mut overdeclared = valid.clone();
    overdeclared[2] = 0xd4;
    assert_eq!(
        Ed25519PublicKey::from_spki_der(&overdeclared).unwrap_err(),
        ImportPublicKeyError::Malformed
    );
}

#[test]
fn nested_field_cannot_borrow_bytes_beyond_its_container() {
    // 规范的长形式容器：外层内容 211 字节，位串声明内容 201 字节。
    let valid = spki_der(ED448_OID, &[0x44; 200]);

    // 位串多报 1 字节内容（202），并在整个对象之后补上这 1 字节：
    // 输入里这些字节确实存在，但位于外层容器声明的内容之外——
    // 嵌套字段不能借用外层之后的字节补足自己声明的长度。
    let mut borrowing = valid.clone();
    borrowing[12] = 0xca; // 位串内容 201 → 202
    borrowing.push(0x00); // 字节补在外层容器之外
    assert_eq!(
        Ed25519PublicKey::from_spki_der(&borrowing).unwrap_err(),
        ImportPublicKeyError::Malformed
    );
}

#[test]
fn foreign_oid_seen_but_corrupt_structure_is_malformed_not_unsupported() {
    // 完整、规范的长形式 Ed448 容器作为对照。
    let valid = spki_der(ED448_OID, &[0x44; 200]);
    assert_oid(&expect_unsupported(&valid), &[1, 3, 101, 113]);

    // 截断：即使已能读到 Ed448 标识，输入不完整就是编码损坏。
    for cut in [2, 10, 100, valid.len() - 1] {
        assert_eq!(
            Ed25519PublicKey::from_spki_der(&valid[..cut]).unwrap_err(),
            ImportPublicKeyError::Malformed,
            "truncated at {cut}"
        );
    }

    // 完整对象之后还有字节。
    let mut trailing = valid.clone();
    trailing.push(0x00);
    assert_eq!(
        Ed25519PublicKey::from_spki_der(&trailing).unwrap_err(),
        ImportPublicKeyError::Malformed
    );

    // 内部长度不合法：位串长形式带冗余前导零（0x82 0x00 0xc9）。
    let mut bad_inner = valid.clone();
    bad_inner.splice(11..13, [0x82, 0x00, 0xc9]);
    assert_eq!(
        Ed25519PublicKey::from_spki_der(&bad_inner).unwrap_err(),
        ImportPublicKeyError::Malformed
    );

    // 位串未使用位数非零：与算法无关的结构约束。
    let mut bad_bits = valid.clone();
    bad_bits[13] = 0x07;
    assert_eq!(
        Ed25519PublicKey::from_spki_der(&bad_bits).unwrap_err(),
        ImportPublicKeyError::Malformed
    );
}
