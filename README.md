# inkseal

当前版本提供命令行版本查询，以及对单个文件计算 SHA-256 摘要的功能。

## 构建与运行

```sh
cargo build --offline
./target/debug/inkseal --version
```

输出：

```text
inkseal 0.1.0
```

`--version` 必须单独使用；不带参数或附带多余参数都属于用法错误。

## 文件摘要

使用 `digest` 子命令对单个文件计算 SHA-256 摘要：

```sh
./target/debug/inkseal digest <文件路径>
```

成功时在标准输出写出恰好 64 个小写十六进制字符并以换行结束，退出码为 0：

```sh
$ ./target/debug/inkseal digest message.txt
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

输出不附带文件名或任何标签，便于直接保存或与其他工具的结果逐字比较。

摘要只取决于文件的原始字节：

- 不包含文件名、路径或时间信息；相同内容存放在不同位置得到相同结果。
- 不做文本解码或换行转换，零字节、非 UTF-8 数据和不同换行形式（LF、CRLF 等）都原样参与计算。
- 空文件是合法输入，得到标准空字节序列的 SHA-256 摘要 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`。
- 以流式方式读取，内存占用不随文件大小增长。
- 每次调用只处理一个文件。

### 失败与退出状态

| 情况 | 退出码 | 输出位置 | 内容 |
| --- | --- | --- | --- |
| 成功 | 0 | 标准输出 | 64 个小写十六进制字符 + 换行 |
| 文件不存在、无法打开、路径指向目录或读取中途失败 | 1 | 标准错误 | 说明原因并指出出错路径；标准输出保持为空 |
| 缺少文件路径、给出多个路径或使用未知子命令 | 2 | 标准错误 | 仅输出用法提示 |

即使已经读取了部分内容，读取中途失败也不会输出部分内容的摘要。路径中的空格和非 ASCII 字符按实际路径处理，例如：

```sh
./target/debug/inkseal digest "合同 文件.txt"
```

用法提示为：

```text
Usage: inkseal --version
       inkseal digest <file path>
```

## 库接口

inkseal 同时提供公开的 Rust 库接口，可对任何实现 `std::io::Read` 的输入计算与命令行完全一致的摘要：

```rust
use inkseal::digest_reader;

let digest = digest_reader(&b"abc"[..])?;
assert_eq!(
    digest.to_hex(),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
);
```

- `digest_reader(reader)` 以流式方式读取并返回 `Result<Digest, DigestError>`。
- `Digest` 是明确的摘要类型，可通过 `to_hex()`（或 `Display`）得到与命令行一致的 64 字符小写十六进制文本，也可通过 `as_bytes()` 取得 32 字节结果。
- 读取失败时返回类型化错误 `DigestError`，可通过 `io_error()` 取得底层的 `std::io::Error`，不会被当作成功摘要。

密码运算使用成熟的 [`sha2`](https://crates.io/crates/sha2) 库。
