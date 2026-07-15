<div align="center">

[English](README.md) | [中文](README.cn.md)

</div>

# DID-WBA 身份认证示例

本目录只保留少量面向当前 Python DID-WBA 流程的示例。新接入应使用 e1
身份与 HTTP Message Signatures；旧 k1 和 `Authorization: DIDWba` 兼容行为
继续由 SDK 测试覆盖，不再为其维护独立可运行示例。

## 示例

| 目标 | 程序 |
|---|---|
| 创建当前 e1 DID 材料 | `create_did_document.py` |
| 校验生成的 DID 材料 | `validate_did_document.py` |
| 完整运行 e1 身份认证与 Token 复用 | `e1_authenticate_and_verify.py` |

FastAPI 中间件集成、challenge 处理、生产环境 DID 发布和配置细节请参阅
[DID_WBA_AUTH_GUIDE.md](DID_WBA_AUTH_GUIDE.md)。

## 环境准备

在源码仓库根目录运行：

```bash
uv sync
```

完整身份认证示例是自包含程序，会在临时目录生成一次性 DID 和 JWT 密钥，
不再使用仓库中旧的共享测试身份。

## 创建 e1 DID

```bash
uv run python examples/python/did_wba_examples/create_did_document.py
```

当前创建示例明确使用 `did_profile="e1"`，生成：

```text
examples/python/did_wba_examples/generated/e1/did.json
examples/python/did_wba_examples/generated/e1/key-1_private.pem
examples/python/did_wba_examples/generated/e1/key-1_public.pem
```

生成结果包含 `e1_` DID 标识、Ed25519 身份认证密钥以及
`eddsa-jcs-2022` Data Integrity proof。

## 校验 DID

```bash
uv run python examples/python/did_wba_examples/validate_did_document.py
```

## 运行完整身份认证

```bash
uv run python examples/python/did_wba_examples/e1_authenticate_and_verify.py
```

程序完整演示：

1. 创建 e1 DID 与 Ed25519 身份认证密钥。
2. 验证 DID 文档绑定关系和 proof。
3. 使用 HTTP Message Signatures 完成请求认证。
4. 签发并缓存 RS256 Bearer Token。
5. 使用缓存 Token 完成第二次请求认证。

预期输出：

```text
Created e1 DID: did:wba:example.com:agents:alice:e1_<fingerprint>
DID document proof: eddsa-jcs-2022
Request authentication: http_signatures
Issued and cached Bearer token: True
Bearer token authentication: bearer
Authenticated DID: did:wba:example.com:agents:alice:e1_<fingerprint>
```
