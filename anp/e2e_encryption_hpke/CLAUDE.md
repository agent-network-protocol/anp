# e2e_encryption_hpke/

> L2 文档 | 父级: [../CLAUDE.md](../CLAUDE.md)

1. **地位**: 基于 HPKE (RFC 9180) 的端到端加密模块，传输无关
2. **边界**: 输入为 X25519/secp256r1 密钥和协议消息 dict，输出为协议响应 dict 和加解密结果；不依赖任何传输层
3. **约束**: 字段名 snake_case、proof 类型 EcdsaSecp256r1Signature2019、DID 格式 did:wba:...

## 与 e2e_encryption_v2/ 的差异

| 维度 | e2e_encryption_v2/ | e2e_encryption_hpke/ |
|------|---------------------|----------------------|
| 密钥协商 | secp256r1 ECDHE | X25519 + HPKE (RFC 9180) |
| 初始化 | 4 步握手 | 一步初始化 (e2ee_init) |
| 密钥派生 | TLS 1.3 派生 | 链式 ratchet（消息级前向安全）|
| 群聊 E2EE | 不支持 | Sender Keys + epoch |
| 密钥分离 | 同一密钥签名+协商 | 签名(secp256r1) / 协商(X25519) 物理分离 |
| proof 签名 | W3C hash 拼接 | 直接 JCS 签名（排除 proof_value）|

## 成员清单

**models.py**: 常量、枚举（MessageType/ErrorCode/EpochReason/SeqMode）和 Pydantic 模型

**hpke.py**: HPKE Base 模式封装（RFC 9180 手动实现：X25519 + HKDF-SHA256 + AES-128-GCM）

**key_pair.py**: X25519 密钥对管理 + DID 文档公钥提取（keyAgreement/verificationMethod）

**ratchet.py**: 链式 ratchet 密钥派生（私聊 msg/ck/key/nonce 标签，群聊 gmsg/gck 标签）

**crypto.py**: AES-128-GCM 加解密（确定性 nonce，Base64 I/O）

**seq_manager.py**: 序号管理（严格/窗口模式）和防重放

**proof.py**: EcdsaSecp256r1Signature2019 proof 签名（JCS 规范化 + ECDSA-SHA256）

**message_builder.py**: 7 种消息构建函数

**message_parser.py**: 消息解析和类型检测

**session.py**: 私聊 E2EE 会话（IDLE → ACTIVE 两态状态机）

**group_session.py**: 群聊 Sender Key 会话（epoch 管理、Sender Key 分发/接收）

**key_manager.py**: 多会话密钥管理器（按 DID 对/session_id/group_did 索引）

**__init__.py**: 模块公共 API 统一导出

## 复用的外部函数

| 函数 | 来源 | 用途 |
|------|------|------|
| `generate_random_hex` | `anp.utils.crypto_tool` | 生成 session_id |
| `jcs.canonicalize` | `jcs` 库 | proof 签名 JCS 规范化 |

## 协议规范

09-ANP-端到端即时消息协议规范.md

⚡触发器: 一旦本文件夹增删文件或架构逻辑调整，请立即重写此文档。
