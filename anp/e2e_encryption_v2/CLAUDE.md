# e2e_encryption_v2/

> L2 文档 | 父级: [../CLAUDE.md](../CLAUDE.md) | 分形协议: 三层结构

1. **地位**: 端到端加密 V2 模块，传输无关，与传输层完全解耦
2. **边界**: 输入为 DID 密钥和协议消息 dict，输出为协议响应 dict 和加解密结果；不依赖任何传输层
3. **约束**: 字段名 snake_case、proof 类型 EcdsaSecp256r1Signature2019、DID 格式 did:wba:...

## 成员清单

**models.py**: Pydantic 数据模型和枚举（MessageType、E2eeType、ErrorCode、各消息 Content 模型）

**message_builder.py**: 消息构建函数，接收参数返回 dict（build_source_hello / build_destination_hello / build_finished / build_encrypted_message / build_error）

**message_parser.py**: 消息解析与验证（detect_message_type / parse_* / verify_hello_proof / decrypt_message）

**session.py**: E2EE 会话管理核心（E2eeSession 状态机：IDLE → HANDSHAKE_INITIATED → HANDSHAKE_COMPLETING → ACTIVE）

**key_manager.py**: 多会话密钥管理（E2eeKeyManager：按 DID 对 / secret_key_id / session_id 索引）

**__init__.py**: 模块公共 API 统一导出

## 与 e2e_encryption/ 的差异

| 维度 | e2e_encryption/ | e2e_encryption_v2/ |
|------|----------------|---------------------|
| 传输层 | WebSocket（强耦合） | 无（返回 dict） |
| 字段命名 | camelCase | snake_case |
| DID 格式 | did:anp:... | did:wba:... |
| proof 类型 | EcdsaSecp256k1Signature2019 | EcdsaSecp256r1Signature2019 |
| 消息类型 | sourceHello/destinationHello/finished/message | e2ee_hello/e2ee_finished/e2ee/e2ee_error |

## 复用的 crypto_tool.py 函数

generate_random_hex, generate_ec_key_pair, get_hex_from_public_key, get_public_key_from_hex,
load_private_key_from_pem, get_pem_from_private_key, generate_shared_secret, derive_tls13_data_keys,
get_key_length_from_cipher_suite, generate_16_char_from_random_num, encrypt_aes_gcm_sha256,
decrypt_aes_gcm_sha256, generate_signature_for_json, verify_signature_for_json

⚡触发器: 一旦本文件夹增删文件或架构逻辑调整，请立即重写此文档。
