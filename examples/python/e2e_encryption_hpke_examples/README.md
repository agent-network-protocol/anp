# E2EE HPKE (端到端加密 HPKE) 示例

本目录包含 `anp.e2e_encryption_hpke` 模块的使用示例，演示基于 HPKE (RFC 9180) 的端到端加密会话建立、私聊/群聊加密通信和密钥生命周期管理。

## 概述

E2EE HPKE 是 ANP 协议的新一代端到端加密实现，相比 E2EE V2 具有以下特点：

- **一步初始化** -- 无需多轮握手，发起方发送 `e2ee_init` 后双方立即进入 ACTIVE 状态
- **链式 Ratchet** -- 消息级前向安全，每条消息使用独立的加密密钥
- **群聊支持** -- 基于 Sender Key 的群聊 E2EE，支持 epoch 管理和密钥轮转
- **密钥分离** -- 签名密钥 (secp256r1) 和密钥协商 (X25519) 物理分离
- **传输无关** -- 所有方法只接收和返回 `dict`，不直接发送网络请求

## 示例文件

| 文件 | 说明 | 难度 |
|------|------|------|
| `basic_private_chat.py` | 一步初始化 + 双向加密 + Rekey | 入门 |
| `group_chat_example.py` | 三方群聊 Sender Key + Epoch 推进 | 进阶 |
| `key_manager_example.py` | HpkeKeyManager 多会话生命周期管理 | 进阶 |
| `error_handling_example.py` | 异常场景处理（过期、错误密钥、重放） | 进阶 |

## 运行方式

所有示例均为自包含的离线脚本，不依赖网络或外部文件。

```bash
# 基础私聊示例
uv run python examples/python/e2e_encryption_hpke_examples/basic_private_chat.py

# 群聊示例
uv run python examples/python/e2e_encryption_hpke_examples/group_chat_example.py

# KeyManager 生命周期管理示例
uv run python examples/python/e2e_encryption_hpke_examples/key_manager_example.py

# 错误处理示例
uv run python examples/python/e2e_encryption_hpke_examples/error_handling_example.py
```

## 核心概念

### 私聊初始化流程

```
Alice (initiator)                          Bob (responder)
     |                                          |
     |  1. initiate_session()                   |
     |     -> e2ee_init                         |
     |  ---------------------------------------->
     |                                          |
     |                 2. process_init()         |
     |                    状态 -> ACTIVE         |
     |                                          |
     |     Alice 状态也已 ACTIVE                |
     |                                          |
     |  3. encrypt_message / decrypt_message    |
     |  <--------------------------------------->
     |                                          |
```

### 群聊 Sender Key 流程

```
Alice (sender)                  Bob / Charlie (receivers)
     |                                    |
     |  1. generate_sender_key()          |
     |                                    |
     |  2. build_sender_key_distribution()|
     |     -> group_e2ee_key              |
     |  ---------------------------------->
     |                                    |
     |              3. process_sender_key()|
     |                                    |
     |  4. encrypt_group_message()        |
     |     -> group_e2ee_msg              |
     |  ---------------------------------->
     |                                    |
     |          5. decrypt_group_message() |
     |                                    |
```

### 会话状态机

```
私聊：IDLE -> ACTIVE（一步初始化）
群聊：通过 Sender Key 分发激活，epoch 推进后需重新分发
```

- **IDLE**: 初始状态，可发起初始化或接收 e2ee_init
- **ACTIVE**: 初始化完成，可进行加密/解密通信

### HpkeKeyManager

管理多个并发的私聊和群聊会话：

- `register_session()` / `register_group_session()` -- 注册会话
- `get_active_session(local_did, peer_did)` -- 按 DID 对查找私聊会话
- `get_session_by_id(session_id)` -- 按 session_id 查找（用于消息路由）
- `get_group_session(group_did)` -- 按 group_did 查找群聊会话
- `cleanup_expired()` -- 清理过期会话

## 依赖

所有示例仅依赖项目核心依赖：

- `cryptography` -- 密码学原语（X25519、ECDSA、AES-GCM、HKDF）
- `pydantic` -- 数据模型验证
- `jcs` -- JSON Canonicalization Scheme（proof 签名）

无需额外安装任何可选依赖。

## 相关资源

- [E2EE HPKE 模块源码](../../../anp/e2e_encryption_hpke/)
- [E2EE HPKE 单元测试](../../../anp/unittest/e2e_hpke/)
- [E2EE V2 示例（对比参考）](../e2e_encryption_v2_examples/)
- [ANP 协议白皮书](../../../../AgentNetworkProtocol/01-agentnetworkprotocol-technical-white-paper.md)
