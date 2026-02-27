# E2EE V2 (端到端加密 V2) 示例

本目录包含 `anp.e2e_encryption_v2` 模块的使用示例，演示基于 ECDHE 的端到端加密会话建立、加密通信和密钥生命周期管理。

## 概述

E2EE V2 是 ANP 协议的端到端加密层实现，具有以下特点：

- **传输无关** -- 所有方法只接收和返回 `dict`，不直接发送网络请求
- **ECDHE 密钥交换** -- 使用 secp256r1 椭圆曲线进行临时密钥协商
- **AES-128-GCM** -- 使用 TLS 1.3 风格的密钥派生和对称加密
- **DID 身份绑定** -- 基于 `did:wba` 标准进行身份认证和签名

## 示例文件

| 文件 | 说明 | 难度 |
|------|------|------|
| `basic_handshake.py` | 完整握手 + 双向加密通信 | 入门 |
| `key_manager_example.py` | E2eeKeyManager 多会话生命周期管理 | 进阶 |
| `error_handling_example.py` | 异常场景处理（过期、错误密钥、状态违规） | 进阶 |

## 运行方式

所有示例均为自包含的离线脚本，不依赖网络或外部文件。

```bash
# 基础握手示例
uv run python examples/python/e2e_encryption_v2_examples/basic_handshake.py

# KeyManager 生命周期管理示例
uv run python examples/python/e2e_encryption_v2_examples/key_manager_example.py

# 错误处理示例
uv run python examples/python/e2e_encryption_v2_examples/error_handling_example.py
```

## 核心概念

### 握手流程

```
Alice (initiator)                          Bob (responder)
     |                                          |
     |  1. initiate_handshake()                 |
     |     -> SourceHello                       |
     |  ---------------------------------------->
     |                                          |
     |                 2. process_source_hello() |
     |            DestinationHello + Finished <- |
     |  <----------------------------------------
     |                                          |
     |  3. process_destination_hello()          |
     |     -> Finished                          |
     |  ---------------------------------------->
     |                                          |
     |  4. process_finished()                   |  4. process_finished()
     |     状态 -> ACTIVE                       |     状态 -> ACTIVE
     |                                          |
```

### 会话状态机

```
IDLE -> HANDSHAKE_INITIATED -> HANDSHAKE_COMPLETING -> ACTIVE
```

- **IDLE**: 初始状态，可发起握手或接收 SourceHello
- **HANDSHAKE_INITIATED**: 已发送 SourceHello，等待 DestinationHello
- **HANDSHAKE_COMPLETING**: 已交换 Hello，等待对方 Finished
- **ACTIVE**: 握手完成，可进行加密/解密通信

### E2eeKeyManager

管理多个并发会话的密钥生命周期：

- `register_pending_session()` -- 注册握手中的会话
- `promote_pending_session()` -- 握手完成后提升为 active
- `get_active_session(local_did, peer_did)` -- 按 DID 对查找
- `get_session_by_key_id(secret_key_id)` -- 按密钥 ID 查找
- `cleanup_expired()` -- 清理过期会话

## 依赖

所有示例仅依赖项目核心依赖：

- `cryptography` -- 密码学原语（ECDHE、AES-GCM）
- `pydantic` -- 数据模型验证

无需额外安装任何可选依赖。

## 相关资源

- [E2EE V2 模块源码](../../../anp/e2e_encryption_v2/)
- [E2EE V2 单元测试](../../../anp/unittest/e2e_v2/)
- [ANP 协议白皮书](../../../../AgentNetworkProtocol/01-agentnetworkprotocol-technical-white-paper.md)
