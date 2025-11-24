# AP2 协议示例

本目录包含 AP2（智能体支付协议）实现的示例代码。

## 概述

AP2 是基于 ANP（智能体协商协议）构建的协议，用于智能体之间的安全支付和交易流程。支持多种签名算法，包括 RS256 和 ES256K。

## 示例列表

### 完整流程（单进程）

**文件**: `ap2_complete_flow.py`

同时启动商户服务与购物者客户端，快速回放从 CartMandate 创建到收据发放的完整 AP2 流程。

**运行**:
```bash
uv run python examples/python/ap2_examples/ap2_complete_flow.py
```

### 独立商户 & 购物者（双进程）

**文件**: `merchant_server.py`, `shopper_client.py`

将职责拆分成两个独立进程，便于分别调试 HTTP API、部署到不同主机或演示真实网络交互。

**运行步骤**:
1. 终端 A：启动商户服务（默认绑定本机 IP）
   ```bash
   uv run python examples/python/ap2_examples/merchant_server.py
   ```
   可选参数：`--host 0.0.0.0`、`--port 8889`

2. 终端 B：启动购物者客户端，并指向商户 URL
   ```bash
   uv run python examples/python/ap2_examples/shopper_client.py \
     --merchant-url http://<merchant-host>:<port> \
     --merchant-did did:wba:didhost.cc:public
   ```
   若使用仓库内置的公用 DID/证书，上述参数可省略，默认即为本地演示配置。

### Agent 级积木

**文件**: `merchant_agent.py`, `shopper_agent.py`

封装了常用的构建/验证逻辑，不包含 HTTP 服务。可在更复杂的集成场景或测试中直接复用。

## 支持的算法

| 算法 | 描述 | 密钥类型 | 签名大小 | 使用场景 |
|------|------|----------|----------|----------|
| **RS256** | 使用 SHA-256 的 RSASSA-PKCS1-v1_5 | RSA (2048+ 位) | ~256 字节 | 通用场景 |
| **ES256K** | 使用 secp256k1 和 SHA-256 的 ECDSA | EC (secp256k1) | ~70 字节 | 区块链/加密货币 |

## 核心组件

### CartMandate（购物车授权）
- 包含购物车信息
- 由商户使用 `merchant_authorization` 签名
- 包含二维码支付数据
- 由购物者验证

### PaymentMandate（支付授权）
- 包含支付确认信息
- 由用户使用 `user_authorization` 签名
- 通过 `cart_hash` 引用 CartMandate
- 由商户验证

## 依赖项

所有示例需要：
- `pyjwt` - JWT 编码/解码
- `cryptography` - 加密原语
- `pydantic` - 数据验证

这些依赖已包含在项目依赖中。

## 扩展阅读

- [ES256K 支持文档](../../../docs/ap2/ES256K_SUPPORT.md)
- [AP2 协议规范](../../../docs/ap2/流程整理.md)
- [ANP 协议](../../../README.cn.md)

## 贡献指南

添加新示例时：
1. 遵循现有代码结构
2. 包含详细注释
3. 添加错误处理
4. 更新本 README
5. 提交前测试示例

