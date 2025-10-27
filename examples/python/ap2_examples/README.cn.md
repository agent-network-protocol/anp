# AP2 协议示例

本目录包含 AP2（智能体支付协议）实现的示例代码。

## 概述

AP2 是基于 ANP（智能体协商协议）构建的协议，用于智能体之间的安全支付和交易流程。支持多种签名算法，包括 RS256 和 ES256K。

## 示例列表

### ES256K 示例

**文件**: `es256k_example.py`

演示如何使用 ES256K（基于 secp256k1 曲线的 ECDSA）算法对 CartMandate 和 PaymentMandate 进行签名。这对于区块链和加密货币应用特别有用。

**运行**:
```bash
uv run python examples/python/ap2_examples/es256k_example.py
```

**功能特性**:
- 生成 ES256K (secp256k1) 密钥对
- 使用 ES256K 签名构建 CartMandate
- 使用 ES256K 验证 CartMandate
- 使用 ES256K 签名构建 PaymentMandate
- 使用 ES256K 验证 PaymentMandate

**适用场景**:
- 基于区块链的支付系统
- 加密货币交易
- 与比特币/以太坊生态系统集成
- 需要较小签名大小的应用

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

