<div align="center">

[English](README.md) | [中文](README.cn.md)

</div>

# AP2 协议工具

本模块提供一组正交工具，用于构建和验证 AP2 协议数据结构，如 `CartMandate`（购物车授权）、`PaymentMandate`（支付授权）和收据凭证。

## 核心原则

本库遵循以下设计原则：

- **坚实的基础**：优先考虑可靠性和正确性。基于 `pydantic` 实现健壮的数据验证。
- **可扩展架构**：数据模型和函数设计为可组合，便于开发者构建复杂工作流。
- **API 正交性**：每个组件职责清晰。`cart_mandate` 工具处理购物车逻辑，`payment_mandate` 处理支付授权，`credential_mandate` 处理收据签发。
- **清晰的文档**：所有主要函数和模型都有详细文档。

## 使用方法

主要工作流涉及两方："购物者"和"商户"。流程如下：

1. 购物者向商户请求 `CartMandate`
2. 商户创建并签名 `CartMandate` 返回
3. 购物者验证 `CartMandate`，然后创建并签名包含原始购物车哈希的 `PaymentMandate`
4. 商户接收并验证 `PaymentMandate`，确认支付授权
5. 商户签发 `PaymentReceipt` 凭证给购物者
6. 购物者验证 `PaymentReceipt` 确保真实性

### 核心组件

模块提供三种主要组件：

- **数据模型**：`pydantic` 模型，表示核心数据结构（如 `CartMandate`、`PaymentMandateContents`、`PaymentReceipt`）
- **构建器**：构建和签名授权及凭证的函数（如 `build_cart_mandate`、`build_payment_receipt`）
- **验证器**：验证完整性和签名的函数（如 `validate_payment_mandate`、`validate_credential`）

### 示例：创建和验证完整流程

此示例演示从购物车创建到收据签发的完整交互流程。

```python
import json
from datetime import datetime, timezone

# 密钥加载辅助函数（实际应用中请安全管理这些密钥）
from anp.utils.crypto_tool import load_private_key_from_string
# 导入模型、构建器和验证器
from anp.ap2.models import (
    CartContents,
    CartMandate,
    MoneyAmount,
    PaymentDetails,
    PaymentDetailsTotal,
    PaymentMandateContents,
    PaymentReceiptContents,
    PaymentRequest,
    PaymentResponse,
    PaymentResponseDetails,
    PaymentStatus,
)
from anp.ap2.cart_mandate import build_cart_mandate, validate_cart_mandate
from anp.ap2.credential_mandate import build_payment_receipt, validate_credential
from anp.ap2.payment_mandate import build_payment_mandate, validate_payment_mandate
from anp.ap2.mandate import compute_hash

# --- 0. 设置：DID 和密钥 ---
# 在实际系统中，这些对每一方都是唯一的。
# 为简化示例，我们重用相同的密钥。
private_key_pem = ""
public_key_pem = ""

shopper_did = "did:wba:example:shopper"
merchant_did = "did:wba:example:merchant"
shopper_kid = "shopper-key-1"
merchant_kid = "merchant-key-1"
algorithm = "ES256K"
# 凭证使用 RS256（参见 credential_mandate.py）
credential_algorithm = "RS256"


# --- 1. 商户：创建购物车授权 ---
# 商户定义购物车内容
cart_contents = CartContents(
    id="cart-123",
    payment_request=PaymentRequest(
        details=PaymentDetails(
            id="order-456",
            total=PaymentDetailsTotal(
                label="总计",
                amount=MoneyAmount(currency="CNY", value=100.00),
            ),
        )
    ),
)

# 商户签名购物车内容以创建安全的 CartMandate
cart_mandate = build_cart_mandate(
    contents=cart_contents,
    merchant_private_key=private_key_pem,
    merchant_did=merchant_did,
    merchant_kid=merchant_kid,
    shopper_did=shopper_did,
    algorithm=algorithm,
)

print("[商户] CartMandate 已创建。")

# --- 2. 购物者：验证购物车授权 ---
# 购物者接收 CartMandate 并验证其真实性
validate_cart_mandate(
    cart_mandate=cart_mandate,
    merchant_public_key=public_key_pem,
    merchant_algorithm=algorithm,
    expected_shopper_did=shopper_did,
)
print("[购物者] CartMandate 验证成功。")

# 购物者计算购物车内容的哈希，用于下一步
cart_hash = compute_hash(cart_mandate.contents.model_dump(exclude_none=True))
print(f"[购物者] 购物车哈希: {cart_hash[:32]}...")


# --- 3. 购物者：创建支付授权 ---
# 购物者创建支付授权，通过哈希链接到购物车
payment_mandate_contents = PaymentMandateContents(
    payment_mandate_id="pm-789",
    payment_details_id=cart_mandate.contents.payment_request.details.id,
    payment_details_total=cart_mandate.contents.payment_request.details.total,
    payment_response=PaymentResponse(
        request_id=cart_mandate.contents.payment_request.details.id,
        method_name="EXAMPLE_PAY",
        details=PaymentResponseDetails(channel="mock_channel"),
    ),
    cart_hash=cart_hash,  # 链接支付到购物车
)

# 购物者签名支付授权
payment_mandate = build_payment_mandate(
    contents=payment_mandate_contents,
    user_private_key=private_key_pem,
    user_did=shopper_did,
    user_kid=shopper_kid,
    merchant_did=merchant_did,
    algorithm=algorithm,
)
print("[购物者] PaymentMandate 已创建。")


# --- 4. 商户：验证支付授权 ---
# 此检查确保支付针对正确的、未修改的购物车
if not validate_payment_mandate(
    payment_mandate=payment_mandate,
    shopper_public_key=public_key_pem,
    shopper_algorithm=algorithm,
    expected_merchant_did=merchant_did,
    expected_cart_hash=cart_hash,
):
    raise ValueError("PaymentMandate 验证失败")
print("[商户] PaymentMandate 验证成功。")
# 支付授权的哈希用于链中的下一步
pmt_hash = compute_hash(payment_mandate.payment_mandate_contents.model_dump(exclude_none=True))
print(f"[商户] PaymentMandate 哈希: {pmt_hash[:32]}...")


# --- 5. 商户：签发支付收据凭证 ---
receipt_contents = PaymentReceiptContents(
    id="receipt-888",
    payment_mandate_id=payment_mandate.payment_mandate_contents.payment_mandate_id,
    status=PaymentStatus.SUCCESS,
    timestamp=datetime.now(timezone.utc).isoformat(),
)

# 商户签名收据，通过 pmt_hash 链接到支付授权
payment_receipt = build_payment_receipt(
    contents=receipt_contents,
    pmt_hash=pmt_hash,
    merchant_private_key=private_key_pem,  # 为简化使用相同密钥
    merchant_did=merchant_did,
    merchant_kid=merchant_kid,
    algorithm=credential_algorithm,
    shopper_did=shopper_did,
)
print("[商户] PaymentReceipt 凭证已签发。")


# --- 6. 购物者：验证支付收据 ---
# 购物者接收收据并验证其真实性及与支付的链接
cred_payload = validate_credential(
    credential=payment_receipt,
    merchant_public_key=public_key_pem,
    merchant_algorithm=credential_algorithm,
    expected_shopper_did=shopper_did,
    expected_pmt_hash=pmt_hash,
)
print("[购物者] PaymentReceipt 验证成功。")
print(f"[购物者] 收据签发者: {cred_payload['iss']}")
print(f"[购物者] 凭证哈希: {cred_payload.get('cred_hash', '')[:32]}...")
```

## API 参考

### 数据模型

| 模型 | 说明 |
|------|------|
| `CartContents` | 购物车内容 |
| `CartMandate` | 签名的购物车授权 |
| `PaymentMandateContents` | 支付授权内容 |
| `PaymentMandate` | 签名的支付授权 |
| `PaymentReceiptContents` | 支付收据内容 |
| `PaymentReceipt` | 签名的支付收据凭证 |
| `MoneyAmount` | 金额（货币+数值） |
| `PaymentDetails` | 支付详情 |
| `PaymentRequest` | 支付请求 |
| `PaymentResponse` | 支付响应 |
| `PaymentStatus` | 支付状态枚举 |

### 构建器函数

| 函数 | 说明 |
|------|------|
| `build_cart_mandate()` | 构建并签名 CartMandate |
| `build_payment_mandate()` | 构建并签名 PaymentMandate |
| `build_payment_receipt()` | 构建并签名 PaymentReceipt |

### 验证器函数

| 函数 | 说明 |
|------|------|
| `validate_cart_mandate()` | 验证 CartMandate 签名和内容 |
| `validate_payment_mandate()` | 验证 PaymentMandate 签名和哈希链接 |
| `validate_credential()` | 验证凭证签名和链接 |

### 工具函数

| 函数 | 说明 |
|------|------|
| `compute_hash()` | 计算数据的规范化哈希 |

## 流程概览

```
购物者                                商户
  │                                    │
  │  1. 请求 CartMandate               │
  │ ─────────────────────────────────> │
  │                                    │ 创建并签名 CartMandate
  │  2. 返回签名的 CartMandate          │
  │ <───────────────────────────────── │
  │                                    │
验证 CartMandate                        │
计算 cart_hash                          │
创建并签名 PaymentMandate               │
  │                                    │
  │  3. 发送 PaymentMandate            │
  │ ─────────────────────────────────> │
  │                                    │ 验证 PaymentMandate
  │                                    │ 验证 cart_hash 匹配
  │                                    │ 签发 PaymentReceipt
  │  4. 返回 PaymentReceipt            │
  │ <───────────────────────────────── │
  │                                    │
验证 PaymentReceipt                     │
交易完成 ✓                              │
```

## 示例

查看 `examples/python/ap2_examples/` 获取完整示例：

```bash
# 运行完整 AP2 流程
uv run python examples/python/ap2_examples/ap2_complete_flow.py
```

## 相关文档

- [AP2 协议规范](../../docs/ap2/ap2-flow.md) - 详细协议规范
- [OpenANP README](../openanp/README.cn.md) - 智能体开发
- [项目 README](../../README.cn.md) - 概览

## 许可证

MIT License
