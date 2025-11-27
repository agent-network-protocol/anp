# AP2 API Reference

本文档提供 AP2 协议的核心 API 参考。

## 核心函数

### build_cart_mandate

构建购物车授权（CartMandate），由商户签名。

**函数签名**：

```python
def build_cart_mandate(
    contents: dict,
    shopper_did: str,
    merchant_private_key: str,
    merchant_did: str,
    merchant_kid: str,
    algorithm: str = "RS256",
    ttl_seconds: int = 900,
) -> CartMandate
```

**参数**：

- `contents` (dict): 购物车内容（plain dict，developer-controlled）
- `shopper_did` (str): 购物者 DID（JWT 受众）
- `merchant_private_key` (str): 商户私钥（PEM 格式）
- `merchant_did` (str): 商户 DID（JWT 签发者和主体）
- `merchant_kid` (str): 商户密钥 ID（用于 JWT header）
- `algorithm` (str): JWT 签名算法，默认 "RS256"
- `ttl_seconds` (int): 有效期（秒），默认 900（15 分钟）

**返回**：

- `CartMandate`: Pydantic 模型实例，包含 `contents` 和 `merchant_authorization`

**示例**：

```python
from anp.ap2.cart_mandate import build_cart_mandate

cart = build_cart_mandate(
    contents={
        "id": "cart-123",
        "user_signature_required": False,
        "timestamp": "2025-01-17T09:00:00Z",
        "payment_request": {
            "method_data": [...],
            "details": {...},
            "options": {...}
        }
    },
    shopper_did="did:wba:example.com:shopper",
    merchant_private_key=merchant_key_pem,
    merchant_did="did:wba:example.com:merchant",
    merchant_kid="merchant-key-001",
    algorithm="RS256",
    ttl_seconds=900
)

# 访问字段
print(cart.contents)  # dict
print(cart.merchant_authorization)  # JWT string
```

---

### validate_cart_mandate

验证购物车授权（CartMandate）的签名和内容哈希。

**函数签名**：

```python
def validate_cart_mandate(
    cart_mandate: CartMandate,
    merchant_public_key: str,
    merchant_algorithm: str,
    expected_shopper_did: str,
) -> bool
```

**参数**：

- `cart_mandate` (CartMandate): 待验证的 CartMandate 实例
- `merchant_public_key` (str): 商户公钥（PEM 格式）
- `merchant_algorithm` (str): JWT 算法（如 "RS256"）
- `expected_shopper_did` (str): 预期的购物者 DID（验证 JWT 受众）

**返回**：

- `bool`: 验证成功返回 `True`，失败返回 `False`

**示例**：

```python
from anp.ap2.cart_mandate import validate_cart_mandate

is_valid = validate_cart_mandate(
    cart_mandate=cart,
    merchant_public_key=merchant_public_key_pem,
    merchant_algorithm="RS256",
    expected_shopper_did="did:wba:example.com:shopper"
)

if is_valid:
    print("✅ CartMandate 验证成功")
else:
    print("❌ CartMandate 验证失败")
```

---

### build_payment_mandate

构建支付授权（PaymentMandate），由购物者签名。

**函数签名**：

```python
def build_payment_mandate(
    contents: dict,
    merchant_did: str,
    shopper_did: str,
    shopper_kid: str,
    shopper_private_key: str,
    algorithm: str = "RS256",
    ttl_seconds: int = 15552000,
) -> PaymentMandate
```

**参数**：

- `contents` (dict): 支付授权内容（必须包含 `cart_hash` 字段）
- `merchant_did` (str): 商户 DID（JWT 受众）
- `shopper_did` (str): 购物者 DID（JWT 签发者和主体）
- `shopper_kid` (str): 购物者密钥 ID（用于 JWT header）
- `shopper_private_key` (str): 购物者私钥（PEM 格式）
- `algorithm` (str): JWT 签名算法，默认 "RS256"
- `ttl_seconds` (int): 有效期（秒），默认 15552000（180 天）

**返回**：

- `PaymentMandate`: Pydantic 模型实例，包含 `payment_mandate_contents` 和 `user_authorization`

**注意**：

- `contents` 必须包含 `cart_hash` 字段以维护哈希链

**示例**：

```python
from anp.ap2.payment_mandate import build_payment_mandate
from anp.ap2.utils import compute_hash

# 计算前序 CartMandate 的哈希
cart_hash = compute_hash(cart.contents)

# 构建 PaymentMandate
payment = build_payment_mandate(
    contents={
        "payment_mandate_id": "pm-456",
        "payment_details_id": "order-123",
        "cart_hash": cart_hash,  # 哈希链关键字段
        "payment_details_total": {...},
        "payment_response": {...},
        "merchant_agent": "MerchantAgent",
        "timestamp": "2025-01-17T09:05:00Z"
    },
    merchant_did="did:wba:example.com:merchant",
    shopper_did="did:wba:example.com:shopper",
    shopper_kid="shopper-key-001",
    shopper_private_key=shopper_key_pem,
    algorithm="RS256",
    ttl_seconds=15552000
)

# 访问字段
print(payment.payment_mandate_contents)  # dict
print(payment.user_authorization)  # JWT string
print(payment.id)  # 从 contents 中提取的 payment_mandate_id
```

---

### validate_payment_mandate

验证支付授权（PaymentMandate）的签名、内容哈希和哈希链。

**函数签名**：

```python
def validate_payment_mandate(
    payment_mandate: PaymentMandate,
    shopper_public_key: str,
    shopper_algorithm: str,
    expected_merchant_did: str,
    expected_cart_hash: str,
) -> bool
```

**参数**：

- `payment_mandate` (PaymentMandate): 待验证的 PaymentMandate 实例
- `shopper_public_key` (str): 购物者公钥（PEM 格式）
- `shopper_algorithm` (str): JWT 算法（如 "RS256"）
- `expected_merchant_did` (str): 预期的商户 DID（验证 JWT 受众）
- `expected_cart_hash` (str): 预期的 cart_hash（验证哈希链完整性）

**返回**：

- `bool`: 验证成功返回 `True`，失败返回 `False`

**示例**：

```python
from anp.ap2.payment_mandate import validate_payment_mandate
from anp.ap2.utils import compute_hash

# 计算 cart_hash 用于验证
cart_hash = compute_hash(cart.contents)

is_valid = validate_payment_mandate(
    payment_mandate=payment,
    shopper_public_key=shopper_public_key_pem,
    shopper_algorithm="RS256",
    expected_merchant_did="did:wba:example.com:merchant",
    expected_cart_hash=cart_hash
)

if is_valid:
    print("✅ PaymentMandate 验证成功，哈希链完整")
else:
    print("❌ PaymentMandate 验证失败")
```

---

## 辅助函数

### compute_hash

计算内容的规范化哈希（JCS + SHA-256 + Base64URL）。

**函数签名**：

```python
def compute_hash(contents: dict) -> str
```

**参数**：

- `contents` (dict): 待哈希的内容

**返回**：

- `str`: Base64URL 编码的 SHA-256 哈希（无填充）

**示例**：

```python
from anp.ap2.utils import compute_hash

cart_hash = compute_hash(cart.contents)
print(f"cart_hash: {cart_hash}")  # 43 字符的 base64url 字符串
```

---

## 模型

### CartMandate

购物车授权模型。

**字段**：

- `contents` (dict): 购物车内容（plain dict）
- `merchant_authorization` (str): 商户授权签名（JWT）

**方法**：

- `model_dump()`: 转换为 dict
- `CartMandate.model_validate(data)`: 从 dict 创建实例

---

### PaymentMandate

支付授权模型。

**字段**：

- `payment_mandate_contents` (dict): 支付授权内容（plain dict）
- `user_authorization` (str): 用户授权签名（JWT）

**属性**：

- `id` (str): 从 `payment_mandate_contents` 中提取的 `payment_mandate_id`

**方法**：

- `model_dump()`: 转换为 dict
- `PaymentMandate.model_validate(data)`: 从 dict 创建实例

---

## 哈希链模式

AP2 使用哈希链保证数据完整性：

```
CartMandate(cart_hash)
    ↓
PaymentMandate(cart_hash, pmt_hash)
    ↓
    ├─→ PaymentReceipt(pmt_hash)
    └─→ FulfillmentReceipt(pmt_hash)
```

**关键特性**：

- 只需验证最新的 mandate
- 哈希链密码学保证整条链的完整性
- 每个 mandate 的哈希包含在下一个 mandate 的内容中

**完整示例**：

```python
from anp.ap2.cart_mandate import build_cart_mandate, validate_cart_mandate
from anp.ap2.payment_mandate import build_payment_mandate, validate_payment_mandate
from anp.ap2.utils import compute_hash

# 1. 构建 CartMandate
cart = build_cart_mandate(
    contents=cart_contents_dict,
    shopper_did=shopper_did,
    merchant_private_key=merchant_key,
    merchant_did=merchant_did,
    merchant_kid=merchant_kid
)

# 2. 验证 CartMandate
assert validate_cart_mandate(cart, merchant_public_key, "RS256", shopper_did)

# 3. 计算 cart_hash
cart_hash = compute_hash(cart.contents)

# 4. 构建 PaymentMandate（包含 cart_hash）
payment = build_payment_mandate(
    contents={
        "payment_mandate_id": "pm-456",
        "cart_hash": cart_hash,  # 哈希链链接
        ...
    },
    merchant_did=merchant_did,
    shopper_did=shopper_did,
    shopper_kid=shopper_kid,
    shopper_private_key=shopper_key
)

# 5. 验证 PaymentMandate（包含哈希链验证）
assert validate_payment_mandate(
    payment,
    shopper_public_key,
    "RS256",
    merchant_did,
    cart_hash  # 验证哈希链
)

# ✅ 如果 PaymentMandate 验证通过，整条链都是有效的
```

---

## 注意事项

1. **参数顺序**：注意 `build_cart_mandate` 和 `build_payment_mandate` 的参数顺序不同
2. **哈希链**：`PaymentMandate.contents` 必须包含 `cart_hash` 字段
3. **返回类型**：validate 函数返回 `bool`，不抛出异常
4. **模型转换**：使用 Pydantic 内置的 `model_dump()` 和 `model_validate()`
5. **TTL**：CartMandate 默认 15 分钟，PaymentMandate 默认 180 天
