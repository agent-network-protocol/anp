# AP2 Protocol Module

AP2 (Agent Payment Protocol v2) 模块为 ANP 提供支付协议支持，实现购物车授权（CartMandate）和支付授权（PaymentMandate）的构建与验证。

## 功能特性

- **CartMandate 构建和验证**：商户创建包含商品信息和支付方式的购物车授权
- **PaymentMandate 构建和验证**：用户创建支付授权凭证
- **多算法支持**：支持 RS256 和 ES256K 签名算法
  - RS256：使用 PyJWT 库（默认）
  - ES256K：使用 python-jose 库
- **JCS 规范化**：符合 RFC 8785 标准的 JSON 规范化
- **完整的数据模型**：基于 Pydantic 的类型安全数据模型
- **灵活的 DID 支持**：支持 `did:wba` 等多种 DID 格式

## 模块结构

```
anp/ap2/
├── __init__.py           # 模块入口
├── models.py             # Pydantic 数据模型
├── cart_mandate.py       # CartMandate 构建器和验证器
├── payment_mandate.py    # PaymentMandate 构建器和验证器
├── client.py             # HTTP 客户端（DID WBA 认证）
└── utils.py              # 工具函数（JCS、哈希计算）
```

## 快速开始

### 方式一：使用 HTTP 客户端（推荐）

如果您需要通过 HTTP 发送 AP2 请求到商户服务器，使用 `AP2Client`：

```python
from anp.ap2 import AP2Client, PaymentMandateBuilder
from datetime import datetime, timezone

# 初始化客户端（自动处理 DID WBA 认证）
client = AP2Client(
    did_document_path="path/to/did-doc.json",
    private_key_path="path/to/did-private-key.pem",
    client_did="did:wba:didhost.cc:shopper",
)

# 1. 发送 create_cart_mandate 请求
items = [{
    "id": "sku-001",
    "sku": "Nike-Air-Max-90",
    "quantity": 1,
    "options": {"color": "red", "size": "42"},
}]

shipping_address = {
    "recipient_name": "张三",
    "phone": "13800138000",
    "region": "北京市",
    "city": "北京市",
    "address_line": "朝阳区某某街道123号",
    "postal_code": "100000",
}

cart_mandate = await client.create_cart_mandate(
    merchant_url="https://merchant.example.com",
    merchant_did="did:wba:merchant.example.com:merchant",
    cart_mandate_id="cart-123",
    items=items,
    shipping_address=shipping_address,
)

# 2. 验证 CartMandate 并获取 cart_hash
from anp.ap2 import CartMandateVerifier
verifier = CartMandateVerifier(merchant_public_key, algorithm="RS256")
cart_payload = verifier.verify(cart_mandate, expected_aud=client_did)
cart_hash = cart_payload["cart_hash"]

# 3. 创建 PaymentMandate
from anp.ap2 import PaymentMandateBuilder, PaymentMandateContents, PaymentDetailsTotal, PaymentResponse, MoneyAmount

builder = PaymentMandateBuilder(
    user_private_key=user_private_key,
    user_did=client_did,
    user_kid="shopper-key-001",
    algorithm="RS256",
    merchant_did=merchant_did,
)

pmt_contents = PaymentMandateContents(
    payment_mandate_id="pm_123",
    payment_details_id=cart_mandate.contents.payment_request.details.id,
    payment_details_total=PaymentDetailsTotal(
        label="Total",
        amount=MoneyAmount(currency="CNY", value=120.0),
        refund_period=30,
    ),
    payment_response=PaymentResponse(
        request_id=cart_mandate.contents.payment_request.details.id,
        method_name="QR_CODE",
        details={"channel": "ALIPAY", "out_trade_no": "order_123"},
    ),
    merchant_agent="MerchantAgent",
    timestamp=datetime.now(timezone.utc).isoformat(),
)

payment_mandate = builder.build(pmt_contents, cart_hash)

# 4. 发送 PaymentMandate
response = await client.send_payment_mandate(
    merchant_url="https://merchant.example.com",
    merchant_did=merchant_did,
    payment_mandate=payment_mandate,
)
```

### 方式二：手动构建和验证

### 1. 生成密钥对

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# 生成 RSA 密钥对
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# 导出私钥
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode('utf-8')

# 导出公钥
public_pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode('utf-8')
```

### 2. 创建 CartMandate（商户端）

```python
from anp.ap2 import (
    CartMandateBuilder,
    CartContents,
    PaymentRequest,
    PaymentMethodData,
    QRCodePaymentData,
    PaymentDetails,
    DisplayItem,
    MoneyAmount,
    PaymentDetailsTotal,
    PaymentRequestOptions,
)

# 初始化构建器（使用默认的 RS256 算法）
builder = CartMandateBuilder(
    merchant_private_key=merchant_private_key,
    merchant_did="did:wba:didhost.cc:merchant",
    merchant_kid="merchant-key-001",
    algorithm="RS256",  # 可选，默认为 RS256
    shopper_did="did:wba:didhost.cc:shopper",
)

# 创建购物车内容
cart_contents = CartContents(
    id="cart_123",
    user_signature_required=False,
    timestamp="2025-01-17T08:00:00Z",
    payment_request=PaymentRequest(
        method_data=[
            PaymentMethodData(
                supported_methods="QR_CODE",
                data=QRCodePaymentData(
                    channel="ALIPAY",
                    qr_url="https://pay.example.com/qrcode/abc123",
                    out_trade_no="order_20250117_123456",
                    expires_at="2025-01-17T09:15:00Z",
                ),
            )
        ],
        details=PaymentDetails(
            id="order_123",
            displayItems=[
                DisplayItem(
                    id="sku-id-123",
                    sku="Product-SKU",
                    label="Product Name",
                    quantity=1,
                    amount=MoneyAmount(currency="CNY", value=120.0),
                )
            ],
            total=PaymentDetailsTotal(
                label="Total",
                amount=MoneyAmount(currency="CNY", value=120.0)
            ),
        ),
        options=PaymentRequestOptions(requestShipping=True),
    ),
)

# 构建 CartMandate
cart_mandate = builder.build(
    cart_contents=cart_contents,
    extensions=["anp.ap2.qr.v1", "anp.human_presence.v1"],
)

print(f"CartMandate created: {cart_mandate.contents.id}")
print(f"Authorization: {cart_mandate.merchant_authorization[:50]}...")
```

### 3. 验证 CartMandate（用户端）

```python
from anp.ap2 import CartMandateVerifier

# 初始化验证器
verifier = CartMandateVerifier(merchant_public_key=merchant_public_key)

# 验证 CartMandate
try:
    payload = verifier.verify(
        cart_mandate=cart_mandate,
        expected_aud="did:anp:shopper"
    )

    cart_hash = payload["cart_hash"]
    print(f"CartMandate verified successfully!")
    print(f"Issued by: {payload['iss']}")
    print(f"Cart hash: {cart_hash}")

except Exception as e:
    print(f"Verification failed: {e}")
```

### 4. 创建 PaymentMandate（用户端）

```python
from anp.ap2 import (
    PaymentMandateBuilder,
    PaymentMandateContents,
    PaymentDetailsTotal,
    PaymentResponse,
)
from datetime import datetime, timezone

# 初始化构建器
builder = PaymentMandateBuilder(
    user_private_key=user_private_key,
    user_did="did:wba:didhost.cc:shopper",
    user_kid="shopper-key-001",
    algorithm="RS256",  # 可选，默认为 RS256
    merchant_did="did:wba:didhost.cc:merchant",
)

# 创建支付授权内容
pmt_contents = PaymentMandateContents(
    payment_mandate_id="pm_12345",
    payment_details_id="order_123",
    payment_details_total=PaymentDetailsTotal(
        label="Total",
        amount=MoneyAmount(currency="CNY", value=120.0),
        refund_period=30,
    ),
    payment_response=PaymentResponse(
        request_id="order_123",
        method_name="QR_CODE",
        details={
            "channel": "ALIPAY",
            "out_trade_no": "order_20250117_123456"
        },
    ),
    merchant_agent="MerchantAgent",
    timestamp=datetime.now(timezone.utc).isoformat(),
)

# 构建 PaymentMandate（需要 cart_hash）
payment_mandate = builder.build(
    payment_mandate_contents=pmt_contents,
    cart_hash=cart_hash,  # 来自 CartMandate 验证
    extensions=["anp.ap2.qr.v1"],
)

print(f"PaymentMandate created: {payment_mandate.payment_mandate_contents.payment_mandate_id}")
print(f"Chained prev_hash: {payment_mandate.payment_mandate_contents.prev_hash}")
```

### 5. 验证 PaymentMandate（商户端）

```python
from anp.ap2 import PaymentMandateVerifier

# 初始化验证器
verifier = PaymentMandateVerifier(user_public_key=user_public_key)

# 验证 PaymentMandate
try:
    payload = verifier.verify(
        payment_mandate=payment_mandate,
        expected_cart_hash=cart_hash,
        expected_aud="did:anp:merchant"
    )

    print(f"PaymentMandate verified successfully!")
    print(f"Issued by: {payload['iss']}")
    print(f"Transaction data: {payload['transaction_data']}")

except Exception as e:
    print(f"Verification failed: {e}")
```

## 完整流程示例

```python
from anp.ap2 import *

# 1. 商户创建 CartMandate
cart_builder = CartMandateBuilder(
    merchant_private_key=merchant_private_key,
    merchant_did="did:anp:merchant",
    merchant_kid="merchant-key-001",
    shopper_did="did:anp:shopper",
)
cart_mandate = cart_builder.build(cart_contents)

# 2. 用户验证 CartMandate 并获取 cart_hash
cart_verifier = CartMandateVerifier(merchant_public_key=merchant_public_key)
cart_payload = cart_verifier.verify(cart_mandate, expected_aud="did:anp:shopper")
cart_hash = cart_payload["cart_hash"]

# 3. 用户创建 PaymentMandate
payment_builder = PaymentMandateBuilder(
    user_private_key=user_private_key,
    user_did="did:anp:shopper",
    user_kid="shopper-key-001",
    merchant_did="did:anp:merchant",
)
payment_mandate = payment_builder.build(pmt_contents, cart_hash)

# 4. 商户验证 PaymentMandate
payment_verifier = PaymentMandateVerifier(user_public_key=user_public_key)
payment_payload = payment_verifier.verify(
    payment_mandate,
    expected_cart_hash=cart_hash,
    expected_aud="did:anp:merchant"
)

print("✅ Complete AP2 flow verified successfully!")
```

## API 参考

### AP2Client

**初始化参数：**
- `did_document_path` (str): DID 文档路径
- `private_key_path` (str): DID 私钥路径
- `client_did` (str): 客户端 DID

**create_cart_mandate() 方法参数：**
- `merchant_url` (str): 商户 API 基础 URL（如 `https://merchant.example.com`）
- `merchant_did` (str): 商户 DID
- `cart_mandate_id` (str): 购物车授权 ID
- `items` (List[Dict]): 商品列表
- `shipping_address` (Dict): 收货地址
- `remark` (Optional[str]): 备注

**返回：** CartMandate

**send_payment_mandate() 方法参数：**
- `merchant_url` (str): 商户 API 基础 URL
- `merchant_did` (str): 商户 DID
- `payment_mandate` (PaymentMandate): 支付授权对象

**返回：** Dict（商户响应）

**异常：**
- `Exception`: HTTP 请求失败或响应错误

**说明：**
- `AP2Client` 自动处理 DID WBA 认证头
- 第一次请求使用 `force_new=True` 生成新的认证头
- 后续请求会复用之前的 access token
- 所有 HTTP 请求使用 `aiohttp` 异步发送

### 便捷函数

```python
# 发送 create_cart_mandate（无需创建 client 实例）
from anp.ap2 import create_cart_mandate

cart = await create_cart_mandate(
    merchant_url="https://merchant.example.com",
    merchant_did="did:wba:merchant.example.com:merchant",
    cart_mandate_id="cart-123",
    items=[...],
    shipping_address={...},
    did_document_path="path/to/did-doc.json",
    private_key_path="path/to/key.pem",
    client_did="did:wba:didhost.cc:shopper",
)

# 发送 send_payment_mandate
from anp.ap2 import send_payment_mandate

response = await send_payment_mandate(
    merchant_url="https://merchant.example.com",
    merchant_did=merchant_did,
    payment_mandate=payment_mandate,
    did_document_path="path/to/did-doc.json",
    private_key_path="path/to/key.pem",
    client_did="did:wba:didhost.cc:shopper",
)
```

### CartMandateBuilder

**初始化参数：**
- `merchant_private_key` (str): 商户私钥（PEM 格式，RSA 或 EC）
- `merchant_did` (str): 商户 DID（如 `did:wba:didhost.cc:merchant`）
- `merchant_kid` (str): 商户密钥标识符
- `algorithm` (str): JWT 签名算法，`"RS256"` 或 `"ES256K"`，默认 `"RS256"`
- `shopper_did` (Optional[str]): 购物者 DID

**build() 方法参数：**
- `cart_contents` (CartContents): 购物车内容
- `cnf` (Optional[Dict]): 持有者绑定信息
- `sd_hash` (Optional[str]): SD-JWT/VC 哈希指针
- `ttl_seconds` (int): 有效期（秒），默认 900 秒（15 分钟）
- `extensions` (Optional[List[str]]): 扩展列表

**返回：** CartMandate

### CartMandateVerifier

**初始化参数：**
- `merchant_public_key` (str): 商户公钥（PEM 格式，RSA 或 EC）
- `algorithm` (str): JWT 签名算法，`"RS256"` 或 `"ES256K"`，默认 `"RS256"`

**verify() 方法参数：**
- `cart_mandate` (CartMandate): 待验证的 CartMandate
- `expected_aud` (Optional[str]): 期望的 aud 值
- `verify_time` (bool): 是否验证时间有效性，默认 True

**返回：** Dict（JWT payload）

**异常：**
- `jwt.InvalidSignatureError`: 签名无效
- `jwt.ExpiredSignatureError`: JWT 已过期
- `ValueError`: cart_hash 不匹配

### PaymentMandateBuilder

**初始化参数：**
- `user_private_key` (str): 用户私钥（PEM 格式，RSA 或 EC）
- `user_did` (str): 用户 DID（如 `did:wba:didhost.cc:shopper`）
- `user_kid` (str): 用户密钥标识符
- `algorithm` (str): JWT 签名算法，`"RS256"` 或 `"ES256K"`，默认 `"RS256"`
- `merchant_did` (Optional[str]): 商户 DID

**build() 方法参数：**
- `payment_mandate_contents` (PaymentMandateContents): 支付授权内容
- `cart_hash` (str): 购物车哈希（来自 CartMandate）
- `cnf` (Optional[Dict]): 持有者绑定信息
- `sd_hash` (Optional[str]): SD-JWT/VC 哈希指针
- `ttl_seconds` (int): 有效期（秒），默认 15552000 秒（180 天）
- `extensions` (Optional[List[str]]): 扩展列表

**返回：** PaymentMandate

### PaymentMandateVerifier

**初始化参数：**
- `user_public_key` (str): 用户公钥（PEM 格式，RSA 或 EC）
- `algorithm` (str): JWT 签名算法，`"RS256"` 或 `"ES256K"`，默认 `"RS256"`

**verify() 方法参数：**
- `payment_mandate` (PaymentMandate): 待验证的 PaymentMandate
- `expected_cart_hash` (str): 期望的 cart_hash
- `expected_aud` (Optional[str]): 期望的 aud 值
- `verify_time` (bool): 是否验证时间有效性，默认 True

**返回：** Dict（JWT payload）

**异常：**
- `jwt.InvalidSignatureError`: 签名无效
- `jwt.ExpiredSignatureError`: JWT 已过期
- `ValueError`: transaction_data 不匹配

## 测试

运行测试：

```bash
# 运行所有 AP2 测试
uv run pytest tests/test_ap2.py -v

# 运行特定测试类
uv run pytest tests/test_ap2.py::TestCartMandate -v

# 运行特定测试方法
uv run pytest tests/test_ap2.py::TestCartMandate::test_build_cart_mandate_response -v
```

## ES256K 算法支持

对于需要使用 ES256K 算法的场景（如以太坊兼容的椭圆曲线签名），需要安装额外依赖：

```bash
pip install python-jose[cryptography]
```

然后在初始化时指定算法：

```python
# 使用 ES256K 算法创建 CartMandate
builder = CartMandateBuilder(
    merchant_private_key=ec_private_key,  # EC 私钥（secp256k1 曲线）
    merchant_did="did:wba:didhost.cc:merchant",
    merchant_kid="merchant-key-001",
    algorithm="ES256K",  # 指定 ES256K 算法
)

# 验证时也需要指定算法
verifier = CartMandateVerifier(
    merchant_public_key=ec_public_key,
    algorithm="ES256K"
)
```

## 技术规范

- **JWT 算法**：
  - RS256（默认）：RSA 签名，使用 SHA-256
  - ES256K：椭圆曲线签名（secp256k1），使用 SHA-256
- **哈希算法**：SHA-256
- **JCS 标准**：RFC 8785
- **编码格式**：Base64URL（无填充）
- **DID 格式**：支持 `did:wba` 等格式（如 `did:wba:didhost.cc:public`）
- **有效期**：
  - CartMandate: 默认 900 秒（15 分钟）
  - PaymentMandate: 默认 15552000 秒（180 天）

## 相关文档

- [AP2 协议规范](../../docs/ap2/ap2-flow.md)
- [JWT 规范 (RFC 7519)](https://datatracker.ietf.org/doc/html/rfc7519)
- [JCS 规范 (RFC 8785)](https://datatracker.ietf.org/doc/html/rfc8785)
- [JWS 规范 (RFC 7515)](https://datatracker.ietf.org/doc/html/rfc7515)

## 许可证

本项目采用 MIT 许可证开源。详见 [LICENSE](../../LICENSE) 文件。
