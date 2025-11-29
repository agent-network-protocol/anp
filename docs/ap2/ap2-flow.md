# ad.json 描述方法

```json
    {
      "type": "StructuredInterface",
      "protocol": "AP2/ANP",
      "version": "0.0.1",
      "url": "https://grand-hotel.com/api/ap2.json",
      "description": "An implementation of the AP2 protocol based on the ANP protocol, used for payment and transactions between agents."
    },
```

ap2.json 内容：

```json
{
  "ap2/anp": "0.0.1",
  "roles": [
    "shopper": {
      "description": "shopper Agent - handles user interaction, PIN validation, QR code display",
      "endpoints": {
        "receive_delivery_receipt": "/ap2/shopper/receive_delivery_receipt"
      }
    },
    "merchant": {
      "description": "Merchant Agent - generates cart, creates QR orders, issues delivery receipts",
      "endpoints": {
        "create_cart_mandate": "/ap2/merchant/create_cart_mandate",
        "send_payment_mandate": "/ap2/merchant/send_payment_mandate",
      }
    }
  ]
}
```

roles 的类型：

```json
AP2Role = "merchant" | "shopper" | "credentials-provider" | "payment-processor"
```

也可以直接在 Interface 中描述：

```json
    {
      "type": "StructuredInterface",
      "type": "StructuredInterface",
      "protocol": "AP2/ANP",
      "version": "0.0.1",
      "description": "An implementation of the AP2 protocol based on the ANP protocol, used for payment and transactions between agents."
    },
    "content":{
        "roles": [
            "shopper": {
            "description": "shopper Agent - handles user interaction, PIN validation, QR code display",
            "endpoints": {
                "receive_delivery_receipt": "/ap2/shopper/receive_delivery_receipt"
            }
            },
            "merchant": {
            "description": "Merchant Agent - generates cart, creates QR orders, issues delivery receipts",
            "endpoints": {
                "create_cart_mandate": "/ap2/merchant/create_cart_mandate",
                "send_payment_mandate": "/ap2/merchant/send_payment_mandate",
            }
            }
        ]
    }
```

# 凭证定义

## 1. CartMandate（购物车授权）

**方向**：MA → TA

**数据结构**：

```json
{
  "contents": {
    "id": "cart_shoes_123",
    "user_signature_required": false,
    "timestamp": "2025-01-17T09:00:00Z",
    "payment_request": {
      "method_data": [
        {
          "supported_methods": "QR_CODE",
          "data": {
            "channel": "ALIPAY",
            "qr_url": "https://pay.example.com/qrcode/abc123",
            "out_trade_no": "order_20250117_123456",
            "expires_at": "2025-01-17T09:15:00Z"
          }
        },
        {
          "supported_methods": "QR_CODE",
          "data": {
            "channel": "WECHAT",
            "qr_url": "https://pay.example.com/qrcode/abc123",
            "out_trade_no": "order_20250117_123456",
            "expires_at": "2025-01-17T09:15:00Z"
          }
        }
      ],
      "details": {
        "id": "order_shoes_123",
        "displayItems": [
          {
            "id": "sku-id-123",
            "label": "Nike Air Max 90",
            "quantity": 1,
            "options": {
              "color": "red",
              "size": "42"
            },
            "amount": {
              "currency": "CNY",
              "value": 120.0
            },
            "pending": null,
            "remark": "请尽快发货"
          }
        ],
        "shipping_address": {
          "recipient_name": "张三",
          "phone": "13800138000",
          "region": "北京市",
          "city": "北京市",
          "address_line": "朝阳区某某街道123号",
          "postal_code": "100000"
        },
        "shipping_options": null,
        "modifiers": null,
        "total": {
          "label": "Total",
          "amount": {
            "currency": "CNY",
            "value": 120.0
          },
          "pending": null
        }
      },
      "options": {
        "requestPayerName": false,
        "requestPayerEmail": false,
        "requestPayerPhone": false,
        "requestShipping": true,
        "shippingType": null
      }
    }
  },
  "merchant_authorization": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**字段说明**：

- `contents`: CartContents 对象，包含购物车完整信息
  - `id`: 购物车唯一标识符
  - `user_signature_required`: 是否需要用户签名（通常为 false）
  - `timestamp`: ISO-8601 格式的时间戳
  - `payment_request`: 支付请求详情，包含 method_data、details、options
- `merchant_authorization`: JWS 格式的商户授权签名（详见下节）

**关键点**：

- `merchant_authorization` 是对整个 `contents` 的 JWS 签名（RS256 或 ES256K）
- `cart_hash = b64url(sha256(JCS(contents)))`，cart_hash 包含在 JWT payload 中

---

## Merchant Authorization（商户授权凭证）

### 概述

`merchant_authorization` 字段是商户对购物车内容 (`CartContents`) 的**短期数字签名授权凭证**，用于保证购物车内容的真实性与完整性。
该字段取代旧版的 `merchant_signature`，并采用符合 JOSE/JWT 标准的 **JSON Web Signature (JWS)** 容器格式。

---

### 数据类型

- **类型**：base64url 编码的紧凑 JWS 字符串（`header.payload.signature`）
- **算法**：`RS256` 或 `ES256K`
- **字段**：`CartMandate.merchant_authorization`

---

### Header 格式

```json
{
  "alg": "RS256",
  "kid": "MA-key-001",
  "typ": "JWT"
}
```

或：

```json
{
  "alg": "ES256K",
  "kid": "MA-es256k-key-001",
  "typ": "JWT"
}
```

---

### Payload 格式

**基础实现（必需字段）**：

```json
{
  "iss": "did:wba:a.com:MA", // 签发者（商户智能体 DID）
  "sub": "did:wba:a.com:MA", // 主体（可与 iss 相同）
  "aud": "did:wba:a.com:TA", // 受众（交易智能体或支付处理方）
  "iat": 1730000000, // 签发时间（秒）
  "exp": 1730000900, // 过期时间（建议 15 分钟，即 900 秒）
  "jti": "uuid", // 全局唯一标识符（防重放攻击）
  "cart_hash": "<b64url>" // 对 CartMandate.contents 的哈希（见下节）
}
```

**可选扩展字段**（当前基础实现未包含，保留用于未来扩展）：

```json
{
  "cnf": { "kid": "did:wba:a.com:TA#keys-1" }, // 持有者绑定信息
  "sd_hash": "<b64url>", // SD-JWT / VC 哈希指针
  "extensions": ["anp.ap2.qr.v1"] // 协议扩展标识
}
```

---

### `cart_hash` 计算规则

```text
cart_hash = Base64URL( SHA-256( JCS(CartMandate.contents) ) )
```

- 使用 [RFC 8785 JSON Canonicalization Scheme (JCS)](https://datatracker.ietf.org/doc/rfc8785/) 对 `CartMandate.contents` 进行规范化。
- 对规范化后的 UTF-8 字节执行 `SHA-256` 哈希。
- 将结果 Base64URL 编码（去掉“=”填充）。

---

### 签名生成流程（商户端 MA）

1. 计算 `cart_hash`：对 `CartMandate.contents` 执行 JCS 规范化后进行 SHA-256 哈希
2. 构造 JWT Payload（必需字段：`iss/sub/aud/iat/exp/jti/cart_hash`）
3. 构造 JWT Header（`alg=RS256` 或 `alg=ES256K`, `kid=<商户公钥标识>`, `typ=JWT`）
4. 用商户私钥对 Header 和 Payload 进行签名，生成紧凑 JWS（`header.payload.signature`）
5. 将生成的 JWS 作为 `merchant_authorization` 写入 `CartMandate` 对象

---

### 验签流程（交易端 TA）

1. 对 `CartMandate.contents` 重新计算 `cart_hash'`。
2. 解析 `merchant_authorization`：

   - 提取 Header → `kid`。
   - 通过 DID 文档或注册表获取 MA 的公钥。
   - 验证 JWS 签名（RS256 或 ES256K，与 Header 匹配）。

3. 校验声明：

   - `iss/aud/iat/exp/jti` 均符合规范；
   - 当前时间在 `[iat, exp]` 内；
   - `jti` 未被重复使用。

4. 校验数据绑定：

   - `payload.cart_hash == cart_hash'`，否则拒绝。

5. 识别扩展：

   - 如存在 `sd_hash`，进入 SD-JWT/VC 路径；
   - 如存在 `cnf`，可用于后续持有者验证。

---

### 参考实现（Python / PyJWT）

**基础实现**（与 `/anp/ap2/cart_mandate.py` 一致）：

```python
import json, base64, hashlib, uuid, time
import jwt  # pip install pyjwt

def jcs_canonicalize(obj):
    """JSON Canonicalization Scheme (RFC 8785)"""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def b64url_no_pad(b: bytes) -> str:
    """Base64URL encode without padding"""
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

def compute_hash(contents: dict) -> str:
    """Compute hash of contents using JCS + SHA-256"""
    canon = jcs_canonicalize(contents)
    digest = hashlib.sha256(canon.encode("utf-8")).digest()
    return b64url_no_pad(digest)

def build_cart_mandate(
    contents: dict,
    shopper_did: str,
    merchant_private_key: str,
    merchant_did: str,
    merchant_kid: str,
    algorithm: str = "RS256",
    ttl_seconds: int = 900
) -> CartMandate:
    """Build CartMandate with merchant authorization

    Returns CartMandate instance with contents and merchant_authorization.
    Uses core build_mandate() function with hash_field_name="cart_hash".
    """
    cart_hash = compute_hash(contents)
    now = int(time.time())

    payload = {
        "iss": merchant_did,
        "sub": merchant_did,
        "aud": shopper_did,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": str(uuid.uuid4()),
        "cart_hash": cart_hash
    }
    headers = {
        "alg": algorithm,
        "kid": merchant_kid,
        "typ": "JWT"
    }

    merchant_authorization = jwt.encode(payload, merchant_private_key, algorithm=algorithm, headers=headers)

    return CartMandate.model_validate({
        "contents": contents,
        "merchant_authorization": merchant_authorization
    })
```

---

### 校验清单

| 校验项       | 要求                                      |
| ------------ | ----------------------------------------- | --- |
| 签名算法     | RS256 或 ES256K（需与 Header.alg 一致）   |
| 时间窗       | `iat ≤ now ≤ exp`，有效期 ≤ 15 分钟       | jti |
| 重放防护     | `jti` 全局唯一                            |
| 签发者与受众 | `iss=MA`，`aud=TA`（或 MPP）              |
| 数据一致性   | `payload.cart_hash == computed_cart_hash` |
| DID 解析     | 通过 `kid` → DID 文档解析公钥             |
| 兼容扩展     | 支持解析 `cnf`、`sd_hash` 字段            |

---

### 向后兼容与升级策略

- 开发者应逐步弃用 `merchant_signature`，统一迁移到 `merchant_authorization`。
- 解析逻辑应具备兼容性：优先读取 `merchant_authorization`，如缺失可回退旧字段。
- 未来 M2/M3 版本中，`sd_hash` 将扩展为 SD-JWT-VC 链路标识，实现可选择性披露与可验证凭证互操作。

---

### 小结

> `merchant_authorization` 是商户为购物车内容生成的短期可验证授权凭证。
> 它结合 `cart_hash`、`cnf` 与 `sd_hash` 提供完整的**数据完整性验证、身份绑定、隐私升级通路**。
> 所有签发与验证过程均基于标准 JWS/JWT 机制，可直接在现有 JOSE 库上实现。

## 2. PaymentMandate（支付授权）

**方向**：TA → MA

**数据结构**：

```json
{
  "payment_mandate_contents": {
    "payment_mandate_id": "pm_12345",
    "payment_details_id": "order_shoes_123",
    "payment_details_total": {
      "label": "Total",
      "amount": {
        "currency": "CNY",
        "value": 120.0
      },
      "pending": null,
      "refund_period": 30
    },
    "payment_response": {
      "request_id": "order_shoes_123",
      "method_name": "QR_CODE",
      "details": {
        "channel": "ALIPAY",
        "out_trade_no": "order_20250117_123456"
      },
      "shipping_address": null,
      "shipping_option": null,
      "payer_name": null,
      "payer_email": null,
      "payer_phone": null
    },
    "merchant_agent": "MerchantAgent",
    "timestamp": "2025-01-17T09:05:00Z",
    "cart_hash": "cart_hash"
  },
  "user_authorization": "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXhhbXBsZ..."
}
```

**字段说明**：

- `payment_mandate_contents`: PaymentMandateContents 对象
  - `payment_mandate_id`: 支付授权唯一标识符
  - `payment_details_id`: 对应 CartMandate 中 payment_request.details.id
  - `payment_details_total`: 支付总金额及退款期限
  - `payment_response`: 支付响应详情（支付方式、渠道等）
  - `merchant_agent`: 商户代理标识
  - `timestamp`: ISO-8601 格式的时间戳
  - `cart_hash`: **前序 CartMandate 的哈希值**（哈希链关键）
- `user_authorization`: JWS 格式的用户授权签名（详见下节）

### user_authorization(用户授权)

user_authorization 是用户/购物者对支付内容的授权签名，采用与 merchant_authorization 相同的 JWS 格式。

**Header 格式**：

```json
{
  "alg": "RS256",
  "kid": "Shopper-key-001",
  "typ": "JWT"
}
```

或：

```json
{
  "alg": "ES256K",
  "kid": "Shopper-es256k-key-001",
  "typ": "JWT"
}
```

**Payload 格式**：

```json
{
  "iss": "did:wba:a.com:TA", // 签发者（购物者智能体 DID）
  "sub": "did:wba:a.com:TA", // 主体（可与 iss 相同）
  "aud": "did:wba:a.com:MA", // 受众（商户智能体）
  "iat": 1730000000, // 签发时间（秒）
  "exp": 1730000900, // 过期时间（建议 180天）
  "jti": "uuid", // 全局唯一标识符（防重放攻击）
  "pmt_hash": "<b64url>" // 对 PaymentMandateContents 的哈希
}
```

**pmt_hash 计算规则**：

```text
pmt_hash = Base64URL( SHA-256( JCS(PaymentMandateContents) ) )
```

**哈希链维护**：

PaymentMandateContents 包含前序 CartMandate 的 `cart_hash` 字段，从而形成哈希链：

```
CartMandate(cart_hash) → PaymentMandate(cart_hash, pmt_hash)
```

格式说明：对象名(前序哈希, 当前哈希)

---

## 3. PaymentReceipt（支付凭证）

**方向**：MA → TA（通过 Webhook）

**数据结构**：

```json
{
  "contents": {
    "credential_type": "PaymentReceipt",
    "version": 1,
    "id": "receipt_uuid_123",
    "timestamp": "2025-01-17T09:10:00Z",
    "payment_mandate_id": "pm_12345",
    "provider": "ALIPAY",
    "status": "SUCCEEDED",
    "transaction_id": "alipay_txn_789",
    "out_trade_no": "order_20250117_123456",
    "paid_at": "2025-01-17T09:08:30Z",
    "amount": {
      "currency": "CNY",
      "value": 120.0
    },
    "pmt_hash": "pmt_hash"
  },
  "merchant_authorization": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**字段说明**：

- `contents`: PaymentReceiptContents 对象（plain dict）
  - `credential_type`: 固定值 "PaymentReceipt"
  - `version`: 凭证版本号，当前为 1
  - `id`: 凭证唯一标识符（UUID）
  - `timestamp`: 凭证签发时间（ISO-8601）
  - `payment_mandate_id`: 对应的 PaymentMandate ID
  - `provider`: 支付提供商（ALIPAY | WECHAT）
  - `status`: 支付状态（SUCCEEDED | FAILED | PENDING | TIMEOUT）
  - `transaction_id`: 支付提供商的交易 ID
  - `out_trade_no`: 外部交易号
  - `paid_at`: 支付完成时间（ISO-8601）
  - `amount`: 支付金额
  - `pmt_hash`: **前序 PaymentMandate 的哈希值**
- `merchant_authorization`: JWS 格式的商户授权签名

**merchant_authorization Payload**：

```json
{
  "iss": "did:wba:a.com:MA",
  "sub": "did:wba:a.com:MA",
  "aud": "did:wba:a.com:TA",
  "iat": 1730000000,
  "exp": 1730000900,
  "jti": "receipt_uuid_123",
  "credential_type": "PaymentReceipt",
  "cred_hash": "<b64url(sha256(JCS(contents)))>"
}
```

**哈希链扩展**：

```
CartMandate(cart_hash) → PaymentMandate(cart_hash, pmt_hash) → PaymentReceipt(pmt_hash, cred_hash)
pmt_hash = Base64URL( SHA-256( JCS(PaymentMandateContents) ) )
```

**哈希链维护**：

PaymentMandateContents 包含前序 CartMandate 的 `cart_hash` 字段，从而形成哈希链：

```
CartMandate(cart_hash) → PaymentMandate(cart_hash, pmt_hash)
```

格式说明：对象名(前序哈希, 当前哈希)

---

## 3. PaymentReceipt（支付凭证）

**方向**：MA → TA（通过 Webhook）

**数据结构**：

```json
{
  "contents": {
    "credential_type": "PaymentReceipt",
    "version": 1,
    "id": "receipt_uuid_123",
    "timestamp": "2025-01-17T09:10:00Z",
    "payment_mandate_id": "pm_12345",
    "provider": "ALIPAY",
    "status": "SUCCEEDED",
    "transaction_id": "alipay_txn_789",
    "out_trade_no": "order_20250117_123456",
    "paid_at": "2025-01-17T09:08:30Z",
    "amount": {
      "currency": "CNY",
      "value": 120.0
    },
    "pmt_hash": "pmt_hash"
  },
  "merchant_authorization": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**字段说明**：

- `contents`: PaymentReceiptContents 对象（plain dict）
  - `credential_type`: 固定值 "PaymentReceipt"
  - `version`: 凭证版本号，当前为 1
  - `id`: 凭证唯一标识符（UUID）
  - `timestamp`: 凭证签发时间（ISO-8601）
  - `payment_mandate_id`: 对应的 PaymentMandate ID
  - `provider`: 支付提供商（ALIPAY | WECHAT）
  - `status`: 支付状态（SUCCEEDED | FAILED | PENDING | TIMEOUT）
  - `transaction_id`: 支付提供商的交易 ID
  - `out_trade_no`: 外部交易号
  - `paid_at`: 支付完成时间（ISO-8601）
  - `amount`: 支付金额
  - `pmt_hash`: **前序 PaymentMandate 的哈希值**
- `merchant_authorization`: JWS 格式的商户授权签名

**merchant_authorization Payload**：

```json
{
  "iss": "did:wba:a.com:MA",
  "sub": "did:wba:a.com:MA",
  "aud": "did:wba:a.com:TA",
  "iat": 1730000000,
  "exp": 1730000900,
  "jti": "receipt_uuid_123",
  "credential_type": "PaymentReceipt",
  "cred_hash": "<b64url(sha256(JCS(contents)))>"
}
```

**哈希链扩展**：

```
CartMandate(cart_hash) → PaymentMandate(cart_hash, pmt_hash) → PaymentReceipt(pmt_hash, cred_hash)
```

---

## 4. FulfillmentReceipt（履约凭证）

**方向**：MA → TA（通过 Webhook）

**数据结构**：

```json
{
  "contents": {
    "credential_type": "FulfillmentReceipt",
    "version": 1,
    "id": "fulfillment_uuid_456",
    "timestamp": "2025-01-18T10:00:00Z",
    "order_id": "order_shoes_123",
    "items": [
      {
        "id": "sku-id-123",
        "quantity": 1
      }
    ],
    "fulfilled_at": "2025-01-18T09:45:00Z",
    "shipping": {
      "carrier": "顺丰速运",
      "tracking_number": "SF1234567890",
      "delivered_eta": "2025-01-20T18:00:00Z"
    },
    "pmt_hash": "pmt_hash",
    "metadata": {
      "warehouse": "Beijing-001",
      "notes": "已发货，请注意查收"
    }
  },
  "merchant_authorization": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**字段说明**：

- `contents`: FulfillmentReceiptContents 对象（plain dict）
  - `credential_type`: 固定值 "FulfillmentReceipt"
  - `version`: 凭证版本号，当前为 1
  - `id`: 凭证唯一标识符（UUID）
  - `timestamp`: 凭证签发时间（ISO-8601）
  - `order_id`: 订单 ID
  - `items`: 履约商品列表
  - `fulfilled_at`: 履约完成时间（ISO-8601）
  - `shipping`: 物流信息（可选）
  - `pmt_hash`: **前序 PaymentMandate 的哈希值**
  - `metadata`: 业务特定的履约数据（可选）
- `merchant_authorization`: JWS 格式的商户授权签名

**merchant_authorization Payload**：

```json
{
  "iss": "did:wba:a.com:MA",
  "sub": "did:wba:a.com:MA",
  "aud": "did:wba:a.com:TA",
  "iat": 1730000000,
  "exp": 1730000900,
  "jti": "fulfillment_uuid_456",
  "credential_type": "FulfillmentReceipt",
  "cred_hash": "<b64url(sha256(JCS(contents)))>"
}
```

**注意**：PaymentReceipt 和 FulfillmentReceipt 都包含 `pmt_hash` 字段（指向同一个 PaymentMandate），形成分支哈希链。

---

---

## 4. FulfillmentReceipt（履约凭证）

**方向**：MA → TA（通过 Webhook）

**数据结构**：

```json
{
  "contents": {
    "credential_type": "FulfillmentReceipt",
    "version": 1,
    "id": "fulfillment_uuid_456",
    "timestamp": "2025-01-18T10:00:00Z",
    "order_id": "order_shoes_123",
    "items": [
      {
        "id": "sku-id-123",
        "quantity": 1
      }
    ],
    "fulfilled_at": "2025-01-18T09:45:00Z",
    "shipping": {
      "carrier": "顺丰速运",
      "tracking_number": "SF1234567890",
      "delivered_eta": "2025-01-20T18:00:00Z"
    },
    "pmt_hash": "pmt_hash",
    "metadata": {
      "warehouse": "Beijing-001",
      "notes": "已发货，请注意查收"
    }
  },
  "merchant_authorization": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**字段说明**：

- `contents`: FulfillmentReceiptContents 对象（plain dict）
  - `credential_type`: 固定值 "FulfillmentReceipt"
  - `version`: 凭证版本号，当前为 1
  - `id`: 凭证唯一标识符（UUID）
  - `timestamp`: 凭证签发时间（ISO-8601）
  - `order_id`: 订单 ID
  - `items`: 履约商品列表
  - `fulfilled_at`: 履约完成时间（ISO-8601）
  - `shipping`: 物流信息（可选）
  - `pmt_hash`: **前序 PaymentMandate 的哈希值**
  - `metadata`: 业务特定的履约数据（可选）
- `merchant_authorization`: JWS 格式的商户授权签名

**merchant_authorization Payload**：

```json
{
  "iss": "did:wba:a.com:MA",
  "sub": "did:wba:a.com:MA",
  "aud": "did:wba:a.com:TA",
  "iat": 1730000000,
  "exp": 1730000900,
  "jti": "fulfillment_uuid_456",
  "credential_type": "FulfillmentReceipt",
  "cred_hash": "<b64url(sha256(JCS(contents)))>"
}
```

**注意**：PaymentReceipt 和 FulfillmentReceipt 都包含 `pmt_hash` 字段（指向同一个 PaymentMandate），形成分支哈希链。

---

# 消息定义

## 1. create_cart_mandate

**方向**：Shopper (TA) → Merchant (MA)

**API 路径**：`POST /ap2/merchant/create_cart_mandate`

**请求消息结构**：

```json
{
  "messageId": "cart-request-001",
  "from": "did:wba:a.com:shopper",
  "to": "did:wba:a.com:merchant",
  "data": {
    "cart_mandate_id": "cart-mandate-id-123",
    "items": [
      {
        "id": "sku-id-123",
        "quantity": 1,
        "options": {
          "color": "red",
          "size": "42"
        },
        "remark": "请尽快发货"
      }
    ],
    "shipping_address": {
      "recipient_name": "张三",
      "phone": "13800138000",
      "region": "北京市",
      "city": "北京市",
      "address_line": "朝阳区某某街道123号",
      "postal_code": "100000"
    },
    "remark": "请尽快发货"
  }
}
```

**响应消息结构**（返回 CartMandate）：

```json
{
  "messageId": "cart-response-001",
  "from": "did:wba:a.com:merchant",
  "to": "did:wba:a.com:shopper",
  "data": {
    "contents": {
      "id": "cart-mandate-id-123",
      "user_signature_required": false,
      "payment_request": {
        "method_data": [
          {
            "supported_methods": "QR_CODE",
            "data": {
              "channel": "ALIPAY",
              "qr_url": "https://pay.example.com/qrcode/abc123",
              "out_trade_no": "order_20250117_123456",
              "expires_at": "2025-01-17T09:15:00Z"
            }
          }
        ],
        "details": {
          "id": "order_shoes_123",
          "displayItems": [
            {
              "id": "sku-id-123",
              "label": "Nike Air Max 90",
              "quantity": 1,
              "options": {
                "color": "red",
                "size": "42"
              },
              "amount": {
                "currency": "CNY",
                "value": 120.0
              },
              "pending": null
            }
          ],
          "total": {
            "label": "Total",
            "amount": {
              "currency": "CNY",
              "value": 120.0
            },
            "pending": null
          }
        },
        "shipping_address": {
          "shipping_address": null,
          "shipping_option": null,
          "payer_name": null,
          "payer_email": null,
          "payer_phone": null
        }
      }
    },
    "merchant_authorization": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "timestamp": "2025-01-17T09:00:01Z"
  }
}
```

**关键点**：

- 请求中的 `items` 包含商品 SKU、数量及可选属性
- 响应返回完整的 CartMandate，包含二维码信息
- `merchant_authorization` 是商户对购物车内容的授权签名

## 2. send_payment_mandate

**方向**：Shopper (TA) → Merchant (MA)

**API 路径**：`POST /ap2/merchant/send_payment_mandate`

**请求消息结构**：

```json
{
  "messageId": "payment-mandate-001",
  "from": "did:wba:a.com:shopper",
  "to": "did:wba:a.com:merchant",
  "mandate_webhook_url": "https://merchant.example.com/ap2/mandate",
  "data": {
    "payment_mandate_contents": {
      "payment_mandate_id": "pm_12345",
      "payment_details_id": "order_shoes_123",
      "payment_details_total": {
        "label": "Total",
        "amount": {
          "currency": "CNY",
          "value": 120.0
        },
        "pending": null,
        "refund_period": 30
      },
      "payment_response": {
        "request_id": "order_shoes_123",
        "method_name": "QR_CODE",
        "details": {
          "channel": "ALIPAY",
          "out_trade_no": "order_20250117_123456"
        },
        "shipping_address": null,
        "shipping_option": null,
        "payer_name": null,
        "payer_email": null,
        "payer_phone": null
      },
      "merchant_agent": "MerchantAgent",
      "timestamp": "2025-01-17T09:05:00Z",
      "cart_hash": "cart_hash"
    },
    "user_authorization": "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXhhbXBsZ..."
  }
}
```

**关键点**：

- `payment_mandate_contents.cart_hash` 存储前序 CartMandate 的哈希值
- `user_authorization` 包含对整个 `payment_mandate_contents` 的签名

## 消息流转顺序

完整的 AP2 交易流程包含以下步骤：

1. **TA 请求** → MA：`create_cart_mandate`

   - TA 发送购物车请求，包含商品信息和配送地址

2. **MA 响应** → TA：`CartMandate`

   - MA 返回签名的购物车授权，包含支付二维码
   - 包含 `merchant_authorization` 签名

3. **TA 发送** → MA：`PaymentMandate`

   - 用户完成支付后，TA 发送支付授权
   - 包含 `user_authorization` 签名和 `cart_hash`（指向前序 CartMandate）

4. **MA 推送** → TA：`PaymentReceipt`（通过 Webhook）

   - MA 确认支付成功后，推送支付凭证
   - 包含支付提供商的交易信息和 `pmt_hash`（指向前序 PaymentMandate）

5. **MA 推送** → TA：`FulfillmentReceipt`（通过 Webhook，可选）
   - MA 完成订单履约后，推送履约凭证
   - 包含物流信息和 `pmt_hash`（指向前序 PaymentMandate）

**哈希链完整视图**：

```
CartMandate(cart_hash)
    ↓
PaymentMandate(cart_hash,pmt_hash)
    ↓
    ├─→ PaymentReceipt(pmt_hash,cred_hash)
    └─→ FulfillmentReceipt(pmt_hash,cred_hash)
```
