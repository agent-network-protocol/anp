
# ad.json描述方法

增加一个Protocol
```json
    {
      "type": "StructuredInterface",
      "protocol": "AP2/ANP",
      "version": "0.0.1",
      "url": "https://grand-hotel.com/api/ap2.json",
      "description": "An implementation of the AP2 protocol based on the ANP protocol, used for payment and transactions between agents."
    },
```

ap2.json内容：
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

roles的类型：
```json
AP2Role = "merchant" | "shopper" | "credentials-provider" | "payment-processor"
```

也可以直接在Interface中描述：

```json
    {
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

**完整消息结构**（包含 ANP 消息头）：

```json
{
  "contents": {
    "id": "cart_shoes_123",
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
            "sku": "Nike-Air-Max-90",
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
  "merchant_authorization": "sig_merchant_shoes_abc1",  # 代码中已经更改为merchant_authorization
  "timestamp": "2025-08-26T19:36:36.377022Z"
}
```

**关键点**：
- `contents` 包含购物车内容、支付请求和二维码信息
- `merchant_authorization` 是对 `cart_hash` 的 JWS 签名（RS256 或 ES256K）
- `cart_hash = b64url(sha256(JCS(contents)))`


以下是你可直接纳入《ANP-AP2 最小实现规范（M1）》中的 **正式版本段落**，用于指导开发者实现 `merchant_authorization` 字段的签名与验签逻辑。语法、格式、字段含义及流程均已对齐最新规范。

---

## Merchant Authorization（商户授权凭证）

### 概述

`merchant_authorization` 字段是商户对购物车内容 (`CartContents`) 的**短期数字签名授权凭证**，用于保证购物车内容的真实性与完整性。
该字段取代旧版的 `merchant_signature`，并采用符合 JOSE/JWT 标准的 **JSON Web Signature (JWS)** 容器格式。

---

### 数据类型

* **类型**：base64url 编码的紧凑 JWS 字符串（`header.payload.signature`）
* **算法**：`RS256` 或 `ES256K`
* **字段**：`CartMandate.merchant_authorization`

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

```json
{
  "iss": "did:wba:a.com:MA",             // 签发者（商户智能体 DID）
  "sub": "did:wba:a.com:MA",             // 主体（可与 iss 相同）
  "aud": "did:wba:a.com:TA",             // 受众（交易智能体或支付处理方）
  "iat": 1730000000,               // 签发时间（秒）
  "exp": 1730000900,               // 过期时间（建议 180天）
  "jti": "uuid",                   // 全局唯一标识符（防重放攻击）
  "cart_hash": "<b64url>",         // 对 CartMandate.contents 的哈希（见下节）
  "cnf": { "kid": "did:wba:a.com:TA#keys-1" },  // （推荐）持有者绑定信息，kid是did文档中的key对应的ID。
  "sd_hash": "<b64url, optional>", // （可选）SD-JWT / VC 哈希指针占位
}
```

---

### `cart_hash` 计算规则

```text
cart_hash = Base64URL( SHA-256( JCS(CartMandate.contents) ) )
```

* 使用 [RFC 8785 JSON Canonicalization Scheme (JCS)](https://datatracker.ietf.org/doc/rfc8785/) 对 `CartMandate.contents` 进行规范化。
* 对规范化后的 UTF-8 字节执行 `SHA-256` 哈希。
* 将结果 Base64URL 编码（去掉“=”填充）。

---

### 签名生成流程（商户端 MA）

1. 计算 `cart_hash`。
2. 构造 JWT Payload（含 `iss/sub/aud/iat/exp/jti/cart_hash/cnf/sd_hash/extensions`）。
3. 构造 Header（`alg=RS256` 或 `alg=ES256K`, `kid=<商户公钥标识>`）。
4. 用商户私钥对 payload 进行签名，生成紧凑 JWS。
5. 将生成的 JWS 作为 `merchant_authorization` 写入 `CartMandate` 对象。

---

### 验签流程（交易端 TA）

1. 对 `CartMandate.contents` 重新计算 `cart_hash'`。
2. 解析 `merchant_authorization`：

   * 提取 Header → `kid`。
   * 通过 DID 文档或注册表获取 MA 的公钥。
   * 验证 JWS 签名（RS256 或 ES256K，与 Header 匹配）。
3. 校验声明：

   * `iss/aud/iat/exp/jti` 均符合规范；
   * 当前时间在 `[iat, exp]` 内；
   * `jti` 未被重复使用。
4. 校验数据绑定：

   * `payload.cart_hash == cart_hash'`，否则拒绝。
5. 识别扩展：

   * 如存在 `sd_hash`，进入 SD-JWT/VC 路径；
   * 如存在 `cnf`，可用于后续持有者验证。

---

### 参考实现（Python / PyJWT）

```python
import json, base64, hashlib, uuid, time
import jwt  # pip install pyjwt

def jcs_canonicalize(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

def b64url_no_pad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")

def compute_cart_hash(contents: dict) -> str:
    canon = jcs_canonicalize(contents)
    digest = hashlib.sha256(canon.encode("utf-8")).digest()
    return b64url_no_pad(digest)

def sign_merchant_authorization(contents: dict, ma_private_pem: str, kid: str,
                                iss: str, aud: str, cnf: dict = None,
                                sd_hash: str = None, ttl_seconds: int = 900) -> str:
    now = int(time.time())
    payload = {
        "iss": iss,
        "sub": iss,
        "aud": aud,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": str(uuid.uuid4()),
        "cart_hash": compute_cart_hash(contents),
        "extensions": ["anp.ap2.qr.v1","anp.human_presence.v1"]
    }
    if cnf: payload["cnf"] = cnf
    if sd_hash: payload["sd_hash"] = sd_hash
    headers = {"alg": "RS256", "kid": kid, "typ": "JWT"}
    return jwt.encode(payload, ma_private_pem, algorithm="RS256", headers=headers)
```

---

### 校验清单

| 校验项    | 要求                                        |
| ------ | ----------------------------------------- |
| 签名算法   | RS256 或 ES256K（需与 Header.alg 一致） |
| 时间窗    | `iat ≤ now ≤ exp`，有效期 ≤ 15 分钟             |
| 重放防护   | `jti` 全局唯一                                |
| 签发者与受众 | `iss=MA`，`aud=TA`（或 MPP）                  |
| 数据一致性  | `payload.cart_hash == computed_cart_hash` |
| DID 解析 | 通过 `kid` → DID 文档解析公钥                     |
| 兼容扩展   | 支持解析 `cnf`、`sd_hash` 字段                   |

---

### 向后兼容与升级策略

* 开发者应逐步弃用 `merchant_signature`，统一迁移到 `merchant_authorization`。
* 解析逻辑应具备兼容性：优先读取 `merchant_authorization`，如缺失可回退旧字段。
* 未来 M2/M3 版本中，`sd_hash` 将扩展为 SD-JWT-VC 链路标识，实现可选择性披露与可验证凭证互操作。

---

### 小结

> `merchant_authorization` 是商户为购物车内容生成的短期可验证授权凭证。
> 它结合 `cart_hash`、`cnf` 与 `sd_hash` 提供完整的**数据完整性验证、身份绑定、隐私升级通路**。
> 所有签发与验证过程均基于标准 JWS/JWT 机制，可直接在现有 JOSE 库上实现。

## 2. PaymentMandate（支付授权）

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
            "out_trade_no": "order_20250117_123456",
        },
        "shipping_address": null,
        "shipping_option": null,
        "payer_name": null,
        "payer_email": null,
        "payer_phone": null
    },
    "merchant_agent": "MerchantAgent",
    "timestamp": "2025-08-26T19:36:36.377022Z"
  },
  "user_authorization": "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXhhbXBsZ..."
}
```

字段说明：
- payment_details_id：cart mandate中Payment request的detail的ID


### user_authorization(用户授权)

user_authorization的生成方式参考： [## Merchant Authorization（商户授权凭证）](#merchant-authorization商户授权凭证)

不同点：使用transaction_data代替cart_hash，transaction_data包含cart_hash和pmt_hash。

```json
"transaction_data": [
    "<cart_hash>",                            // b64url(sha256(JCS(CartMandate.contents)))
    "<pmt_hash>"                              // b64url(sha256(JCS(PaymentMandate.contents_wo_sig)))
  ],
```

pmt_hash的生成方式参考cart_hash的生成方式：

```text
pmt_hash = Base64URL( SHA-256( JCS(PaymentMandate.contents) ) )
```

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
        "sku": "Nike-Air-Max-90",
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
              "sku": "Nike-Air-Max-90",
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

payment_mandate的定义参考上面。

```json
{

  "messageId": "payment-mandate-001",
  "from": "did:wba:a.com:shopper",
  "to": "did:wba:a.com:merchant",
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
      "timestamp": "2025-01-17T09:05:00Z"
    },
    "user_authorization": "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6ZXhhbXBsZ..."
  }
}
```


## 消息流转顺序

1. **TA 请求** → MA：`create_cart_mandate`（不在三个核心消息中，但触发购物车创建）
2. **MA 返回（在http响应中）** → TA：`CartMandate`（购物车授权 + 二维码）
3. **TA 返回** → MA：`PaymentMandate`（支付授权）


