# DID WBA 身份认证集成指南

> [English Version](DID_WBA_AUTH_GUIDE.en.md)

本文档说明如何使用 ANP SDK（`anp` 包）为 Python HTTP Server 集成 DID WBA 身份认证。读完本文档后，你可以快速为任何 Python HTTP 服务添加去中心化身份验证能力。

## 1. 认证原理

### 1.1 什么是 DID WBA

DID WBA（Web-Based Agent）是一种基于 W3C DID 标准的去中心化身份认证方法。它允许客户端在首次 HTTP 请求中携带 DID 和签名，服务端无需额外交互即可验证客户端身份。

核心特点：
- 基于非对称加密，客户端持有私钥，服务端通过 DID 文档获取公钥验证签名
- 当前 SDK 默认使用 **HTTP Message Signatures**；旧版 `Authorization: DIDWba ...` 头仍然兼容
- 首次认证后服务端颁发 Access Token；标准返回头为 `Authentication-Info`，并在迁移期额外返回兼容 `Authorization: Bearer ...`
- 与 HTTPS 配合，客户端通过 TLS 证书验证服务端，服务端通过 DID 签名验证客户端

> **当前 SDK 默认行为（重要）**
>
> - `create_did_wba_document()` 默认创建 `e1_` 路径型 DID
> - `DIDWbaAuthHeader` 默认发送 `Signature-Input` / `Signature`
> - `resolve_did_wba_document()` 会自动校验 `e1_` / `k1_` 与 DID 文档绑定关系
> - 对 `e1_` DID，proof 是绑定关系的一部分，必须存在且有效

### 1.2 认证流程

```
首次请求（默认 HTTP Message Signatures）：
Client                              Server                    Client DID Server
  |                                    |                            |
  |-- HTTP Request ------------------>|                            |
  |   Signature-Input: sig1=(...)     |                            |
  |   Signature: sig1=:...:           |-- GET /user/alice/...----->|
  |   Content-Digest: sha-256=:...:   |<-- DID Document -----------|
  |                                   |                            |
  |                                   |  1. 验证 DID 文档 id / 绑定 / proof
  |                                   |  2. 验证 created / expires / nonce
  |                                   |  3. 验证 HTTP Message Signature
  |                                   |  4. 验证 Content-Digest
  |                                   |  5. 验证成功 → 生成 JWT
  |                                   |
  |<-- HTTP Response -----------------|
  |    Authentication-Info: access_token="..." |
  |    Authorization: Bearer <JWT>    |  (兼容返回)
  |                                   |

后续请求（使用 JWT，更快）：
Client                              Server
  |                                    |
  |-- HTTP Request ------------------>|
  |   Authorization: Bearer <JWT>     |
  |                                   |  验证 JWT 签名和有效期
  |<-- HTTP Response -----------------|
```

### 1.3 默认请求头格式（HTTP Message Signatures）

首次认证时，客户端默认发送以下头字段：

```http
POST /orders HTTP/1.1
Host: api.example.com
Content-Type: application/json
Content-Digest: sha-256=:BASE64_SHA256_DIGEST:
Signature-Input: sig1=("@method" "@target-uri" "@authority" "content-digest");created=1733402096;expires=1733402156;nonce="abc123";keyid="did:wba:example.com:user:alice:e1_<fingerprint>#key-1"
Signature: sig1=:BASE64_SIGNATURE:
```

关键点：
- `keyid`：完整 DID URL，指向 DID 文档中的验证方法
- `created` / `expires`：签名时间窗口
- `nonce`：防重放挑战值
- `Signature`：对 RFC 9421 signature base 的签名
- `Content-Digest`：请求消息体完整性摘要

### 1.3.1 兼容请求头格式（旧版 DIDWba）

如果客户端显式使用 `auth_mode="legacy_didwba"`，或者对接旧客户端，仍可发送：

```http
Authorization: DIDWba did="did:wba:example.com:user:alice:k1_<fingerprint>", nonce="abc123", timestamp="2024-12-05T12:34:56Z", verification_method="key-1", signature="base64url(签名值)"
```

### 1.4 签名验证过程

服务端收到请求后执行以下步骤：

默认 HTTP Message Signatures 流程中，服务端会：

1. 解析 `Signature-Input` / `Signature` / `Content-Digest`
2. 验证时间窗口与 `nonce`
3. 根据 `keyid` 解析 DID 文档
4. 校验 DID 文档 `id`
5. 校验 `e1_` / `k1_` 路径绑定与 DID 文档公钥是否一致
6. 对 `e1_` DID，强制校验 DID Document proof，并要求 proof 使用的公钥就是绑定 key
7. 用 DID 文档中的对应公钥验证请求签名
8. 验证通过后生成 RS256 JWT Token 返回给客户端

## 2. 安装依赖

```bash
pip install anp
# 或使用 uv
uv add anp
```

如果需要 FastAPI 支持：

```bash
pip install anp[api]
# 或
uv add anp --extra api
```

## 3. 服务端集成

### 3.1 核心类介绍

ANP SDK 提供以下核心类用于服务端认证：

| 类 | 模块 | 用途 |
|---|------|------|
| `DidWbaVerifierConfig` | `anp.authentication` | 验证器配置（JWT 密钥、过期时间等） |
| `DidWbaVerifier` | `anp.authentication` | 核心验证器，验证 DID WBA 头和 Bearer Token |
| `auth_middleware` | `anp.openanp.middleware` | FastAPI 中间件，自动拦截请求做认证 |
| `create_auth_middleware` | `anp.openanp.middleware` | 中间件工厂函数，一行创建中间件 |

### 3.2 最小示例：FastAPI + DID WBA 认证

```python
"""使用 ANP SDK 为 FastAPI 服务添加 DID WBA 认证的最小示例。"""

from fastapi import FastAPI, Request
from anp.authentication import DidWbaVerifier, DidWbaVerifierConfig
from anp.openanp.middleware import auth_middleware

# 1. 准备 JWT 密钥（RS256）
#    生成方式：openssl genrsa -out private.pem 2048
#              openssl rsa -in private.pem -pubout -out public.pem
with open("private.pem") as f:
    jwt_private_key = f.read()
with open("public.pem") as f:
    jwt_public_key = f.read()

# 2. 创建验证器
config = DidWbaVerifierConfig(
    jwt_private_key=jwt_private_key,
    jwt_public_key=jwt_public_key,
    jwt_algorithm="RS256",
    access_token_expire_minutes=60,
)
verifier = DidWbaVerifier(config)

# 3. 创建 FastAPI 应用并注册中间件
app = FastAPI()

# 免认证路径列表
exempt_paths = ["/health", "/docs", "/openapi.json"]

@app.middleware("http")
async def did_wba_auth(request: Request, call_next):
    return await auth_middleware(
        request, call_next, verifier, exempt_paths=exempt_paths
    )

# 4. 定义路由
@app.get("/health")
async def health():
    """免认证端点。"""
    return {"status": "healthy"}

@app.get("/api/protected")
async def protected(request: Request):
    """受保护端点，需要 DID 认证。"""
    did = request.state.did          # 认证通过后自动注入 DID
    return {"message": "认证成功", "did": did}
```

### 3.3 DidWbaVerifierConfig 配置详解

```python
from anp.authentication import DidWbaVerifierConfig

config = DidWbaVerifierConfig(
    # JWT 签名密钥（PEM 格式字符串），用于生成和验证 Bearer Token
    jwt_private_key="-----BEGIN RSA PRIVATE KEY-----\n...",
    jwt_public_key="-----BEGIN PUBLIC KEY-----\n...",
    jwt_algorithm="RS256",            # JWT 签名算法

    # Token 有效期
    access_token_expire_minutes=60,   # Bearer Token 过期时间（分钟）

    # 安全参数
    nonce_expiration_minutes=6,       # Nonce 记录过期时间（应略大于 timestamp 过期时间）
    timestamp_expiration_minutes=5,   # 时间戳有效窗口（分钟）

    # 可选：自定义 Nonce 验证函数（用于分布式部署共享 Nonce 状态）
    # 签名：(did: str, nonce: str) -> bool（也支持 async）
    external_nonce_validator=None,

    # 可选：域名白名单，限制允许认证的域名
    allowed_domains=["example.com", "localhost"],
)
```

### 3.4 中间件行为说明

`auth_middleware` 的工作流程：

1. 检查请求路径是否在 `exempt_paths` 中（支持通配符如 `*/ad.json`、`/info/*`）
2. 如果免认证，直接放行
3. 如果需要认证，从请求的 `Authorization` 头提取认证信息
4. 如果请求中带有 `Signature-Input` / `Signature`，执行默认 HTTP Message Signatures 验证流程；如果是 `DIDWba` 开头，则走兼容验证流程。验证通过后：
   - 将认证结果存入 `request.state.auth_result`
   - 将 DID 存入 `request.state.did`
   - 在响应头 `Authentication-Info` 中返回 access token
   - 在迁移期额外通过响应头 `Authorization` 返回 `Bearer <JWT>` 以兼容旧客户端
5. 如果是 `Bearer` 开头，验证 JWT Token
6. 认证失败返回 401 或 403 JSON 响应

### 3.5 简化写法：使用 create_auth_middleware

```python
from fastapi import FastAPI
from anp.authentication import DidWbaVerifierConfig
from anp.openanp.middleware import create_auth_middleware

app = FastAPI()

config = DidWbaVerifierConfig(
    jwt_private_key=open("private.pem").read(),
    jwt_public_key=open("public.pem").read(),
    jwt_algorithm="RS256",
)

# 一行注册中间件
app.middleware("http")(
    create_auth_middleware(config, exempt_paths=["/health", "/docs"])
)
```

### 3.6 在路由函数中获取认证信息

中间件认证通过后，在路由函数中通过 `request.state` 获取认证信息：

```python
@app.get("/api/data")
async def get_data(request: Request):
    # 获取已认证的 DID
    did: str = request.state.did
    # 例如：did = "did:wba:example.com:user:alice"

    # 获取完整认证结果
    auth_result: dict = request.state.auth_result
    # 首次认证：{"access_token": "...", "token_type": "bearer", "did": "...", "auth_scheme": "...", "response_headers": {...}}
    # Bearer Token 认证：{"did": "...", "auth_scheme": "bearer", "response_headers": {}}

    return {"did": did, "data": "..."}
```

### 3.7 不使用中间件：手动调用验证器

如果你不使用 FastAPI 或需要更细粒度的控制，可以直接使用 `DidWbaVerifier`：

```python
from anp.authentication import DidWbaVerifier, DidWbaVerifierConfig, DidWbaVerifierError

config = DidWbaVerifierConfig(
    jwt_private_key=open("private.pem").read(),
    jwt_public_key=open("public.pem").read(),
)
verifier = DidWbaVerifier(config)

# 在任意 HTTP 框架中使用
async def handle_request(method: str, url: str, headers: dict, body: bytes):
    try:
        result = await verifier.verify_request(
            method=method,
            url=url,
            headers=headers,
            body=body,
        )
        did = result["did"]
        access_token = result.get("access_token")  # 首次 DID 认证才有
        return did, access_token
    except DidWbaVerifierError as e:
        # e.status_code: 401（认证失败）、403（权限不足）、500（内部错误）
        return None, None
```

适用于 aiohttp、Flask、Django 等任意 Python HTTP 框架。

## 4. 客户端集成

### 4.1 使用 DIDWbaAuthHeader

SDK 提供 `DIDWbaAuthHeader` 类自动管理认证头和 Token 缓存：

```python
from anp.authentication import DIDWbaAuthHeader
import httpx

# 1. 创建认证客户端
authenticator = DIDWbaAuthHeader(
    did_document_path="path/to/did.json",       # DID 文档路径
    private_key_path="path/to/private-key.pem",  # 对应私钥路径
)

server_url = "https://example.com"

# 2. 首次请求：默认自动生成 HTTP Message Signatures
headers = authenticator.get_auth_header(server_url, force_new=True)
# 默认返回 {"Signature-Input": "...", "Signature": "..."}
# 如果 auth_mode="legacy_didwba"，则返回 {"Authorization": "DIDWba ..."}

with httpx.Client() as client:
    response = client.get(f"{server_url}/api/data", headers=headers)

    # 3. 从响应中提取并缓存 Bearer Token
    authenticator.update_token(server_url, dict(response.headers))

    # 4. 后续请求：自动使用缓存的 Bearer Token
    headers = authenticator.get_auth_header(server_url)
    # headers = {"Authorization": "Bearer eyJ..."}
    response = client.get(f"{server_url}/api/other", headers=headers)
```

### 4.2 DIDWbaAuthHeader 关键方法

| 方法 | 说明 |
|------|------|
| `get_auth_header(server_url, force_new=False)` | 获取认证头。有缓存 Token 时返回 Bearer 头；否则默认生成 HTTP Message Signatures 头；若 `auth_mode=\"legacy_didwba\"` 则生成旧版 DIDWba 头 |
| `update_token(server_url, headers)` | 从响应头中提取 Bearer Token 并缓存 |
| `clear_token(server_url)` | 清除指定域名的缓存 Token |
| `clear_all_tokens()` | 清除所有缓存 Token |

### 4.3 处理 Token 过期

```python
response = client.get(f"{server_url}/api/data", headers=headers)

if response.status_code == 401:
    # Token 过期或无效，清除缓存，重新进行 DID 认证
    authenticator.clear_token(server_url)
    headers = authenticator.get_auth_header(server_url, force_new=True)
    response = client.get(f"{server_url}/api/data", headers=headers)

    # 缓存新 Token
    authenticator.update_token(server_url, dict(response.headers))
```

## 5. DID 文档和密钥准备

### 5.1 生成 DID 文档

使用 SDK 提供的函数生成 DID 文档：

```python
from anp.authentication import create_did_wba_document

did_document, private_keys = create_did_wba_document(
    hostname="example.com",
    path_segments=["user", "alice"],
)
# 默认路径型 DID 形如：did:wba:example.com:user:alice:e1_<fingerprint>
# private_keys 包含生成的私钥对象

import json
with open("did.json", "w") as f:
    json.dump(did_document, f, indent=2)
```

或使用命令行工具：

```bash
uv run python tools/did_generater/generate_did_doc.py "did:wba:example.com:user:alice"
```

### 5.2 生成 JWT RS256 密钥对

服务端需要一对 RS256 密钥用于签发和验证 Bearer Token（这对密钥与 DID 文档中的密钥不同）：

```bash
# 生成 RSA 私钥
openssl genrsa -out RS256-private.pem 2048

# 导出公钥
openssl rsa -in RS256-private.pem -pubout -out RS256-public.pem
```

### 5.3 部署 DID 文档

DID 文档必须部署到可通过 HTTPS 访问的路径：

```
did:wba:example.com              → https://example.com/.well-known/did.json
did:wba:example.com:user:alice   → https://example.com/user/alice/did.json
did:wba:example.com%3A3000       → https://example.com:3000/.well-known/did.json
```

服务端验证时会根据客户端 DID 自动解析对应 URL 获取 DID 文档。

## 6. 完整示例

本目录下提供了可运行的完整示例：

- `http_server.py` — FastAPI 服务端，集成 DID WBA 认证中间件
- `http_client.py` — HTTP 客户端，演示完整的认证和 Token 复用流程
- `authenticate_and_verify.py` — 离线演示，不需要启动服务器，演示认证+验证完整流程
- `create_did_document.py` — 生成 DID 文档示例

运行方式：

```bash
# 终端 1：启动服务端
uv run python examples/python/did_wba_examples/http_server.py

# 终端 2：运行客户端
uv run python examples/python/did_wba_examples/http_client.py
```

## 7. 自定义 DID 文档解析

默认情况下，SDK 通过 HTTPS 请求解析 DID 文档。在开发/测试环境中可替换为本地解析：

```python
from anp.authentication import did_wba_verifier as verifier_module

# 方式一：替换全局解析函数（适用于测试）
async def local_resolver(did: str) -> dict:
    # 从本地文件或数据库加载 DID 文档
    return load_did_from_db(did)

verifier_module.resolve_did_wba_document = local_resolver

# 方式二：在生产环境中，确保客户端 DID 对应的 HTTPS 路径可访问即可
# SDK 会自动从 https://<domain>/<path>/did.json 获取文档
```

## 8. 安全注意事项

1. **私钥保管**：DID 私钥和 JWT 私钥必须安全存储，不要提交到代码仓库
2. **HTTPS**：生产环境必须使用 HTTPS，DID 文档的获取也必须通过 HTTPS
3. **Nonce 防重放**：内置的 Nonce 验证是内存级的（单进程有效）。分布式部署时应通过 `external_nonce_validator` 接入 Redis 等共享存储
4. **时间戳**：服务端和客户端的时钟偏差不应超过配置的 `timestamp_expiration_minutes`
5. **Token 有效期**：根据业务需要调整 `access_token_expire_minutes`，建议不超过 24 小时
6. **域名白名单**：生产环境建议配置 `allowed_domains` 限制认证来源

## 9. 参考资料

- [did:wba 方法规范](https://github.com/agent-network-protocol/AgentNetworkProtocol/blob/main/03-did-wba-method-design-specification.md)
- [W3C DID Core 规范](https://www.w3.org/TR/did-core/)
- [ANP SDK 仓库](https://github.com/agent-network-protocol/AgentConnect)
- [JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785)
