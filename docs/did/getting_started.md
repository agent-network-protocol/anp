# DID (去中心化身份标识符) 入门指南

## 1. 概述

去中心化身份标识符 (DID) 是一种新型的身份标识符，它使个人和组织能够创建和控制自己的数字身份，无需依赖于中心化的注册机构。AgentConnect 实现了 Web Based Agent (WBA) 的DID标准，允许通过Web服务器解析DID文档。

本指南将帮助你理解并使用 AgentConnect 的 DID WBA 功能，包括：

- DID文档的创建
- 密钥对的生成和管理
- 设置DID服务器
- 使用DID私钥对HTTP请求进行签名
- DID身份验证

## 2. DID文档和私钥创建

### 2.1 基本概念

DID文档是描述去中心化身份的JSON-LD文档，包含以下核心元素：

- `id`: DID的唯一标识符
- `verificationMethod`: 用于验证身份的方法列表
- `authentication`: 身份验证方法引用列表
- `service`: 可选的服务端点列表

### 2.2 创建DID文档和私钥

以下示例展示如何使用AgentConnect创建DID文档和相应的私钥：

```python
from anp.authentication import create_did_wba_document

# Create DID document and key pair
did_document, keys = create_did_wba_document(
    hostname="example.com",              # Hostname
    path_segments=["user", "alice"],     # Optional path segments
    agent_description_url="https://example.com/agents/alice/description.json"  # Optional agent description URL
)

# did_document is the generated DID document
# keys is a dictionary containing private and public keys in format {method_fragment: (private_key_bytes, public_key_bytes)}
```

生成的DID将格式为: `did:wba:example.com:user:alice`

### 2.3 保存私钥和DID文档

私钥必须安全存储，因为它们用于身份验证和签名操作：

```python
import json
from pathlib import Path

def save_private_key(unique_id, keys, did_document):
    # Create user directory
    user_dir = Path("did_keys") / f"user_{unique_id}"
    user_dir.mkdir(parents=True, exist_ok=True)
    
    # Save private keys
    for method_fragment, (private_key_bytes, _) in keys.items():
        private_key_path = user_dir / f"{method_fragment}_private.pem"
        with open(private_key_path, 'wb') as f:
            f.write(private_key_bytes)
    
    # Save DID document
    did_path = user_dir / "did.json"
    with open(did_path, 'w', encoding='utf-8') as f:
        json.dump(did_document, f, indent=2)
    
    return str(user_dir)
```

## 3. 设置DID服务器

DID WBA标准要求DID文档能够通过HTTP请求获取。你需要设置一个Web服务器来提供这些文档。

### 3.1 服务器要求

- 服务器必须能够响应对DID文档的GET请求
- 文档应以JSON格式提供
- 服务器应支持HTTPS (生产环境)

### 3.2 服务器路由

DID服务器应支持以下路由：

1. **获取DID文档**: `GET https://{hostname}/{path_segments}/did.json`
2. **上传DID文档**: `PUT https://{hostname}/{path_segments}/did.json`

### 3.3 实现示例

以下是使用aiohttp实现简单DID服务器的例子：

```python
from aiohttp import web
import json
import os
from pathlib import Path

# Storage directory for DID documents
DID_STORAGE = Path("did_storage")
DID_STORAGE.mkdir(exist_ok=True)

async def get_did_document(request):
    # Extract user ID from URL
    user_id = request.match_info.get('user_id')
    
    # Look up DID document
    did_path = DID_STORAGE / f"user_{user_id}" / "did.json"
    
    if not did_path.exists():
        return web.Response(status=404, text="DID document not found")
    
    with open(did_path, 'r') as f:
        did_document = json.load(f)
    
    return web.json_response(did_document)

async def put_did_document(request):
    # Extract user ID from URL
    user_id = request.match_info.get('user_id')
    
    # Read DID document from request
    try:
        did_document = await request.json()
    except Exception:
        return web.Response(status=400, text="Invalid JSON")
    
    # Create user directory
    user_dir = DID_STORAGE / f"user_{user_id}"
    user_dir.mkdir(exist_ok=True)
    
    # Save DID document
    did_path = user_dir / "did.json"
    with open(did_path, 'w') as f:
        json.dump(did_document, f, indent=2)
    
    return web.Response(status=200, text="DID document uploaded successfully")

# Create web application
app = web.Application()
app.router.add_get('/wba/user/{user_id}/did.json', get_did_document)
app.router.add_put('/wba/user/{user_id}/did.json', put_did_document)

# Start server
if __name__ == '__main__':
    web.run_app(app, host='0.0.0.0', port=9000)
```

## 4. 使用DID私钥对HTTP请求进行签名

### 4.1 DID身份验证概述

DID WBA身份验证过程包括：

1. 客户端生成一个nonce（随机数）和时间戳
2. 客户端使用私钥对包含nonce、时间戳、服务域名和DID的数据进行签名
3. 客户端将DID、nonce、时间戳、验证方法ID和签名发送到服务器
4. 服务器解析DID文档，验证签名

### 4.2 创建身份验证头

AgentConnect提供`DIDWbaAuthHeader`类，简化了身份验证过程：

```python
from anp.authentication import DIDWbaAuthHeader

# Create DIDWbaAuthHeader instance
auth_client = DIDWbaAuthHeader(
    did_document_path="path/to/did.json",
    private_key_path="path/to/key-1_private.pem"
)

# Get authentication header for specific URL
url = "https://example.com/resource"
auth_headers = auth_client.get_auth_header(url)

# Send request with authentication header
async with aiohttp.ClientSession() as session:
    async with session.get(url, headers=auth_headers) as response:
        # Process response
        pass
```

### 4.3 手动创建身份验证头

如果需要更精细的控制，可以手动创建身份验证头：

```python
import json
import hashlib
import secrets
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Load private key
with open("path/to/private_key.pem", "rb") as f:
    private_key_bytes = f.read()
    private_key = load_pem_private_key(private_key_bytes, password=None)

# Generate nonce and timestamp
nonce = secrets.token_hex(16)
timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

# Construct data to sign
data_to_sign = {
    "nonce": nonce,
    "timestamp": timestamp,
    "service": "example.com",
    "did": "did:wba:example.com:user:alice"
}

# Normalize JSON
import jcs
canonical_json = jcs.canonicalize(data_to_sign)

# Calculate SHA-256 hash
content_hash = hashlib.sha256(canonical_json).digest()

# Sign with private key
if isinstance(private_key, ec.EllipticCurvePrivateKey):
    signature_bytes = private_key.sign(
        content_hash,
        ec.ECDSA(hashes.SHA256())
    )
else:
    # Handle other types of private keys
    pass

# Encode signature
from base64 import urlsafe_b64encode
signature = urlsafe_b64encode(signature_bytes).rstrip(b'=').decode('ascii')

# Construct authentication JSON
auth_json = {
    "did": "did:wba:example.com:user:alice",
    "nonce": nonce,
    "timestamp": timestamp,
    "verification_method": "key-1",  # Verification method ID used
    "signature": signature
}

# Create Authorization header
auth_header = {"Authorization": f"DID {json.dumps(auth_json)}"}
```

## 5. 完整流程示例

以下是一个完整的DID WBA身份验证流程示例：

```python
import secrets
import asyncio
import aiohttp
import json
from pathlib import Path
from anp.authentication import create_did_wba_document, DIDWbaAuthHeader

async def main():
    # 1. Generate unique identifier
    unique_id = secrets.token_hex(8)
    
    # 2. Set server information
    server_domain = "example.com"
    base_path = f"/wba/user/{unique_id}"
    did_path = f"{base_path}/did.json"
    
    # 3. Create DID document
    did_document, keys = create_did_wba_document(
        hostname=server_domain,
        path_segments=["wba", "user", unique_id]
    )
    
    # 4. Save private keys and DID document
    user_dir = Path("did_keys") / f"user_{unique_id}"
    user_dir.mkdir(parents=True, exist_ok=True)
    
    # Save private keys
    for method_fragment, (private_key_bytes, _) in keys.items():
        private_key_path = user_dir / f"{method_fragment}_private.pem"
        with open(private_key_path, 'wb') as f:
            f.write(private_key_bytes)
    
    # Save DID document
    did_document_path = user_dir / "did.json"
    with open(did_document_path, 'w', encoding='utf-8') as f:
        json.dump(did_document, f, indent=2)
    
    # 5. Upload DID document to server
    document_url = f"https://{server_domain}{did_path}"
    async with aiohttp.ClientSession() as session:
        async with session.put(
            document_url,
            json=did_document,
            headers={'Content-Type': 'application/json'}
        ) as response:
            if response.status != 200:
                print(f"Failed to upload DID document: {response.status}")
                return
    
    # 6. Create DIDWbaAuthHeader instance
    private_key_path = user_dir / "key-1_private.pem"
    auth_client = DIDWbaAuthHeader(
        did_document_path=str(did_document_path),
        private_key_path=str(private_key_path)
    )
    
    # 7. Create authentication request
    test_url = f"https://{server_domain}/wba/test"
    auth_headers = auth_client.get_auth_header(test_url)
    
    # 8. Send authentication request
    async with aiohttp.ClientSession() as session:
        async with session.get(test_url, headers=auth_headers) as response:
            if response.status == 200:
                print("DID authentication successful")
                # Get token from response headers
                token = auth_client.update_token(test_url, dict(response.headers))
                if token:
                    print(f"Received token: {token}")
            else:
                print(f"DID authentication failed: {response.status}")

if __name__ == "__main__":
    asyncio.run(main())
```

## 6. 安全最佳实践

### 6.1 私钥保护

- 私钥应加密存储
- 限制对私钥文件的访问权限
- 考虑使用硬件安全模块(HSM)或密钥管理服务

### 6.2 DID服务器安全

- 使用HTTPS保护DID服务器
- 实施访问控制，限制谁可以更新DID文档
- 定期备份DID文档

### 6.3 身份验证建议

- 使用短暂的令牌（如JWT）
- 实施令牌刷新机制
- 监控异常的身份验证请求
- 更换和轮换密钥

## 7. 故障排除

### 7.1 常见问题

1. **DID文档无法解析**
   - 检查DID格式是否正确
   - 确保DID服务器正常运行
   - 验证DID路径是否正确

2. **身份验证失败**
   - 验证私钥和DID文档是否匹配
   - 检查时间戳是否在服务器允许的范围内
   - 确保使用了正确的验证方法ID

3. **签名验证失败**
   - 确保使用了正确的密钥和算法
   - 验证数据规范化过程
   - 检查签名格式是否正确

### 7.2 调试工具

AgentConnect提供了日志功能，可帮助调试DID相关问题：

```python
import logging
from anp.utils.log_base import set_log_color_level

# Set log level
set_log_color_level(logging.DEBUG)  # or INFO, WARNING, ERROR
```

## 8. 参考资料

- [W3C DID规范](https://www.w3.org/TR/did-core/)
- [AgentConnect GitHub 仓库](https://github.com/agent-network-protocol/AgentConnect)
- [示例代码](https://github.com/agent-network-protocol/AgentConnect/tree/main/examples/did_wba_examples)
