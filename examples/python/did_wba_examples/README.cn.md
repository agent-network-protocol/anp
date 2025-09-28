<div align="center">
  
[English](README.md) | [中文](README.cn.md)

</div>

# DID-WBA身份认证示例

本目录包含使用AgentConnect进行DID-WBA（Decentralized Identifier - Web-Based Authentication）身份认证的示例代码。

## 文件说明

- `create_did_document.py` - 创建DID文档和密钥对
- `authenticate_and_verify.py` - 完整的身份认证和验证流程演示
- `validate_did_document.py` - 验证DID文档结构的有效性
- `generated/` - 存储生成的DID文档和密钥文件

## 前置条件

### 环境设置
确保已正确安装AgentConnect：

```bash
# 方式一：通过pip安装
pip install agent-connect

# 方式二：源码安装（推荐开发者）
git clone https://github.com/agent-network-protocol/AgentConnect.git
cd AgentConnect
uv sync
```

### 依赖文件
部分示例需要以下文件（如果不存在会自动生成）：
- `docs/did_public/public-did-doc.json` - 公共DID文档
- `docs/did_public/public-private-key.pem` - 私钥文件
- `docs/jwt_rs256/RS256-private.pem` - JWT私钥
- `docs/jwt_rs256/RS256-public.pem` - JWT公钥

## 示例详解

### 1. 创建DID文档 (`create_did_document.py`)

**功能**：演示如何为智能体生成DID身份文档和相关密钥对

**核心特性**：
- 生成符合DID-WBA标准的身份文档
- 创建secp256k1验证密钥对
- 自动配置验证方法和服务端点

#### 运行示例
```bash
uv run python examples/python/did_wba_examples/create_did_document.py
```

#### 预期输出
```
DID document saved to .../generated/did.json
Registered verification method key-1 → private key: key-1_private.pem public key: key-1_public.pem
Generated DID identifier: did:wba:demo.agent-network:agents:demo
```

#### 生成的文件
- `generated/did.json` - DID文档
- `generated/key-1_private.pem` - 私钥文件
- `generated/key-1_public.pem` - 公钥文件

### 2. 身份认证验证 (`authenticate_and_verify.py`)

**功能**：展示完整的DID-WBA身份认证流程，包括认证头生成和验证

**核心流程**：
1. 生成DID认证头
2. 验证DID认证头
3. 生成访问令牌
4. 验证Bearer令牌

#### 运行示例
```bash
uv run python examples/python/did_wba_examples/authenticate_and_verify.py
```

#### 预期输出
```
DID header verified. Issued bearer token.
Bearer token verified. Associated DID: did:wba:...
```

#### 技术要点
- **DID解析**：本地模拟DID文档解析过程
- **JWT验证**：使用RS256算法进行令牌签名验证
- **授权流程**：演示从DID认证到Bearer令牌的完整授权链

### 3. DID文档验证 (`validate_did_document.py`)

**功能**：验证生成的DID文档是否符合DID-WBA规范

**验证项目**：
- DID标识符格式（必须以`did:wba:`开头）
- 必需的JSON-LD上下文
- 验证方法完整性
- 公钥JWK格式验证
- 服务端点有效性

#### 运行示例
```bash
uv run python examples/python/did_wba_examples/validate_did_document.py
```

#### 预期输出
```
DID document validation succeeded.
```

## DID-WBA核心概念

### DID标识符结构
```
did:wba:domain:path:segments
```
- `did:wba` - DID方法标识符
- `domain` - 主域名
- `path:segments` - 路径段，标识特定智能体

### 验证方法
使用`EcdsaSecp256k1VerificationKey2019`类型：
- **算法**：ECDSA with secp256k1 curve
- **格式**：JWK (JSON Web Key)
- **用途**：数字签名和身份验证

### 服务端点
- **类型**：`AgentDescription`
- **作用**：指向智能体描述文档的HTTPS端点
- **安全性**：必须使用HTTPS协议

## 故障排除

### 常见问题

#### 1. 文件不存在错误
```
FileNotFoundError: DID文档文件不存在
```
**解决方案**：
- 先运行`create_did_document.py`生成必要文件
- 检查文件路径是否正确

#### 2. 密钥格式错误
```
ValueError: Invalid key format
```
**解决方案**：
- 确保私钥文件为PEM格式
- 重新生成密钥对

#### 3. DID验证失败
```
ValueError: DID identifier must start with 'did:wba:'
```
**解决方案**：
- 检查DID文档格式是否正确
- 运行`validate_did_document.py`进行诊断

### 调试技巧

1. **启用详细日志**：
   ```python
   import logging
   logging.basicConfig(level=logging.DEBUG)
   ```

2. **检查生成的文件**：
   ```bash
   cat generated/did.json | python -m json.tool
   ```

3. **验证密钥对匹配**：
   使用`validate_did_document.py`检查密钥对一致性

## 代码结构说明

### 导入依赖
```python
from agent_connect.authentication import create_did_wba_document
from agent_connect.authentication import DIDWbaAuthHeader
from agent_connect.authentication.did_wba_verifier import DidWbaVerifier
```

### 基本使用模式
```python
# 1. 创建DID文档
did_document, keys = create_did_wba_document(
    hostname="your-domain.com",
    path_segments=["agents", "your-agent"],
    agent_description_url="https://your-domain.com/agents/your-agent"
)

# 2. 生成认证头
authenticator = DIDWbaAuthHeader(
    did_document_path="path/to/did.json",
    private_key_path="path/to/private.pem"
)
headers = authenticator.get_auth_header(server_url)

# 3. 验证认证
verifier = DidWbaVerifier(config)
result = await verifier.verify_auth_header(authorization, domain)
```

## 相关文档

- [DID-WBA规范](https://github.com/agent-network-protocol/AgentNetworkProtocol)
- [ANP Crawler示例](../anp_crawler_examples/README.md)
- [AgentConnect核心文档](../../../README.cn.md)
- [Authentication模块API](../../../agent_connect/authentication/)

## 安全注意事项

1. **私钥保护**：
   - 永远不要将私钥提交到版本控制系统
   - 在生产环境中使用安全的密钥管理服务

2. **HTTPS要求**：
   - 所有DID文档服务端点必须使用HTTPS
   - 验证SSL证书有效性

3. **令牌过期**：
   - 合理设置JWT令牌过期时间
   - 实现令牌刷新机制

4. **域名验证**：
   - 确保DID标识符中的域名与实际服务域名匹配
   - 防止域名欺骗攻击