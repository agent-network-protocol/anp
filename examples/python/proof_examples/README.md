# W3C Data Integrity Proof 模块

本模块提供符合 W3C Data Integrity 规范的通用 Proof 生成和验证功能，用于为 JSON 文档添加可验证的数字签名。

## 功能特性

- ✅ **W3C 标准兼容** — 完全遵循 [W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/) 规范
- ✅ **多种签名套件** — 支持 `EcdsaSecp256k1Signature2019` 和 `Ed25519Signature2020`
- ✅ **JCS 规范化** — 使用 RFC 8785 (JSON Canonicalization Scheme) 确保签名确定性
- ✅ **完整的 Proof 选项** — 支持 `domain`、`challenge`、`proofPurpose` 等可选字段
- ✅ **篡改检测** — 任何文档修改都会导致验证失败
- ✅ **离线验证** — 持有公钥的任何第三方都可以离线验证

## 快速开始

### 基本使用

```python
from cryptography.hazmat.primitives.asymmetric import ec
from anp.proof import generate_w3c_proof, verify_w3c_proof

# 1. 生成密钥对
private_key = ec.generate_private_key(ec.SECP256K1())
public_key = private_key.public_key()

# 2. 为文档生成 Proof
document = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:wba:example.com:alice",
    "name": "Agent Alice",
    "capabilities": ["search", "booking"]
}

signed_doc = generate_w3c_proof(
    document=document,
    private_key=private_key,
    verification_method="did:wba:example.com:alice#key-1",
    proof_purpose="assertionMethod"
)

# 3. 验证 Proof
is_valid = verify_w3c_proof(signed_doc, public_key)
print(f"验证结果: {is_valid}")  # 输出: 验证结果: True
```

### 生成的 Proof 结构

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:wba:example.com:alice",
  "name": "Agent Alice",
  "capabilities": ["search", "booking"],
  "proof": {
    "type": "EcdsaSecp256k1Signature2019",
    "created": "2026-02-08T11:00:00Z",
    "verificationMethod": "did:wba:example.com:alice#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "X63j0DLc-Wh2PxSN4EMPX2Hy1Tc4X5eKPz0Ta..."
  }
}
```

## API 文档

### `generate_w3c_proof()`

为 JSON 文档生成 W3C Data Integrity Proof。

**参数：**
- `document` (dict): 要签名的 JSON 文档
- `private_key` (EllipticCurvePrivateKey | Ed25519PrivateKey): 私钥
- `verification_method` (str): DID 验证方法 URL，如 `"did:wba:example.com#key-1"`
- `proof_purpose` (str, 可选): Proof 用途，默认 `"assertionMethod"`
  - `"assertionMethod"` — 通用声明/断言
  - `"authentication"` — 证明 DID 控制权
  - `"capabilityInvocation"` — 调用能力
  - `"capabilityDelegation"` — 委托能力
- `proof_type` (str, 可选): 显式指定 Proof 类型，默认根据密钥类型自动检测
- `created` (str, 可选): ISO 8601 时间戳，默认当前 UTC 时间
- `domain` (str, 可选): 域限制
- `challenge` (str, 可选): 挑战字符串（用于防重放）

**返回：** 包含 `proof` 字段的新文档（原文档不变）

**支持的签名类型：**
- `EllipticCurvePrivateKey` (secp256k1) → `EcdsaSecp256k1Signature2019`
- `Ed25519PrivateKey` → `Ed25519Signature2020`

### `verify_w3c_proof()`

验证 JSON 文档的 W3C Data Integrity Proof。

**参数：**
- `document` (dict): 包含 `proof` 字段的文档
- `public_key` (EllipticCurvePublicKey | Ed25519PublicKey): 公钥
- `expected_purpose` (str, 可选): 期望的 `proofPurpose`，如果提供则必须匹配
- `expected_domain` (str, 可选): 期望的 `domain`，如果提供则必须匹配
- `expected_challenge` (str, 可选): 期望的 `challenge`，如果提供则必须匹配

**返回：** `True` 如果验证通过，否则 `False`

## 使用场景

### 1. Agent 身份声明

Agent 声明自己的身份和能力，其他 Agent 可以离线验证：

```python
from cryptography.hazmat.primitives.asymmetric import ec
from anp.proof import generate_w3c_proof

private_key = ec.generate_private_key(ec.SECP256K1())

agent_claim = {
    "@context": ["https://www.w3.org/ns/did/v1"],
    "id": "did:wba:example.com:agents:alice",
    "type": "AgentIdentityClaim",
    "name": "Agent Alice",
    "capabilities": ["search", "booking", "payment"]
}

signed_claim = generate_w3c_proof(
    document=agent_claim,
    private_key=private_key,
    verification_method="did:wba:example.com:agents:alice#key-1",
    proof_purpose="assertionMethod"
)
```

### 2. Verifiable Credential

签发可验证凭证（VC）：

```python
from cryptography.hazmat.primitives.asymmetric import ed25519
from anp.proof import generate_w3c_proof

issuer_key = ed25519.Ed25519PrivateKey.generate()

credential = {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential", "AgentCapabilityCredential"],
    "issuer": "did:wba:issuer.example.com",
    "issuanceDate": "2026-02-08T00:00:00Z",
    "credentialSubject": {
        "id": "did:wba:example.com:agents:bob",
        "capability": "hotel-booking",
        "level": "certified"
    }
}

signed_vc = generate_w3c_proof(
    document=credential,
    private_key=issuer_key,
    verification_method="did:wba:issuer.example.com#key-1",
    proof_purpose="assertionMethod",
    domain="example.com"
)
```

### 3. DID 认证

证明对 DID 的控制权（带 challenge）：

```python
signed_auth = generate_w3c_proof(
    document={"id": did, "timestamp": "2026-02-08T11:00:00Z"},
    private_key=private_key,
    verification_method=f"{did}#key-1",
    proof_purpose="authentication",
    challenge="server-nonce-xyz"
)

# 服务器验证
is_valid = verify_w3c_proof(
    signed_auth,
    public_key,
    expected_purpose="authentication",
    expected_challenge="server-nonce-xyz"
)
```

## 技术细节

### Proof 生成流程

遵循 W3C Data Integrity 规范：

1. **规范化文档** — 使用 JCS (RFC 8785) 规范化 JSON（排除 `proof` 字段）
2. **规范化 Proof 选项** — 规范化 `type`、`created`、`verificationMethod`、`proofPurpose` 等
3. **哈希计算** — 分别计算 SHA-256 哈希
4. **拼接** — `hash(proof_options) || hash(document)`
5. **签名** — 使用私钥签名
6. **编码** — Base64URL 编码 → `proofValue`

### 支持的 Proof Types

| Proof Type | 算法 | 密钥曲线 | 哈希 | 签名格式 |
|------------|------|----------|------|----------|
| `EcdsaSecp256k1Signature2019` | ECDSA | secp256k1 | SHA-256 | R\|\|S (64 字节) |
| `Ed25519Signature2020` | EdDSA | Curve25519 | — | 原始签名 (64 字节) |

### 安全特性

- ✅ **规范化确保确定性** — 相同内容总是产生相同签名
- ✅ **篡改检测** — 任何字段修改都会导致验证失败
- ✅ **时间戳** — `created` 字段记录签名时间
- ✅ **域绑定** — `domain` 字段防止跨域重放
- ✅ **挑战响应** — `challenge` 字段防止重放攻击

## 运行示例

完整示例代码位于 [`examples/python/proof_examples/proof_example.py`](../../../examples/python/proof_examples/proof_example.py)：

```bash
uv run python examples/python/proof_examples/proof_example.py
```

示例包含：
1. secp256k1 Agent 身份声明签名
2. Ed25519 Verifiable Credential 签发
3. 篡改检测演示

## 运行测试

```bash
# 运行 Proof 模块测试
uv run pytest anp/unittest/proof/test_proof.py -v

# 运行所有测试
uv run pytest
```

测试覆盖：
- ✅ secp256k1 和 Ed25519 签名生成
- ✅ Proof 验证（有效/无效）
- ✅ 篡改检测
- ✅ 密钥类型不匹配处理
- ✅ domain/challenge/proofPurpose 验证
- ✅ Unicode 内容
- ✅ 嵌套文档
- ✅ 键序无关性

## 与现有 ANP 模块的关系

| 模块 | 用途 | 签名格式 |
|------|------|----------|
| `anp.authentication` | DID WBA 在线认证 | JWT/JWS |
| `anp.ap2` | 支付协议 (CartMandate, PaymentMandate) | JWT/JWS |
| **`anp.proof`** | **通用离线签名（VC、身份声明等）** | **W3C Proof** |

**设计理念：**
- **JWT/JWS** — 适合会话认证、授权令牌（短期有效、自包含）
- **W3C Proof** — 适合长期可验证声明（VC、DID 文档、身份断言）

两者互补，共同构建完整的 Agent 信任体系。

## 参考资料

- [W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
- [RFC 8785 - JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785.html)
- [DID Core](https://www.w3.org/TR/did-core/)

## License

MIT License - 详见 [LICENSE](../../../LICENSE) 文件
