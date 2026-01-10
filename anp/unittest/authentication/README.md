# 身份认证单元测试

本目录包含所有与 DID WBA 身份认证相关的单元测试。

## 目录结构

```
anp/unittest/authentication/
├── __init__.py                  # 测试包初始化
├── test_authentication.py       # 完整的身份认证测试套件
└── README.md                   # 本文件
```

## 测试文件说明

### test_authentication.py

完整的 DID WBA 身份认证测试套件,包含 6 个测试类,共 19 个测试用例。

#### 测试类详情

##### 1. TestDIDDocumentCreation (2个测试)
DID 文档创建测试:
- `test_create_did_document_basic` - 测试创建基本 DID 文档
- `test_create_did_document_with_path` - 测试创建带路径的 DID 文档

##### 2. TestAuthenticationHeaderVersion (5个测试)
不同版本认证头测试:
- `test_version_1_0_uses_service_field` - 验证版本 1.0 使用 service 字段
- `test_version_1_1_uses_aud_field` - 验证版本 1.1 使用 aud 字段
- `test_version_1_2_uses_aud_field` - 验证版本 1.2 使用 aud 字段
- `test_default_version_is_1_0` - 验证默认版本是 1.0
- `test_backward_compatibility_no_version` - 验证向后兼容性(无版本号)

##### 3. TestCrossVersionAuthentication (4个测试)
跨版本认证场景测试:
- `test_v1_0_client_to_v1_0_server` - 1.0 客户端 → 1.0 服务器(成功)
- `test_v1_1_client_to_v1_1_server` - 1.1 客户端 → 1.1 服务器(成功)
- `test_v1_0_client_to_v1_1_server_fails` - 1.0 客户端 → 1.1 服务器(失败)
- `test_v1_1_client_to_v1_0_server_fails` - 1.1 客户端 → 1.0 服务器(失败)

##### 4. TestJSONAuthentication (3个测试)
JSON 格式认证测试:
- `test_json_uses_v_field` - 验证 JSON 使用 "v" 字段而不是 "version"
- `test_json_version_1_0` - 测试 JSON 版本 1.0 认证
- `test_json_version_1_1` - 测试 JSON 版本 1.1 认证

##### 5. TestPublicDIDAuthentication (3个测试)
使用公共测试 DID 文档进行测试:
- `test_public_did_version_1_0` - 使用公共 DID 测试版本 1.0
- `test_public_did_version_1_1` - 使用公共 DID 测试版本 1.1
- `test_public_did_json_format` - 使用公共 DID 测试 JSON 格式

**测试数据:**
- DID 文档: `docs/did_public/public-did-doc.json`
- 私钥: `docs/did_public/public-private-key.pem`

##### 6. TestAuthHeaderParsing (2个测试)
认证头解析测试:
- `test_extract_auth_header_with_version` - 测试提取带版本号的认证头
- `test_extract_auth_header_without_version` - 测试提取无版本号的认证头(向后兼容)

## 测试覆盖范围

### ✅ 核心功能
- DID 文档创建和验证
- 签名生成和验证
- 认证头格式化和解析
- JSON 格式认证

### ✅ 版本兼容性
- 版本 < 1.1: 使用 `service` 字段
- 版本 >= 1.1: 使用 `aud` 字段
- 默认版本: 1.0
- 向后兼容: 无版本号默认为 1.0

### ✅ 跨版本场景
| 客户端版本 | 服务器版本 | 结果 | 原因 |
|-----------|-----------|------|------|
| 1.0 | 1.0 | ✅ 成功 | 签名字段匹配(service) |
| 1.1 | 1.1 | ✅ 成功 | 签名字段匹配(aud) |
| 1.0 | 1.1 | ❌ 失败 | 签名字段不匹配 |
| 1.1 | 1.0 | ❌ 失败 | 签名字段不匹配 |

### ✅ 数据格式
- HTTP Authorization 头格式
- JSON 认证格式
- 字段名一致性("v" 字段)

## 运行测试

### 运行身份认证所有测试
```bash
uv run pytest anp/unittest/authentication/ -v
```

### 运行特定测试文件
```bash
uv run pytest anp/unittest/authentication/test_authentication.py -v
```

### 运行特定测试类
```bash
uv run pytest anp/unittest/authentication/test_authentication.py::TestCrossVersionAuthentication -v
```

### 运行特定测试方法
```bash
uv run pytest anp/unittest/authentication/test_authentication.py::TestAuthenticationHeaderVersion::test_version_1_0_uses_service_field -v
```

### 查看测试覆盖率
```bash
uv run pytest anp/unittest/authentication/ --cov=anp.authentication --cov-report=html
```

## 测试数据

### 公共测试数据
测试使用项目提供的公共测试数据:
- **DID 文档**: `docs/did_public/public-did-doc.json`
  - DID: `did:wba:didhost.cc:public`
  - 验证方法: EcdsaSecp256k1VerificationKey2019
- **私钥**: `docs/did_public/public-private-key.pem`
  - 格式: PKCS8 PEM
  - 算法: secp256k1

### 动态生成数据
部分测试动态生成 DID 文档和密钥对,用于测试文档创建功能。

## 测试原则

遵循项目要求:
1. **不使用 mock**: 所有测试使用真实函数调用
2. **真实签名**: 使用真实的加密库和密钥进行签名验证
3. **独立测试**: 每个测试独立运行,无执行顺序依赖
4. **快速执行**: 单个测试 < 100ms,全部测试 < 1秒
5. **清晰命名**: 测试名称清晰描述测试场景
6. **充分断言**: 使用断言消息提供失败时的上下文

## 添加新测试

在相应测试类中添加新的测试方法:

```python
def test_new_authentication_scenario(self):
    """测试新的认证场景"""
    # 准备测试数据
    did_document, keys = create_did_wba_document("example.com")

    # 执行测试
    result = some_function(did_document)

    # 验证结果
    self.assertTrue(result, "详细的失败消息")
```

## 相关示例

身份认证相关示例位于 `examples/python/did_wba_examples/`:
- `create_did_document.py` - 创建 DID 文档
- `authenticate_and_verify.py` - 认证和验证示例
- `validate_did_document.py` - 验证 DID 文档

运行示例验证功能:
```bash
uv run python examples/python/did_wba_examples/create_did_document.py
uv run python examples/python/did_wba_examples/authenticate_and_verify.py
uv run python examples/python/did_wba_examples/validate_did_document.py
```

## 注意事项

1. 测试代码位于 `anp/unittest/authentication/` 目录
2. 正式代码中不要包含 mock
3. 所有测试应该快速执行
4. 使用描述性的测试方法名和文档字符串
5. 测试失败时提供有用的错误信息
6. 保持测试的独立性和可重复性
