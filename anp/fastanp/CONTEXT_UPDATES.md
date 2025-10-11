# Context 注入机制和认证中间件更新说明

## 更新日期
2025-10-10

## 更新内容

### 0. 中间件强制认证（最新更新）

**变更**：中间件现在会强制要求认证，除非是排除的路径。

**认证策略**：
- ✅ **排除路径**：无需认证，可直接访问
  - `/ad.json` - Agent Description
  - `/docs` - API 文档
  - `/openapi.json` - OpenAPI 规范
  - `/favicon.ico` - 网站图标
  - `/info/*` - 所有 OpenRPC 文档路径
  
- ❌ **其他路径**：必须提供有效的 Authorization header
  - 没有 Authorization → 返回 401 Unauthorized
  - Authorization 无效 → 返回 401/403（根据错误类型）
  - 验证异常 → 返回 500 Internal Server Error

**响应示例**：
```json
// 401 - 缺少 Authorization header
{
  "error": "Unauthorized",
  "message": "Missing authorization header"
}

// 401/403 - 认证失败
{
  "error": "Unauthorized", 
  "message": "Invalid signature"
}
```

**使用场景**：
```python
# 启用强制认证中间件
anp = FastANP(
    app=app,
    ...,
    enable_auth_middleware=True  # 启用中间件
)

# 公开访问（无需认证）
GET /ad.json              ✓ 允许
GET /info/method.json     ✓ 允许（OpenRPC 文档）
GET /docs                 ✓ 允许

# 需要认证
POST /rpc                 ✗ 需要 Authorization header
GET /custom-api           ✗ 需要 Authorization header
```

## 更新内容

### 1. 中间件自动验证和存储 (middleware.py)

**变更**：中间件现在会自动验证 Authorization 头，并将结果存储在 `request.state` 中。

```python
async def dispatch(self, request: Request, call_next: Callable) -> Response:
    # 解析并验证 authorization header
    authorization = request.headers.get("Authorization")
    
    if authorization:
        try:
            result = await self.verifier.verify_auth_header(authorization, self.domain)
            # 存储到 request.state
            request.state.auth_result = result
            request.state.did = result.get('did')
        except Exception:
            request.state.auth_result = None
            request.state.did = None
```

**优点**：
- 避免重复验证 token
- 所有下游处理器都可以通过 `request.state` 访问认证信息
- 统一的认证处理点

### 2. 移除 JSON-RPC 端点的重复认证 (fastanp.py, interface_manager.py)

**变更前**：
```python
# 旧代码：会验证两次 token
auth_dependency = self.auth_middleware.verify_auth_header
self.interface_manager.register_jsonrpc_endpoint(
    app=self.app,
    auth_dependency=auth_dependency  # ❌ 会导致重复验证
)
```

**变更后**：
```python
# 新代码：从 request.state 读取，不重复验证
self.interface_manager.register_jsonrpc_endpoint(
    app=self.app
    # 不需要 auth_dependency
)

# 在 JSON-RPC 处理器中
auth_result = getattr(request.state, 'auth_result', None)
did = getattr(request.state, 'did', None)
```

**优点**：
- 只验证一次 token（在中间件中）
- 性能提升
- 代码更简洁

### 3. Request 参数自动注入 (interface_manager.py)

**新功能**：现在支持在接口函数中直接注入 `Request` 对象。

```python
from fastapi import Request

@anp.interface("/info/my_method.json")
def my_method(param: str, req: Request) -> dict:
    # Request 会被自动注入
    client_host = req.client.host if req.client else None
    method = req.method
    
    return {
        "param": param,
        "client_host": client_host,
        "method": method
    }
```

**实现**：
```python
# 检测 Request 参数
if param.annotation == Request or (
    hasattr(param.annotation, '__name__') and 
    param.annotation.__name__ == 'Request'
):
    # 跳过，稍后注入
    continue

# 注入 Request
for param_name, param in sig.parameters.items():
    if param.annotation == Request:
        final_params[param_name] = request
        break
```

### 4. Session 只使用 DID 作为唯一标识 (context.py)

**变更前**：Session 基于 `DID + Token` 生成唯一标识
```python
def _generate_session_id(self, did: str, token: str) -> str:
    combined = f"{did}:{token}"  # ❌ 每次 token 不同会创建新 session
    return hashlib.sha256(combined.encode()).hexdigest()
```

**变更后**：Session 只基于 `DID` 生成唯一标识
```python
def _generate_session_id(self, did: str) -> str:
    return hashlib.sha256(did.encode()).hexdigest()  # ✓ 同一 DID 共享 session

def get_or_create(self, did: str, anonymous: bool = False) -> Session:
    # 不再需要 token 参数
    session_id = self._generate_session_id(did)
    # ...
```

**优点**：
- 同一个 DID 的所有请求共享同一个 Session
- Session 管理更简单
- 更符合用户预期（基于身份而非 token）

**影响**：
- 即使 access token 过期并重新获取，session 数据依然保留
- 更适合长期会话管理

## 使用示例

### 示例 1：Context 注入（Session 基于 DID）

```python
from anp.fastanp import Context

@anp.interface("/info/counter.json")
def counter(ctx: Context) -> dict:
    # 同一个 DID 的请求会共享 session
    count = ctx.session.get("count", 0) + 1
    ctx.session.set("count", count)
    
    return {
        "count": count,
        "session_id": ctx.session.id,
        "did": ctx.did
    }
```

### 示例 2：Request 注入

```python
from fastapi import Request

@anp.interface("/info/info.json")
def get_info(req: Request) -> dict:
    return {
        "client_host": req.client.host if req.client else None,
        "method": req.method,
        "path": req.url.path
    }
```

### 示例 3：组合使用 Context + Request

```python
from fastapi import Request
from anp.fastanp import Context

@anp.interface("/info/combined.json")
def combined(message: str, ctx: Context, req: Request) -> dict:
    # 访问 session 数据
    visit_count = ctx.session.get("visits", 0) + 1
    ctx.session.set("visits", visit_count)
    
    # 访问请求信息
    client = req.client.host if req.client else "unknown"
    
    return {
        "message": message,
        "visits": visit_count,
        "client": client,
        "did": ctx.did
    }
```

### 示例 4：从 request.state 访问认证信息

```python
from fastapi import Request

@anp.interface("/info/auth_info.json")
def auth_info(req: Request) -> dict:
    # 中间件已经验证并存储了认证信息
    did = getattr(req.state, 'did', None)
    auth_result = getattr(req.state, 'auth_result', None)
    
    return {
        "did": did,
        "authenticated": auth_result is not None
    }
```

## 数据流

```
1. 客户端请求（带 Authorization header）
   ↓
2. AuthMiddleware.dispatch()
   - 验证 Authorization header
   - 存储到 request.state.auth_result
   - 存储到 request.state.did
   ↓
3. JSON-RPC 处理器
   - 从 request.state 读取 auth_result
   - 从 request.state 读取 did
   - 基于 DID 获取/创建 Session
   ↓
4. 自动注入参数
   - Context: 包含 session, did, request, auth_result
   - Request: FastAPI Request 对象
   ↓
5. 调用接口函数
   - 函数可以访问 Context 和 Request
   - Session 数据基于 DID 持久化
```

## 兼容性

### 不兼容变更

1. **SessionManager.get_or_create()** 签名改变：
   - 旧：`get_or_create(did, token=None, anonymous=False)`
   - 新：`get_or_create(did, anonymous=False)`

2. **register_jsonrpc_endpoint()** 签名改变：
   - 旧：`register_jsonrpc_endpoint(app, rpc_path, auth_dependency)`
   - 新：`register_jsonrpc_endpoint(app, rpc_path)`

### 迁移建议

如果你直接使用了这些 API，需要更新调用代码：

```python
# 旧代码
session = session_manager.get_or_create(did="xxx", token="yyy")

# 新代码
session = session_manager.get_or_create(did="xxx")
```

## 测试

运行测试验证功能：

```bash
cd /Users/cs/work/AgentConnect
uv run python examples/python/fastanp_examples/test_context_updates.py
```

所有测试都应该通过 ✓

## 总结

这次更新主要优化了：
1. ✅ 避免重复验证 token
2. ✅ 统一的认证信息存储（request.state）
3. ✅ 支持 Request 参数自动注入
4. ✅ Session 基于 DID 管理，更符合直觉
5. ✅ 更简洁的代码和更好的性能

所有修改都向后兼容用户代码（接口函数），只是内部实现方式优化。

