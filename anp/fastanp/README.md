# FastANP - Fast Agent Network Protocol Framework

FastANP 是一个基于 FastAPI 的插件框架，用于快速构建符合 ANP（Agent Network Protocol）规范的智能体。它以插件方式增强 FastAPI，提供自动 OpenRPC 生成、JSON-RPC 端点处理、Context 注入和 DID WBA 认证等功能。

## 核心特性

- 🔌 **插件化设计**：FastAPI 作为主框架，FastANP 提供辅助工具
- 📄 **自动 OpenRPC 生成**：Python 函数自动转换为 OpenRPC 文档
- 🚀 **JSON-RPC 自动分发**：统一的 `/rpc` 端点自动路由到对应函数
- 🎯 **Context 自动注入**：基于 DID + Access Token 的 Session 管理
- 🔐 **内置 DID WBA 认证**：集成身份验证和 JWT token 管理
- 🛠️ **完全可控**：用户完全控制路由和 ad.json 生成

## 安装

确保已安装 `anp` 包及其可选依赖：

```bash
# 使用 uv
uv sync --extra api

# 或使用 pip
pip install -e ".[api]"
```

## 快速开始

### 最小示例

```python
from fastapi import FastAPI
from anp.fastanp import FastANP, Context
from anp.authentication.did_wba_verifier import DidWbaVerifierConfig

# 初始化 FastAPI
app = FastAPI()

# 初始化 FastANP 插件（不启用认证）
anp = FastANP(
    app=app,
    name="Simple Agent",
    description="A simple ANP agent",
    base_url="https://example.com",
    did="did:wba:example.com:agent:simple",
    enable_auth_middleware=False  # 关闭认证用于演示
)

# 定义 ad.json 路由（用户完全控制）
@app.get("/ad.json")
def get_agent_description():
    ad = anp.get_common_header()
    ad["interfaces"] = [
        anp.interfaces[hello].link_summary
    ]
    return ad

# 注册接口方法
@anp.interface("/info/hello.json", description="Say hello")
def hello(name: str) -> dict:
    """
    Greet someone by name.
    
    Args:
        name: The name to greet
    """
    return {"message": f"Hello, {name}!"}

# 运行服务器
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

运行后访问：
- Agent Description: `http://localhost:8000/ad.json`
- OpenRPC 文档: `http://localhost:8000/info/hello.json`
- JSON-RPC endpoint: `POST http://localhost:8000/rpc`

### 调用示例

```bash
curl -X POST http://localhost:8000/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "hello",
    "params": {"name": "World"}
  }'
```

响应：
```json
{
  "jsonrpc": "2.0",
  "result": {
    "message": "Hello, World!"
  },
  "id": 1
}
```

## 核心概念

### 1. 插件化设计

FastANP 不再是一个独立框架，而是 FastAPI 的增强插件：

```python
# FastAPI 是主框架
app = FastAPI()

# FastANP 作为插件注入
anp = FastANP(app=app, ...)
```

### 2. 用户控制路由

用户完全控制所有路由，包括 `ad.json`：

```python
@app.get("/ad.json")
def get_agent_description():
    # 获取公共头部
    ad = anp.get_common_header()
    
    # 添加 Information（用户自定义）
    ad["Infomations"] = [
        {
            "type": "Product",
            "description": "My products",
            "url": f"{anp.base_url}/products.json"
        }
    ]
    
    # 添加 Interface（通过 FastANP 辅助）
    ad["interfaces"] = [
        anp.interfaces[my_func].link_summary,  # URL 引用模式
        anp.interfaces[another_func].content,   # 嵌入模式
    ]
    
    return ad
```

### 3. Interface 装饰器

使用 `@anp.interface(path)` 装饰器注册接口：

```python
@anp.interface("/info/search.json", description="Search items")
def search(query: str, limit: int = 10) -> dict:
    """
    Search for items.
    
    Args:
        query: Search query
        limit: Maximum results
    """
    return {"results": [...]}
```

FastANP 自动：
1. 生成 OpenRPC 文档
2. 注册 `GET /info/search.json` 返回 OpenRPC 文档
3. 将函数添加到 JSON-RPC 分发器

### 4. Interface 访问方式

通过 `anp.interfaces[function]` 访问接口元数据：

```python
# 访问方式
anp.interfaces[my_func].link_summary   # URL 引用格式
anp.interfaces[my_func].content        # 嵌入格式
anp.interfaces[my_func].openrpc_doc    # 原始 OpenRPC 文档
```

**link_summary 示例**：

使用独立的jsonrpc文件：

```python
{
    "type": "StructuredInterface",
    "protocol": "openrpc",
    "description": "...",
    "url": "https://example.com/info/search.json"
}
```

**content 示例**：

在文档内部放置jsonrpc接口。

```python
{
    "type": "StructuredInterface",
    "protocol": "openrpc",
    "description": "...",
    "content": {
        "openrpc": "1.3.2",
        "info": {...},
        "methods": [...]
    }
}
```

### 5. Context 自动注入

FastANP 支持自动 Context 注入，提供 Session 管理：

```python
from anp.fastanp import Context

@anp.interface("/info/echo.json")
def echo(message: str, ctx: Context) -> dict:
    """
    Echo with context.
    
    Args:
        message: Message to echo
        ctx: Automatically injected context
    """
    # 访问 Session（基于 DID + Access Token）
    visit_count = ctx.session.get("visit_count", 0)
    visit_count += 1
    ctx.session.set("visit_count", visit_count)
    
    return {
        "message": message,
        "session_id": ctx.session.id,
        "did": ctx.did,
        "visit_count": visit_count
    }
```

**Context 对象包含**：
- `ctx.session` - Session 对象（持久化会话数据）
- `ctx.did` - 请求方 DID
- `ctx.request` - FastAPI Request 对象
- `ctx.auth_result` - 认证结果字典

**Session 方法**：
- `session.id` - Session ID（基于 DID 生成）
- `session.get(key, default)` - 获取会话数据
- `session.set(key, value)` - 设置会话数据
- `session.clear()` - 清空会话数据

**注意**：Session 的唯一标识基于 DID，而不是 DID + Access Token，这意味着同一个 DID 的多个请求会共享同一个 Session

### 6. Request 自动注入

FastANP 支持自动 Request 注入，提供 Request 对象：

```python
from fastapi import Request

@anp.interface("/info/info.json")
def info(req: Request) -> dict:
    """Get request information."""
    return {
        "method": req.method,
        "path": req.url.path
    }
```

## API 参考

### FastANP 初始化参数

| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `app` | FastAPI | ✓ | FastAPI 应用实例 |
| `name` | str | ✓ | 智能体名称 |
| `description` | str | ✓ | 智能体描述 |
| `base_url` | str | ✓ | 基础 URL（如 `https://example.com`） |
| `did` | str | ✓ | DID 标识符 |
| `owner` | dict | - | 所有者信息 |
| `jsonrpc_server_url` | str | - | JSON-RPC 端点路径（默认 `/rpc`） |
| `jsonrpc_server_name` | str | - | JSON-RPC 服务器名称 |
| `jsonrpc_server_description` | str | - | JSON-RPC 服务器描述 |
| `enable_auth_middleware` | bool | - | 是否启用认证中间件（默认 True） |
| `auth_config` | DidWbaVerifierConfig | - | 认证配置对象（启用认证时必需） |
| `api_version` | str | - | API 版本（默认 "1.0.0"） |

### 方法说明

#### `get_common_header(ad_url=None)`

获取 Agent Description 的公共头部字段。

```python
ad = anp.get_common_header()
# Returns: { "protocolType": "ANP", "name": "...", "did": "...", ... }
```

#### `@anp.interface(path, description=None, humanAuthorization=False)`

装饰器，将 Python 函数注册为 Interface。

**参数**：
- `path`: OpenRPC 文档 URL 路径（如 `/info/search.json`）
- `description`: 方法描述（可选，默认使用 docstring）
- `humanAuthorization`: 是否需要人工授权（可选）

**自动行为**：
1. 注册函数到 JSON-RPC 分发器
2. 自动注册 `GET {path}` 路由返回 OpenRPC 文档
3. 检查函数名全局唯一性（重复则抛出异常）
4. 支持 Context 参数自动注入

#### `interfaces` 属性

字典对象，key 为函数，value 为 InterfaceProxy。

```python
anp.interfaces[my_func].link_summary   # 获取 URL 引用格式
anp.interfaces[my_func].content        # 获取嵌入格式
anp.interfaces[my_func].openrpc_doc    # 获取原始 OpenRPC 文档
```

#### `auth_middleware` 属性

认证中间件，可选添加到 FastAPI：

```python
if anp.auth_middleware:
    app.add_middleware(anp.auth_middleware)
```

## 完整示例

查看 `examples/python/fastanp_examples/` 目录获取完整示例：

- **simple_agent.py** - 最小示例
- **hotel_booking_agent.py** - 完整的酒店预订智能体，包含：
  - 多个 Interface
  - Pydantic 数据模型
  - Context 注入
  - 自定义 ad.json 路由
  - 静态 Information 路由

## 高级用法

### 1. 使用 Pydantic 模型

```python
from pydantic import BaseModel

class SearchRequest(BaseModel):
    query: str
    limit: int = 10
    offset: int = 0

@anp.interface("/info/search.json")
def search(request: SearchRequest) -> dict:
    """Search with Pydantic model validation."""
    return {"results": [...], "total": 100}
```

FastANP 自动将 Pydantic 模型转换为 JSON Schema。

### 2. 自定义 ad.json 路由

支持路径参数和其他自定义逻辑：

```python
@app.get("/{agent_id}/ad.json")
def get_agent_description(agent_id: str):
    """Get AD for specific agent."""
    ad = anp.get_common_header()
    
    # 根据 agent_id 自定义内容
    if agent_id == "premium":
        ad["interfaces"] = [anp.interfaces[premium_search].content]
    else:
        ad["interfaces"] = [anp.interfaces[basic_search].link_summary]
    
    return ad
```

### 3. 异步函数支持

```python
@anp.interface("/info/async_search.json")
async def async_search(query: str) -> dict:
    """Async interface method."""
    result = await some_async_operation(query)
    return {"result": result}
```

### 4. 添加认证中间件

```python
from anp.authentication.did_wba_verifier import DidWbaVerifierConfig

# 读取 JWT 密钥
with open("jwt_private_key.pem", 'r') as f:
    jwt_private_key = f.read()
with open("jwt_public_key.pem", 'r') as f:
    jwt_public_key = f.read()

# 创建认证配置
auth_config = DidWbaVerifierConfig(
    jwt_private_key=jwt_private_key,
    jwt_public_key=jwt_public_key,
    jwt_algorithm="RS256",
    allowed_domains=["example.com", "localhost"]  # 可选：域名白名单
)

# 初始化 FastANP（自动启用认证中间件）
anp = FastANP(
    app=app,
    ...,
    enable_auth_middleware=True,
    auth_config=auth_config
)
```

**认证排除路径**：

中间件自动排除以下路径（支持通配符）：
- `/favicon.ico`
- `/health`
- `/docs`
- `*/ad.json` - 所有以 `/ad.json` 结尾的路径
- `/info/*` - 所有 OpenRPC 文档路径

其他所有路径都需要 DID WBA 认证

## 从旧版本迁移

### 旧版本（框架模式）

```python
from anp.fastanp import FastANP

app = FastANP(name="...", ...)  # FastANP 是框架

@app.interface()
def hello(name: str) -> dict:
    return {"message": f"Hello, {name}!"}

app.run()  # FastANP 控制运行
```

### 新版本（插件模式）

```python
from fastapi import FastAPI
from anp.fastanp import FastANP

app = FastAPI()  # FastAPI 是框架
anp = FastANP(app=app, name="...", ...)  # FastANP 是插件

@app.get("/ad.json")
def get_ad():
    ad = anp.get_common_header()
    ad["interfaces"] = [anp.interfaces[hello].link_summary]
    return ad

@anp.interface("/info/hello.json")
def hello(name: str) -> dict:
    return {"message": f"Hello, {name}!"}

# 用 FastAPI/Uvicorn 运行
import uvicorn
uvicorn.run(app, host="0.0.0.0", port=8000)
```

## 生成的端点

FastANP 自动生成以下端点：

### 1. JSON-RPC 统一端点
- **URL**: `POST /rpc`（可配置）
- **描述**: JSON-RPC 2.0 统一入口
- **认证**: 根据 `enable_auth_middleware` 参数决定

### 2. OpenRPC 文档端点
- **URL**: `GET {path}`（每个接口一个）
- **描述**: 返回该接口的 OpenRPC 文档
- **认证**: 自动排除（公开访问，匹配 `/info/*`）

### 3. Agent Description 端点
- **URL**: 用户自定义（如 `/ad.json` 或 `/{agent_id}/ad.json`）
- **描述**: 智能体描述文档
- **认证**: 自动排除（公开访问，匹配 `*/ad.json`）

### 4. 用户定义端点
- **Information 路由**: 用户完全控制（如 `/products/*.json`）
- **认证**: 默认需要认证（除非路径匹配排除模式）

## 函数名唯一性

FastANP 要求所有注册的函数名全局唯一：

```python
@anp.interface("/info/search1.json")
def search(query: str) -> dict:
    pass

@anp.interface("/info/search2.json")
def search(query: str) -> dict:  # ❌ 错误！函数名重复
    pass
```

解决方案：使用不同的函数名

```python
@anp.interface("/info/search_products.json")
def search_products(query: str) -> dict:
    pass

@anp.interface("/info/search_users.json")
def search_users(query: str) -> dict:
    pass
```

## 许可证

本项目采用 MIT 许可证开源。详见 [LICENSE](../../LICENSE) 文件。
