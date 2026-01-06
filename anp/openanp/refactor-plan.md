# OpenANP 重构计划

## 一、FastANP vs OpenANP 接口对比分析

### 1.1 设计理念对比

| 维度 | FastANP | OpenANP |
|------|---------|---------|
| 设计定位 | 完整框架（插件模式） | 轻量 SDK |
| 核心理念 | 用户控制路由 | 自动生成路由 |
| 状态管理 | 有 Session/Context | 无状态设计 |
| 代码量 | ~2100 行 | ~3800 行 |

### 1.2 接口使用方式对比

**FastANP 方式：**

```python
app = FastAPI()
anp = FastANP(app=app, name="Hotel", did="...", agent_domain="...")

@anp.interface("/info/search.json", description="Search hotels")
def search(query: str, ctx: Context) -> dict:
    return {"results": [...]}

# 用户必须手动定义 ad.json 路由
@app.get("/ad.json")
def get_ad():
    ad = anp.get_common_header()
    ad["interfaces"] = [anp.interfaces[search].link_summary]
    return ad
```

**OpenANP 方式：**

```python
@anp_agent(AgentConfig(name="Hotel", did="...", prefix="/hotel"))
class HotelAgent:
    @interface
    async def search(self, query: str) -> dict:
        return {"results": [...]}

app = FastAPI()
app.include_router(HotelAgent.router())  # 自动生成 ad.json、interface.json、/rpc
```

### 1.3 关键差异

| 特性 | FastANP | OpenANP |
|------|---------|---------|
| 装饰器 | `@anp.interface(path)` | `@interface` |
| 类装饰器 | 无 | `@anp_agent(config)` |
| 路由生成 | 手动 + 半自动 | 全自动 |
| Context 注入 | ✓ 支持 | ✗ 不支持 |
| Session 管理 | ✓ 基于 DID | ✗ 无状态 |
| 中间件 | 内置 DID WBA | Protocol 定义（未实现） |
| 流式支持 | ✗ | ✓ SSE |
| P2P 模式 | 可实现 | 原生支持 |
| 客户端 SDK | 基础 | 完整 RemoteAgent |

### 1.4 推荐选择

**OpenANP 更适合的场景：**

- 简单代理，快速开发
- P2P 混合代理（同时是客户端和服务器）
- 需要完整客户端 SDK
- 需要流式响应

**FastANP 更适合的场景：**

- 需要 Session/Context 管理
- 需要用户自定义内容和灵活路由控制
- 复杂业务逻辑，需要请求上下文

### 1.5 结论

建议使用 OpenANP 接口，但需要增强中间件和 Context 支持。OpenANP 的接口更简洁，`@anp_agent` + `@interface` 的组合比 FastANP 的方式更直观。但需要从 FastANP 移植：

- 中间件机制（DID WBA 认证）
- Context/Session 注入
- 用户自定义内容的支持方式

---

## 二、重构目标

- **Client 部分**：使用 anp_crawler 模块替代 openanp/client/http.py
- **Server 部分**：保持 OpenANP 接口，添加 FastANP 风格的中间件支持
- **用户自定义**：提供扩展点支持用户自定义内容

---

## 三、重构方案

### 3.1 Client 重构

**当前问题：**

- `openanp/client/http.py` 与 `anp_crawler/anp_client.py` 功能重复
- 两者都实现了 HTTP 请求、JSON-RPC 调用、DID 认证

**重构方案：**

保留 `openanp/client/http.py` 的函数式 API（因为它支持批量和流式请求），但内部使用 anp_crawler 的组件：

```python
# openanp/client/http.py 重构后
from anp.anp_crawler.anp_client import ANPClient
from anp.anp_crawler.anp_interface import ANPInterfaceConverter

# 保持原有的函数式 API
async def fetch(url: str, auth: DIDWbaAuthHeader, ...) -> str:
    # 内部可选使用 ANPClient 或直接 aiohttp
    ...

async def call_rpc(url: str, method: str, params: dict, auth: DIDWbaAuthHeader) -> Any:
    # 保持 Fail Fast 风格
    ...

# 保留批量和流式支持（anp_crawler 没有）
async def call_rpc_batch(...) -> dict[str, Any]: ...
async def call_rpc_stream(...) -> AsyncIterator[dict]: ...
```

**RemoteAgent 增强：**

```python
# openanp/client/agent.py
from anp.anp_crawler.anp_interface import ANPInterfaceConverter

class RemoteAgent:
    # 使用 ANPInterfaceConverter 进行 OpenRPC -> OpenAI Tools 转换
    @property
    def tools(self) -> list[dict]:
        return ANPInterfaceConverter().convert_to_openai_tools(self._interface_data)
```

### 3.2 Server 重构 - 添加中间件支持

**目标：** 在 OpenANP 自动生成的路由中集成 FastANP 风格的中间件。

**方案 A：在 AgentConfig 中添加中间件配置**

```python
@dataclass(frozen=True)
class AgentConfig:
    name: str
    did: str
    # 新增
    middleware: list[IRPCMiddleware] | None = None
    auth_config: DidWbaVerifierConfig | None = None
    enable_auth: bool = True
```

**方案 B：在 autogen.py 中支持中间件注入**

修改 `create_agent_router()` 函数：

```python
def create_agent_router(
    config: AgentConfig,
    methods: list[RPCMethodInfo],
    instance: Any | None = None,
    middleware: list[IRPCMiddleware] | None = None,  # 新增
) -> APIRouter:
    router = APIRouter(prefix=config.prefix, tags=config.tags or ["ANP"])

    # 如果配置了认证，添加中间件
    if config.auth_config:
        from anp.fastanp.middleware import create_auth_middleware
        auth_mw = create_auth_middleware(config.auth_config)
        # 注册到 router 或通过依赖注入

    ...
```

### 3.3 Context 注入支持

**方案：** 扩展 `@interface` 装饰器，支持 Context 参数

```python
@interface
async def search(self, query: str, ctx: Context) -> dict:
    # ctx 自动注入，包含 session、did、request
    user_did = ctx.did
    ctx.session.set("last_query", query)
    return {"results": [...]}
```

**实现位置：** `autogen.py` 的 RPC 处理逻辑

```python
# 在处理 RPC 请求时
async def handle_rpc_request(request: Request, body: dict):
    method_name = body.get("method")
    params = body.get("params", {})

    handler = handlers.get(method_name)
    sig = inspect.signature(handler)

    # 检查是否需要 Context
    for param_name, param in sig.parameters.items():
        if param.annotation == Context:
            # 从 request.state 获取认证信息（由中间件设置）
            auth_result = getattr(request.state, 'auth_result', {})
            did = auth_result.get('did', 'anonymous')
            session = session_manager.get_or_create(did)
            params[param_name] = Context(session=session, did=did, request=request)

    result = await handler(**params)
    return result
```

### 3.4 用户自定义内容支持

**问题：** OpenANP 自动生成所有路由，用户如何添加自定义内容？

**方案 1：通过 AgentConfig 的 url_config**

```python
@anp_agent(AgentConfig(
    name="Hotel",
    did="...",
    url_config={
        "ad_url": "/custom/ad.json",
        "interface_url": "/custom/interface.json",
        "rpc_url": "/custom/rpc",
    }
))
class HotelAgent:
    ...
```

**方案 2：提供 hook 机制**

```python
@anp_agent(config)
class HotelAgent:
    @interface
    async def search(self, query: str) -> dict:
        return {"results": [...]}

    # 可选：自定义 ad.json 内容
    def customize_ad(self, ad: dict) -> dict:
        ad["custom_field"] = "custom_value"
        ad["Infomations"] = [...]  # 添加自定义信息
        return ad
```

**方案 3：混合模式（推荐）**

```python
# 使用 OpenANP 装饰器定义接口
@anp_agent(config)
class HotelAgent:
    @interface
    async def search(self, query: str) -> dict:
        return {"results": [...]}

# 获取自动生成的路由
router = HotelAgent.router()

# 用户可以扩展或覆盖特定路由
@router.get("/hotel/custom-info.json")
async def custom_info():
    return {"custom": "data"}

# 或者完全自定义 ad.json（覆盖自动生成的）
from anp.openanp import generate_ad
@router.get("/hotel/ad.json", response_class=JSONResponse)
async def custom_ad():
    base_ad = generate_ad(config, HotelAgent)
    base_ad["Infomations"] = [...]  # 自定义
    return base_ad

app.include_router(router)
```

---

## 四、关键文件修改

### 4.1 需要修改的文件

| 文件 | 修改内容 |
|------|----------|
| `anp/openanp/types.py` | 添加 Context、Session 类型（或从 fastanp 导入） |
| `anp/openanp/decorators.py` | 支持 Context 参数检测 |
| `anp/openanp/autogen.py` | 添加中间件支持、Context 注入 |
| `anp/openanp/client/agent.py` | 集成 ANPInterfaceConverter |
| `anp/openanp/__init__.py` | 导出新的类型和函数 |

### 4.2 需要新增的文件

| 文件 | 内容 |
|------|------|
| `anp/openanp/context.py` | Context 和 SessionManager（可复用 fastanp 的） |
| `anp/openanp/middleware.py` | 中间件支持（可复用 fastanp 的） |

### 4.3 可能需要删除的文件

- `anp/openanp/client/http.py` 的部分重复代码（保留独有功能）

---

## 五、实施步骤

### Phase 1: Client 重构

1. 在 RemoteAgent 中集成 ANPInterfaceConverter
2. 保持 http.py 的函数式 API 不变
3. 添加单元测试

### Phase 2: 中间件支持

1. 复制 `fastanp/middleware.py` 到 `openanp/middleware.py`
2. 修改 AgentConfig 添加 auth_config 字段
3. 修改 autogen.py 支持中间件注入
4. 添加单元测试

### Phase 3: Context 支持

1. 复制 `fastanp/context.py` 到 `openanp/context.py`
2. 修改 autogen.py 的 RPC 处理逻辑支持 Context 注入
3. 修改 schema_gen.py 跳过 Context 参数
4. 添加单元测试

### Phase 4: 用户自定义支持

1. 实现 hook 机制（customize_ad 等）
2. 文档说明混合模式的使用方法
3. 添加示例代码

### Phase 5: 清理和文档

1. 移除重复代码
2. 更新 README
3. 添加迁移指南

---

## 六、用户确认的决定

- **Client 重构**：完全用 anp_crawler 替代 `openanp/client/http.py`
- **Context 实现**：复制 `fastanp/context.py` 到 `openanp/` 目录
- **中间件级别**：在 Router 级别注册，每个 Agent 独立管理
- **向后兼容**：可以重构 API，提供迁移指南

---

## 七、最终实施计划

### Phase 1: Client 完全重构

**目标：** 删除 `openanp/client/http.py`，使用 anp_crawler 模块

**步骤：**

1. 修改 `openanp/client/agent.py`：
   - 导入 `anp_crawler.anp_client.ANPClient`
   - 导入 `anp_crawler.anp_interface.ANPInterfaceConverter`
   - 重构 RemoteAgent 使用 ANPClient 进行 HTTP 请求
   - 使用 ANPInterfaceConverter 进行 OpenRPC → OpenAI Tools 转换

2. 修改 `openanp/client/openrpc.py`：
   - 导入 `anp_crawler.anp_parser.ANPDocumentParser`
   - 复用解析逻辑

3. 删除 `openanp/client/http.py`

4. 更新 `openanp/client/__init__.py` 导出

**修改文件：**

- `anp/openanp/client/agent.py` - 重构
- `anp/openanp/client/openrpc.py` - 重构
- `anp/openanp/client/http.py` - 删除
- `anp/openanp/client/__init__.py` - 更新导出

### Phase 2: Context 和 Session 支持

**目标：** 将 fastanp 的 Context/Session 复制到 openanp

**步骤：**

1. 复制 `fastanp/context.py` → `openanp/context.py`
2. 适配导入路径
3. 更新 `openanp/__init__.py` 导出 Context、Session、SessionManager

**新增文件：**

- `anp/openanp/context.py`

**修改文件：**

- `anp/openanp/__init__.py`

### Phase 3: 中间件支持（Router 级别）

**目标：** 在 OpenANP 的自动生成路由中集成中间件

**步骤：**

1. 复制 `fastanp/middleware.py` → `openanp/middleware.py`
2. 适配导入路径
3. 修改 `openanp/types.py`：
   - 在 AgentConfig 添加 `auth_config: DidWbaVerifierConfig | None = None`
4. 修改 `openanp/autogen.py` 的 `create_agent_router()`：

```python
def create_agent_router(
    config: AgentConfig,
    methods: list[RPCMethodInfo],
    instance: Any | None = None,
) -> APIRouter:
    router = APIRouter(prefix=config.prefix, tags=config.tags or ["ANP"])

    # 如果配置了认证，注册中间件到 router
    if config.auth_config:
        from .middleware import create_auth_middleware
        auth_middleware = create_auth_middleware(config.auth_config)
        # 使用 FastAPI 的依赖注入或 middleware
    ...
```

**新增文件：**

- `anp/openanp/middleware.py`

**修改文件：**

- `anp/openanp/types.py` - 添加 auth_config 字段
- `anp/openanp/autogen.py` - 集成中间件

### Phase 4: Context 注入到 RPC Handler

**目标：** 在 RPC 处理时自动注入 Context

**步骤：**

1. 修改 `openanp/autogen.py` 的 RPC 处理逻辑：
   - 检查 handler 签名是否有 Context 参数
   - 从 request.state 获取认证信息
   - 创建 Session 和 Context 对象
   - 注入到 handler 调用

2. 修改 `openanp/schema_gen.py`：
   - 在 `extract_method_schemas()` 中跳过 Context 参数
   - 确保 Context 不出现在 OpenRPC 文档中

3. 修改 `openanp/decorators.py`：
   - 在 `extract_rpc_methods()` 中记录是否有 Context 参数

**修改文件：**

- `anp/openanp/autogen.py` - Context 注入逻辑
- `anp/openanp/schema_gen.py` - 跳过 Context 参数
- `anp/openanp/decorators.py` - 记录 Context 需求

### Phase 5: Interface 模式和文档链接支持

**目标：**

- Interface 支持 content（嵌入，默认）和 link（链接）两种模式
- 提供 Information 文档链接的便捷接口
- 用户自定义内容采用混合模式

#### 5.1 Interface 模式设计

参考 FastANP 的 InterfaceProxy，在 `@interface` 装饰器中添加 mode 参数：

```python
# 默认：content 模式，嵌入 OpenRPC 文档
@interface
async def search(self, query: str) -> dict:
    ...

# 可选：link 模式，仅提供 URL 链接
@interface(mode="link")
async def book(self, hotel_id: str) -> dict:
    ...
```

**link 模式使用独立路径：** 每个方法生成独立的 OpenRPC 文档端点

- `search` → `/hotel/interface/search.json`
- `book` → `/hotel/interface/book.json`

**生成的 ad.json 结构：**

```json
"interfaces": [
    // content 模式（默认）- 嵌入完整 OpenRPC
    {
        "type": "StructuredInterface",
        "protocol": "openrpc",
        "description": "Search hotels",
        "content": { /* 完整 OpenRPC 文档 */ }
    },
    // link 模式 - 独立 URL
    {
        "type": "StructuredInterface",
        "protocol": "openrpc",
        "description": "Book hotel",
        "url": "https://hotel.com/hotel/interface/book.json"
    }
]
```

**实现：**

- 在 RPCMethodInfo 添加 `mode: Literal["content", "link"] = "content"` 字段
- 在 autogen.py 为 link 模式的方法生成独立的 GET 端点（`/prefix/interface/{method_name}.json`）
- 在 autogen.py 生成 ad.json 时根据 mode 输出不同格式

#### 5.2 Information 文档链接接口设计

**设计方案：类属性 + 装饰器**

```python
@anp_agent(AgentConfig(name="Hotel", did="...", prefix="/hotel"))
class HotelAgent:
    # 方式 1：类属性定义静态 Informations
    informations = [
        # URL 模式：托管静态文件
        Information(
            type="Product",
            description="Luxury hotel rooms with premium amenities",
            path="/products/luxury-rooms.json",
            file="data/luxury-rooms.json"
        ),
        # URL 模式：外部链接
        Information(
            type="VideoObject",
            description="Hotel tour video",
            url="https://cdn.hotel.com/tour.mp4"
        ),
        # Content 模式：内嵌内容
        Information(
            type="Organization",
            description="Hotel contact information",
            mode="content",
            content={"name": "Grand Hotel", "phone": "+1-234-567"}
        ),
    ]

    # 方式 2：使用装饰器定义动态 Information
    @information(type="Product", description="Available rooms", path="/products/rooms.json")
    def get_rooms(self) -> dict:
        return {"rooms": self.db.get_all_rooms()}

    # 方式 3：装饰器的内嵌模式
    @information(type="Service", description="Room service menu", mode="content")
    def get_service_menu(self) -> dict:
        return {"menu": [...]}

    @interface
    async def search(self, query: str) -> dict:
        return {"results": [...]}
```

**Information 类设计（支持 URL 和 Content 两种模式）：**

```python
@dataclass(frozen=True)
class Information:
    """文档链接定义，支持 URL 模式和 Content 模式"""
    type: str                                      # 类型：Product, Information, VideoObject 等
    description: str                               # 描述
    mode: Literal["url", "content"] = "url"        # 输出模式
    path: str | None = None                        # 相对路径（URL 模式，由 OpenANP 托管）
    url: str | None = None                         # 外部 URL（URL 模式）
    file: str | None = None                        # 静态文件路径（URL 模式托管时使用）
    content: dict | None = None                    # 内嵌内容（Content 模式）

    def __post_init__(self):
        if self.mode == "url" and not self.path and not self.url:
            raise ValueError("URL mode Information must have either 'path' or 'url'")
        if self.mode == "content" and not self.content:
            raise ValueError("Content mode Information must have 'content'")
```

**生成的 ad.json（支持两种模式）：**

```json
{
    "Infomations": [
        // URL 模式（默认）
        {
            "type": "Product",
            "description": "Luxury hotel rooms with premium amenities",
            "url": "https://hotel.com/hotel/products/luxury-rooms.json"
        },
        {
            "type": "VideoObject",
            "description": "Hotel tour video",
            "url": "https://cdn.hotel.com/tour.mp4"
        },
        // Content 模式（内嵌）
        {
            "type": "Organization",
            "description": "Hotel contact information",
            "content": {"name": "Grand Hotel", "phone": "+1-234-567"}
        },
        {
            "type": "Product",
            "description": "Available rooms",
            "url": "https://hotel.com/hotel/products/rooms.json"
        },
        {
            "type": "Service",
            "description": "Room service menu",
            "content": {"menu": [...]}
        }
    ],
    "interfaces": [...]
}
```

**@information 装饰器设计：**

```python
def information(
    type: str,
    description: str,
    path: str | None = None,
    mode: Literal["url", "content"] = "url",
) -> Callable:
    """
    装饰器：将方法注册为动态 Information 端点

    Args:
        type: Information 类型
        description: 描述
        path: URL 路径（URL 模式必需）
        mode: "url"（托管并返回 URL）或 "content"（内嵌到 ad.json）

    Example:
        # URL 模式
        @information(type="Product", description="Room list", path="/products/rooms.json")
        def get_rooms(self) -> dict:
            return {"rooms": [...]}

        # Content 模式
        @information(type="Service", description="Menu", mode="content")
        def get_menu(self) -> dict:
            return {"menu": [...]}
    """
```

#### 5.3 混合模式用户自定义

用户可以在获取 router 后自由扩展或覆盖：

```python
@anp_agent(config)
class HotelAgent:
    informations = [...]  # 声明式定义

    @interface
    async def search(self, query: str) -> dict:
        return {"results": [...]}

# 获取自动生成的 router
router = HotelAgent.router()

# 混合模式：用户可以覆盖或扩展任何路由
@router.get("/hotel/custom-info.json")
async def custom_info():
    return {"custom": "data"}

# 覆盖 ad.json（如果需要完全自定义）
from anp.openanp import generate_ad
@router.get("/hotel/ad.json", response_class=JSONResponse)
async def custom_ad():
    base_ad = generate_ad(config, HotelAgent)
    base_ad["custom_field"] = "custom_value"
    return base_ad

app.include_router(router)
```

**修改文件：**

- `anp/openanp/types.py` - 添加 Information 类、RPCMethodInfo 添加 mode 字段
- `anp/openanp/decorators.py` - 添加 `@information` 装饰器、`@interface` 支持 mode 参数
- `anp/openanp/autogen.py` - 支持 Information 路由生成和 ad.json 中的 Informations 字段
- `anp/openanp/__init__.py` - 导出 Information 类和 `@information` 装饰器

### Phase 6: 更新示例和测试

**目标：** 更新所有示例代码和测试

**步骤：**

1. 更新 `openanp/example/simple_server.py` - 添加认证配置
2. 更新 `openanp/example/simple_client.py` - 使用新的 RemoteAgent
3. 更新 `openanp/example/hybrid_agent.py` - 演示 Context 使用
4. 添加单元测试

**修改文件：**

- `anp/openanp/example/*.py`
- `anp/unittest/` 或新建测试文件

### Phase 7: 清理和文档

**目标：** 清理代码并更新文档

**步骤：**

1. 删除不再需要的文件
2. 更新 `openanp/README.md`
3. 添加迁移指南

---

## 八、文件修改汇总

### 删除的文件

- `anp/openanp/client/http.py`

### 新增的文件

- `anp/openanp/context.py` （从 fastanp 复制）
- `anp/openanp/middleware.py` （从 fastanp 复制）

### 修改的文件

| 文件 | 修改内容 |
|------|----------|
| `anp/openanp/client/agent.py` | 使用 anp_crawler 的 ANPClient 和 ANPInterfaceConverter |
| `anp/openanp/client/openrpc.py` | 使用 anp_crawler 的 ANPDocumentParser |
| `anp/openanp/client/__init__.py` | 更新导出 |
| `anp/openanp/types.py` | 添加 Information 类、AgentConfig 添加 auth_config 字段、RPCMethodInfo 添加 mode 字段 |
| `anp/openanp/autogen.py` | 中间件集成、Context 注入、Information 路由生成、ad.json 中的 Informations 字段 |
| `anp/openanp/schema_gen.py` | 跳过 Context 参数 |
| `anp/openanp/decorators.py` | 添加 `@information` 装饰器、`@interface` 支持 mode 参数、记录 Context 需求 |
| `anp/openanp/__init__.py` | 导出 Information、`@information`、Context、Session 等 |
| `anp/openanp/example/*.py` | 更新示例 |
| `anp/openanp/README.md` | 更新文档 |

---

## 九、完整示例代码

### 9.1 简单代理（无认证）

```python
from fastapi import FastAPI
from anp.openanp import AgentConfig, anp_agent, interface, Information

@anp_agent(AgentConfig(
    name="Hotel Service",
    did="did:wba:example.com:hotel",
    prefix="/hotel",
))
class HotelAgent:
    # 静态 Information 定义（URL 和 Content 模式）
    informations = [
        Information(
            type="Product",
            description="Luxury rooms catalog",
            path="/products/luxury.json",
            file="data/luxury-rooms.json"
        ),
        Information(
            type="Organization",
            description="Hotel contact info",
            mode="content",
            content={"name": "Grand Hotel", "phone": "+1-234-567"}
        ),
    ]

    @interface  # 默认 content 模式
    async def search(self, query: str) -> dict:
        """Search for hotels."""
        return {"results": [{"name": "Tokyo Hotel", "price": 100}]}

    @interface(mode="link")  # link 模式，生成 /hotel/interface/book.json
    async def book(self, hotel_id: str, date: str) -> dict:
        """Book a hotel room."""
        return {"booking_id": "12345", "status": "confirmed"}

app = FastAPI()
app.include_router(HotelAgent.router())
```

### 9.2 带认证、Context 和动态 Information 的代理

```python
from fastapi import FastAPI
from anp.openanp import (
    AgentConfig, anp_agent, interface, information,
    Context, Information
)
from anp.authentication import DidWbaVerifierConfig

config = AgentConfig(
    name="Hotel Service",
    did="did:wba:example.com:hotel",
    prefix="/hotel",
    auth_config=DidWbaVerifierConfig(
        jwt_private_key_path="keys/private.pem",
        jwt_public_key_path="keys/public.pem",
    ),
)

@anp_agent(config)
class HotelAgent:
    # 静态 Information
    informations = [
        Information(type="Product", description="Room catalog", path="/products/rooms.json", file="data/rooms.json"),
        Information(type="VideoObject", description="Hotel tour", url="https://cdn.hotel.com/tour.mp4"),
        Information(type="Contact", description="Contact info", mode="content", content={"email": "info@hotel.com"}),
    ]

    # 动态 Information（URL 模式）
    @information(type="Product", description="Dynamic room availability", path="/products/availability.json")
    def get_availability(self) -> dict:
        return {"available_rooms": self.db.get_available()}

    # 动态 Information（Content 模式）
    @information(type="Service", description="Today's specials", mode="content")
    def get_specials(self) -> dict:
        return {"specials": ["Breakfast buffet", "Spa discount"]}

    @interface  # content 模式
    async def search(self, query: str, ctx: Context) -> dict:
        """Search with session support."""
        ctx.session.set("last_query", query)
        return {"results": [...], "user_did": ctx.did}

    @interface(mode="link")  # link 模式
    async def book(self, hotel_id: str, ctx: Context) -> dict:
        """Book with authentication."""
        return {"booking_id": "12345", "booked_by": ctx.did}

app = FastAPI()
app.include_router(HotelAgent.router())
```

### 9.3 混合模式自定义

```python
@anp_agent(config)
class HotelAgent:
    @interface
    async def search(self, query: str) -> dict:
        return {"results": [...]}

# 获取 router
router = HotelAgent.router()

# 用户扩展
@router.get("/hotel/custom.json")
async def custom_endpoint():
    return {"custom": "data"}

# 用户覆盖 ad.json
from anp.openanp import generate_ad
@router.get("/hotel/ad.json")
async def custom_ad():
    ad = generate_ad(config, HotelAgent)
    ad["Infomations"].append({
        "type": "Custom",
        "description": "User defined information",
        "url": "https://hotel.com/hotel/custom.json"
    })
    return ad

app = FastAPI()
app.include_router(router)
```
