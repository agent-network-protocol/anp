# OpenANP SDK

现代化的 ANP（Agent Network Protocol）Python SDK。

[English](README.md) | 中文

## 设计理念

- **SDK，而非框架**：提供能力，不强制实现方式
- **P2P 优先**：每个智能体既是客户端也是服务端
- **不可变性**：核心数据结构使用 frozen dataclass
- **快速失败**：异常立即抛出，无成功/错误包装
- **类型安全**：完整的类型提示和 Protocol 定义
- **OpenRPC 1.3.2 兼容**：严格遵循 OpenRPC 规范

---

## 架构概览

```
┌─────────────────────────────────────────────────────────┐
│                      你的智能体                          │
├─────────────────────────────────────────────────────────┤
│  服务端（暴露方法）        │  客户端（调用远程）           │
│  - @anp_agent 装饰器       │  - RemoteAgent.discover()    │
│  - @interface 装饰器       │  - agent.call() / agent.x()  │
│  - @information 装饰器     │  - ANPClient (anp_crawler)   │
│  - .router() → FastAPI     │                              │
│  - Context 注入            │                              │
└─────────────────────────────────────────────────────────┘
                            │
                      ANP 协议
                            │
┌─────────────────────────────────────────────────────────┐
│                    远程智能体                            │
└─────────────────────────────────────────────────────────┘
```

---

## 快速开始

### 服务端：暴露方法

```python
from fastapi import FastAPI
from anp.openanp import anp_agent, interface, AgentConfig, Context

@anp_agent(AgentConfig(
    name="Hotel Service",
    did="did:wba:example.com:hotel",
    prefix="/hotel",
    description="酒店预订服务",
))
class HotelAgent:
    @interface
    async def search(self, query: str) -> dict:
        """搜索酒店。"""
        return {"results": [{"name": "Tokyo Hotel", "price": 100}]}

    @interface
    async def search_with_session(self, query: str, ctx: Context) -> dict:
        """带会话追踪的搜索。"""
        # ctx.did - 调用者的 DID
        # ctx.session - 该 DID 的会话
        ctx.session.set("last_query", query)
        return {"results": [...], "user": ctx.did}

app = FastAPI()
app.include_router(HotelAgent.router())

# 自动生成：
# - GET /hotel/ad.json
# - GET /hotel/interface.json
# - POST /hotel/rpc
```

### 客户端：调用远程智能体

```python
from anp.openanp import RemoteAgent
from anp.authentication import DIDWbaAuthHeader

# 设置认证（DID-WBA）
auth = DIDWbaAuthHeader(
    did_document_path="/path/to/did-doc.json",
    private_key_path="/path/to/private-key.pem",
)

# 从 ad.json 发现智能体
agent = await RemoteAgent.discover("https://hotel.example.com/ad.json", auth)

# 查看可用方法
print(f"Agent: {agent.name}")
print(f"Methods: {agent.method_names}")

# 调用方法 - 动态访问
result = await agent.search(query="Tokyo")

# 或显式调用
result = await agent.call("search", query="Tokyo")

# 获取 OpenAI Tools 格式（用于 LLM 集成）
tools = agent.tools
```

---

## 核心 API 详解

### 1. @anp_agent 装饰器

将一个类标记为 ANP 智能体，自动生成 FastAPI 路由。

```python
from anp.openanp import anp_agent, AgentConfig

@anp_agent(AgentConfig(
    name="Agent Name",           # 必需：智能体名称
    did="did:wba:...",           # 必需：DID 标识符
    prefix="/agent",             # 必需：路由前缀
    description="描述",          # 可选：智能体描述
    tags=["tag1", "tag2"],       # 可选：标签列表
))
class MyAgent:
    def __init__(self, config: str = "default"):
        # 支持构造函数参数
        self.config = config
    ...

# 使用方式 1：无参构造（类方法）
router = MyAgent.router()

# 使用方式 2：有参构造（实例方法）
agent = MyAgent(config="custom")
router = agent.router()
```

**生成的端点：**
| 端点 | 说明 |
|------|------|
| `GET /prefix/ad.json` | Agent Description 文档 |
| `GET /prefix/interface.json` | OpenRPC 接口文档 |
| `POST /prefix/rpc` | JSON-RPC 2.0 端点 |

---

### 2. @interface 装饰器

将方法标记为 JSON-RPC 端点。

```python
from anp.openanp import interface, Context

class MyAgent:
    # =========================================================================
    # 基础用法（content 模式）
    # =========================================================================
    @interface
    async def method1(self, param: str) -> dict:
        """方法会嵌入到 interface.json 中。"""
        return {"result": param}

    # =========================================================================
    # Link 模式（独立接口文件）
    # =========================================================================
    @interface(mode="link")
    async def method2(self, param: str) -> dict:
        """生成独立的 interface/method2.json 文件。"""
        return {"result": param}

    # =========================================================================
    # Context 注入（重要！）
    # =========================================================================
    @interface
    async def method3(self, param: str, ctx: Context) -> dict:
        """ctx 参数自动注入，无需客户端传递。"""
        # ctx.did - 调用者的 DID（非常重要！）
        caller = ctx.did

        # ctx.session - 基于 DID 的会话存储
        ctx.session.set("key", "value")
        value = ctx.session.get("key", "default")

        # ctx.request - FastAPI Request 对象
        headers = ctx.request.headers

        return {"caller": caller, "value": value}
```

**接口模式：**
| 模式 | 说明 | 适用场景 |
|------|------|----------|
| `content`（默认） | 嵌入 interface.json | 常规方法 |
| `link` | 独立 interface/{method}.json | 复杂方法、单独文档 |

---

### 3. Context - 请求上下文

Context 是 OpenANP 的核心特性，通过参数注入自动提供。

```python
from anp.openanp import Context

@interface
async def my_method(self, param: str, ctx: Context) -> dict:
    # =========================================================================
    # ctx.did - 调用者身份（非常重要！）
    # =========================================================================
    # 唯一识别调用者的 DID
    # 用于：身份识别、权限控制、个性化服务、审计日志
    caller_did = ctx.did
    print(f"调用者: {caller_did}")

    # =========================================================================
    # ctx.session - 会话存储
    # =========================================================================
    # 基于 DID 自动隔离，不同用户的数据互不影响
    # 适用于：购物车、用户偏好、临时状态

    # 存储数据
    ctx.session.set("cart", {"item1": 2})
    ctx.session.set("preferences", {"theme": "dark"})

    # 读取数据
    cart = ctx.session.get("cart", {})
    prefs = ctx.session.get("preferences", {})

    # 清除会话
    ctx.session.clear()

    # =========================================================================
    # ctx.request - FastAPI Request
    # =========================================================================
    headers = ctx.request.headers
    client_host = ctx.request.client.host

    return {"caller": caller_did}
```

**Session 关键点：**
- Session 基于 DID 哈希生成 ID
- 不同 DID 的会话自动隔离
- 支持任意类型的值（字典、列表等）
- 默认 60 分钟超时，自动清理

---

### 4. @information 装饰器

定义动态 Information（元数据）。

```python
from anp.openanp import information, Information

class MyAgent:
    # =========================================================================
    # 静态 Information（类属性）
    # =========================================================================
    informations = [
        # URL 模式：外部链接
        Information(
            type="ImageObject",
            description="商店 Logo",
            url="https://cdn.example.com/logo.png",
        ),
        # Content 模式：内嵌内容
        Information(
            type="Contact",
            description="联系方式",
            mode="content",
            content={"phone": "123-456-7890"},
        ),
    ]

    # =========================================================================
    # 动态 Information（URL 模式）
    # =========================================================================
    @information(
        type="Product",
        description="商品列表",
        path="/products/list.json",  # 生成独立端点
    )
    def get_products(self) -> dict:
        return {"items": self.db.get_products()}

    # =========================================================================
    # 动态 Information（Content 模式）
    # =========================================================================
    @information(
        type="Offer",
        description="特别优惠",
        mode="content",  # 内容嵌入 ad.json
    )
    def get_offers(self) -> dict:
        return {"offers": self.get_current_offers()}
```

**Information 模式：**
| 模式 | 说明 | 在 ad.json 中 |
|------|------|---------------|
| URL（默认） | 生成独立端点 | 包含 url 字段 |
| Content | 内容嵌入 | 包含 content 字段 |

---

### 5. RemoteAgent - 客户端 SDK

**RemoteAgent 将远端智能体的所有方法下载到本地，并转化成本地方法来调用。** 它创建一个代理对象，让调用远程智能体就像调用本地方法一样。

> **RemoteAgent vs ANPCrawler**：RemoteAgent 是代理风格的客户端（方法调用像本地方法），而 ANPCrawler 是爬虫风格的客户端（爬取和解析文档）。在代码中进行智能体间通信使用 RemoteAgent；在 LLM 工具集成或数据收集场景使用 ANPCrawler。

```python
from anp.openanp import RemoteAgent
from anp.authentication import DIDWbaAuthHeader

# =========================================================================
# 1. 创建认证
# =========================================================================
auth = DIDWbaAuthHeader(
    did_document_path="/path/to/did-doc.json",
    private_key_path="/path/to/private-key.pem",
)

# =========================================================================
# 2. 发现智能体
# =========================================================================
agent = await RemoteAgent.discover(
    "https://example.com/agent/ad.json",
    auth,
)

# 智能体信息
print(f"名称: {agent.name}")
print(f"描述: {agent.description}")
print(f"URL: {agent.url}")
print(f"方法: {agent.method_names}")

# =========================================================================
# 3. 调用方法
# =========================================================================
# 方式 1：动态属性访问
result = await agent.search(query="Tokyo")

# 方式 2：显式调用
result = await agent.call("search", query="Tokyo")

# =========================================================================
# 4. LLM 集成
# =========================================================================
# 获取 OpenAI Tools 格式
tools = agent.tools
# [
#   {
#     "type": "function",
#     "function": {
#       "name": "search",
#       "description": "Search for hotels",
#       "parameters": {...}
#     }
#   }
# ]

# =========================================================================
# 5. 方法信息
# =========================================================================
for method in agent.methods:
    print(f"方法: {method.name}")
    print(f"描述: {method.description}")
    print(f"参数: {method.params}")
```

---

### 6. 错误处理

快速失败设计 - 异常立即抛出。

```python
from anp.openanp.client import HttpError, RpcError

try:
    agent = await RemoteAgent.discover(url, auth)
    result = await agent.search(query="Tokyo")
except HttpError as e:
    print(f"HTTP {e.status}: {e} (url: {e.url})")
except RpcError as e:
    print(f"RPC {e.code}: {e} (data: {e.data})")
except ValueError as e:
    print(f"发现失败: {e}")
except AttributeError as e:
    print(f"方法不存在: {e}")
```

---

## P2P 模式

每个智能体既是服务端也是客户端。

```python
from anp.openanp import anp_agent, interface, AgentConfig, Context, RemoteAgent
from anp.authentication import DIDWbaAuthHeader

@anp_agent(AgentConfig(
    name="Travel Agent",
    did="did:wba:example.com:travel",
    prefix="/travel",
))
class TravelAgent:
    def __init__(self, auth: DIDWbaAuthHeader):
        self.auth = auth

    @interface
    async def plan_trip(self, destination: str, ctx: Context) -> dict:
        """规划旅行 - 我既是服务端也是客户端。"""
        # 保存到会话
        ctx.session.set("destination", destination)

        # 作为客户端发现并调用酒店智能体
        hotel = await RemoteAgent.discover(
            "http://localhost:8000/hotel/ad.json",
            self.auth
        )

        hotels = await hotel.search(query=destination)
        return {
            "destination": destination,
            "hotels": hotels,
            "planner_did": ctx.did,
        }

# 创建时传入认证用于客户端调用
auth = DIDWbaAuthHeader(...)
travel_agent = TravelAgent(auth)
app.include_router(travel_agent.router())
```

---

## 完整示例

查看 `examples/python/openanp_examples/` 目录：

| 文件 | 说明 | 复杂度 |
|------|------|--------|
| `minimal_server.py` | 极简服务端 (~30 行) | ⭐ |
| `minimal_client.py` | 极简客户端 (~25 行) | ⭐ |
| `advanced_server.py` | 完整服务端（Context、Session、Information） | ⭐⭐⭐ |
| `advanced_client.py` | 完整客户端（发现、LLM 集成、错误处理） | ⭐⭐⭐ |

### 运行示例

```bash
# 安装依赖
uv sync --extra api

# 终端 1：启动服务端
uvicorn examples.python.openanp_examples.minimal_server:app --port 8000

# 终端 2：运行客户端
uv run python examples/python/openanp_examples/minimal_client.py
```

---

## API 参考

### 服务端导出

| 导出 | 说明 |
|------|------|
| `@anp_agent` | 定义 ANP 智能体的装饰器 |
| `@interface` | 暴露方法为 JSON-RPC 的装饰器 |
| `@information` | 定义动态 Information 的装饰器 |
| `AgentConfig` | 智能体配置 |
| `Information` | Information 定义 |
| `Context` | 请求上下文（session/DID） |
| `Session` | DID 的会话存储 |
| `SessionManager` | 管理跨 DID 的会话 |
| `create_agent_router` | 从配置创建 FastAPI 路由 |
| `generate_ad` | 生成 ad.json 文档 |

### 客户端导出

| 导出 | 说明 |
|------|------|
| `RemoteAgent` | 远程智能体的高级客户端 |
| `Method` | 方法定义（name、params、rpc_url） |
| `HttpError` | HTTP 请求失败 |
| `RpcError` | JSON-RPC 错误响应 |

---

## 许可证

MIT License
