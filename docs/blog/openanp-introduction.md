# OpenANP：简化 ANP 协议开发的现代化 SDK

## 前言

在智能体快速发展的今天，Agent 之间的互联互通变得越来越重要。ANP（Agent Network Protocol）作为一种开源的智能体通信协议，为 Agent 之间的发现、认证和交互提供了坚实的基础。然而，直接基于 ANP 协议进行开发，开发者需要处理大量的底层细节：DID 认证、JSON-RPC 通信、OpenRPC 文档生成、会话管理等等。

**OpenANP** 应运而生，它是一个现代化的 Python SDK，旨在大幅简化基于 ANP 协议的开发难度，让开发者能够专注于业务逻辑，而不是协议细节。

OpenANP刚刚发布，欢迎试用，并且提出改进建议，同时也希望能够贡献你的想法和代码，成为ANP的贡献者！

---

## 一、为什么设计 OpenANP？

### 1.1 ANP 协议开发的痛点

在没有 OpenANP 之前，开发一个符合 ANP 规范的智能体需要：

- **手动编写 ad.json**：Agent Description 文档需要严格遵循 JSON-LD 格式
- **手动生成 OpenRPC 文档**：每个 RPC 方法都需要编写详细的参数和返回值 Schema
- **处理 JSON-RPC 2.0 协议**：包括请求验证、错误处理、批量请求等
- **实现 DID WBA 认证**：包括签名生成、Token 验证等复杂流程
- **管理会话状态**：根据调用者 DID 进行会话隔离

这些工作繁琐且容易出错，严重影响了开发效率。

### 1.2 OpenANP 的设计目标

OpenANP 的核心设计目标是：**让开发者用最少的代码，构建功能完整的 ANP 智能体**。

具体而言：

- **30 行代码搭建服务端**：使用装饰器自动生成所有协议文档和端点
- **25 行代码实现客户端**：自动发现远程智能体并像调用本地方法一样调用远程方法
- **零配置 Schema 生成**：从 Python 类型提示自动生成 JSON Schema
- **开箱即用的认证**：内置 DID WBA 认证支持

---

## 二、核心设计思路

OpenANP 遵循以下设计理念：

### 2.1 SDK，而非框架

OpenANP 是一个 SDK，不是一个框架。它**提供能力，而不强制实现方式**。开发者可以：

- 使用装饰器快速开发（最简单）
- 手动调用底层函数（最灵活）
- 混合使用（推荐）

```
┌─────────────────────────────────────────────────────────┐
│                      你的智能体                          │
├─────────────────────────────────────────────────────────┤
│  服务端（暴露方法）        │  客户端（调用远程）           │
│  - @anp_agent 装饰器       │  - RemoteAgent.discover()    │
│  - @interface 装饰器       │  - agent.call() / agent.x()  │
│  - @information 装饰器     │                              │
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

### 2.2 P2P 优先

每个智能体既是客户端也是服务端。一个 Agent 可以同时：
- **对外提供服务**：通过 `@interface` 暴露 RPC 方法
- **调用其他 Agent**：通过 `RemoteAgent` 发现和调用远程智能体

### 2.3 不可变性

核心数据结构使用 `frozen dataclass`，确保配置不会被意外修改，这对并发访问和调试至关重要。

### 2.4 快速失败

异常立即抛出，不使用成功/错误包装。这让问题能够在第一时间暴露，便于调试。

### 2.5 类型安全

完整的类型提示和 Protocol 定义，配合现代 IDE 提供优秀的开发体验。

### 2.6 OpenRPC 1.3.2 兼容

严格遵循 OpenRPC 规范，确保与其他 ANP 实现的互操作性。

---

## 三、模块介绍

OpenANP 由以下核心模块组成：

### 3.1 装饰器模块 (`decorators.py`)

提供三个核心装饰器：

| 装饰器 | 说明 |
|--------|------|
| `@anp_agent` | 将类标记为 ANP 智能体，自动生成 FastAPI 路由 |
| `@interface` | 将方法标记为 JSON-RPC 端点 |
| `@information` | 定义动态 Information（元数据） |

### 3.2 类型定义模块 (`types.py`)

定义所有核心数据类型：

| 类型 | 说明 |
|------|------|
| `AgentConfig` | 不可变的智能体配置 |
| `RPCMethodInfo` | RPC 方法元信息 |
| `Information` | Information 文档定义 |
| `Context` | 请求上下文 |
| `Session` | 会话存储 |

### 3.3 上下文管理模块 (`context.py`)

提供基于 DID 的会话管理：

- **Session**：单个用户的会话对象，支持 key-value 存储
- **SessionManager**：管理所有会话，自动清理过期会话
- **Context**：请求上下文，包含 DID、Session、Request 等信息

### 3.4 自动路由生成模块 (`autogen.py`)

自动生成 FastAPI 路由：

- `GET /prefix/ad.json` - Agent Description 文档
- `GET /prefix/interface.json` - OpenRPC 接口文档
- `GET /prefix/interface/{method}.json` - 单独的方法接口文档（link 模式）
- `POST /prefix/rpc` - JSON-RPC 2.0 端点

### 3.5 Schema 生成模块 (`schema_gen.py`)

从 Python 类型提示自动生成 JSON Schema：

```python
# Python 类型
async def search(self, query: str, limit: int = 10) -> dict:
    ...

# 自动生成的 Schema
{
    "type": "object",
    "properties": {
        "query": {"type": "string"},
        "limit": {"type": "integer", "default": 10}
    },
    "required": ["query"]
}
```

### 3.6 客户端模块 (`client/`)

提供远程智能体调用能力：

| 类 | 说明 |
|----|------|
| `RemoteAgent` | 远程智能体代理，支持动态方法调用 |
| `Method` | 方法定义（name, params, rpc_url） |
| `HttpError` | HTTP 请求错误 |
| `RpcError` | JSON-RPC 错误响应 |

### 3.7 工具函数模块 (`utils.py`)

提供纯函数工具：

- `generate_ad_document()` - 生成 ad.json 文档
- `generate_rpc_interface()` - 生成 OpenRPC 文档
- `validate_rpc_request()` - 验证 JSON-RPC 请求
- `create_rpc_response()` / `create_rpc_error()` - 创建响应

---

## 四、开发指南

### 4.1 环境准备

```bash
# 安装依赖（包含 FastAPI）
uv sync --extra api

# 或使用 pip
pip install anp[api]
```

### 4.2 快速开发服务端

#### 极简示例（约 30 行代码）

```python
from fastapi import FastAPI
from anp.openanp import anp_agent, interface, AgentConfig

@anp_agent(AgentConfig(
    name="Calculator",
    did="did:wba:example.com:calculator",
    prefix="/agent",
    description="A simple calculator agent",
))
class CalculatorAgent:
    """极简计算器智能体"""

    @interface
    async def add(self, a: int, b: int) -> int:
        """计算两数之和"""
        return a + b

    @interface
    async def multiply(self, a: int, b: int) -> int:
        """计算两数之积"""
        return a * b

app = FastAPI(title="Calculator Agent")
app.include_router(CalculatorAgent.router())
```

运行服务：

```bash
uvicorn your_module:app --port 8000
```

自动生成的端点：
- `GET /agent/ad.json` - Agent Description
- `GET /agent/interface.json` - OpenRPC 文档
- `POST /agent/rpc` - JSON-RPC 端点

#### 带 Context 的服务端

Context 是 OpenANP 的核心特性，通过参数注入自动提供：

```python
from anp.openanp import anp_agent, interface, AgentConfig, Context

@anp_agent(AgentConfig(
    name="Hotel Service",
    did="did:wba:example.com:hotel",
    prefix="/hotel",
))
class HotelAgent:
    @interface
    async def search(self, query: str, ctx: Context) -> dict:
        """带会话追踪的搜索"""
        # ctx.did - 调用者的 DID（身份标识）
        caller = ctx.did

        # ctx.session - 基于 DID 的会话存储
        ctx.session.set("last_query", query)
        history = ctx.session.get("search_history", [])
        history.append(query)
        ctx.session.set("search_history", history)

        return {
            "results": [{"name": "Tokyo Hotel", "price": 100}],
            "caller": caller,
            "query_count": len(history),
        }
```

**Context 的关键属性：**

| 属性 | 类型 | 说明 |
|------|------|------|
| `ctx.did` | `str` | 调用者的 DID，用于身份识别 |
| `ctx.session` | `Session` | 基于 DID 隔离的会话存储 |
| `ctx.request` | `Request` | FastAPI Request 对象 |
| `ctx.auth_result` | `dict` | 认证结果 |

#### 带 Information 的服务端

Information 用于在 ad.json 中暴露元数据：

```python
from anp.openanp import anp_agent, interface, information, AgentConfig, Information

@anp_agent(AgentConfig(
    name="Hotel Service",
    did="did:wba:example.com:hotel",
    prefix="/hotel",
))
class HotelAgent:
    # 静态 Information（类属性）
    informations = [
        Information(
            type="VideoObject",
            description="酒店宣传视频",
            url="https://cdn.example.com/tour.mp4",
        ),
        Information(
            type="Contact",
            description="联系方式",
            mode="content",  # 内嵌到 ad.json
            content={"phone": "+86-123-4567"},
        ),
    ]

    # 动态 Information（方法）
    @information(
        type="Product",
        description="今日房态",
        path="/availability.json",
    )
    def get_availability(self) -> dict:
        return {"available_rooms": 42}

    @interface
    async def search(self, query: str) -> dict:
        return {"results": [...]}
```

#### 自定义 ad.json

通过 `customize_ad` 钩子自定义生成的 ad.json：

```python
@anp_agent(config)
class HotelAgent:
    @interface
    async def search(self, query: str) -> dict:
        return {"results": [...]}

    def customize_ad(self, ad: dict, base_url: str) -> dict:
        """自定义 ad.json - 由 OpenANP 自动调用"""
        ad["custom_metadata"] = {"version": "2.0.0"}
        ad["support"] = {"email": "support@hotel.com"}
        return ad
```

### 4.3 快速开发客户端

#### 极简示例（约 25 行代码）

```python
import asyncio
from anp.openanp import RemoteAgent
from anp.authentication import DIDWbaAuthHeader

async def main():
    # 1. 创建认证
    auth = DIDWbaAuthHeader(
        did_document_path="/path/to/did-doc.json",
        private_key_path="/path/to/private-key.pem",
    )

    # 2. 发现智能体（自动获取 ad.json 和 interface.json）
    agent = await RemoteAgent.discover(
        "http://localhost:8000/agent/ad.json",
        auth,
    )

    print(f"连接成功: {agent.name}")
    print(f"可用方法: {agent.method_names}")

    # 3. 调用方法 - 动态属性访问（推荐）
    result = await agent.add(a=10, b=20)
    print(f"10 + 20 = {result}")

    # 或使用显式调用
    result = await agent.call("multiply", a=6, b=7)
    print(f"6 × 7 = {result}")

asyncio.run(main())
```

#### RemoteAgent 的核心特性

**RemoteAgent 将远端智能体的所有方法下载到本地，并转化成本地方法来调用。**

```python
# 智能体信息
print(agent.name)           # 智能体名称
print(agent.description)    # 智能体描述
print(agent.method_names)   # 可用方法列表

# 方法调用
result = await agent.search(query="Tokyo")  # 动态访问
result = await agent.call("search", query="Tokyo")  # 显式调用

# LLM 集成 - 获取 OpenAI Tools 格式
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
```

#### 错误处理

OpenANP 采用快速失败设计：

```python
from anp.openanp.client import HttpError, RpcError

try:
    agent = await RemoteAgent.discover(url, auth)
    result = await agent.search(query="Tokyo")
except HttpError as e:
    print(f"HTTP 错误 {e.status}: {e} (url: {e.url})")
except RpcError as e:
    print(f"RPC 错误 {e.code}: {e} (data: {e.data})")
except ValueError as e:
    print(f"发现失败: {e}")
except AttributeError as e:
    print(f"方法不存在: {e}")
```

### 4.4 P2P 模式：既是客户端也是服务端

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
        """规划旅行 - 我既是服务端也是客户端"""
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

## 五、接口模式

OpenANP 支持两种接口模式：

### Content 模式（默认）

所有方法合并到单个 `interface.json`，适合方法较少的智能体。

```python
@interface  # 默认 content 模式
async def search(self, query: str) -> dict:
    ...
```

### Link 模式

每个方法生成独立的接口文件，适合复杂方法或需要独立版本控制的场景。

```python
@interface(mode="link")
async def book(self, hotel_id: str) -> dict:
    ...
```

生成的 ad.json 结构：

```json
{
  "interfaces": [
    {
      "type": "StructuredInterface",
      "protocol": "openrpc",
      "url": "https://example.com/hotel/interface.json",
      "description": "Hotel Service JSON-RPC interface"
    },
    {
      "type": "StructuredInterface",
      "protocol": "openrpc",
      "url": "https://example.com/hotel/interface/book.json",
      "description": "Book a hotel room"
    }
  ]
}
```

---

## 六、完整示例

完整的示例代码位于 `examples/python/openanp_examples/` 目录：

| 文件 | 说明 |
|------|------|
| `minimal_server.py` | 极简服务端（约 30 行） |
| `minimal_client.py` | 极简客户端（约 25 行） |
| `advanced_server.py` | 完整服务端（Context、Session、Information） |
| `advanced_client.py` | 完整客户端（发现、LLM 集成、错误处理） |

运行示例：

```bash
# 安装依赖
uv sync --extra api

# 终端 1：启动服务端
uvicorn examples.python.openanp_examples.minimal_server:app --port 8000

# 终端 2：运行客户端
uv run python examples/python/openanp_examples/minimal_client.py
```

---

## 七、总结

OpenANP 通过以下方式简化了 ANP 协议的开发：

| 特性 | 说明 |
|------|------|
| 装饰器驱动 | `@anp_agent`、`@interface`、`@information` 一行代码搞定 |
| 自动 Schema 生成 | 从 Python 类型提示自动生成 JSON Schema |
| Context 注入 | 自动注入会话和认证信息 |
| RemoteAgent 代理 | 像调用本地方法一样调用远程智能体 |
| LLM 集成 | 一键导出 OpenAI Tools 格式 |
| P2P 支持 | 每个智能体既是客户端也是服务端 |

如果你正在构建基于 ANP 协议的智能体应用，OpenANP 将是你的得力助手。欢迎使用并提供反馈！

---

## 参考资料

- [OpenANP README (中文)](../anp/openanp/README.cn.md)
- [OpenANP README (English)](../anp/openanp/README.md)
- [ANP 协议规范](https://github.com/anthropics/agent-network-protocol)
- [OpenRPC 规范](https://open-rpc.org/)

---

*本文基于 OpenANP v0.0.2 编写*
