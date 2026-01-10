# OpenANP Examples

OpenANP - 极简的 ANP (Agent Network Protocol) Python SDK。

## 🚀 30 秒快速开始

### 服务端（3 步搭建 ANP Server）

```python
from fastapi import FastAPI
from anp.openanp import AgentConfig, anp_agent, interface

@anp_agent(AgentConfig(
    name="My Agent",
    did="did:wba:example.com:agent",
    prefix="/agent",
))
class MyAgent:
    @interface
    async def hello(self, name: str) -> str:
        return f"Hello, {name}!"

app = FastAPI()
app.include_router(MyAgent.router())
```

启动：`uvicorn app:app --port 8000`

### 客户端（3 行调用远程代理）

```python
from anp.openanp import RemoteAgent

agent = await RemoteAgent.discover("http://localhost:8000/agent/ad.json", auth)
result = await agent.hello(name="World")  # "Hello, World!"
```

---

## 📁 示例文件

| 文件 | 说明 | 复杂度 |
|------|------|--------|
| `minimal_server.py` | 极简服务端 | ⭐ |
| `minimal_client.py` | 极简客户端 | ⭐ |
| `advanced_server.py` | 完整服务端（Context、Session、Information） | ⭐⭐⭐ |
| `advanced_client.py` | 完整客户端（方法发现、错误处理、LLM集成） | ⭐⭐⭐ |

---

## 🏃 运行示例

### 前提条件

```bash
# 安装依赖（需要 api extra）
uv sync --extra api
```

### 运行极简示例

```bash
# 终端 1：启动服务端
uvicorn examples.python.openanp_examples.minimal_server:app --port 8000

# 终端 2：运行客户端
uv run python examples/python/openanp_examples/minimal_client.py
```

### 运行完整示例

```bash
# 终端 1：启动服务端
uvicorn examples.python.openanp_examples.advanced_server:app --port 8000

# 终端 2：运行客户端
uv run python examples/python/openanp_examples/advanced_client.py
```

---

## 🔧 服务端 API

### @anp_agent - 代理装饰器

```python
@anp_agent(AgentConfig(
    name="Agent Name",           # 代理名称
    did="did:wba:...",           # DID 标识符
    prefix="/agent",             # 路由前缀
    description="描述",          # 可选：描述
    tags=["tag1"],               # 可选：标签
))
class MyAgent:
    ...
```

### @interface - RPC 方法

```python
# 基础用法（content 模式，嵌入 interface.json）
@interface
async def method(self, param: str) -> dict:
    ...

# Link 模式（独立 interface 文件）
@interface(mode="link")
async def method(self, param: str) -> dict:
    ...

# Context 注入（获取 session、DID、request）
@interface
async def method(self, param: str, ctx: Context) -> dict:
    ctx.session.set("key", "value")
    return {"did": ctx.did}
```

### Information - 信息文档

```python
class MyAgent:
    # 静态 Information
    informations = [
        Information(type="ImageObject", description="Logo", url="https://..."),
        Information(type="Contact", mode="content", content={"phone": "123"}),
    ]

    # 动态 Information（URL 模式）
    @information(type="Product", path="/products/list.json")
    def get_products(self) -> dict:
        return {"items": [...]}

    # 动态 Information（Content 模式，嵌入 ad.json）
    @information(type="Offer", mode="content")
    def get_offers(self) -> dict:
        return {"discount": "20%"}
```

---

## 📡 生成的端点

| 端点 | 说明 |
|------|------|
| `GET /prefix/ad.json` | Agent Description 文档 |
| `GET /prefix/interface.json` | OpenRPC 接口文档（content 模式方法） |
| `GET /prefix/interface/{method}.json` | 独立接口文档（link 模式方法） |
| `GET /prefix/{path}` | 动态 Information 端点 |
| `POST /prefix/rpc` | JSON-RPC 2.0 端点 |

---

## 🔌 客户端 API

### RemoteAgent - 远程代理

```python
from anp.openanp import RemoteAgent

# 发现代理
agent = await RemoteAgent.discover(ad_url, auth)

# 代理信息
print(agent.name)           # 代理名称
print(agent.description)    # 描述
print(agent.methods)        # 方法列表

# 方法调用（两种方式）
result = await agent.hello(name="World")              # 动态属性
result = await agent.call("hello", name="World")      # 显式调用

# LLM 集成
tools = agent.tools  # OpenAI Tools 格式
```

---

## 🧪 手动测试

### 测试 JSON-RPC 调用

```bash
# 调用 add 方法
curl -X POST http://localhost:8000/agent/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"add","params":{"a":10,"b":20},"id":1}'

# 响应: {"jsonrpc":"2.0","result":30,"id":1}
```

### 查看 Agent Description

```bash
curl http://localhost:8000/agent/ad.json | jq
```

### 查看 OpenRPC 接口文档

```bash
curl http://localhost:8000/agent/interface.json | jq
```

---

## 📖 更多资源

- [ANP 协议规范](https://github.com/agent-network-protocol)
- [AgentConnect 文档](../../../docs/)
