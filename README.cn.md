<div align="center">

[English](README.md) | [中文](README.cn.md)

</div>

# AgentConnect

## AgentConnect是什么

AgentConnect是[Agent Network Protocol(ANP)](https://github.com/agent-network-protocol/AgentNetworkProtocol)的开源SDK实现。

AgentNetworkProtocol(ANP)的目标是成为**智能体互联网时代的HTTP**，为数十亿智能体构建一个开放、安全、高效的协作网络。

<p align="center">
  <img src="/images/agentic-web.png" width="50%" alt="Agentic Web"/>
</p>

## 🚀 快速开始 - 30秒构建ANP智能体

OpenANP是构建ANP智能体最简单的方式。只需几行代码即可完成：

### 服务端（3步搭建）

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

运行：`uvicorn app:app --port 8000`

### 客户端（3行调用）

```python
from anp.openanp import RemoteAgent

agent = await RemoteAgent.discover("http://localhost:8000/agent/ad.json", auth)
result = await agent.hello(name="World")  # "Hello, World!"
```

### 自动生成的端点

| 端点 | 说明 |
|------|------|
| `GET /agent/ad.json` | Agent Description 文档 |
| `GET /agent/interface.json` | OpenRPC 接口文档 |
| `POST /agent/rpc` | JSON-RPC 2.0 端点 |

📖 **完整示例**：[OpenANP 示例](examples/python/openanp_examples/)

---

## 两种使用ANP SDK的方式

### 🔧 方式一：OpenANP（推荐 - 构建智能体）

最优雅、最简洁的ANP智能体SDK：

```python
from anp.openanp import anp_agent, interface, RemoteAgent

# 服务端：构建你的智能体
@anp_agent(AgentConfig(name="Hotel", did="did:wba:...", prefix="/hotel"))
class HotelAgent:
    @interface
    async def search(self, query: str) -> dict:
        return {"results": [...]}

# 客户端：调用远程智能体
agent = await RemoteAgent.discover("https://hotel.example.com/ad.json", auth)
result = await agent.search(query="Tokyo")
```

**特性：**
- **装饰器驱动**：`@anp_agent` + `@interface` = 完整智能体
- **自动生成**：ad.json、interface.json、JSON-RPC 端点
- **Context 注入**：自动管理会话和 DID
- **LLM 集成**：内置 OpenAI Tools 格式导出

📖 **完整文档**：[OpenANP README](anp/openanp/README.cn.md)

---

### 🔍 方式二：ANP Crawler（文档爬取）

爬虫风格的SDK，用于爬取和解析ANP文档（类似于ANP的网络爬虫）：

```python
from anp.anp_crawler import ANPCrawler

# 使用DID认证初始化爬虫
crawler = ANPCrawler(
    did_document_path="path/to/did.json",
    private_key_path="path/to/key.pem"
)

# 爬取智能体描述并获取OpenAI Tools格式
content, tools = await crawler.fetch_text("https://example.com/ad.json")

# 执行发现的工具
result = await crawler.execute_tool_call("search_poi", {"query": "北京"})

# 或直接调用JSON-RPC
result = await crawler.execute_json_rpc(
    endpoint="https://example.com/rpc",
    method="search",
    params={"query": "hotel"}
)
```

你可以将crawler的接口封装为LLM的tools，这样可以作为ANP客户端与ANP server进行交互。

**特性：**
- **爬虫风格**：像网络爬虫一样爬取和解析ANP文档
- **OpenAI Tools格式**：转换接口用于LLM集成
- **直接JSON-RPC**：无需接口发现即可调用方法
- **无需LLM**：确定性的数据收集

📖 **完整文档**：[ANP Crawler README](anp/anp_crawler/README.cn.md)

---

### RemoteAgent vs ANPCrawler

| 特性 | RemoteAgent | ANPCrawler |
|------|-------------|------------|
| **风格** | 代理对象（像本地方法） | 爬虫（爬取文档） |
| **用法** | `agent.search(query="Tokyo")` | `crawler.execute_tool_call("search", {...})` |
| **类型安全** | 完整类型提示，异常驱动 | 基于字典的返回 |
| **适用场景** | 使用代码访问固定的智能体，构建ANP的Skills | 使用LLM驱动的方式，访问远程的ANP智能体，并且与智能体进行交互 |

```python
# RemoteAgent：方法调用像本地方法一样
agent = await RemoteAgent.discover(url, auth)
result = await agent.search(query="Tokyo")  # 像调用本地方法

# ANPCrawler：爬虫风格的文档爬取
crawler = ANPCrawler(did_path, key_path)
content, tools = await crawler.fetch_text(url)  # 爬取和解析文档
result = await crawler.execute_tool_call("search", {"query": "Tokyo"})
```

---

## 安装

### 方式一：通过pip安装
```bash
pip install anp
```

### 方式二：源码安装（推荐开发者使用）

```bash
# 克隆仓库
git clone https://github.com/agent-network-protocol/AgentConnect.git
cd AgentConnect

# 使用UV配置环境
uv sync

# 安装可选依赖
uv sync --extra api      # FastAPI/OpenAI 集成
uv sync --extra dev      # 开发工具

# 运行示例
uv run python examples/python/did_wba_examples/create_did_document.py
```

---

## 所有核心模块

| 模块 | 说明 | 文档 |
|------|------|------|
| **OpenANP** | 装饰器驱动的智能体开发（推荐） | [README](anp/openanp/README.cn.md) |
| **ANP Crawler** | 轻量级发现与交互SDK | [README](anp/anp_crawler/README.cn.md) |
| **FastANP** | FastAPI插件框架 | [README](anp/fastanp/README.cn.md) |
| **AP2** | 智能体支付协议v2 | [README](anp/ap2/README.cn.md) |
| **Authentication** | DID-WBA身份认证 | [示例](examples/python/did_wba_examples/) |

---

## 按模块分类的示例

### OpenANP示例（推荐入门）
位置：`examples/python/openanp_examples/`

| 文件 | 说明 | 复杂度 |
|------|------|--------|
| `minimal_server.py` | 极简服务端（约30行） | ⭐ |
| `minimal_client.py` | 极简客户端（约25行） | ⭐ |
| `advanced_server.py` | 完整功能（Context、Session、Information） | ⭐⭐⭐ |
| `advanced_client.py` | 完整客户端（发现、LLM集成） | ⭐⭐⭐ |

```bash
# 终端1：启动服务端
uvicorn examples.python.openanp_examples.minimal_server:app --port 8000

# 终端2：运行客户端
uv run python examples/python/openanp_examples/minimal_client.py
```

### ANP Crawler示例
位置：`examples/python/anp_crawler_examples/`

```bash
# 快速入门
uv run python examples/python/anp_crawler_examples/simple_amap_example.py

# 完整演示
uv run python examples/python/anp_crawler_examples/amap_crawler_example.py
```

### DID-WBA身份认证示例
位置：`examples/python/did_wba_examples/`

```bash
# 创建DID文档
uv run python examples/python/did_wba_examples/create_did_document.py

# 身份认证演示
uv run python examples/python/did_wba_examples/authenticate_and_verify.py
```

### FastANP示例
位置：`examples/python/fastanp_examples/`

```bash
# 简单智能体
uv run python examples/python/fastanp_examples/simple_agent.py

# 酒店预订智能体（完整示例）
uv run python examples/python/fastanp_examples/hotel_booking_agent.py
```

### AP2支付协议示例
位置：`examples/python/ap2_examples/`

```bash
# 完整AP2流程（商户+购物者）
uv run python examples/python/ap2_examples/ap2_complete_flow.py
```

---

## 工具

### ANP网络探索器
使用自然语言探索智能体网络：[ANP网络探索器](https://service.agent-network-protocol.com/anp-explorer/)

### DID文档生成工具
```bash
uv run python tools/did_generater/generate_did_doc.py <did> [--agent-description-url URL]
```

---

## 联系我们

- **作者**：常高伟
- **邮箱**：chgaowei@gmail.com
- **官网**：[https://agent-network-protocol.com/](https://agent-network-protocol.com/)
- **Discord**：[https://discord.gg/sFjBKTY7sB](https://discord.gg/sFjBKTY7sB)
- **GitHub**：[https://github.com/agent-network-protocol/AgentNetworkProtocol](https://github.com/agent-network-protocol/AgentNetworkProtocol)
- **微信**：flow10240

## 许可证

本项目基于MIT许可证开源。详细信息请参阅[LICENSE](LICENSE)文件。

---

**Copyright (c) 2024 GaoWei Chang**
