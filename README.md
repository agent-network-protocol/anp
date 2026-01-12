<div align="center">

[English](README.md) | [中文](README.cn.md)

</div>

# AgentConnect

## What is AgentConnect

AgentConnect is an open-source SDK implementation of the [Agent Network Protocol (ANP)](https://github.com/agent-network-protocol/AgentNetworkProtocol).

The goal of Agent Network Protocol (ANP) is to become the **HTTP of the Intelligent Agent Internet Era**, building an open, secure, and efficient collaborative network for billions of intelligent agents.

<p align="center">
  <img src="/images/agentic-web.png" width="50%" alt="Agentic Web"/>
</p>

## 🚀 Quick Start - Build an ANP Agent in 30 Seconds

OpenANP is the simplest way to build ANP agents. Here's a complete server in just a few lines:

### Server (3 Steps)

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

Run: `uvicorn app:app --port 8000`

### Client (3 Lines)

```python
from anp.openanp import RemoteAgent

agent = await RemoteAgent.discover("http://localhost:8000/agent/ad.json", auth)
result = await agent.hello(name="World")  # "Hello, World!"
```

### Generated Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /agent/ad.json` | Agent Description document |
| `GET /agent/interface.json` | OpenRPC interface document |
| `POST /agent/rpc` | JSON-RPC 2.0 endpoint |

📖 **Full examples**: [OpenANP Examples](examples/python/openanp_examples/)

---

## Two Ways to Use ANP SDK

### 🔧 Option 1: OpenANP (Recommended - Building Agents)

The most elegant and minimal SDK for building ANP agents:

```python
from anp.openanp import anp_agent, interface, RemoteAgent

# Server: Build your agent
@anp_agent(AgentConfig(name="Hotel", did="did:wba:...", prefix="/hotel"))
class HotelAgent:
    @interface
    async def search(self, query: str) -> dict:
        return {"results": [...]}

# Client: Call remote agents
agent = await RemoteAgent.discover("https://hotel.example.com/ad.json", auth)
result = await agent.search(query="Tokyo")
```

**Features:**
- **Decorator-based**: `@anp_agent` + `@interface` = complete agent
- **Auto-generated**: ad.json, interface.json, JSON-RPC endpoint
- **Context Injection**: Automatic session and DID management
- **LLM Integration**: Built-in OpenAI Tools format export

📖 **Full Documentation**: [OpenANP README](anp/openanp/README.md)

---

### 🔍 Option 2: ANP Crawler (Document Fetching)

Crawler-style SDK for fetching and parsing ANP documents (like a web crawler for ANP):

```python
from anp.anp_crawler import ANPCrawler

# Initialize crawler with DID authentication
crawler = ANPCrawler(
    did_document_path="path/to/did.json",
    private_key_path="path/to/key.pem"
)

# Crawl agent description and get OpenAI Tools format
content, tools = await crawler.fetch_text("https://example.com/ad.json")

# Execute discovered tools
result = await crawler.execute_tool_call("search_poi", {"query": "Beijing"})

# Or call JSON-RPC directly
result = await crawler.execute_json_rpc(
    endpoint="https://example.com/rpc",
    method="search",
    params={"query": "hotel"}
)
```

**Features:**
- **Crawler Style**: Fetch and parse ANP documents like a web crawler
- **OpenAI Tools Format**: Converts interfaces for LLM integration
- **Direct JSON-RPC**: Call methods without interface discovery
- **No LLM Required**: Deterministic data collection

📖 **Full Documentation**: [ANP Crawler README](anp/anp_crawler/README.md)

---

### RemoteAgent vs ANPCrawler

| Feature | RemoteAgent | ANPCrawler |
|---------|-------------|------------|
| **Style** | Proxy object (like local methods) | Crawler (fetch documents) |
| **Usage** | `agent.search(query="Tokyo")` | `crawler.execute_tool_call("search", {...})` |
| **Type Safety** | Full type hints, exceptions | Dict-based returns |
| **Best For** | Agent-to-agent calls in code | LLM tool integration, data collection |

```python
# RemoteAgent: Methods feel like local calls
agent = await RemoteAgent.discover(url, auth)
result = await agent.search(query="Tokyo")  # Like calling a local method

# ANPCrawler: Crawler-style document fetching
crawler = ANPCrawler(did_path, key_path)
content, tools = await crawler.fetch_text(url)  # Fetch and parse documents
result = await crawler.execute_tool_call("search", {"query": "Tokyo"})
```

---

## Installation

### Option 1: Install via pip
```bash
pip install anp
```

### Option 2: Source Installation (Recommended for Developers)

```bash
# Clone the repository
git clone https://github.com/agent-network-protocol/AgentConnect.git
cd AgentConnect

# Setup environment with UV
uv sync

# Install with optional dependencies
uv sync --extra api      # FastAPI/OpenAI integration
uv sync --extra dev      # Development tools

# Run examples
uv run python examples/python/did_wba_examples/create_did_document.py
```

---

## All Core Modules

| Module | Description | Documentation |
|--------|-------------|---------------|
| **OpenANP** | Decorator-driven agent development (recommended) | [README](anp/openanp/README.md) |
| **ANP Crawler** | Lightweight discovery & interaction SDK | [README](anp/anp_crawler/README.md) |
| **FastANP** | FastAPI plugin framework | [README](anp/fastanp/README.md) |
| **AP2** | Agent Payment Protocol v2 | [README](anp/ap2/README.md) |
| **Authentication** | DID-WBA identity authentication | [Examples](examples/python/did_wba_examples/) |

---

## Examples by Module

### OpenANP Examples (Recommended Starting Point)
Location: `examples/python/openanp_examples/`

| File | Description | Complexity |
|------|-------------|------------|
| `minimal_server.py` | Minimal server (~30 lines) | ⭐ |
| `minimal_client.py` | Minimal client (~25 lines) | ⭐ |
| `advanced_server.py` | Full features (Context, Session, Information) | ⭐⭐⭐ |
| `advanced_client.py` | Full client (discovery, LLM integration) | ⭐⭐⭐ |

```bash
# Terminal 1: Start server
uvicorn examples.python.openanp_examples.minimal_server:app --port 8000

# Terminal 2: Run client
uv run python examples/python/openanp_examples/minimal_client.py
```

### ANP Crawler Examples
Location: `examples/python/anp_crawler_examples/`

```bash
# Quick start
uv run python examples/python/anp_crawler_examples/simple_amap_example.py

# Complete demonstration
uv run python examples/python/anp_crawler_examples/amap_crawler_example.py
```

### DID-WBA Authentication Examples
Location: `examples/python/did_wba_examples/`

```bash
# Create DID document
uv run python examples/python/did_wba_examples/create_did_document.py

# Authentication demonstration
uv run python examples/python/did_wba_examples/authenticate_and_verify.py
```

### FastANP Examples
Location: `examples/python/fastanp_examples/`

```bash
# Simple agent
uv run python examples/python/fastanp_examples/simple_agent.py

# Hotel booking agent (full example)
uv run python examples/python/fastanp_examples/hotel_booking_agent.py
```

### AP2 Payment Protocol Examples
Location: `examples/python/ap2_examples/`

```bash
# Complete AP2 flow (merchant + shopper)
uv run python examples/python/ap2_examples/ap2_complete_flow.py
```

---

## Tools

### ANP Network Explorer
Explore the agent network using natural language: [ANP Network Explorer](https://service.agent-network-protocol.com/anp-explorer/)

### DID Document Generator
```bash
uv run python tools/did_generater/generate_did_doc.py <did> [--agent-description-url URL]
```

---

## Contact Us

- **Author**: GaoWei Chang
- **Email**: chgaowei@gmail.com
- **Website**: [https://agent-network-protocol.com/](https://agent-network-protocol.com/)
- **Discord**: [https://discord.gg/sFjBKTY7sB](https://discord.gg/sFjBKTY7sB)
- **GitHub**: [https://github.com/agent-network-protocol/AgentNetworkProtocol](https://github.com/agent-network-protocol/AgentNetworkProtocol)
- **WeChat**: flow10240

## License

This project is open-sourced under the MIT License. See [LICENSE](LICENSE) file for details.

---

**Copyright (c) 2024 GaoWei Chang**
