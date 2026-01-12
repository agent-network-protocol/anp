# OpenANP Examples

OpenANP - The simplest ANP (Agent Network Protocol) Python SDK.

## 🚀 Quick Start in 30 Seconds

### Server (Build an ANP Server in 3 Steps)

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

### Client (Call Remote Agent in 3 Lines)

```python
from anp.openanp import RemoteAgent

agent = await RemoteAgent.discover("http://localhost:8000/agent/ad.json", auth)
result = await agent.hello(name="World")  # "Hello, World!"
```

---

## 📁 Example Files

| File | Description | Complexity |
|------|-------------|------------|
| `minimal_server.py` | Minimal server | ⭐ |
| `minimal_client.py` | Minimal client | ⭐ |
| `advanced_server.py` | Full features (Context, Session, Information) | ⭐⭐⭐ |
| `advanced_client.py` | Full client (discovery, error handling, LLM integration) | ⭐⭐⭐ |

---

## 🏃 Running Examples

### Prerequisites

```bash
# Install dependencies (requires api extra)
uv sync --extra api
```

### Run Minimal Example

```bash
# Terminal 1: Start server
uvicorn examples.python.openanp_examples.minimal_server:app --port 8000

# Terminal 2: Run client
uv run python examples/python/openanp_examples/minimal_client.py
```

### Run Advanced Example

```bash
# Terminal 1: Start server
uvicorn examples.python.openanp_examples.advanced_server:app --port 8000

# Terminal 2: Run client
uv run python examples/python/openanp_examples/advanced_client.py
```

---

## 🔧 Server API

### @anp_agent - Agent Decorator

```python
@anp_agent(AgentConfig(
    name="Agent Name",           # Agent name
    did="did:wba:...",           # DID identifier
    prefix="/agent",             # Route prefix
    description="Description",   # Optional: description
    tags=["tag1"],               # Optional: tags
))
class MyAgent:
    ...
```

### @interface - RPC Methods

```python
# Basic usage (content mode, embedded in interface.json)
@interface
async def method(self, param: str) -> dict:
    ...

# Link mode (separate interface file)
@interface(mode="link")
async def method(self, param: str) -> dict:
    ...

# Context injection (access session, DID, request)
@interface
async def method(self, param: str, ctx: Context) -> dict:
    ctx.session.set("key", "value")
    return {"did": ctx.did}
```

### Information - Information Documents

```python
class MyAgent:
    # Static Information
    informations = [
        Information(type="ImageObject", description="Logo", url="https://..."),
        Information(type="Contact", mode="content", content={"phone": "123"}),
    ]

    # Dynamic Information (URL mode)
    @information(type="Product", path="/products/list.json")
    def get_products(self) -> dict:
        return {"items": [...]}

    # Dynamic Information (Content mode, embedded in ad.json)
    @information(type="Offer", mode="content")
    def get_offers(self) -> dict:
        return {"discount": "20%"}
```

---

## 📡 Generated Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /prefix/ad.json` | Agent Description document |
| `GET /prefix/interface.json` | OpenRPC interface document (content mode methods) |
| `GET /prefix/interface/{method}.json` | Separate interface document (link mode methods) |
| `GET /prefix/{path}` | Dynamic Information endpoints |
| `POST /prefix/rpc` | JSON-RPC 2.0 endpoint |

---

## 🔌 Client API

### RemoteAgent - Remote Agent

```python
from anp.openanp import RemoteAgent

# Discover agent
agent = await RemoteAgent.discover(ad_url, auth)

# Agent info
print(agent.name)           # Agent name
print(agent.description)    # Description
print(agent.methods)        # Method list

# Call methods (two ways)
result = await agent.hello(name="World")              # Dynamic attribute
result = await agent.call("hello", name="World")      # Explicit call

# LLM Integration
tools = agent.tools  # OpenAI Tools format
```

---

## 🧪 Manual Testing

### Test JSON-RPC Call

```bash
# Call add method
curl -X POST http://localhost:8000/agent/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"add","params":{"a":10,"b":20},"id":1}'

# Response: {"jsonrpc":"2.0","result":30,"id":1}
```

### View Agent Description

```bash
curl http://localhost:8000/agent/ad.json | jq
```

### View OpenRPC Interface Document

```bash
curl http://localhost:8000/agent/interface.json | jq
```

---

## 📖 More Resources

- [ANP Protocol Specification](https://github.com/agent-network-protocol)
- [AgentConnect Documentation](../../../docs/)
