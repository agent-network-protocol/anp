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

## Core Modules

### OpenANP (Recommended - Simplest Way to Build ANP Agents)
The most elegant and minimal SDK for building ANP agents:
- **Decorator-based**: `@anp_agent` + `@interface` = complete agent
- **Auto-generated**: ad.json, interface.json, JSON-RPC endpoint
- **Context Injection**: Automatic session and DID management
- **Client SDK**: `RemoteAgent.discover()` for calling remote agents
- **LLM Integration**: Built-in OpenAI Tools format export

For complete documentation, see [OpenANP Examples](examples/python/openanp_examples/)

### Authentication
Agent identity authentication system based on DID-WBA (Decentralized Identifier - Web-Based Authentication):
- **Identity Management**: Create and manage agent DID documents
- **Identity Verification**: Provide end-to-end identity authentication and authorization
- **Secure Communication**: Ensure security and trustworthiness of inter-agent communication

### ANP Crawler (Agent Discovery & Interaction)
Discovery and interaction tools for the agent network:
- **Agent Discovery**: Automatically discover and parse agent description documents
- **Interface Parsing**: Parse JSON-RPC interfaces and convert them to callable tools
- **Protocol Interaction**: Support communication with agents that comply with ANP protocol
- **Direct JSON-RPC**: Execute JSON-RPC requests directly without interface discovery

### FastANP (Fast Development Framework)
Plugin-based framework for building ANP agents with FastAPI:
- **Plugin Architecture**: FastAPI as main framework, FastANP as helper plugin
- **Automatic OpenRPC**: Generate OpenRPC documents from Python functions
- **Context Injection**: Automatic session and Request object injection
- **DID WBA Authentication**: Built-in authentication middleware with wildcard path exemption
- **Flexible Routing**: Full control over all routes including ad.json
- **Session Management**: Built-in session management based on DID

For complete documentation, see [FastANP README](anp/fastanp/README.md)

### AP2 (Agent Payment Protocol v2)
Secure payment authorization protocol for agent transactions:
- **CartMandate**: Shopping cart authorization with merchant signature
- **PaymentMandate**: Payment authorization with user signature
- **ES256K Signing**: Support for ECDSA secp256k1 signatures
- **Hash Integrity**: Cart and payment data integrity verification
- **DID WBA Integration**: Seamless integration with DID-based authentication

**Specification Document**: [AP2 Protocol Specification](docs/ap2/ap2-flow.md)

## Usage

### Option 1: Install via pip
```bash
pip install anp
```

### Option 2: Source Installation (Recommended for Developers)

```bash
# 下载源码
git clone https://github.com/agent-network-protocol/AgentConnect.git
cd AgentConnect

# 使用UV配置环境
uv sync

# 运行示例
uv run python examples/python/did_wba_examples/create_did_document.py
```

## Example Demonstration

### OpenANP Agent Development Example (Recommended)
Location: `examples/python/openanp_examples/`

The simplest way to build ANP agents. Perfect for getting started.

#### Example Files
| File | Description | Complexity |
|------|-------------|------------|
| `minimal_server.py` | Minimal server (~30 lines) | ⭐ |
| `minimal_client.py` | Minimal client (~25 lines) | ⭐ |
| `advanced_server.py` | Full features (Context, Session, Information) | ⭐⭐⭐ |
| `advanced_client.py` | Full client (discovery, LLM integration) | ⭐⭐⭐ |

#### Running Examples
```bash
# Terminal 1: Start server
uvicorn examples.python.openanp_examples.minimal_server:app --port 8000

# Terminal 2: Run client
uv run python examples/python/openanp_examples/minimal_client.py
```

**Detailed Documentation**: [OpenANP Examples README](examples/python/openanp_examples/README.md)

### DID-WBA Authentication Example
Location: `examples/python/did_wba_examples/`

#### Main Examples
- **Create DID Document** (`create_did_document.py`)  
  Demonstrate how to generate DID documents and key pairs for agents
  
- **Authenticate and Verify** (`authenticate_and_verify.py`)  
  Demonstrate the complete DID-WBA authentication and verification process

#### Running Examples
```bash
# Create DID Document
uv run python examples/python/did_wba_examples/create_did_document.py

# Authentication Demonstration
uv run python examples/python/did_wba_examples/authenticate_and_verify.py
```

**Detailed Documentation**: [DID-WBA Example](examples/python/did_wba_examples/README.md)

### ANP Crawler Agent Interaction Example
Location: `examples/python/anp_crawler_examples/`

#### Main Examples
- **Simple Example** (`simple_amap_example.py`)  
  Quick Start: Connect to AMAP service and call the map search interface
  
- **Complete Example** (`amap_crawler_example.py`)  
  Complete Demonstration: Agent discovery, interface parsing, and tool calling

#### Running Examples
```bash
# Quick Experience
uv run python examples/python/anp_crawler_examples/simple_amap_example.py

# Complete Function Demonstration
uv run python examples/python/anp_crawler_examples/amap_crawler_example.py
```

**Detailed Documentation**: [ANP Crawler Example](examples/python/anp_crawler_examples/README.md)

### FastANP Agent Development Example
Location: `examples/python/fastanp_examples/`

#### Main Examples
- **Simple Agent** (`simple_agent.py`)
  Minimal FastANP setup with single interface method

- **Hotel Booking Agent** (`hotel_booking_agent.py`)
  Complete example with multiple interfaces, Pydantic models, and session management

#### Running Examples
```bash
# Simple Agent
uv run python examples/python/fastanp_examples/simple_agent.py

# Hotel Booking Agent
uv run python examples/python/fastanp_examples/hotel_booking_agent.py
```

#### Testing Examples
```bash
# Test with Python client
uv run python examples/python/fastanp_examples/test_hotel_booking_client.py

# Or test manually with curl
# Get Agent Description
curl http://localhost:8000/ad.json | jq

# Call JSON-RPC method
curl -X POST http://localhost:8000/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "search_rooms", "params": {"query": {"check_in_date": "2025-01-01", "check_out_date": "2025-01-05", "guest_count": 2, "room_type": "deluxe"}}}'
```

**Detailed Documentation**: [FastANP Examples](examples/python/fastanp_examples/README.md)

### AP2 Payment Protocol Example
Location: `examples/python/ap2_examples/`

#### Main Examples
- **Complete Flow** (`ap2_complete_flow.py`)
  Full demonstration of AP2 payment protocol including merchant and shopper agents

#### Features
- **Merchant Agent**: Handles cart creation and payment verification
- **Shopper Agent**: Creates shopping cart and authorizes payment
- **Mandate Verification**: Both CartMandate and PaymentMandate verification
- **Local IP Communication**: Two agents communicate over local network
- **ES256K Signatures**: Uses ECDSA secp256k1 for all mandate signatures

#### Running Example
```bash
# Run complete AP2 flow
uv run python examples/python/ap2_examples/ap2_complete_flow.py
```

#### Flow Overview
1. Merchant agent starts on local IP
2. Shopper sends `create_cart_mandate` request
3. Merchant verifies DID WBA auth, creates and signs CartMandate
4. Shopper verifies CartMandate signature
5. Shopper creates and signs PaymentMandate
6. Shopper sends PaymentMandate to merchant
7. Merchant verifies PaymentMandate and confirms payment

For detailed protocol specification, see [AP2 Protocol Documentation](docs/ap2/ap2-flow.md)

## Tool Recommendations

### ANP Network Explorer Tool
Use the web interface to explore the agent network using natural language: [ANP Network Explorer Tool](https://service.agent-network-protocol.com/anp-explorer/)

### DID Document Generator Tool
Command line tool to quickly generate DID documents:
```bash
uv run python tools/did_generater/generate_did_doc.py <did> [--agent-description-url URL]
```

## Contact Us

- **Author**：GaoWei Chang  
- **Email**：chgaowei@gmail.com  
- **Website**：[https://agent-network-protocol.com/](https://agent-network-protocol.com/)  
- **Discord**：[https://discord.gg/sFjBKTY7sB](https://discord.gg/sFjBKTY7sB)  
- **GitHub**：[https://github.com/agent-network-protocol/AgentNetworkProtocol](https://github.com/agent-network-protocol/AgentNetworkProtocol)
- **WeChat**：flow10240

## License

This project is open-sourced under the MIT License. Detailed information please refer to [LICENSE](LICENSE) file.

---

**Copyright (c) 2024 GaoWei Chang**
