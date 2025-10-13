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

## Core Modules

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

## Usage

### Option 1: Install via pip
```bash
pip install agent-connect
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
