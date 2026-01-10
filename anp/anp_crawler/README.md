<div align="center">

[English](README.md) | [中文](README.cn.md)

</div>

# ANP Crawler Module

Lightweight SDK for discovering and interacting with ANP (Agent Network Protocol) agents.

## Purpose

**ANP Crawler works like a web crawler for ANP documents** - it fetches, parses, and extracts callable interfaces from Agent Description documents. It focuses on **deterministic data collection**—no LLM calls are performed within the module—so it can be embedded inside production services or offline tooling.

> **ANPCrawler vs RemoteAgent**: ANPCrawler is a crawler-style client (fetch and parse documents), while RemoteAgent (in OpenANP) is a proxy-style client that downloads methods and transforms them into local method calls. Use ANPCrawler for LLM tool integration or data collection; use RemoteAgent for agent-to-agent communication in code.

**Key Features:**
- ✅ Crawler Style - Fetch and parse ANP documents like a web crawler
- ✅ OpenAI Tools Format - Automatic interface conversion for LLM integration
- ✅ No LLM Required - Pure deterministic data collection
- ✅ DID-WBA Authentication - Secure agent-to-agent communication
- ✅ Production Ready - Suitable for embedding in services

---

## Installation

```bash
pip install anp
```

Or with UV:
```bash
uv sync
```

---

## Quick Start

### Option 1: Using ANPCrawler (Recommended)

The high-level crawler handles everything automatically:

```python
import asyncio
from anp.anp_crawler import ANPCrawler

async def main():
    # Initialize crawler with DID authentication
    crawler = ANPCrawler(
        did_document_path="path/to/did-doc.json",
        private_key_path="path/to/private-key.pem"
    )

    # Discover agent and parse interfaces
    content, tools = await crawler.fetch_text("https://example.com/ad.json")

    # List available tools
    print(f"Available tools: {crawler.list_available_tools()}")

    # Execute a tool
    result = await crawler.execute_tool_call("search", {"query": "hotel"})
    print(f"Result: {result}")

asyncio.run(main())
```

### Option 2: Using ANPClient (Lower Level)

For more control over the request/response cycle:

```python
import asyncio
from anp.anp_crawler import ANPClient

async def main():
    client = ANPClient(
        did_document_path="path/to/did-doc.json",
        private_key_path="path/to/private-key.pem"
    )

    # Fetch and parse URL
    response = await client.fetch("https://example.com/ad.json")
    if response["success"]:
        print(f"Content: {response['data']}")

    # Call JSON-RPC method directly
    result = await client.call_jsonrpc(
        server_url="https://example.com/rpc",
        method="search",
        params={"query": "hotel"}
    )
    print(f"Result: {result}")

asyncio.run(main())
```

---

## API Reference

### ANPCrawler

High-level crawler for discovering and interacting with ANP agents.

#### Constructor

```python
ANPCrawler(
    did_document_path: str,     # Path to DID document JSON file
    private_key_path: str,      # Path to private key PEM file
    cache_enabled: bool = True  # Enable URL caching (default: True)
)
```

#### Methods

##### `fetch_text(url: str) → Tuple[Dict, List]`

Fetches and parses an Agent Description or interface document.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `url` | `str` | URL to fetch (ad.json or interface document) |

**Returns:**
```python
# content_json:
{
    "agentDescriptionURI": str,  # Agent Description URI
    "contentURI": str,           # Content URI (without query params)
    "content": str               # Raw content
}

# interfaces_list: List of OpenAI Tools format interfaces
[
    {
        "type": "function",
        "function": {
            "name": "search",
            "description": "Search for items",
            "parameters": {
                "type": "object",
                "properties": {...},
                "required": [...]
            }
        }
    }
]
```

**Example:**
```python
content, tools = await crawler.fetch_text("https://example.com/ad.json")
print(f"Found {len(tools)} tools")
```

---

##### `execute_tool_call(tool_name: str, arguments: Dict) → Dict`

Executes a discovered tool via JSON-RPC.

**Parameters:**
| Name | Type | Description |
|------|------|-------------|
| `tool_name` | `str` | Name of the tool (from `list_available_tools()`) |
| `arguments` | `Dict` | Arguments to pass to the tool |

**Returns:**
```python
{
    "success": bool,           # Whether execution succeeded
    "result": Any,             # JSON-RPC result (on success)
    "error": str,              # Error message (on failure)
    "url": str,                # Server URL used
    "method": str,             # JSON-RPC method name
    "tool_name": str           # Tool name
}
```

**Example:**
```python
result = await crawler.execute_tool_call("search_poi", {"query": "Beijing"})
if result["success"]:
    print(f"Found: {result['result']}")
```

---

##### `execute_json_rpc(endpoint: str, method: str, params: Dict, request_id: str = None) → Dict`

Executes a JSON-RPC call directly (no interface discovery required).

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `endpoint` | `str` | ✓ | JSON-RPC server URL |
| `method` | `str` | ✓ | Method name |
| `params` | `Dict` | ✓ | Method parameters |
| `request_id` | `str` | - | Request ID (auto-generated if not provided) |

**Returns:**
```python
{
    "success": bool,
    "result": Any,             # JSON-RPC result
    "error": Dict,             # JSON-RPC error object
    "endpoint": str,
    "method": str,
    "request_id": str,
    "response": dict           # Full JSON-RPC response
}
```

**Example:**
```python
result = await crawler.execute_json_rpc(
    endpoint="https://example.com/rpc",
    method="search",
    params={"query": "hotel", "limit": 10}
)
```

---

##### `list_available_tools() → List[str]`

Returns names of all discovered tools.

```python
tools = crawler.list_available_tools()
# ['search', 'book', 'cancel']
```

---

##### `get_tool_interface_info(tool_name: str) → Optional[Dict]`

Gets metadata for a specific tool.

**Returns:**
```python
{
    "tool_name": str,
    "method_name": str,
    "servers": List[Dict],
    "interface_data": Dict
}
```

---

##### Cache Management

```python
# Check if URL was visited
crawler.is_url_visited("https://example.com/ad.json")

# Get all visited URLs
visited = crawler.get_visited_urls()

# Get cache size
size = crawler.get_cache_size()

# Clear cache
crawler.clear_cache()

# Clear tool interfaces
crawler.clear_tool_interfaces()
```

---

### ANPClient

Low-level HTTP client with DID-WBA authentication.

#### Constructor

```python
ANPClient(
    did_document_path: str,    # Path to DID document JSON file
    private_key_path: str      # Path to private key PEM file
)
```

#### Methods

##### `fetch_url(url, method="GET", headers=None, params=None, body=None) → Dict`

Sends an HTTP request with DID-WBA authentication.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `url` | `str` | ✓ | Request URL |
| `method` | `str` | - | HTTP method (default: "GET") |
| `headers` | `Dict` | - | Additional headers |
| `params` | `Dict` | - | URL query parameters |
| `body` | `Dict` | - | Request body (for POST/PUT) |

**Returns:**
```python
{
    "success": bool,
    "text": str,               # Response text
    "content_type": str,       # Content-Type header
    "encoding": str,           # Response encoding
    "status_code": int,        # HTTP status code
    "url": str,                # Final URL (after redirects)
    "error": str               # Error message (on failure)
}
```

---

##### `fetch(url: str) → Dict`

Simplified fetch that returns parsed JSON.

**Returns:**
```python
{
    "success": bool,
    "data": Dict,              # Parsed JSON data
    "error": str               # Error message (on failure)
}
```

---

##### `call_jsonrpc(server_url, method, params, request_id=None) → Dict`

Executes a JSON-RPC 2.0 call.

**Parameters:**
| Name | Type | Required | Description |
|------|------|----------|-------------|
| `server_url` | `str` | ✓ | JSON-RPC endpoint URL |
| `method` | `str` | ✓ | Method name |
| `params` | `Dict` | ✓ | Method parameters |
| `request_id` | `str` | - | Request ID (auto-generated) |

**Returns:**
```python
{
    "success": bool,
    "result": Any,             # JSON-RPC result
    "error": Dict,             # JSON-RPC error
    "request_id": str
}
```

**Example:**
```python
result = await client.call_jsonrpc(
    "https://example.com/rpc",
    "search",
    {"query": "Tokyo"}
)
if result["success"]:
    print(result["result"])
```

---

### ANPDocumentParser

Parses Agent Description documents and extracts interfaces.

```python
from anp.anp_crawler import ANPDocumentParser

parser = ANPDocumentParser()
result = parser.parse_document(
    content="...",           # Raw content string
    content_type="application/json",
    source_url="https://example.com/ad.json"
)

# result["interfaces"] contains extracted interface definitions
```

---

### ANPInterfaceConverter

Converts interface definitions to OpenAI Tools format.

```python
from anp.anp_crawler import ANPInterfaceConverter

converter = ANPInterfaceConverter()
tool = converter.convert_to_openai_tools(interface_data)

# Returns OpenAI Tools format:
# {
#     "type": "function",
#     "function": {
#         "name": "...",
#         "description": "...",
#         "parameters": {...}
#     }
# }
```

---

## Typical Workflow

```
1. Initialize ANPCrawler
   └─ Provide DID document and private key for authentication

2. Fetch Agent Description (ad.json)
   └─ crawler.fetch_text(url)
   └─ Returns content and interface list

3. Discover Available Tools
   └─ crawler.list_available_tools()
   └─ Returns tool names

4. Execute Tools
   └─ crawler.execute_tool_call(name, args)
   └─ Or: crawler.execute_json_rpc(endpoint, method, params)

5. Process Results
   └─ Handle success/error responses
```

---

## LLM Integration

ANP Crawler automatically converts interfaces to OpenAI Tools format:

```python
import openai
from anp.anp_crawler import ANPCrawler

async def agent_with_tools():
    # Discover tools from remote agent
    crawler = ANPCrawler(did_doc_path, key_path)
    content, tools = await crawler.fetch_text("https://example.com/ad.json")

    # Use tools with OpenAI
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Find hotels in Tokyo"}],
        tools=tools  # Directly use discovered tools
    )

    # Execute tool calls
    for tool_call in response.choices[0].message.tool_calls:
        result = await crawler.execute_tool_call(
            tool_call.function.name,
            json.loads(tool_call.function.arguments)
        )
        print(f"Result: {result}")
```

---

## Module Layout

```
anp/anp_crawler/
├── __init__.py          # Public exports
├── anp_crawler.py       # ANPCrawler - high-level crawler
├── anp_client.py        # ANPClient - HTTP client with DID auth
├── anp_parser.py        # ANPDocumentParser - document parsing
├── anp_interface.py     # ANPInterfaceConverter - OpenAI Tools conversion
├── Interface.md         # Data model documentation
└── test/                # Test fixtures
```

---

## Examples

See `examples/python/anp_crawler_examples/` for complete examples:

| File | Description |
|------|-------------|
| `simple_amap_example.py` | Quick start with AMAP service |
| `amap_crawler_example.py` | Complete demonstration |

```bash
# Run simple example
uv run python examples/python/anp_crawler_examples/simple_amap_example.py

# Run complete example
uv run python examples/python/anp_crawler_examples/amap_crawler_example.py
```

---

## Related Documentation

- [OpenANP README](../openanp/README.md) - Building ANP agents
- [DID-WBA Examples](../../examples/python/did_wba_examples/) - Authentication
- [Project README](../../README.md) - Overview

---

## License

MIT License
