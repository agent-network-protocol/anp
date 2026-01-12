<div align="center">

[English](README.md) | [中文](README.cn.md)

</div>

# FastANP - Fast Agent Network Protocol Framework

FastANP is a plugin framework based on FastAPI for rapidly building ANP (Agent Network Protocol) compliant agents. It enhances FastAPI as a plugin, providing automatic OpenRPC generation, JSON-RPC endpoint handling, Context injection, and DID WBA authentication.

## Core Features

- 🔌 **Plugin Design**: FastAPI as main framework, FastANP as helper plugin
- 📄 **Automatic OpenRPC Generation**: Python functions auto-converted to OpenRPC documents
- 🚀 **JSON-RPC Auto-dispatch**: Unified `/rpc` endpoint auto-routes to corresponding functions
- 🎯 **Context Auto-injection**: Session management based on DID + Access Token
- 🔐 **Built-in DID WBA Auth**: Integrated identity verification and JWT token management
- 🛠️ **Full Control**: User has complete control over routing and ad.json generation

## Installation

Ensure the `anp` package with optional dependencies is installed:

```bash
# Using uv
uv sync --extra api

# Or using pip
pip install -e ".[api]"
```

## Quick Start

### Minimal Example

```python
from fastapi import FastAPI
from anp.fastanp import FastANP, Context
from anp.authentication.did_wba_verifier import DidWbaVerifierConfig

# Initialize FastAPI
app = FastAPI()

# Initialize FastANP plugin (without auth)
anp = FastANP(
    app=app,
    name="Simple Agent",
    description="A simple ANP agent",
    base_url="https://example.com",
    did="did:wba:example.com:agent:simple",
    enable_auth_middleware=False  # Disable auth for demo
)

# Define ad.json route (user has full control)
@app.get("/ad.json")
def get_agent_description():
    ad = anp.get_common_header()
    ad["interfaces"] = [
        anp.interfaces[hello].link_summary
    ]
    return ad

# Register interface method
@anp.interface("/info/hello.json", description="Say hello")
def hello(name: str) -> dict:
    """
    Greet someone by name.

    Args:
        name: The name to greet
    """
    return {"message": f"Hello, {name}!"}

# Run server
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

After running, access:
- Agent Description: `http://localhost:8000/ad.json`
- OpenRPC Document: `http://localhost:8000/info/hello.json`
- JSON-RPC endpoint: `POST http://localhost:8000/rpc`

### Call Example

```bash
curl -X POST http://localhost:8000/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "hello",
    "params": {"name": "World"}
  }'
```

Response:
```json
{
  "jsonrpc": "2.0",
  "result": {
    "message": "Hello, World!"
  },
  "id": 1
}
```

## Core Concepts

### 1. Plugin Design

FastANP is no longer a standalone framework, but an enhancement plugin for FastAPI:

```python
# FastAPI is the main framework
app = FastAPI()

# FastANP is injected as a plugin
anp = FastANP(app=app, ...)
```

### 2. User-Controlled Routing

Users have full control over all routes, including `ad.json`:

```python
@app.get("/ad.json")
def get_agent_description():
    # Get common header
    ad = anp.get_common_header()

    # Add Information (user-defined)
    ad["Infomations"] = [
        {
            "type": "Product",
            "description": "My products",
            "url": f"{anp.base_url}/products.json"
        }
    ]

    # Add Interface (via FastANP helper)
    ad["interfaces"] = [
        anp.interfaces[my_func].link_summary,  # URL reference mode
        anp.interfaces[another_func].content,   # Embedded mode
    ]

    return ad
```

### 3. Interface Decorator

Use the `@anp.interface(path)` decorator to register interfaces:

```python
@anp.interface("/info/search.json", description="Search items")
def search(query: str, limit: int = 10) -> dict:
    """
    Search for items.

    Args:
        query: Search query
        limit: Maximum results
    """
    return {"results": [...]}
```

FastANP automatically:
1. Generates OpenRPC document
2. Registers `GET /info/search.json` to return OpenRPC document
3. Adds function to JSON-RPC dispatcher

### 4. Interface Access

Access interface metadata via `anp.interfaces[function]`:

```python
# Access methods
anp.interfaces[my_func].link_summary   # URL reference format
anp.interfaces[my_func].content        # Embedded format
anp.interfaces[my_func].openrpc_doc    # Raw OpenRPC document
```

**link_summary example** (separate jsonrpc file):

```python
{
    "type": "StructuredInterface",
    "protocol": "openrpc",
    "description": "...",
    "url": "https://example.com/info/search.json"
}
```

**content example** (embedded in document):

```python
{
    "type": "StructuredInterface",
    "protocol": "openrpc",
    "description": "...",
    "content": {
        "openrpc": "1.3.2",
        "info": {...},
        "methods": [...]
    }
}
```

### 5. Context Auto-injection

FastANP supports automatic Context injection for Session management:

```python
from anp.fastanp import Context

@anp.interface("/info/echo.json")
def echo(message: str, ctx: Context) -> dict:
    """
    Echo with context.

    Args:
        message: Message to echo
        ctx: Automatically injected context
    """
    # Access Session (based on DID + Access Token)
    visit_count = ctx.session.get("visit_count", 0)
    visit_count += 1
    ctx.session.set("visit_count", visit_count)

    return {
        "message": message,
        "session_id": ctx.session.id,
        "did": ctx.did,
        "visit_count": visit_count
    }
```

**Context object contains**:
- `ctx.session` - Session object (persistent session data)
- `ctx.did` - Requester's DID
- `ctx.request` - FastAPI Request object
- `ctx.auth_result` - Authentication result dictionary

**Session methods**:
- `session.id` - Session ID (generated from DID)
- `session.get(key, default)` - Get session data
- `session.set(key, value)` - Set session data
- `session.clear()` - Clear session data

**Note**: Session ID is based on DID only (not DID + Access Token), meaning multiple requests from the same DID share the same Session.

### 6. Request Auto-injection

FastANP supports automatic Request injection:

```python
from fastapi import Request

@anp.interface("/info/info.json")
def info(req: Request) -> dict:
    """Get request information."""
    return {
        "method": req.method,
        "path": req.url.path
    }
```

## API Reference

### FastANP Constructor Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `app` | FastAPI | ✓ | FastAPI application instance |
| `name` | str | ✓ | Agent name |
| `description` | str | ✓ | Agent description |
| `base_url` | str | ✓ | Base URL (e.g., `https://example.com`) |
| `did` | str | ✓ | DID identifier |
| `owner` | dict | - | Owner information |
| `jsonrpc_server_url` | str | - | JSON-RPC endpoint path (default `/rpc`) |
| `jsonrpc_server_name` | str | - | JSON-RPC server name |
| `jsonrpc_server_description` | str | - | JSON-RPC server description |
| `enable_auth_middleware` | bool | - | Enable auth middleware (default True) |
| `auth_config` | DidWbaVerifierConfig | - | Auth config (required when auth enabled) |
| `api_version` | str | - | API version (default "1.0.0") |

### Methods

#### `get_common_header(ad_url=None)`

Get common header fields for Agent Description.

```python
ad = anp.get_common_header()
# Returns: { "protocolType": "ANP", "name": "...", "did": "...", ... }
```

#### `@anp.interface(path, description=None, humanAuthorization=False)`

Decorator to register a Python function as an Interface.

**Parameters**:
- `path`: OpenRPC document URL path (e.g., `/info/search.json`)
- `description`: Method description (optional, defaults to docstring)
- `humanAuthorization`: Whether human authorization is required (optional)

**Automatic behaviors**:
1. Registers function to JSON-RPC dispatcher
2. Auto-registers `GET {path}` route returning OpenRPC document
3. Checks function name global uniqueness (throws exception if duplicate)
4. Supports Context parameter auto-injection

#### `interfaces` Property

Dictionary object, key is function, value is InterfaceProxy.

```python
anp.interfaces[my_func].link_summary   # Get URL reference format
anp.interfaces[my_func].content        # Get embedded format
anp.interfaces[my_func].openrpc_doc    # Get raw OpenRPC document
```

## Complete Examples

See `examples/python/fastanp_examples/` directory for complete examples:

- **simple_agent.py** - Minimal example
- **hotel_booking_agent.py** - Complete hotel booking agent with:
  - Multiple Interfaces
  - Pydantic data models
  - Context injection
  - Custom ad.json route
  - Static Information routes

## Advanced Usage

### 1. Using Pydantic Models

```python
from pydantic import BaseModel

class SearchRequest(BaseModel):
    query: str
    limit: int = 10
    offset: int = 0

@anp.interface("/info/search.json")
def search(request: SearchRequest) -> dict:
    """Search with Pydantic model validation."""
    return {"results": [...], "total": 100}
```

FastANP automatically converts Pydantic models to JSON Schema.

### 2. Custom ad.json Route

Supports path parameters and other custom logic:

```python
@app.get("/{agent_id}/ad.json")
def get_agent_description(agent_id: str):
    """Get AD for specific agent."""
    ad = anp.get_common_header()

    # Customize content based on agent_id
    if agent_id == "premium":
        ad["interfaces"] = [anp.interfaces[premium_search].content]
    else:
        ad["interfaces"] = [anp.interfaces[basic_search].link_summary]

    return ad
```

### 3. Async Function Support

```python
@anp.interface("/info/async_search.json")
async def async_search(query: str) -> dict:
    """Async interface method."""
    result = await some_async_operation(query)
    return {"result": result}
```

### 4. Adding Auth Middleware

```python
from anp.authentication.did_wba_verifier import DidWbaVerifierConfig

# Read JWT keys
with open("jwt_private_key.pem", 'r') as f:
    jwt_private_key = f.read()
with open("jwt_public_key.pem", 'r') as f:
    jwt_public_key = f.read()

# Create auth config
auth_config = DidWbaVerifierConfig(
    jwt_private_key=jwt_private_key,
    jwt_public_key=jwt_public_key,
    jwt_algorithm="RS256",
    allowed_domains=["example.com", "localhost"]  # Optional: domain whitelist
)

# Initialize FastANP (auto-enables auth middleware)
anp = FastANP(
    app=app,
    ...,
    enable_auth_middleware=True,
    auth_config=auth_config
)
```

**Auth exempt paths**:

Middleware auto-exempts the following paths (supports wildcards):
- `/favicon.ico`
- `/health`
- `/docs`
- `*/ad.json` - All paths ending with `/ad.json`
- `/info/*` - All OpenRPC document paths

All other paths require DID WBA authentication.

## Generated Endpoints

FastANP automatically generates the following endpoints:

### 1. JSON-RPC Unified Endpoint
- **URL**: `POST /rpc` (configurable)
- **Description**: JSON-RPC 2.0 unified entry point
- **Auth**: Depends on `enable_auth_middleware` parameter

### 2. OpenRPC Document Endpoints
- **URL**: `GET {path}` (one per interface)
- **Description**: Returns interface's OpenRPC document
- **Auth**: Auto-exempt (public access, matches `/info/*`)

### 3. Agent Description Endpoint
- **URL**: User-defined (e.g., `/ad.json` or `/{agent_id}/ad.json`)
- **Description**: Agent description document
- **Auth**: Auto-exempt (public access, matches `*/ad.json`)

### 4. User-Defined Endpoints
- **Information routes**: User has full control (e.g., `/products/*.json`)
- **Auth**: Requires auth by default (unless path matches exempt pattern)

## Function Name Uniqueness

FastANP requires all registered function names to be globally unique:

```python
@anp.interface("/info/search1.json")
def search(query: str) -> dict:
    pass

@anp.interface("/info/search2.json")
def search(query: str) -> dict:  # ❌ Error! Duplicate function name
    pass
```

Solution: Use different function names

```python
@anp.interface("/info/search_products.json")
def search_products(query: str) -> dict:
    pass

@anp.interface("/info/search_users.json")
def search_users(query: str) -> dict:
    pass
```

## Related Documentation

- [OpenANP README](../openanp/README.md) - Decorator-driven agent development
- [ANP Crawler README](../anp_crawler/README.md) - Lightweight discovery SDK
- [Project README](../../README.md) - Overview

## License

This project is open-sourced under the MIT License. See [LICENSE](../../LICENSE) file.
