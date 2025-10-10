# FastANP Examples

This directory contains examples demonstrating how to build ANP agents with FastANP.

## Examples

### 1. simple_agent.py - Minimal Example

The most basic FastANP agent with a single interface method.

**Features**:
- Minimal FastANP setup
- Single interface method
- Custom ad.json route
- No authentication

**Run**:
```bash
cd /path/to/AgentConnect
uv run python examples/python/fastanp_examples/simple_agent.py
```

**Test**:
```bash
# Get Agent Description
curl http://localhost:8000/ad.json | jq

# Get OpenRPC document
curl http://localhost:8000/info/hello.json | jq

# Call hello method
curl -X POST http://localhost:8000/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "hello", "params": {"name": "World"}}'
```

### 2. simple_agent_with_context.py - Context Injection Example

Demonstrates Context injection and session management.

**Features**:
- Context automatic injection
- Session-based counter
- Session data persistence

**Run**:
```bash
cd /path/to/AgentConnect
uv run python examples/python/fastanp_examples/simple_agent_with_context.py
```

**Test**:
```bash
# Call counter method multiple times
curl -X POST http://localhost:8000/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "counter", "params": {}}'

# Call again - count will increment
curl -X POST http://localhost:8000/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 2, "method": "counter", "params": {}}'
```

### 3. hotel_booking_agent.py - Complete Example

A complete hotel booking agent with multiple features.

**Features**:
- Multiple interface methods
- Pydantic data models
- Context injection with session management
- Custom Information routes
- Path parameters in ad.json route
- Mix of link and embedded interface modes

**Run**:
```bash
cd /path/to/AgentConnect
uv run python examples/python/fastanp_examples/hotel_booking_agent.py
```

**Test**:
```bash
# Get Agent Description (with agent_id)
curl http://localhost:8000/booking-agent/ad.json | jq

# Get Agent Description (simple)
curl http://localhost:8000/ad.json | jq

# Get OpenRPC documents
curl http://localhost:8000/info/search_rooms.json | jq
curl http://localhost:8000/info/get_rooms.json | jq

# Get Information routes
curl http://localhost:8000/products/luxury-rooms.json | jq
curl http://localhost:8000/info/hotel-basic-info.json | jq

# Call search_rooms method
curl -X POST http://localhost:8000/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "search_rooms",
    "params": {
      "query": {
        "check_in_date": "2025-01-01",
        "check_out_date": "2025-01-05",
        "guest_count": 2,
        "room_type": "deluxe"
      }
    }
  }'

# Call get_rooms method (with context/session)
curl -X POST http://localhost:8000/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "get_rooms",
    "params": {
      "query": "luxury suite"
    }
  }'
```

## Key Concepts Demonstrated

### 1. Plugin-Based Design

```python
from fastapi import FastAPI
from anp.fastanp import FastANP

# FastAPI is the main framework
app = FastAPI()

# FastANP is a plugin
anp = FastANP(app=app, name="...", ...)
```

### 2. User-Controlled Routes

All routes are defined by the user:

```python
@app.get("/ad.json")
def get_agent_description():
    ad = anp.get_common_header()
    ad["interfaces"] = [...]
    return ad

@app.get("/info/custom.json")
def custom_info():
    return {"data": "..."}
```

### 3. Interface Decorator

```python
@anp.interface("/info/method.json", description="Description")
def my_method(param: str) -> dict:
    return {"result": "..."}
```

This automatically:
- Generates OpenRPC document
- Registers `GET /info/method.json` endpoint
- Adds method to JSON-RPC dispatcher
- Checks for duplicate function names

### 4. Interface Access Modes

```python
# URL reference mode (recommended)
anp.interfaces[my_func].link_summary

# Embedded mode (for single interfaces)
anp.interfaces[my_func].content

# Raw OpenRPC document
anp.interfaces[my_func].openrpc_doc
```

### 5. Context Injection

```python
from anp.fastanp import Context

@anp.interface("/info/method.json")
def method_with_context(param: str, ctx: Context) -> dict:
    # Access session (based on DID + Access Token)
    count = ctx.session.get("count", 0) + 1
    ctx.session.set("count", count)
    
    return {
        "session_id": ctx.session.id,
        "did": ctx.did,
        "count": count
    }
```

### 6. Pydantic Models

```python
from pydantic import BaseModel

class MyRequest(BaseModel):
    field1: str
    field2: int = 10

@anp.interface("/info/method.json")
def method(request: MyRequest) -> dict:
    return {"received": request.field1}
```

FastANP automatically converts Pydantic models to JSON Schema.

## Testing JSON-RPC

All examples expose a JSON-RPC 2.0 endpoint at `/rpc` by default.

**Request Format**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "method_name",
  "params": {
    "param1": "value1",
    "param2": "value2"
  }
}
```

**Success Response**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "key": "value"
  }
}
```

**Error Response**:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32601,
    "message": "Method not found",
    "data": "Method 'unknown' does not exist"
  }
}
```

## Common Patterns

### Pattern 1: Simple ad.json with Link References

```python
@app.get("/ad.json")
def get_ad():
    ad = anp.get_common_header()
    ad["interfaces"] = [
        anp.interfaces[func1].link_summary,
        anp.interfaces[func2].link_summary,
    ]
    return ad
```

### Pattern 2: ad.json with Embedded Content

```python
@app.get("/ad.json")
def get_ad():
    ad = anp.get_common_header()
    ad["interfaces"] = [
        anp.interfaces[main_func].content  # Embedded OpenRPC
    ]
    return ad
```

### Pattern 3: ad.json with Information

```python
@app.get("/ad.json")
def get_ad():
    ad = anp.get_common_header()
    
    # Add Information items
    ad["Infomations"] = [
        {
            "type": "Product",
            "description": "Available products",
            "url": f"{anp.base_url}/products.json"
        }
    ]
    
    # Add interfaces
    ad["interfaces"] = [anp.interfaces[func].link_summary]
    
    return ad
```

### Pattern 4: Parametrized ad.json

```python
@app.get("/{agent_id}/ad.json")
def get_ad(agent_id: str):
    ad = anp.get_common_header()
    
    # Customize based on agent_id
    if agent_id == "premium":
        ad["interfaces"] = [anp.interfaces[premium_func].content]
    else:
        ad["interfaces"] = [anp.interfaces[basic_func].link_summary]
    
    return ad
```

## Next Steps

1. Read [FastANP README](../../../anp/fastanp/README.md) for complete documentation
2. Read [QuickStart Guide](../../../anp/fastanp/QUICKSTART.md) for step-by-step tutorial
3. Check [Implementation Summary](../../../anp/fastanp/IMPLEMENTATION.md) for architecture details

## Tips

- **Function names must be unique**: FastANP requires all interface function names to be globally unique
- **Context is optional**: Only add `ctx: Context` parameter if you need session management
- **Use link_summary by default**: Embedded mode is best for single-interface agents
- **Define your own routes**: FastANP doesn't automatically register any routes except `/rpc` and OpenRPC docs
