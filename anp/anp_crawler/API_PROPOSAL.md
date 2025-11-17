# ANPClient High-Level API Proposal

## Problem Statement

The current ANPClient requires users to:
1. Manually construct JSON-RPC requests
2. Manually parse responses and check success
3. Handle JSON parsing errors
4. Manually extract data from response dictionaries
5. Repeat boilerplate code for every interaction

This makes client code verbose, error-prone, and hard to read.

## Proposed High-Level APIs

### 1. `get_agent_description(ad_url: str) -> Dict[str, Any]`

**Purpose**: Fetch and parse agent description in one call.

**Returns**:
```python
{
    "success": bool,
    "data": {
        "name": str,
        "description": str,
        "did": str,
        "interfaces": List[Dict],
        "informations": List[Dict],
        # ... other agent description fields
    },
    "error": Optional[str]
}
```

**Usage**:
```python
result = await client.get_agent_description("http://localhost:8000/ad.json")
if result["success"]:
    interfaces = result["data"]["interfaces"]
```

### 2. `call_jsonrpc(server_url: str, method: str, params: Dict[str, Any], request_id: Optional[str] = None) -> Dict[str, Any]`

**Purpose**: High-level JSON-RPC method call that handles request construction and response parsing.

**Returns**:
```python
{
    "success": bool,
    "result": Any,  # The JSON-RPC result field
    "error": Optional[Dict],  # JSON-RPC error object if present
    "request_id": str
}
```

**Usage**:
```python
result = await client.call_jsonrpc(
    "http://localhost:8000/rpc",
    "calculate",
    {"expression": "2 + 3"}
)
if result["success"]:
    print(result["result"])
```

### 3. `get_information(url: str) -> Dict[str, Any]`

**Purpose**: Fetch information endpoints (like `/info/hello.json`) and parse JSON.

**Returns**:
```python
{
    "success": bool,
    "data": Any,  # Parsed JSON data
    "error": Optional[str]
}
```

**Usage**:
```python
result = await client.get_information("http://localhost:8000/info/hello.json")
if result["success"]:
    print(result["data"]["message"])
```

### 4. `discover_agent(ad_url: str) -> Dict[str, Any]`

**Purpose**: Complete agent discovery that fetches agent description and all referenced interfaces.

**Returns**:
```python
{
    "success": bool,
    "agent": Dict[str, Any],  # Agent description
    "interfaces": List[Dict],  # All discovered interfaces
    "informations": List[Dict],  # All information endpoints
    "error": Optional[str]
}
```

**Usage**:
```python
discovery = await client.discover_agent("http://localhost:8000/ad.json")
if discovery["success"]:
    for interface in discovery["interfaces"]:
        print(f"Found interface: {interface['description']}")
```

## Benefits

1. **Simpler code**: Client code becomes much more readable
2. **Error handling**: Consistent error handling across all methods
3. **Type safety**: Clear return structures
4. **Less boilerplate**: No manual JSON parsing or response checking
5. **Better abstraction**: Hides implementation details

## Migration Path

- Old low-level methods (`fetch_url`) remain available for advanced use cases
- New high-level methods use low-level methods internally
- Gradual migration: users can adopt new APIs incrementally

