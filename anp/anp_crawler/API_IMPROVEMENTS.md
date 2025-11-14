# ANPClient API Improvements

## Summary

Simplified the ANPClient API to a single unified method `fetch()` that handles fetching and parsing any URL (AD URL, info endpoints, or any JSON URL). This makes the API much simpler and easier to use.

## Unified API

### `fetch(url: str) -> Dict[str, Any]`

**Purpose**: Single unified method to fetch and parse any URL.

This method automatically:
- Fetches the URL with DID authentication
- Parses JSON responses
- Returns a consistent structure

**Args**:
- `url`: URL to fetch (can be AD URL, info endpoint, or any JSON URL)

**Returns**:
```python
{
    "success": bool,
    "data": Dict[str, Any],  # Parsed JSON data
    "error": Optional[str]
}
```

**Usage Examples**:

```python
# Fetch agent description
agent_result = await client.fetch("http://localhost:8000/ad.json")
if agent_result["success"]:
    agent_data = agent_result["data"]
    interfaces = agent_data.get("interfaces", [])

# Fetch information endpoint
hello_result = await client.fetch("http://localhost:8000/info/hello.json")
if hello_result["success"]:
    message = hello_result["data"]["message"]

# Fetch any JSON URL
any_result = await client.fetch("http://example.com/data.json")
if any_result["success"]:
    data = any_result["data"]
```

## Before vs After Comparison

### Before: Multiple Methods

```python
# Fetch agent description
agent_result = await client.get_agent_description(ad_url)
if not agent_result["success"]:
    print(f"Failed: {agent_result['error']}")
    return
agent_data = agent_result["data"]

# Fetch information endpoint
hello_result = await client.get_information(f"{server_url}/info/hello.json")
if hello_result["success"]:
    print(hello_result["data"])
```

### After: Single Unified Method

```python
# Fetch agent description
agent_result = await client.fetch(ad_url)
if not agent_result["success"]:
    print(f"Failed: {agent_result['error']}")
    return
agent_data = agent_result["data"]

# Fetch information endpoint
hello_result = await client.fetch(f"{server_url}/info/hello.json")
if hello_result["success"]:
    print(hello_result["data"])
```

## Benefits

1. **Simpler API**: One method instead of multiple specialized methods
2. **Consistent Interface**: Same return structure for all URL types
3. **Less to Learn**: Only need to remember one method
4. **Flexible**: Works with any JSON URL, not just specific types
5. **Easy to Use**: No need to choose between different methods

## Additional Methods

### `call_jsonrpc(server_url: str, method: str, params: Dict[str, Any], request_id: Optional[str] = None) -> Dict[str, Any]`

For JSON-RPC method calls, use the dedicated `call_jsonrpc()` method:

```python
result = await client.call_jsonrpc(
    server_url="http://localhost:8000/rpc",
    method="calculate",
    params={"expression": "2 + 3"}
)
```

## Backward Compatibility

The low-level `fetch_url()` method remains available for advanced use cases that need more control over the HTTP request (custom headers, methods, etc.).
