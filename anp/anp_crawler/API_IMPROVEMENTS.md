# ANPClient API Improvements

## Summary

Added four new high-level APIs to `ANPClient` that hide complexity and make client code much cleaner and easier to read.

## New APIs

### 1. `get_agent_description(ad_url: str) -> Dict[str, Any]`
Fetches and parses agent description in one call.

### 2. `call_jsonrpc(server_url: str, method: str, params: Dict[str, Any], request_id: Optional[str] = None) -> Dict[str, Any]`
High-level JSON-RPC method call that handles request construction and response parsing.

### 3. `get_information(url: str) -> Dict[str, Any]`
Fetches information endpoints and parses JSON.

### 4. `discover_agent(ad_url: str) -> Dict[str, Any]`
Complete agent discovery that fetches agent description and all referenced interfaces.

## Before vs After Comparison

### Before: Manual JSON-RPC Call

```python
# Manual request construction
calc_response = await client.fetch_url(
    url=f"{server_url}/rpc",
    method="POST",
    headers={"Content-Type": "application/json"},
    body={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "calculate",
        "params": {"expression": "2 + 3"}
    }
)

# Manual response parsing
if calc_response.get("success"):
    result = json.loads(calc_response.get("text", "{}"))
    print(f"Result: {json.dumps(result, indent=2)}")
else:
    print(f"Error: {calc_response.get('error', 'Unknown error')}")
```

### After: High-Level API

```python
# Clean, simple call
calc_result = await client.call_jsonrpc(
    server_url=f"{server_url}/rpc",
    method="calculate",
    params={"expression": "2 + 3"}
)

# Simple result handling
if calc_result["success"]:
    print(f"Result: {json.dumps(calc_result['result'], indent=2)}")
else:
    error = calc_result.get("error", {})
    print(f"Error: {error.get('message', 'Unknown error')}")
```

### Before: Manual Agent Description Fetching

```python
# Fetch agent description
response = await client.fetch_url(ad_url)

if not response.get("success", False):
    print(f"Failed: {response.get('error', 'Unknown error')}")
    return

# Parse the agent description
parser = ANPDocumentParser()
content = parser.parse_document(
    content=response.get("text", ""),
    content_type=response.get("content_type", "application/json"),
    source_url=ad_url
)

# Extract data
interfaces = content.get("interfaces", [])
```

### After: High-Level API

```python
# One simple call
agent_result = await client.get_agent_description(ad_url)

if not agent_result["success"]:
    print(f"Failed: {agent_result['error']}")
    return

# Direct access to parsed data
agent_data = agent_result["data"]
interfaces = agent_data.get("interfaces", [])
```

### Before: Manual Information Fetching

```python
# Fetch information
hello_response = await client.fetch_url(f"{server_url}/info/hello.json")

if hello_response.get("success"):
    hello_data = json.loads(hello_response.get("text", "{}"))
    print(f"Hello: {json.dumps(hello_data, indent=2)}")
else:
    print(f"Error: {hello_response.get('error', 'Unknown error')}")
```

### After: High-Level API

```python
# Simple call
hello_result = await client.get_information(f"{server_url}/info/hello.json")

if hello_result["success"]:
    print(f"Hello: {json.dumps(hello_result['data'], indent=2)}")
else:
    print(f"Error: {hello_result['error']}")
```

## Benefits

1. **Less Code**: Reduced from ~50 lines to ~30 lines in the example
2. **More Readable**: Clear intent, no boilerplate
3. **Better Error Handling**: Consistent error structure across all methods
4. **Type Safety**: Clear return structures with documented fields
5. **Less Error-Prone**: No manual JSON parsing or response checking

## Backward Compatibility

All existing low-level methods (`fetch_url`, `get_content_info`) remain available for advanced use cases. The new high-level methods use these internally, so there's no breaking changes.

## Migration Guide

1. Replace `fetch_url` + manual JSON parsing with `get_agent_description` or `get_information`
2. Replace manual JSON-RPC construction with `call_jsonrpc`
3. Use `discover_agent` for complete agent discovery workflows

