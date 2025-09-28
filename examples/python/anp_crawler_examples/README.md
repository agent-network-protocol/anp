<div align="center">
  
[English](README.md) | [中文](README.cn.md)

</div>

# ANPCrawler Examples - AMAP Service

This directory contains examples using ANPCrawler to access AMAP agent services.

## Contents

- `amap_crawler_example.py` - Complete example showcasing all ANPCrawler features
- `simple_amap_example.py` - Simplified example for quick start
- `README.md` - This documentation file

## Prerequisites

### Environment Setup
```bash
# Option 1: Install via pip
pip install agent-connect

# Option 2: Source installation (recommended for developers)
git clone https://github.com/agent-network-protocol/AgentConnect.git
cd AgentConnect
uv sync
```

### DID Authentication Files
Ensure the following files exist:
- `docs/did_public/public-did-doc.json`
- `docs/did_public/public-private-key.pem`

## Running Examples

### Simple Example
```bash
uv run python examples/python/anp_crawler_examples/simple_amap_example.py
```

### Complete Example
```bash
uv run python examples/python/anp_crawler_examples/amap_crawler_example.py
```

## Example Features

### 1. Fetch Agent Description Document
```python
# Access URL and retrieve ad.json content
content_json, interfaces_list = await crawler.fetch_text(
    "https://agent-connect.ai/agents/travel/mcp/agents/amap/ad.json"
)
```

### 2. Parse JSON-RPC Interfaces
```python
# Automatically parse interfaces and convert to OpenAI tool format
tools = crawler.list_available_tools()
```

### 3. Call JSON-RPC Methods
```python
# Call discovered tools/methods
result = await crawler.execute_tool_call(tool_name, arguments)
```

## Example Output

After running examples, you will see:

1. **Agent Description Document Content** - Complete ad.json content
2. **Discovered Interfaces** - JSON-RPC interfaces extracted from agent description
3. **Available Tool List** - Names of callable tools
4. **Tool Call Results** - Actual JSON-RPC call return results

## Troubleshooting

### File Not Found Error
```
FileNotFoundError: DID document file not found
```
**Solution**: Ensure the following files exist:
- `docs/did_public/public-did-doc.json`
- `docs/did_public/public-private-key.pem`

### Network Connection Error
Ensure your network can access the `agent-connect.ai` domain.

### Authentication Failure
Check if DID document and private key files are correctly generated and matched.

## Code Structure

```python
# 1. Initialize crawler
crawler = ANPCrawler(
    did_document_path="path/to/did.json",
    private_key_path="path/to/private-key.pem"
)

# 2. Fetch agent description
content, interfaces = await crawler.fetch_text(url)

# 3. List tools
tools = crawler.list_available_tools()

# 4. Call tools
result = await crawler.execute_tool_call(tool_name, arguments)
```

## Related Documentation

- [ANPCrawler API Documentation](../../../agent_connect/anp_crawler/)
- [DID WBA Authentication Examples](../did_wba_examples/)
- [Project Root README](../../../README.md)