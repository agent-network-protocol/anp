<div align="center">
  
[English](README.md) | [中文](README.cn.md)

</div>

# ANP Crawler Module

## Purpose
The ANP Crawler package provides a lightweight SDK for discovering agent descriptions and callable interfaces across the Agent Network Protocol (ANP). It focuses on deterministic data collection—no LLM calls are performed within the module—so it can be embedded inside production services or offline tooling.

## Module Layout
- `anp_client.py`: Async HTTP client that reuses `DIDWbaAuthHeader` to authenticate outbound requests with DID WBA headers.
- `anp_parser.py`: Normalizes JSON-LD content and extracts metadata from Agent Description documents.
- `anp_interface.py`: Converts interface specifications (OpenRPC, JSON-RPC, natural language descriptors) into OpenAI Tools-compatible schemas.
- `anp_crawler.py`: Legacy crawler retained for backward compatibility; new projects should rely on the lighter classes above.
- `Interface.md`: Additional notes describing the target data model and transformation rules.
- `test/`: Ad hoc fixtures and integration checks.

Both `meta_protocol` and `e2e_encryption` packages coexist in the repository for future adoption; at the moment they do not participate in the ANP crawler flow.

## Typical Flow
1. Instantiate `ANPClient` with a DID document and private key so that downstream services accepting DID WBA can be queried securely.
2. Use the client to fetch an Agent Description entry point (JSON or YAML).
3. Pass the payload to `ANPDocumentParser` to collect content, metadata, and referenced interface URLs.
4. Feed each interface document through `ANPInterfaceConverter` to obtain OpenAI Tools-style descriptors that higher-level agents can invoke directly.

## Minimal Example
```python
from anp.anp_crawler.anp_client import ANPClient
from anp.anp_crawler.anp_parser import ANPDocumentParser

client = ANPClient(
    did_document_path="docs/did_public/public-did-doc.json",
    private_key_path="docs/did_public/public-private-key.pem",
)

async def load_description(url: str):
    response = await client.fetch_url(url)
    if not response["success"]:
        raise RuntimeError(f"Request failed: {response['status_code']}")

    parser = ANPDocumentParser()
    content = parser.parse(response["text"], response["url"])
    return content
```

## Next Steps
- Review the end-to-end example under `examples/python/anp_crawler_examples/` for multi-hop crawls.
- Swap in your own DID credentials to access private agent registries.
- Extend `anp_interface.py` if you need to normalize additional protocol formats.
