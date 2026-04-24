# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

**Environment Setup:**
```bash
uv sync                                    # Sync environment from pyproject.toml
uv sync --extra api                        # Install with FastAPI/OpenAI dependencies
uv sync --extra dev                        # Install with dev/testing dependencies
uv sync --extra api,dev                    # Install all optional dependencies
```

**Testing:**
```bash
uv run pytest                              # Run full test suite
uv run pytest -k <pattern>                 # Run specific tests by name pattern
uv run pytest --cov=anp                    # Run tests with coverage
uv run pytest anp/unittest/                # Run core unit tests only
uv run pytest anp/unittest/openanp/        # Run OpenANP tests only
uv run pytest anp/unittest/ap2/            # Run AP2 tests only
uv run pytest anp/unittest/e2e_v2/         # Run E2E encryption v2 tests only
uv run pytest anp/unittest/proof/          # Run proof tests only
uv run pytest anp/anp_crawler/test/        # Run ANP crawler tests only
```

**Build:**
```bash
uv build --wheel                           # Build wheel for distribution
```

**Running Examples:**
```bash
# OpenANP examples (recommended starting point, requires --extra api)
uvicorn examples.python.openanp_examples.minimal_server:app --port 8000  # Terminal 1
uv run python examples/python/openanp_examples/minimal_client.py         # Terminal 2

# DID WBA authentication examples (offline, no extra deps)
uv run python examples/python/did_wba_examples/create_did_document.py
uv run python examples/python/did_wba_examples/authenticate_and_verify.py

# FastANP examples (requires --extra api)
uv run python examples/python/fastanp_examples/simple_agent.py
uv run python examples/python/fastanp_examples/hotel_booking_agent.py

# ANP Crawler examples
uv run python examples/python/anp_crawler_examples/simple_amap_example.py

# AP2 Payment Protocol example
uv run python examples/python/ap2_examples/ap2_complete_flow.py

# Meta-protocol negotiation (requires Azure OpenAI config in .env)
uv run python examples/python/negotiation_mode/negotiation_bob.py    # Start Bob first
uv run python examples/python/negotiation_mode/negotiation_alice.py  # Then Alice

# DID document generation tool
uv run python tools/did_generater/generate_did_doc.py <did> [--agent-description-url URL]
```

## Architecture Overview

AgentConnect is an open-source SDK implementing the [Agent Network Protocol (ANP)](https://github.com/agent-network-protocol/AgentNetworkProtocol). It provides two main approaches for building and interacting with ANP agents, plus supporting modules for authentication, encryption, payments, and protocol negotiation.

### Two Primary Agent SDKs

**`openanp/` — OpenANP (Recommended for building agents)**
Class-based decorator SDK. Use `@anp_agent(config)` on a class and `@interface` on methods to auto-generate ad.json, OpenRPC interface docs, and JSON-RPC endpoints. Supports `Context` injection for DID/session access, `@information` decorator for data endpoints, and `RemoteAgent` for calling remote agents as if they were local objects.

```python
from anp.openanp import anp_agent, interface, AgentConfig, RemoteAgent

@anp_agent(AgentConfig(name="Hotel", did="did:wba:example.com:hotel", prefix="/hotel"))
class HotelAgent:
    @interface
    async def search(self, query: str) -> dict:
        return {"results": [...]}

# Server: app.include_router(HotelAgent.router())
# Client: agent = await RemoteAgent.discover(url, auth); await agent.search(query="Tokyo")
```

**`anp_crawler/` — ANP Crawler (For document fetching and LLM tool integration)**
Crawler-style SDK for discovering agents, fetching ANP documents, and converting interfaces to OpenAI Tools format. Does not require LLM — deterministic data collection.

```python
from anp.anp_crawler import ANPCrawler
crawler = ANPCrawler(did_document_path="...", private_key_path="...")
content, tools = await crawler.fetch_text("https://example.com/ad.json")
result = await crawler.execute_tool_call("search_poi", {"query": "Beijing"})
```

### Supporting Modules

- **`authentication/`**: DID WBA (Web-based Decentralized Identifiers) authentication — DID document creation (`create_did_wba_document`), auth header generation (`DIDWbaAuthHeader`), RS256 JWT signature verification (`DidWbaVerifier`)
- **`direct_e2ee/`**: ANP-P5 private-chat E2EE SDK surface for Go/Rust parity. It owns P5 wire models, JCS AAD builders, X3DH-like initial material, HKDF `kdf_rk`/`kdf_ck`, pending-confirmation bootstrap, Double Ratchet-like session state, and top-level OPK publish/get sidecar handling for product clients/services to consume.
- Shared P5 direct E2EE vector fixtures live under `testdata/direct_e2ee/`; Go (`golang/direct_e2ee/shared_vectors_test.go`) and Rust (`rust/tests/direct_e2ee_shared_vectors.rs`) must pass the same JSON vectors before product integrations claim cross-language parity.
- P5 key-service calls (`direct.e2ee.publish_prekey_bundle` / `direct.e2ee.get_prekey_bundle`) must bind `meta.target.kind="service"` and use the caller DID document's advertised `ANPMessageService.serviceDid`; do not send legacy target-less control-plane requests.
- **`e2e_encryption_v2/`**: Legacy transport-agnostic E2E encryption v2 using HTTP RESTful dict-based messages, ECDHE key exchange, AES-GCM encryption. Session state machine: IDLE → HANDSHAKE_INITIATED → HANDSHAKE_COMPLETING → ACTIVE. Uses `did:wba:` format and snake_case fields (unlike the older `e2e_encryption/` which is WebSocket-coupled with camelCase). Do not use it for new ANP-P5 direct E2EE service behavior.
- **`e2e_encryption/`**: Legacy WebSocket-based E2E encryption (forward compatibility, uses `did:anp:` format)
- **`proof/`**: W3C Data Integrity Proof generation and verification, strict Appendix-B object proof helpers, group receipt proof helpers, `did_wba_binding` helpers, and RFC 9421 origin proof support
- **`ap2/`**: Agent Payment Protocol v2 — CartMandate (merchant-signed) and PaymentMandate (user-signed) with ES256K (secp256k1) signatures. Two-phase flow: merchant creates CartMandate → user creates PaymentMandate referencing cart hash → merchant verifies. Spec: `docs/ap2/ap2-flow.md`
- **`meta_protocol/`**: LLM-powered dynamic protocol negotiation — agents negotiate communication protocols using LLM-generated code for requester/provider roles
- **`fastanp/`**: Older FastAPI plugin framework (predecessor to OpenANP). Uses `FastANP` class with `@anp.interface(path)` decorator. Still functional but OpenANP is now the recommended approach
- **`utils/`**: Shared cryptographic primitives (`crypto_tool.py`) and LLM integration abstractions

### Key Architectural Patterns

- **DID WBA Auth Flow**: Create DID document → generate JWT auth headers → verify RS256 signatures
- **OpenANP generates three endpoints per agent**: `GET <prefix>/ad.json` (agent description), `GET <prefix>/interface.json` (OpenRPC), `POST <prefix>/rpc` (JSON-RPC 2.0)
- **FastANP vs OpenANP**: FastANP is instance-based plugin (`FastANP(name, did)`), OpenANP is class decorator-based (`@anp_agent`). Both generate OpenRPC from Python type hints
- **Session management**: Based on DID identity (not DID + token), shared across requests from same agent

## Configuration

Copy `.env.example` to `.env` for meta-protocol negotiation features:
```bash
AZURE_OPENAI_API_KEY=<your-key>
AZURE_OPENAI_ENDPOINT=<your-endpoint>
AZURE_OPENAI_API_VERSION=2024-02-01
AZURE_OPENAI_DEPLOYMENT=gpt-4o
AZURE_OPENAI_MODEL_NAME=gpt-4o
```

Optional dependency groups: `api` (FastAPI + OpenAI, needed for OpenANP/FastANP), `dev` (pytest + pytest-asyncio).

## Testing

Tests are distributed across:
- `anp/unittest/` — Core unit tests organized by module (openanp, ap2, authentication, fastanp, e2e_v2, proof, anp_crawler)
- `anp/anp_crawler/test/` — ANP crawler integration tests
- `anp/fastanp/` — FastANP domain normalization tests

Some tests require `.env` configuration for LLM-based features.

## Code Style

Google Python Style Guide: 4-space indentation, type hints on function signatures, Google-style docstrings, `snake_case` functions/modules, `UpperCamelCase` classes, `UPPER_SNAKE_CASE` constants.

## Key Development Notes

- Always use `uv run` prefix when running scripts to ensure correct environment
- Go SDK work under `golang/` must remain pure Go and must not use cgo; prefer cross-platform standard-library or pure-Go dependencies only
- OpenANP `@interface` method names must be unique within a class (tracked by function reference)
- OpenANP `Context` parameter (`ctx: Context`) is auto-injected and excluded from OpenRPC schemas; detected by parameter name `ctx`/`context` or type annotation
- OpenANP `router()` works as both class method (tries no-arg instantiation) and instance method (recommended for constructors with arguments)
- Test DID documents and keys for testing: `docs/did_public/public-did-doc.json`, `docs/did_public/public-private-key.pem`
- Examples organized by feature: `examples/python/{openanp_examples,did_wba_examples,fastanp_examples,anp_crawler_examples,ap2_examples,negotiation_mode}`
