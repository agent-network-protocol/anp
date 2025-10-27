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
uv run pytest -k <pattern>                 # Run specific tests
uv run pytest --cov=anp                    # Run tests with coverage
uv run pytest anp/unittest/                # Run core unit tests only
uv run pytest anp/anp_crawler/test/        # Run ANP crawler tests only
uv run pytest anp/fastanp/                 # Run FastANP tests only
```

**Build and Distribution:**
```bash
uv build --wheel                           # Build wheel for distribution
```

**Running Examples:**
```bash
# DID WBA authentication examples (offline)
uv run python examples/python/did_wba_examples/create_did_document.py
uv run python examples/python/did_wba_examples/authenticate_and_verify.py

# Meta-protocol negotiation (requires Azure OpenAI config in .env)
uv run python examples/python/negotiation_mode/negotiation_bob.py    # Start Bob first
uv run python examples/python/negotiation_mode/negotiation_alice.py  # Then Alice

# FastANP examples (requires --extra api)
uv run python examples/python/fastanp_examples/simple_agent.py
uv run python examples/python/fastanp_examples/hotel_booking_agent.py
uv run python examples/python/fastanp_examples/test_hotel_booking_client.py

# ANP Crawler examples
uv run python examples/python/anp_crawler_examples/simple_amap_example.py
uv run python examples/python/anp_crawler_examples/amap_crawler_example.py

# DID document generation tool
uv run python tools/did_generater/generate_did_doc.py <did> [--agent-description-url URL]
```

## Architecture Overview

AgentConnect implements the Agent Network Protocol (ANP) through a three-layer architecture:

**Core Modules (`anp/`):**
- `authentication/`: DID WBA (Web-based Decentralized Identifiers) authentication system
  - `did_wba.py`: Core DID document creation, resolution, and verification
  - `did_wba_authenticator.py`: Authentication header generation (`DIDWbaAuthHeader`)
  - `did_wba_verifier.py`: Signature verification and token validation (`DidWbaVerifier`)
  - `verification_methods.py`: Cryptographic verification helpers

- `e2e_encryption/`: End-to-end encryption utilities (forward compatibility, not fully activated)
  - WebSocket-based encrypted messaging infrastructure
  - ECDHE key exchange mechanisms

- `meta_protocol/`: LLM-powered protocol negotiation
  - `meta_protocol.py`: Core negotiation logic (`MetaProtocol`, `ProtocolType`)
  - `code_generator/`: Dynamic protocol code generation for requester/provider patterns
  - `protocol_negotiator.py`: Manages protocol discovery and agreement

- `anp_crawler/`: Agent Network Protocol discovery and interoperability tools
  - `anp_crawler.py`: Main crawler for ANP resources and agent descriptions
  - `anp_parser.py`: Parses agent description documents and OpenRPC specifications
  - `anp_interface.py`: Interface extraction and conversion utilities
  - `anp_client.py`: HTTP client for ANP resource fetching

- `fastanp/`: Fast development framework for ANP agents
  - `fastanp.py`: Main FastANP application class with decorator-based interface registration
  - `interface_manager.py`: Function registration and OpenRPC generation
  - `information.py`: Dynamic information management
  - `ad_generator.py`: Agent description document generation
  - `models.py`: Pydantic models for ANP components
  - `utils.py`: Utility functions for URL normalization and type conversion
  - `middleware.py`: Authentication middleware for FastAPI integration

- `utils/`: Shared cryptographic and utility functions
  - `crypto_tool.py`: Low-level cryptographic primitives
  - `llm/`: LLM integration abstractions

**Project Structure:**
- `examples/`: Runnable demonstrations of core functionalities
- `docs/`: Protocol documentation and key material for examples
- `tools/`: Command-line utilities (DID generation, etc.)
- `java/`: Cross-language integration support
- `dist/`: Built distribution artifacts

## Key Concepts

**DID WBA Authentication Flow:**
1. Create DID document with `create_did_wba_document(hostname, path_segments)`
2. Generate authentication headers with `DIDWbaAuthHeader`
3. Verify signatures using `DidWbaVerifier` with RS256 JWT validation

**Meta-Protocol Negotiation:**
- Agents dynamically negotiate communication protocols using LLM-generated code
- Supports both requester and provider role generation
- Enables protocol discovery and automatic adaptation

**ANP Crawler Usage:**
- Traverse agent networks to discover capabilities and endpoints
- Parse OpenRPC specifications embedded in agent descriptions
- Extract and convert protocol interfaces for interoperability

**FastANP Framework:**
- **Plugin Architecture**: FastAPI is the main framework, FastANP is a helper plugin (not a standalone framework)
- **Decorator-based registration**: Use `@anp.interface(path)` to register functions as JSON-RPC methods
- **Automatic OpenRPC generation**: Python functions + type hints → OpenRPC documents
- **Interface access**: `anp.interfaces[function].link_summary` (URL reference) or `.content` (embedded)
- **Context injection**: `ctx: Context` parameter provides session management, DID, and request access
- **Session management**: Based on DID (not DID + token), shared across requests from same agent
- **User-controlled routing**: User explicitly defines all routes including `/ad.json`
- **Built-in authentication middleware**: DID WBA verification with wildcard path exemptions (`*/ad.json`, `/info/*`)

## Configuration

**Environment Variables (`.env`):**

Copy `.env.example` to `.env` and configure the following (required only for meta-protocol negotiation):

```bash
AZURE_OPENAI_API_KEY=<your-key>
AZURE_OPENAI_ENDPOINT=<your-endpoint>
AZURE_OPENAI_API_VERSION=2024-02-01
AZURE_OPENAI_DEPLOYMENT=gpt-4o
AZURE_OPENAI_MODEL_NAME=gpt-4o
```

**Optional Dependencies:**
- `api`: FastAPI + OpenAI integration (required for FastANP framework and meta-protocol negotiation)
- `dev`: Development tools (pytest, pytest-asyncio)

**Security Note:** Never commit secrets to the repository. Use `.env` files loaded via `python-dotenv`.

## Testing Guidelines

Tests are distributed across multiple locations:
- `anp/unittest/`: Core unit tests for ANP components (context, comprehensive FastANP tests)
- `anp/anp_crawler/test/`: Tests for ANP crawler functionality
- `anp/fastanp/`: Tests for FastANP framework (domain normalization tests)

**Test Naming Convention:**
- Test files: `test_<feature>.py`
- Test functions: `test_<behavior>()`

**Focus Areas for Testing:**
- DID WBA authentication handshakes and signature verification
- End-to-end encryption boundaries (forward compatibility)
- Protocol negotiation flows with LLM code generation
- FastANP decorator behavior and OpenRPC generation
- Context injection and session management
- Error conditions and edge cases

**Note:** Some tests may require `.env` configuration for LLM-based features (meta-protocol negotiation).

## Code Style

Follow Google Python Style Guide:
- **Indentation**: 4 spaces
- **Type hints**: Required for function signatures
- **Docstrings**: Google-style format with Args/Returns/Raises sections
- **Naming conventions**:
  - `snake_case` for functions and modules
  - `UpperCamelCase` for classes
  - `UPPER_SNAKE_CASE` for constants
- **Testability**: Prefer dependency injection and isolate network side effects

## Key Development Notes

**FastANP Development:**
- Function names registered with `@anp.interface()` must be globally unique (FastANP tracks by function reference)
- Always use `uv run` prefix when running examples to ensure correct environment
- The `/rpc` endpoint is automatically registered for JSON-RPC 2.0 requests
- OpenRPC documents are automatically served at the paths specified in `@anp.interface(path)`
- Context parameter (`ctx: Context`) is automatically injected and excluded from OpenRPC schemas
- Request parameter (`req: Request`) is automatically injected similarly

**DID WBA Authentication:**
- DID documents are created with `create_did_wba_document(hostname, path_segments)`
- Authentication uses RS256 JWT tokens
- Verifier requires both private and public keys for token generation and verification
- Example keys are available in `docs/did_public/` for testing purposes only

**ANP Crawler Usage:**
- ANPCrawler requires DID document and private key paths for authenticated requests
- Discovered interfaces are automatically converted to callable tools
- Use `list_available_tools()` to see discovered methods
- Use `execute_tool_call(tool_name, arguments)` to invoke remote methods

**Project-Specific Paths:**
- Test DID documents: `docs/did_public/public-did-doc.json`
- Test private keys: `docs/did_public/public-private-key.pem`
- Examples are structured by feature: `examples/python/{did_wba_examples,fastanp_examples,anp_crawler_examples,negotiation_mode}`