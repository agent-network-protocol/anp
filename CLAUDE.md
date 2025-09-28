# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

**Environment Setup:**
```bash
uv venv .venv
uv pip install --python .venv/bin/python --editable .
```

**Testing:**
```bash
uv run pytest                              # Run full test suite
uv run pytest -k <pattern>                 # Run specific tests
uv run pytest --cov=agent_connect          # Run tests with coverage
```

**Build and Distribution:**
```bash
uv build --wheel                           # Build wheel for distribution
uv sync                                    # Sync environment from pyproject.toml
```

**Running Examples:**
```bash
# DID WBA authentication examples (offline)
uv run python examples/python/did_wba_examples/create_did_document.py
uv run python examples/python/did_wba_examples/validate_did_document.py
uv run python examples/python/did_wba_examples/authenticate_and_verify.py

# Meta-protocol negotiation (requires Azure OpenAI config in .env)
python examples/python/negotiation_mode/negotiation_bob.py    # Start Bob first
python examples/python/negotiation_mode/negotiation_alice.py  # Then Alice

# DID document generation tool
python tools/did_generater/generate_did_doc.py <did> [--agent-description-url URL]
```

## Architecture Overview

AgentConnect implements the Agent Network Protocol (ANP) through a three-layer architecture:

**Core Modules (`agent_connect/`):**
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

## Configuration

**Environment Variables (`.env`):**
```
AZURE_OPENAI_API_KEY=<key>          # Required for meta-protocol negotiation
AZURE_OPENAI_ENDPOINT=<endpoint>
AZURE_OPENAI_DEPLOYMENT=<model>
AZURE_OPENAI_MODEL_NAME=<name>
```

**Security Note:** Never commit secrets to the repository. Use `.env` files loaded via `python-dotenv`.

## Testing Guidelines

Tests are located in `agent_connect/unittest/` following pytest conventions. Test files use `test_<area>.py` naming and functions use `test_<behavior>`. Focus on authentication handshakes, encryption boundaries, protocol negotiation flows, and error conditions.

## Code Style

Follow Google Python Style with four-space indentation, type hints, and Google-style docstrings. Use `snake_case` for functions/modules, `UpperCamelCase` for classes, and `UPPER_SNAKE_CASE` for constants. Prefer dependency injection and isolate network side effects for testability.