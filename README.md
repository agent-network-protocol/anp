<div align="center">

[English](README.md) | [中文](README.cn.md)

</div>

# AgentConnect: Multi-language SDK for ANP

AgentConnect is the multi-language SDK and reference implementation for the [Agent Network Protocol (ANP)](https://github.com/agent-network-protocol/AgentNetworkProtocol). It helps agents identify each other, publish discoverable interfaces, call each other over standard RPC, attach verifiable proofs, resolve human-readable handles, and build end-to-end encrypted communication flows.

The Python package name is `anp`; this repository also contains Go, Rust, Dart, TypeScript, and Java SDK implementations or SDK workspaces.

<p align="center">
  <img src="/images/agentic-web.png" width="50%" alt="Agentic Web"/>
</p>

## What is ANP?

ANP is a protocol stack for an open network of interoperable agents. In practice, it answers these questions:

- **Who am I talking to?** DID WBA identities, DID documents, HTTP Message Signatures, and verifier helpers.
- **What can this agent do?** Agent Description documents, OpenRPC interface documents, and JSON-RPC endpoints.
- **Can I trust this object or request?** W3C Data Integrity proofs, Appendix-B object proofs, IM/origin proofs, and DID-WBA binding proofs.
- **How do humans and agents find each other?** WNS handle validation, resolution, and binding verification.
- **How do agents communicate privately?** Direct and group E2EE building blocks used by ANP-compatible clients and services.

## What this repository provides

- **Python agent SDK**: OpenANP for quickly building and calling ANP agents, plus authentication, proof, WNS, AP2, crawler, and E2EE modules.
- **Shared protocol SDKs**: Go and Rust cover core ANP identity/proof/WNS functionality plus selected E2EE surfaces; Dart focuses on core identity, proof, and WNS helpers.
- **Preview/local SDK workspaces**: TypeScript and Java implementations that can be used from source while their public package status matures.
- **Examples and fixtures**: runnable examples, cross-language interop checks, and shared test vectors.
- **Release tooling**: coordinated Python / Go / Rust release workflow and version policy.

## Choose your path

| I want to... | Start here |
|---|---|
| Build a working ANP agent quickly | [Python OpenANP quick start](#quick-start-build-a-python-agent) |
| Add DID WBA authentication to an HTTP service | [DID WBA examples](examples/python/did_wba_examples/) |
| Use the latest stable SDK release | [SDKs and releases](#sdks-and-releases) |
| Call or crawl another ANP agent | [ANP Crawler examples](examples/python/anp_crawler_examples/) |
| Find runnable examples across languages | [Examples guide](docs/examples.md) |
| Work with proofs, WNS, or E2EE | [Core concepts](#core-concepts) and [examples](#examples-by-learning-path) |
| Contribute to the repository | [Development](#development) |

## Table of contents

- [SDKs and releases](#sdks-and-releases)
- [Quick start: build a Python agent](#quick-start-build-a-python-agent)
- [Examples by learning path](#examples-by-learning-path)
- [Examples guide](docs/examples.md)
- [Core concepts](#core-concepts)
- [Repository map](#repository-map)
- [Development](#development)
- [Release and versioning](#release-and-versioning)
- [Security and compatibility notes](#security-and-compatibility-notes)
- [Contact us](#contact-us)
- [License](#license)

## SDKs and releases

Registry status checked on **2026-06-27**. Python, Go, and Rust are the coordinated stable release line in this repository. Dart is published separately. TypeScript and Java are usable from source/local builds, but this README does **not** claim public npm or Maven Central publication for them.

| Language | Package / module | Where to get it | Checked version | Install / use | Examples | Status |
|---|---|---|---|---|---|---|
| Python | `anp` | [PyPI](https://pypi.org/project/anp/) | `0.8.8` | `pip install anp` or `pip install "anp[api]"` for OpenANP/FastAPI extras | [examples/python/](examples/python/) | Stable published SDK |
| Go | `github.com/agent-network-protocol/anp/golang` | Go module proxy / [pkg.go.dev](https://pkg.go.dev/github.com/agent-network-protocol/anp/golang) | `v0.8.8` | `go get github.com/agent-network-protocol/anp/golang@latest` | [golang/examples/](golang/examples/) | Stable published SDK; tag format is `golang/vX.Y.Z` |
| Rust | `anp` | [crates.io](https://crates.io/crates/anp) / [docs.rs](https://docs.rs/anp) | `0.8.8` | `cargo add anp` | [rust/examples/](rust/examples/) | Stable published SDK |
| Dart | `anp` | [pub.dev](https://pub.dev/packages/anp) | `0.8.7` | `dart pub add anp` | [dart/example/](dart/example/) | Published SDK; versioned outside the current Python/Go/Rust release helper |
| TypeScript | `@anp/typescript-sdk` | Source workspace | local `0.1.0` | `cd typescript/ts_sdk && npm install && npm run build` | [typescript/ts_sdk/examples/](typescript/ts_sdk/examples/) | Preview/local source; npm registry check returned not found |
| Java | `com.agentconnect:anp4j`, `com.agentconnect:anp-spring-boot-starter` | Local Maven build | local `1.0.0` | `cd java && mvn clean install -DskipTests` | [java/anp-examples/](java/anp-examples/) | Local SDK; Maven Central metadata check returned not found |

### Minimal install snippets

```bash
# Python core SDK
pip install anp

# Python agent-building extras: FastAPI + OpenAI dependencies
pip install "anp[api]"

# Go
go get github.com/agent-network-protocol/anp/golang@latest

# Rust
cargo add anp

# Dart
dart pub add anp
```

For local repository development, prefer the commands in [Development](#development) instead of installing published packages.

## Quick start: build a Python agent

OpenANP is the fastest way to see ANP in action. It turns ordinary Python methods into discoverable ANP interfaces and exposes the standard agent documents and JSON-RPC endpoint.

Install the API extras if you are using the published package:

```bash
pip install "anp[api]"
```

When developing from this repository, use:

```bash
uv sync --extra api
```

Create `app.py`:

```python
from fastapi import FastAPI
from anp.openanp import AgentConfig, anp_agent, interface

@anp_agent(AgentConfig(
    name="Calculator",
    did="did:wba:example.com:calculator",
    prefix="/agent",
    description="A simple calculator agent",
))
class CalculatorAgent:
    @interface
    async def add(self, a: int, b: int) -> int:
        return a + b

app = FastAPI(title="Calculator Agent")
app.include_router(CalculatorAgent.router())
```

Run the server:

```bash
uvicorn app:app --port 8000
```

OpenANP generates these ANP endpoints automatically:

| Endpoint | Purpose |
|---|---|
| `GET /agent/ad.json` | Agent Description document for discovery |
| `GET /agent/interface.json` | OpenRPC interface document generated from Python type hints |
| `POST /agent/rpc` | JSON-RPC 2.0 endpoint for method calls |

Call it with the repository example client:

```bash
uv run python examples/python/openanp_examples/minimal_client.py
```

Full runnable pair:

```bash
# Terminal 1
uvicorn examples.python.openanp_examples.minimal_server:app --port 8000

# Terminal 2
uv run python examples/python/openanp_examples/minimal_client.py
```

## Examples by learning path

For file paths and copy-paste commands across Python, Go, Rust, Dart, TypeScript, and Java, see the [Examples guide](docs/examples.md).

| Level | Goal | Start here | Notes |
|---|---|---|---|
| Beginner | Build and call an ANP agent | [examples/python/openanp_examples/](examples/python/openanp_examples/) | Requires the `api` optional dependencies. |
| Beginner | Create and verify DID WBA identity | [examples/python/did_wba_examples/](examples/python/did_wba_examples/) | Offline examples are a good first auth smoke test. |
| Beginner | Generate and verify proofs | [examples/python/proof_examples/](examples/python/proof_examples/) | Covers W3C/Data Integrity and ANP proof helpers. |
| Beginner | Validate and resolve WNS handles | [examples/python/wns_examples/](examples/python/wns_examples/) | Some resolution flows require network access or a local resolver. |
| Intermediate | Discover ANP documents and execute tools | [examples/python/anp_crawler_examples/](examples/python/anp_crawler_examples/) | Crawler-style interface discovery and JSON-RPC execution. |
| Intermediate | Run AP2 payment protocol flow | [examples/python/ap2_examples/](examples/python/ap2_examples/) | Merchant/shopper mandate examples. |
| Intermediate | Check Python ↔ Rust interoperability | [examples/python/rust_interop_examples/](examples/python/rust_interop_examples/) | Useful when touching auth or wire fixtures. |
| Advanced | Explore Direct E2EE examples | [examples/python/e2e_encryption_hpke_examples/](examples/python/e2e_encryption_hpke_examples/) and [docs/e2e/direct-e2ee-p5-sdk.md](docs/e2e/direct-e2ee-p5-sdk.md) | Use current P5 docs for product-facing direct E2EE behavior. |
| Advanced | Explore Group E2EE / MLS | [docs/e2e/group-e2ee-p6-anp-mls.md](docs/e2e/group-e2ee-p6-anp-mls.md) | Group E2EE is security-sensitive; follow the documented boundaries. |
| Advanced | Try LLM-assisted protocol negotiation | [examples/python/negotiation_mode/](examples/python/negotiation_mode/) | Requires `.env` LLM provider configuration. |

Language-specific examples are also available in [golang/examples/](golang/examples/), [rust/examples/](rust/examples/), [dart/example/](dart/example/), [typescript/ts_sdk/examples/](typescript/ts_sdk/examples/), and [java/anp-examples/](java/anp-examples/). The central [Examples guide](docs/examples.md) lists the common run commands for each language.

## Core concepts

| Concept | What it means in this repository | Learn more |
|---|---|---|
| DID WBA | Web-based decentralized identifiers, DID documents, verification methods, HTTP Message Signatures, and auth verifier helpers. | [examples/python/did_wba_examples/](examples/python/did_wba_examples/) |
| Agent Description | The `ad.json` document that lets another agent discover who you are and where your interfaces live. | [examples/python/openanp_examples/](examples/python/openanp_examples/) |
| OpenRPC / JSON-RPC | Interface schema and method-call transport generated from Python type hints by OpenANP. | [anp/openanp/](anp/openanp/) |
| Proof | W3C Data Integrity, Appendix-B object proof, group receipt, DID-WBA binding, IM, and RFC 9421 origin proof helpers. | [examples/python/proof_examples/](examples/python/proof_examples/) |
| WNS | WBA Name Space helpers for human-readable handles, `wba://` URIs, resolution, and DID binding verification. | [examples/python/wns_examples/](examples/python/wns_examples/) |
| Direct E2EE | ANP-P5 private-chat E2EE models, session state, prekey handling, and shared vectors across SDKs. | [docs/e2e/direct-e2ee-p5-sdk.md](docs/e2e/direct-e2ee-p5-sdk.md) |
| Group E2EE | ANP-P6 group E2EE / MLS operation surfaces and local-state boundaries. | [docs/e2e/group-e2ee-p6-anp-mls.md](docs/e2e/group-e2ee-p6-anp-mls.md) |
| AP2 | Agent Payment Protocol v2 mandate models and validation helpers. | [examples/python/ap2_examples/](examples/python/ap2_examples/) |
| Legacy / specialized modules | FastANP, older E2EE examples, and meta-protocol negotiation remain available for compatibility or advanced experiments. | [examples/python/fastanp_examples/](examples/python/fastanp_examples/), [examples/python/e2e_encryption_v2_examples/](examples/python/e2e_encryption_v2_examples/), [examples/python/negotiation_mode/](examples/python/negotiation_mode/) |

## Repository map

| Path | Purpose |
|---|---|
| [anp/](anp/) | Python package: OpenANP, authentication, proof, WNS, AP2, crawler, E2EE, and meta-protocol modules. |
| [examples/python/](examples/python/) | Python examples grouped by feature and learning path. |
| [golang/](golang/) | Pure Go ANP SDK module and examples. |
| [rust/](rust/) | Rust `anp` crate, examples, tests, and MLS/E2EE operation surfaces. |
| [dart/](dart/) | Dart SDK package, examples, tests, and Flutter smoke workspace. |
| [typescript/ts_sdk/](typescript/ts_sdk/) | TypeScript SDK preview workspace for Node 20+. |
| [java/](java/) | Java SDK modules: core `anp4j`, Spring Boot starter, and examples. |
| [docs/](docs/) | Protocol-adjacent docs for DID, AP2, E2EE, public fixtures, and PR notes. |
| [testdata/](testdata/) | Shared cross-language fixtures and vectors. |
| [skills/anp-multilang-release/](skills/anp-multilang-release/) | Coordinated Python / Go / Rust release helper and policy. |

## Development

Use the toolchain for the language you are changing. Common local commands:

```bash
# Python
uv sync
uv sync --extra api      # OpenANP / FastAPI examples
uv sync --extra dev      # pytest and development tools
uv run pytest
uv build --wheel

# Go
cd golang
go test ./...

# Rust
cd rust
cargo test

# Dart
cd dart
dart pub get
dart analyze
dart test

# TypeScript preview workspace
cd typescript/ts_sdk
npm install
npm run typecheck
npm test
npm run build

# Java local workspace
cd java
mvn test
```

Some examples require network access or `.env` configuration, especially LLM-assisted negotiation examples under [examples/python/negotiation_mode/](examples/python/negotiation_mode/).

## Release and versioning

Python, Go, and Rust use one coordinated `X.Y.Z` version managed by [skills/anp-multilang-release/](skills/anp-multilang-release/). The release policy is documented in [skills/anp-multilang-release/references/release-policy.md](skills/anp-multilang-release/references/release-policy.md).

Current coordinated release files include:

- Python package version in [pyproject.toml](pyproject.toml) and runtime version in [anp/__init__.py](anp/__init__.py).
- Rust crate version in [rust/Cargo.toml](rust/Cargo.toml).
- Go runtime version in [golang/version.go](golang/version.go).

Tag rules:

- Root release tag: `X.Y.Z`, for example `0.8.8`.
- Go submodule tag: `golang/vX.Y.Z`, for example `golang/v0.8.8`.

Release planning starts with:

```bash
uv run python skills/anp-multilang-release/scripts/release.py plan --version 0.8.8
```

The release command validates the working tree, aligned version files, Python build, Rust dry-run publish, and Go tests before publishing and pushing tags.

## Security and compatibility notes

- Load secrets from `.env` or runtime configuration; never hardcode real private keys or tokens.
- Treat DID private keys, E2EE key material, and decrypted plaintext as sensitive local data.
- Prefer current DID WBA and HTTP Message Signature flows for new integrations; legacy modules remain documented for compatibility.
- Do not assume preview/local SDK workspaces are already published packages unless the README explicitly says so.

## Contact us

- **Author**: GaoWei Chang
- **Email**: chgaowei@gmail.com
- **Website**: [https://agent-network-protocol.com/](https://agent-network-protocol.com/)
- **Discord**: [https://discord.gg/sFjBKTY7sB](https://discord.gg/sFjBKTY7sB)
- **GitHub**: [https://github.com/agent-network-protocol/AgentNetworkProtocol](https://github.com/agent-network-protocol/AgentNetworkProtocol)
- **WeChat**: flow10240

## License

This project is open-sourced under the MIT License. See [LICENSE](LICENSE) for details.

---

**Copyright (c) 2024 GaoWei Chang**
