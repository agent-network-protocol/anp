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
- **Shared protocol SDKs**: Go, Rust, and Dart SDKs for core ANP identity/proof/WNS functionality and selected E2EE surfaces.
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
| Work with proofs, WNS, or E2EE | [Core concepts](#core-concepts) and [examples](#examples-by-learning-path) |
| Contribute to the repository | [Development](#development) |

## Table of contents

- [SDKs and releases](#sdks-and-releases)
- [Quick start: build a Python agent](#quick-start-build-a-python-agent)
- [Examples by learning path](#examples-by-learning-path)
- [Core concepts](#core-concepts)
- [Repository map](#repository-map)
- [Development](#development)
- [Release and versioning](#release-and-versioning)
- [Security and compatibility notes](#security-and-compatibility-notes)
- [Contact us](#contact-us)
- [License](#license)

## SDKs and releases

This section is intentionally structured as the main entry point for package installation. The detailed multi-language version and registry matrix is added in the release-matrix step of this README refresh.

## Quick start: build a Python agent

OpenANP remains the recommended first experience for building an ANP agent in Python. The full quick-start flow is expanded in the next README step. For now, see [examples/python/openanp_examples/](examples/python/openanp_examples/).

## Examples by learning path

The example list will be organized from beginner to advanced paths in the next README step. Current examples are under [examples/python/](examples/python/), [golang/examples/](golang/examples/), [rust/examples/](rust/examples/), [dart/example/](dart/example/), [typescript/ts_sdk/examples/](typescript/ts_sdk/examples/), and [java/anp-examples/](java/anp-examples/).

## Core concepts

This section will keep short, navigable explanations for DID WBA, Agent Description, OpenRPC / JSON-RPC, HTTP Message Signatures, Proof, WNS, Direct E2EE, Group E2EE, and AP2, with links to authoritative docs and examples.

## Repository map

This section will provide a compact map of the Python package, language SDK directories, docs, examples, test data, and release tooling.

## Development

For local Python development, use `uv` from the repository root:

```bash
uv sync
uv run pytest
```

Language-specific development commands are documented in the relevant SDK directories and will be summarized later in this README.

## Release and versioning

Python, Go, and Rust releases are coordinated by the release helper in [skills/anp-multilang-release/](skills/anp-multilang-release/). The detailed user-facing release policy summary is added in the release-matrix step.

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
