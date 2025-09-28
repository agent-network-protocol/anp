<div align="center">
  
[English](README.md) | [中文](README.cn.md)

</div>

## AgentConnect

### What is AgentConnect

AgentConnect is an open-source implementation of the [Agent Network Protocol (ANP)](https://github.com/agent-network-protocol/AgentNetworkProtocol).

The Agent Network Protocol (ANP) aims to become **the HTTP of the Agentic Internet era**.

Our vision is to **define how agents connect with each other and build an open, secure, and efficient collaboration network for billions of agents**.

<p align="center">
  <img src="/images/agentic-web.png" width="50%" alt="Agentic Web"/>
</p>

While current internet infrastructure is well-established, there's still a lack of optimal communication and connection solutions for the specific needs of agent networks. We are committed to addressing three major challenges faced by agent networks:

- 🌐 **Interconnectivity**: Enable communication between all agents, break down data silos, and allow AI to access complete contextual information.
- 🖥️ **Native Interfaces**: AI shouldn't have to mimic human internet interactions; it should interact with the digital world through its most proficient methods (APIs or communication protocols).
- 🤝 **Efficient Collaboration**: Leverage AI for self-organizing and self-negotiating agents to build a more cost-effective and efficient collaboration network than the existing internet.

### AgentConnect Architecture

The technical architecture of AgentConnect is illustrated below:

<p align="center">
  <img src="/images/agent-connect-architecture.png" width="50%" alt="Project Architecture"/>
</p>

Corresponding to the three-layer architecture of the Agent Network Protocol, AgentConnect primarily includes:

1. 🔒 **Authentication and End-to-End Encryption Modules**
   Implements W3C DID-based authentication and end-to-end encrypted communication, including DID document generation, verification, retrieval, and end-to-end encryption based on DID and ECDHE (Elliptic Curve Diffie-Hellman Ephemeral). Currently supports **HTTP-based DID authentication**.

2. 🌍 **Meta-Protocol Module**
   Built on LLM (Large Language Models) and meta-protocols, this module handles application protocol negotiation, protocol code implementation, protocol debugging, and protocol processing. The current release ships the scaffolding but the flows are not yet wired into the default examples.

3. 📡 **Application Layer Protocol Integration Framework**
   Manages protocol specifications and code for communication with other agents, including protocol loading, unloading, configuration, and processing. This framework enables agents to easily load and run required protocols on demand, accelerating protocol negotiation.

Beyond these features, AgentConnect will focus on performance and multi-platform support:

- **Performance**: As a fundamental codebase, we aim to provide optimal performance and plan to rewrite core components in Rust.
- **Multi-Platform**: Currently supports Mac, Linux, and Windows, with future support for mobile platforms and browsers.

### Documentation

- Learn more about AgentNetworkProtocol: [Agent Network Protocol (ANP)](https://github.com/agent-network-protocol/AgentNetworkProtocol)
- For our overall design philosophy, check our technical whitepaper: [AgentNetworkProtocol Technical White Paper](https://github.com/agent-network-protocol/AgentNetworkProtocol/blob/main/01-AgentNetworkProtocol%20Technical%20White%20Paper.md)

Here are some of our blogs:

- This is our understanding of the agent network: [What's Different About the Agentic Web](https://github.com/agent-network-protocol/AgentNetworkProtocol/blob/main/blogs/What-Makes-Agentic-Web-Different.md)

- A brief introduction to did:wba: [did:wba - Web-Based Decentralized Identifiers](https://github.com/agent-network-protocol/AgentNetworkProtocol/blob/main/blogs/did:wba,%20a%20Web-based%20Decentralized%20Identifier.md)

- We compared the differences between did:wba and technologies like OpenID Connect and API keys: [Comparison of did:wba with OpenID Connect and API keys](https://github.com/agent-network-protocol/AgentNetworkProtocol/blob/main/blogs/Comparison%20of%20did:wba%20with%20OpenID%20Connect%20and%20API%20keys.md)

- We analyzed the security principles of did:wba: [Security Principles of did:wba](https://github.com/agent-network-protocol/AgentNetworkProtocol/blob/main/blogs/did%3Awba-security-principles.md)

- Three Technical Approaches to AI-Internet Interaction: [Three Technical Approaches to AI-Internet Interaction](https://github.com/agent-network-protocol/AgentNetworkProtocol/blob/main/blogs/Three_Technical_Approaches_to_AI_Internet_Interaction.md)


### Milestones

Both protocol and implementation development follow this progression:

- [x] Build authentication and end-to-end encrypted communication protocol and implementation. This foundational core is essentially complete.
- [x] Meta-protocol design and implementation. Protocol design and code development are basically complete.
- [ ] Application layer protocol design and development. Currently in progress.

To establish ANP as an industry standard, we plan to form an ANP Standardization Committee at an appropriate time, working towards recognition by international standardization organizations like W3C.

### Installation

```bash
pip install agent-connect
```

### Local Development Setup

Use [uv](https://github.com/astral-sh/uv) to create an isolated environment and install the project in editable mode:

```bash
uv venv .venv
uv pip install --python .venv/bin/python --editable .
```

You can now invoke scripts with uv. The examples below assume the commands are executed from the repository root:

```bash
uv run --python .venv/bin/python python -m pip --version
```

> Tip: set `UV_PYTHON=.venv/bin/python` in your shell to omit the `--python` flag from subsequent `uv run` commands.

Clone the repository (if you have not already):

```bash
git clone https://github.com/agent-network-protocol/AgentConnect.git
```

### Repository Structure

The `agent_connect/` package contains the SDK modules that power the examples and published wheel:

- `agent_connect/authentication`: DID WBA helpers covering document creation, signing, authentication headers, and verification services.
- `agent_connect/anp_crawler`: Utilities that traverse ANP registries and example endpoints; useful for quick interoperability checks.
- `agent_connect/utils`: Shared helpers such as cryptographic primitives and serialization helpers that are reused across modules.
- `agent_connect/meta_protocol`: Meta-protocol negotiation scaffolding based on LLM prompts. The interfaces are present but the flows are not yet activated in this release.
- `agent_connect/e2e_encryption`: Planned end-to-end encryption utilities. The current SDK publishes the package for forward compatibility, although no active features depend on it yet.

Example scripts live under `examples/`, documentation in `docs/`, and packaging artifacts within `dist/`.

### Using AgentConnect

The `agent_connect` package can be imported directly after installation:

```python
from agent_connect.authentication import create_did_wba_document

document, keys = create_did_wba_document(hostname="demo.agent-network")
print(document["id"])
```

#### DID WBA Offline Authentication Workflow

did:wba is a Web-based Decentralized Identifier. More information: [did:wba, a Web-based Decentralized Identifier](https://github.com/agent-network-protocol/AgentNetworkProtocol/blob/main/blogs/did%3Awba%2C%20a%20Web-based%20Decentralized%20Identifier.md).

The `examples/python/did_wba_examples/` directory provides a step-by-step walkthrough that stays fully local (no HTTP traffic required) and demonstrates how to build, validate, and verify DID headers using the SDK:

1. **`create_did_document.py`** – Generates a `did:wba` identifier, writes the DID document to `examples/python/did_wba_examples/generated/did.json`, and stores the associated key pair. Run:

   ```bash
   uv run --python .venv/bin/python python examples/python/did_wba_examples/create_did_document.py
   ```

2. **`validate_did_document.py`** – Loads (or regenerates) the DID document and checks the required contexts, verification method wiring, and HTTPS service endpoint. Run:

   ```bash
   uv run --python .venv/bin/python python examples/python/did_wba_examples/validate_did_document.py
   ```

3. **`authenticate_and_verify.py`** – Uses `DIDWbaAuthHeader` to sign an authentication header with `docs/did_public/public-private-key.pem`, then verifies it with `DidWbaVerifier` configured with the RS256 demo keys under `docs/jwt_rs256/`. The script issues and validates a bearer token entirely in memory. Run:

   ```bash
   uv run --python .venv/bin/python python examples/python/did_wba_examples/authenticate_and_verify.py
   ```

These scripts showcase how to compose the building blocks from `agent_connect/authentication`. When adapting to your infrastructure, replace the demo documents and keys with your own material, or plug in a real DID resolver instead of the local stub used in the examples.

You can also experience DID WBA authentication through our demo page: [DID WBA Authentication Page](https://service.agent-network-protocol.com/wba/examples/). This page demonstrates the process of creating a DID identity on one platform (pi-unlimited.com) and then verifying the identity on another platform (service.agent-network-protocol.com).

#### Meta-Protocol Negotiation Example

We support meta-protocol negotiation where Alice and Bob first negotiate a protocol, generate processing code, and then communicate using the protocol code.

Run the demo code in examples/negotiation_mode directory. Start Bob's node first, then Alice's node.

1. Start Bob's node
```bash
python negotiation_bob.py
```

2. Start Alice's node
```bash
python negotiation_alice.py
```

The logs will show successful connection, protocol negotiation, code generation, and data communication between Alice and Bob.

> Note:
> Meta-protocol negotiation requires Azure OpenAI API configuration (currently only supports Azure OpenAI). Configure these environment variables in the ".env" file in the project root: AZURE_OPENAI_API_KEY, AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_DEPLOYMENT, AZURE_OPENAI_MODEL_NAME


### Tools

#### DID Document Generation Tool
We provide a DID document generation tool, which you can run by executing `python generate_did_doc.py` to generate a DID document.

```bash
python generate_did_doc.py <did> [--agent-description-url URL] [--verbose]
```

For detailed usage, refer to the documentation: [README_did_generater_cn.md](tools/did_generater/README_did_generater_cn.md).

#### Agent Network Explorer

You can explore the Agent Network using natural language through our web-based tool:

- [ANP Network Explorer](https://service.agent-network-protocol.com/anp-explorer/)

This tool allows you to:
- Explore the Agent Network Protocol (ANP) ecosystem using natural language
- Connect to the world of agents through the ANP protocol
- Interact with various types of agents by simply entering the URL of their agent description document

The explorer provides an intuitive interface to understand how agents communicate and operate within the ANP framework, making it easier to visualize the connections and capabilities of different agents in the network.




### Contact Us

Author: Gaowei Chang  
Email: chgaowei@gmail.com  
- Discord: [https://discord.gg/sFjBKTY7sB](https://discord.gg/sFjBKTY7sB)  
- Website: [https://agent-network-protocol.com/](https://agent-network-protocol.com/)  
- GitHub: [https://github.com/agent-network-protocol/AgentNetworkProtocol](https://github.com/agent-network-protocol/AgentNetworkProtocol)
- WeChat: flow10240

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

This project is open-sourced under the MIT License. See the [LICENSE](LICENSE) file for details.

## Copyright Notice
Copyright (c) 2024 GaoWei Chang  
This file is released under the [MIT License](./LICENSE). You are free to use and modify it, but you must retain this copyright notice.
