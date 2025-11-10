# ANP TypeScript SDK v0.1.0 Release Notes

## Overview

We're excited to announce the initial release of the ANP TypeScript SDK! This SDK provides a comprehensive implementation of the Agent Network Protocol (ANP), enabling developers to build intelligent agents that can authenticate, discover, and communicate with other agents in a decentralized network.

## Key Features

### 🔐 DID:WBA Identity Management
- Create and manage decentralized identities using the did:wba method
- Generate and resolve DID documents
- Sign and verify data with DID identities
- Support for multiple key types (ECDSA secp256k1, Ed25519, X25519)

### 🔒 Secure Authentication
- HTTP authentication using DID:WBA signatures
- Access token generation and validation
- Nonce replay prevention
- Clock skew tolerance for distributed systems

### 📋 Agent Description Protocol (ADP)
- Create and publish agent capability descriptions
- Add information resources and interfaces
- Sign and verify agent descriptions with digital signatures
- Fetch and parse agent descriptions from URLs

### 🔍 Agent Discovery
- Active discovery: Find agents from domain names
- Passive discovery: Register with search services
- Search for agents by capabilities
- Automatic pagination handling

### 🤝 Meta-Protocol Negotiation
- Dynamic protocol negotiation between agents
- XState v5 powered state machine for robust flow control
- Code generation coordination
- Test case negotiation
- Error fixing negotiation

### 🔐 End-to-End Encryption
- ECDHE key exchange for secure communication
- AES-GCM encryption and decryption
- Key derivation with HKDF
- Support for encrypted agent-to-agent communication

### 🛠️ Developer Experience
- Full TypeScript support with comprehensive type definitions
- ESM and CommonJS module formats
- High-level API for common operations
- Low-level access for advanced use cases
- Extensive documentation and examples
- 80%+ test coverage

## Installation

```bash
npm install @anp/typescript-sdk
```

## Quick Start

```typescript
import { ANPClient } from '@anp/typescript-sdk';

// Initialize the client
const client = new ANPClient({
  debug: true
});

// Create a DID identity
const identity = await client.did.create({
  domain: 'example.com',
  path: 'agent1'
});

// Create an agent description
const description = client.agent.createDescription({
  name: 'My Agent',
  description: 'A helpful AI agent',
  protocolVersion: '1.0.0'
});

// Discover other agents
const agents = await client.discovery.discoverAgents('example.com');
```

## Documentation

- [Getting Started Guide](./docs/getting-started.md)
- [API Reference](./docs/api-reference.md)
- [Configuration Guide](./docs/configuration.md)
- [Error Handling](./docs/errors.md)

## Examples

Check out the [examples directory](./examples/) for complete working examples:
- Simple agent setup
- Authentication flows
- Agent discovery
- Protocol negotiation
- Encrypted communication

## Requirements

- Node.js >= 18.0.0
- TypeScript >= 5.0.0 (for TypeScript projects)

## What's Next

We're actively working on the following features for future releases:
- WebSocket support for real-time communication
- Plugin system for extensibility
- Browser compatibility
- Enhanced monitoring and telemetry
- Multi-DID support per client

## Contributing

We welcome contributions! Please see our [Contributing Guide](./CONTRIBUTING.md) for details.

## License

MIT License - see [LICENSE](../LICENSE) for details.

## Support

- GitHub Issues: https://github.com/chgaowei/AgentNetworkProtocol/issues
- Documentation: https://github.com/chgaowei/AgentNetworkProtocol#readme

## Acknowledgments

Special thanks to all contributors who helped make this release possible!

---

**Note**: This is an initial release (v0.1.0). While the SDK is functional and well-tested, the API may evolve based on community feedback. We recommend pinning to specific versions in production environments.
