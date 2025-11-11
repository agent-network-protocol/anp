# ANP TypeScript SDK

TypeScript SDK for the Agent Network Protocol (ANP), enabling developers to build intelligent agents that can authenticate, discover, and communicate with other agents in a decentralized network.

## Features

- 🔐 **DID:WBA Identity Management** - Create and manage decentralized identities
- 🔑 **HTTP Authentication** - Secure agent-to-agent authentication
- 📋 **Agent Description Protocol** - Publish and discover agent capabilities
- 🔍 **Agent Discovery** - Find agents through active and passive mechanisms
- 🤝 **Meta-Protocol Negotiation** - Dynamically negotiate communication protocols
- 🔒 **End-to-End Encryption** - Secure message encryption
- 🎯 **Type-Safe** - Full TypeScript support with comprehensive type definitions
- ⚡ **Modern** - Built with ESM and CommonJS support

## Installation

```bash
npm install @anp/typescript-sdk
```

## Quick Start

```typescript
import { ANPClient } from '@anp/typescript-sdk';

// Initialize the SDK
const client = new ANPClient({
  debug: true,
  http: { timeout: 10000 }
});

// Create a DID identity
const identity = await client.did.create({
  domain: 'example.com',
  path: 'agent1'
});

console.log('Created DID:', identity.did);
// Output: did:wba:example.com:agent1

// Create an agent description
let description = client.agent.createDescription({
  name: 'My Agent',
  description: 'An intelligent ANP agent',
  protocolVersion: '0.1.0',
  did: identity.did
});

// Add an interface
description = client.agent.addInterface(description, {
  type: 'Interface',
  protocol: 'HTTP',
  version: '1.1',
  url: 'https://example.com/api'
});

// Sign the description
const signedDescription = await client.agent.signDescription(
  description,
  identity,
  'challenge-string',
  'example.com'
);

// Discover agents
const agents = await client.discovery.discoverAgents('example.com', identity);
console.log(`Found ${agents.length} agents`);

// Make authenticated HTTP requests
const response = await client.http.get(
  'https://other-agent.com/api/data',
  identity
);
```

## Documentation

### Guides
- [Getting Started Guide](./docs/getting-started.md) - Learn the basics
- [API Reference](./docs/api-reference.md) - Complete API documentation
- [Configuration Guide](./docs/configuration.md) - Configuration options
- [Error Handling](./docs/errors.md) - Error types and handling

### Examples
- [Simple Agent](./examples/simple-agent/) - Basic agent creation
- [Authentication](./examples/authentication/) - DID:WBA authentication
- [Discovery](./examples/discovery/) - Agent discovery
- [Protocol Negotiation](./examples/protocol-negotiation/) - Meta-protocol negotiation
- [Encrypted Communication](./examples/encrypted-communication/) - End-to-end encryption

## Development

### Prerequisites

- Node.js >= 18.0.0
- npm or yarn

### Setup

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Build the package
npm run build

# Run linter
npm run lint

# Format code
npm run format
```

### Project Structure

```
ts_sdk/
├── src/                    # Source code
│   ├── core/              # Core modules (DID, Auth, ADP, Discovery)
│   ├── protocol/          # Protocol layer (Meta-protocol, Message Handler)
│   ├── crypto/            # Cryptography module
│   ├── transport/         # Transport layer (HTTP, WebSocket)
│   ├── types/             # TypeScript type definitions
│   ├── errors/            # Error classes
│   └── index.ts           # Public API entry point
├── tests/                 # Test files
│   ├── unit/             # Unit tests
│   └── integration/      # Integration tests
├── examples/             # Example applications
└── docs/                 # Documentation
```

## Contributing

Contributions are welcome! Please read our [Contributing Guide](./CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

MIT License - see the [LICENSE](../LICENSE) file for details.

## Links

- [ANP Specification](https://github.com/chgaowei/AgentNetworkProtocol)
- [Issue Tracker](https://github.com/chgaowei/AgentNetworkProtocol/issues)
- [Discussions](https://github.com/chgaowei/AgentNetworkProtocol/discussions)

## Core Concepts

### DID:WBA (Web-Based Agent DID)

Decentralized identifiers for agents that can be resolved via HTTPS:

```typescript
// Create a DID
const identity = await client.did.create({
  domain: 'example.com',
  path: 'agent1'
});
// Result: did:wba:example.com:agent1

// Resolve a DID
const document = await client.did.resolve('did:wba:example.com:agent1');
// Fetches from: https://example.com/.well-known/did.json
```

### Agent Description Protocol (ADP)

Describe your agent's capabilities and interfaces:

```typescript
const description = client.agent.createDescription({
  name: 'Translation Agent',
  description: 'Translates text between languages',
  protocolVersion: '0.1.0'
});

// Add interfaces
description = client.agent.addInterface(description, {
  type: 'Interface',
  protocol: 'HTTP',
  version: '1.1',
  url: 'https://example.com/translate'
});
```

### Agent Discovery

Find agents through active or passive discovery:

```typescript
// Active: Discover from a domain
const agents = await client.discovery.discoverAgents('example.com');

// Passive: Register with search service
await client.discovery.registerWithSearchService(
  'https://search.anp.network',
  'https://myagent.com/description.json',
  identity
);

// Search for agents
const results = await client.discovery.searchAgents(
  'https://search.anp.network',
  { keywords: 'translation' }
);
```

### Meta-Protocol Negotiation

Dynamically negotiate communication protocols:

```typescript
const machine = client.protocol.createNegotiationMachine({
  localIdentity: identity,
  remoteDID: 'did:wba:other.com:agent',
  candidateProtocols: 'JSON-RPC 2.0, GraphQL',
  maxNegotiationRounds: 5,
  onStateChange: (state) => {
    console.log('State:', state.value);
  }
});

machine.start();
machine.send({ type: 'initiate', remoteDID: '...', candidateProtocols: '...' });
```

### End-to-End Encryption

Secure communication with ECDHE and AES-256-GCM:

```typescript
// Key exchange happens automatically when using the SDK
// Messages are encrypted end-to-end between agents

// Send encrypted message
await client.protocol.sendMessage(
  'did:wba:other.com:agent',
  { data: 'secret message' },
  identity
);
```

## Use Cases

- **AI Agent Networks** - Build networks of AI agents that can discover and communicate
- **Decentralized Services** - Create decentralized service architectures
- **Secure Communication** - Implement secure agent-to-agent communication
- **Protocol Interoperability** - Enable agents with different protocols to communicate
- **Identity Management** - Manage decentralized identities for agents

## Requirements

- Node.js >= 18.0.0
- TypeScript >= 5.0.0 (for development)

## Browser Support

The SDK is designed for Node.js environments. Browser support is planned for future releases.

## Status

🚧 **Under Active Development** - This SDK is currently in early development. APIs may change.

Current version: 0.1.0

### Roadmap

- [x] DID:WBA identity management
- [x] HTTP authentication
- [x] Agent description protocol
- [x] Agent discovery
- [x] Meta-protocol negotiation
- [x] End-to-end encryption
- [ ] WebSocket transport
- [ ] Browser support
- [ ] Plugin system
- [ ] Performance optimizations

## Community

- **GitHub**: [AgentNetworkProtocol](https://github.com/chgaowei/AgentNetworkProtocol)
- **Issues**: [Report bugs or request features](https://github.com/chgaowei/AgentNetworkProtocol/issues)
- **Discussions**: [Join the conversation](https://github.com/chgaowei/AgentNetworkProtocol/discussions)

## Acknowledgments

Built with:
- [XState](https://xstate.js.org/) - State machine management
- [TypeScript](https://www.typescriptlang.org/) - Type safety
- [Vitest](https://vitest.dev/) - Testing framework
