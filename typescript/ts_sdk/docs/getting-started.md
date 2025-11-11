# Getting Started with ANP TypeScript SDK

This guide will help you get started with the Agent Network Protocol (ANP) TypeScript SDK.

## Installation

Install the SDK using npm:

```bash
npm install @anp/typescript-sdk
```

Or using yarn:

```bash
yarn add @anp/typescript-sdk
```

## Quick Start

### 1. Create an ANP Client

```typescript
import { ANPClient } from '@anp/typescript-sdk';

const client = new ANPClient({
  debug: true, // Enable debug logging
});
```

### 2. Create a DID Identity

```typescript
// Create a new DID:WBA identity
const identity = await client.did.create({
  domain: 'example.com',
  path: 'agent1',
});

console.log('Created DID:', identity.did);
// Output: did:wba:example.com:agent1
```

### 3. Create an Agent Description

```typescript
// Create agent description
const description = client.agent.createDescription({
  name: 'My First Agent',
  description: 'A simple ANP agent',
  protocolVersion: '0.1.0',
});

// Add an interface
const descriptionWithInterface = client.agent.addInterface(description, {
  type: 'Interface',
  protocol: 'HTTP',
  version: '1.1',
  url: 'https://example.com/api',
});

// Sign the description
const signedDescription = await client.agent.signDescription(
  descriptionWithInterface,
  identity,
  'challenge-string',
  'example.com'
);
```

### 4. Discover Other Agents

```typescript
// Discover agents from a domain
const agents = await client.discovery.discoverAgents('example.com', identity);

console.log('Found agents:', agents);
```

### 5. Negotiate Protocols

```typescript
// Create a protocol negotiation state machine
const machine = client.protocol.createNegotiationMachine({
  localIdentity: identity,
  remoteDID: 'did:wba:other-agent.com:agent2',
  candidateProtocols: 'JSON-RPC 2.0',
  maxNegotiationRounds: 5,
  onStateChange: (state) => {
    console.log('Protocol state:', state.value);
  },
});

// Start the machine
machine.start();

// Initiate negotiation
machine.send({
  type: 'initiate',
  remoteDID: 'did:wba:other-agent.com:agent2',
  candidateProtocols: 'JSON-RPC 2.0',
});
```

## Configuration Options

The ANPClient accepts the following configuration options:

```typescript
const client = new ANPClient({
  // DID configuration
  did: {
    cacheTTL: 300000, // Cache TTL in milliseconds (default: 5 minutes)
    timeout: 10000, // Resolution timeout in milliseconds (default: 10 seconds)
  },
  
  // Authentication configuration
  auth: {
    maxTokenAge: 3600000, // Max token age in milliseconds (default: 1 hour)
    nonceLength: 32, // Nonce length in bytes (default: 32)
    clockSkewTolerance: 300, // Clock skew tolerance in seconds (default: 5 minutes)
  },
  
  // HTTP configuration
  http: {
    timeout: 10000, // Request timeout in milliseconds (default: 10 seconds)
    maxRetries: 3, // Maximum number of retries (default: 3)
    retryDelay: 1000, // Delay between retries in milliseconds (default: 1 second)
  },
  
  // Debug mode
  debug: false, // Enable debug logging (default: false)
});
```

## Next Steps

- Read the [API Reference](./api-reference.md) for detailed API documentation
- Check out the [Configuration Guide](./configuration.md) for advanced configuration options
- Learn about [Error Handling](./errors.md) to handle errors gracefully
- Explore the [Examples](../examples/) directory for complete example applications

## Common Patterns

### Making Authenticated HTTP Requests

```typescript
// Make an authenticated GET request
const response = await client.http.get(
  'https://example.com/api/data',
  identity
);

const data = await response.json();
```

### Signing and Verifying Data

```typescript
// Sign data
const data = new TextEncoder().encode('Hello, ANP!');
const signature = await client.did.sign(identity, data);

// Verify signature
const isValid = await client.did.verify(
  identity.did,
  data,
  signature
);

console.log('Signature valid:', isValid);
```

### Resolving DIDs

```typescript
// Resolve a DID to its document
const didDocument = await client.did.resolve('did:wba:example.com:agent1');

console.log('DID Document:', didDocument);
```

## Troubleshooting

### DID Resolution Fails

If DID resolution fails, ensure:
- The domain is accessible via HTTPS
- The DID document is published at `https://{domain}/.well-known/did.json`
- The DID document follows the did:wba specification

### Authentication Errors

If authentication fails, check:
- The DID identity has valid keys
- The timestamp is within the clock skew tolerance
- The signature is generated correctly

### Network Errors

The SDK automatically retries failed requests with exponential backoff. You can configure retry behavior in the HTTP configuration.

## Support

For issues and questions:
- GitHub Issues: https://github.com/chgaowei/AgentNetworkProtocol/issues
- Documentation: https://github.com/chgaowei/AgentNetworkProtocol
