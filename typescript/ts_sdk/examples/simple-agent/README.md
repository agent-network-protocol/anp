# Simple Agent Example

This example demonstrates the basics of creating an ANP agent with DID:WBA identity and agent description.

## What This Example Shows

- Creating a DID:WBA identity with domain and path
- Generating cryptographic keys (ECDSA secp256k1)
- Creating an agent description document
- Adding information resources
- Adding interface definitions
- Signing the agent description with proof
- Exporting the DID document

## Running the Example

From the `ts_sdk` directory:

```bash
npm run build
npx tsx examples/simple-agent/index.ts
```

Or from this directory:

```bash
npm install
npm start
```

## Expected Output

```
=== Simple Agent Example ===

Creating DID identity...
✓ Created DID: did:wba:localhost:9000:my-agent
✓ DID Document ID: did:wba:localhost:9000:my-agent
✓ Verification Methods: 2

Creating agent description...
✓ Agent description signed
✓ Proof type: Ed25519Signature2020

Signing data...
✓ Data signed
✓ Verification method: did:wba:localhost:9000:my-agent#auth-key

=== Example Complete ===

Note: To enable DID resolution, publish the DID document at:
http://localhost:9000/.well-known/did.json
```

The example demonstrates:
1. Creating a DID identity with domain `localhost:9000` and path `my-agent`
2. Generating 2 verification methods (authentication and key agreement)
3. Creating and signing an agent description
4. Using Ed25519 signatures for cryptographic proof
5. Signing arbitrary data with the DID identity

## Code Walkthrough

### 1. Initialize SDK
```typescript
const client = new ANPClient();
```

### 2. Create DID Identity
```typescript
const identity = await client.did.create({
  domain: 'myagent.example.com',
  path: 'agent1',
});
```

### 3. Create Agent Description
```typescript
let description = client.agent.createDescription({
  name: 'My Simple Agent',
  description: 'A basic ANP agent example',
  protocolVersion: '0.1.0',
  did: identity.did,
});
```

### 4. Add Resources and Interfaces
```typescript
description = client.agent.addInformation(description, {
  type: 'documentation',
  description: 'Agent API documentation',
  url: 'https://myagent.example.com/docs',
});

description = client.agent.addInterface(description, {
  type: 'api',
  protocol: 'REST',
  version: '1.0',
  url: 'https://myagent.example.com/api/v1',
});
```

### 5. Sign the Description
```typescript
const signedDescription = await client.agent.signDescription(
  description,
  identity,
  'challenge-123',
  'myagent.example.com'
);
```

## Key Concepts

### DID:WBA (Web-Based Agent)
A decentralized identifier method for web-based agents. Format: `did:wba:domain:path`

### Agent Description
A JSON-LD document describing the agent's capabilities, interfaces, and metadata.

### Cryptographic Proof
A digital signature that proves the agent description was created by the DID owner.

### Information Resources
Links to documentation, schemas, or other resources about the agent.

### Interfaces
Definitions of how to interact with the agent (protocols, endpoints, versions).

## Next Steps

After running this example:
- Publish the DID document at `https://myagent.example.com/.well-known/did.json`
- Host the agent description at a public URL
- Implement the REST API endpoints
- Explore the **authentication** example for secure communication
- Try the **discovery** example to make your agent discoverable
