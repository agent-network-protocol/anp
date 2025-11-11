# API Reference

Complete API reference for the ANP TypeScript SDK.

## ANPClient

The main entry point for the SDK.

### Constructor

```typescript
new ANPClient(config?: ANPConfig)
```

Creates a new ANP client instance.

**Parameters:**
- `config` (optional): Configuration options for the client

**Example:**
```typescript
const client = new ANPClient({
  debug: true,
  http: { timeout: 15000 }
});
```

## DID Operations

### client.did.create()

```typescript
async create(options: CreateDIDOptions): Promise<DIDIdentity>
```

Creates a new DID:WBA identity with key pairs.

**Parameters:**
- `options.domain`: The domain for the DID
- `options.path` (optional): The path component of the DID
- `options.keyTypes` (optional): Array of key types to generate

**Returns:** Promise resolving to a DIDIdentity object

**Example:**
```typescript
const identity = await client.did.create({
  domain: 'example.com',
  path: 'agent1'
});
```

### client.did.resolve()

```typescript
async resolve(did: string): Promise<DIDDocument>
```

Resolves a DID to its DID document.

**Parameters:**
- `did`: The DID identifier to resolve

**Returns:** Promise resolving to a DIDDocument

**Example:**
```typescript
const document = await client.did.resolve('did:wba:example.com:agent1');
```

### client.did.sign()

```typescript
async sign(identity: DIDIdentity, data: Uint8Array): Promise<Signature>
```

Signs data using a DID identity's private key.

**Parameters:**
- `identity`: The DID identity to sign with
- `data`: The data to sign

**Returns:** Promise resolving to a Signature object

**Example:**
```typescript
const data = new TextEncoder().encode('message');
const signature = await client.did.sign(identity, data);
```

### client.did.verify()

```typescript
async verify(did: string, data: Uint8Array, signature: Signature): Promise<boolean>
```

Verifies a signature against a DID's public key.

**Parameters:**
- `did`: The DID identifier
- `data`: The signed data
- `signature`: The signature to verify

**Returns:** Promise resolving to true if valid, false otherwise

**Example:**
```typescript
const isValid = await client.did.verify(
  'did:wba:example.com:agent1',
  data,
  signature
);
```

## Agent Description Operations

### client.agent.createDescription()

```typescript
createDescription(metadata: AgentMetadata): AgentDescription
```

Creates a new agent description document.

**Parameters:**
- `metadata.name`: Agent name
- `metadata.description` (optional): Agent description
- `metadata.protocolVersion`: ANP protocol version
- `metadata.did` (optional): Agent's DID
- `metadata.owner` (optional): Owner organization

**Returns:** AgentDescription object

**Example:**
```typescript
const description = client.agent.createDescription({
  name: 'My Agent',
  description: 'An intelligent agent',
  protocolVersion: '0.1.0'
});
```

### client.agent.addInformation()

```typescript
addInformation(description: AgentDescription, info: Information): AgentDescription
```

Adds an information resource to an agent description.

**Parameters:**
- `description`: The agent description to modify
- `info`: Information resource to add

**Returns:** Updated AgentDescription

**Example:**
```typescript
const updated = client.agent.addInformation(description, {
  type: 'Information',
  description: 'API Documentation',
  url: 'https://example.com/docs'
});
```

### client.agent.addInterface()

```typescript
addInterface(description: AgentDescription, iface: Interface): AgentDescription
```

Adds an interface to an agent description.

**Parameters:**
- `description`: The agent description to modify
- `iface`: Interface to add

**Returns:** Updated AgentDescription

**Example:**
```typescript
const updated = client.agent.addInterface(description, {
  type: 'Interface',
  protocol: 'HTTP',
  version: '1.1',
  url: 'https://example.com/api'
});
```

### client.agent.signDescription()

```typescript
async signDescription(
  description: AgentDescription,
  identity: DIDIdentity,
  challenge: string,
  domain: string
): Promise<AgentDescription>
```

Signs an agent description with a DID identity.

**Parameters:**
- `description`: The agent description to sign
- `identity`: The DID identity to sign with
- `challenge`: Challenge string for the proof
- `domain`: Domain for the proof

**Returns:** Promise resolving to signed AgentDescription

**Example:**
```typescript
const signed = await client.agent.signDescription(
  description,
  identity,
  'challenge-123',
  'example.com'
);
```

### client.agent.fetchDescription()

```typescript
async fetchDescription(url: string): Promise<AgentDescription>
```

Fetches and parses an agent description from a URL.

**Parameters:**
- `url`: URL of the agent description

**Returns:** Promise resolving to AgentDescription

**Example:**
```typescript
const description = await client.agent.fetchDescription(
  'https://example.com/agent-description.json'
);
```

## Discovery Operations

### client.discovery.discoverAgents()

```typescript
async discoverAgents(domain: string, identity?: DIDIdentity): Promise<AgentDescriptionItem[]>
```

Discovers agents from a domain using the ADSP protocol.

**Parameters:**
- `domain`: The domain to discover agents from
- `identity` (optional): DID identity for authenticated requests

**Returns:** Promise resolving to array of agent description items

**Example:**
```typescript
const agents = await client.discovery.discoverAgents('example.com', identity);
```

### client.discovery.registerWithSearchService()

```typescript
async registerWithSearchService(
  searchServiceUrl: string,
  agentDescriptionUrl: string,
  identity: DIDIdentity
): Promise<void>
```

Registers an agent with a search service.

**Parameters:**
- `searchServiceUrl`: URL of the search service
- `agentDescriptionUrl`: URL of the agent's description
- `identity`: DID identity for authentication

**Returns:** Promise resolving when registration is complete

**Example:**
```typescript
await client.discovery.registerWithSearchService(
  'https://search.example.com',
  'https://myagent.com/description.json',
  identity
);
```

### client.discovery.searchAgents()

```typescript
async searchAgents(
  searchServiceUrl: string,
  query: SearchQuery,
  identity?: DIDIdentity
): Promise<AgentDescriptionItem[]>
```

Searches for agents using a search service.

**Parameters:**
- `searchServiceUrl`: URL of the search service
- `query`: Search query parameters
- `identity` (optional): DID identity for authenticated requests

**Returns:** Promise resolving to array of matching agents

**Example:**
```typescript
const results = await client.discovery.searchAgents(
  'https://search.example.com',
  { keywords: 'translation', capabilities: ['text'] },
  identity
);
```

## Protocol Operations

### client.protocol.createNegotiationMachine()

```typescript
createNegotiationMachine(config: MetaProtocolConfig): MetaProtocolActor
```

Creates a meta-protocol negotiation state machine.

**Parameters:**
- `config.localIdentity`: Local DID identity
- `config.remoteDID`: Remote agent's DID
- `config.candidateProtocols`: Proposed protocols
- `config.maxNegotiationRounds`: Maximum negotiation rounds
- `config.onStateChange` (optional): State change callback

**Returns:** XState actor for the state machine

**Example:**
```typescript
const machine = client.protocol.createNegotiationMachine({
  localIdentity: identity,
  remoteDID: 'did:wba:other.com:agent',
  candidateProtocols: 'JSON-RPC 2.0',
  maxNegotiationRounds: 5,
  onStateChange: (state) => console.log(state.value)
});
```

### client.protocol.sendMessage()

```typescript
async sendMessage(remoteDID: string, message: any, identity: DIDIdentity): Promise<void>
```

Sends a protocol message to a remote agent.

**Parameters:**
- `remoteDID`: Remote agent's DID
- `message`: Message to send
- `identity`: Local DID identity

**Returns:** Promise resolving when message is sent

**Example:**
```typescript
await client.protocol.sendMessage(
  'did:wba:other.com:agent',
  { action: 'protocolNegotiation', candidateProtocols: 'HTTP' },
  identity
);
```

### client.protocol.receiveMessage()

```typescript
receiveMessage(encryptedMessage: Uint8Array, actor: MetaProtocolActor): void
```

Processes a received protocol message.

**Parameters:**
- `encryptedMessage`: The received message bytes
- `actor`: The state machine actor to process the message

**Example:**
```typescript
client.protocol.receiveMessage(messageBytes, machine);
```

## HTTP Operations

### client.http.request()

```typescript
async request(
  url: string,
  options: RequestOptions,
  identity?: DIDIdentity
): Promise<Response>
```

Makes an HTTP request with optional DID authentication.

**Parameters:**
- `url`: Request URL
- `options`: Request options (method, headers, body)
- `identity` (optional): DID identity for authentication

**Returns:** Promise resolving to Response

**Example:**
```typescript
const response = await client.http.request(
  'https://example.com/api',
  { method: 'POST', body: JSON.stringify(data) },
  identity
);
```

### client.http.get()

```typescript
async get(url: string, identity?: DIDIdentity): Promise<Response>
```

Makes a GET request.

**Parameters:**
- `url`: Request URL
- `identity` (optional): DID identity for authentication

**Returns:** Promise resolving to Response

**Example:**
```typescript
const response = await client.http.get('https://example.com/api', identity);
const data = await response.json();
```

### client.http.post()

```typescript
async post(url: string, body: any, identity?: DIDIdentity): Promise<Response>
```

Makes a POST request.

**Parameters:**
- `url`: Request URL
- `body`: Request body
- `identity` (optional): DID identity for authentication

**Returns:** Promise resolving to Response

**Example:**
```typescript
const response = await client.http.post(
  'https://example.com/api',
  { data: 'value' },
  identity
);
```

## Type Definitions

### DIDIdentity

```typescript
interface DIDIdentity {
  did: string;
  document: DIDDocument;
  privateKeys: Map<string, CryptoKey>;
}
```

### DIDDocument

```typescript
interface DIDDocument {
  '@context': string[];
  id: string;
  verificationMethod: VerificationMethod[];
  authentication: (string | VerificationMethod)[];
  keyAgreement?: VerificationMethod[];
  humanAuthorization?: (string | VerificationMethod)[];
  service?: ServiceEndpoint[];
}
```

### AgentDescription

```typescript
interface AgentDescription {
  protocolType: 'ANP';
  protocolVersion: string;
  type: 'AgentDescription';
  url?: string;
  name: string;
  did?: string;
  owner?: Organization;
  description?: string;
  created?: string;
  securityDefinitions: Record<string, SecurityScheme>;
  security: string;
  Infomations?: Information[];
  interfaces?: Interface[];
  proof?: Proof;
}
```

### Signature

```typescript
interface Signature {
  verificationMethodId: string;
  signature: Uint8Array;
}
```

## Error Types

See [Error Handling](./errors.md) for detailed error documentation.
