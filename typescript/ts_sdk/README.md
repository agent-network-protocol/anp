# ANP TypeScript SDK

TypeScript SDK for the Agent Network Protocol focused on the three Rust-aligned modules:

- `authentication`
- `proof`
- `wns`

Runtime target: **Node 20+**

## Installation

```bash
npm install @anp/typescript-sdk
```

## Quick Start

```ts
import {
  DidProfile,
  createDidDocument,
  createLegacyAuthHeader,
  createSignatureHeaders,
  verifyBinding,
} from '@anp/typescript-sdk';

const bundle = createDidDocument('example.com', {
  pathSegments: ['agents', 'demo'],
  didProfile: DidProfile.K1,
});

const legacyHeader = createLegacyAuthHeader(
  bundle.didDocument,
  'api.example.com',
  bundle.keys['key-1'].privateKeyPem
);

const signatureHeaders = createSignatureHeaders(
  bundle.didDocument,
  'https://api.example.com/orders',
  'POST',
  bundle.keys['key-1'].privateKeyPem,
  {},
  '{"item":"book"}'
);

const binding = await verifyBinding('alice.example.com', {
  didDocument: {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: 'did:wba:example.com:user:alice',
    verificationMethod: [],
    authentication: [],
    service: [
      {
        id: 'did:wba:example.com:user:alice#handle',
        type: 'ANPHandleService',
        serviceEndpoint: 'https://example.com/providers/wns',
      },
    ],
  },
});
```

## Stable Public Naming

Recommended stable aliases:

- `createDidDocument()`
- `createLegacyAuthHeader()`
- `createSignatureHeaders()`
- `createProof()`
- `verifyProof()`
- `verifyBinding()`

Recommended stable namespace objects:

- `authentication`
- `proof`
- `wns`

Low-level Rust-aligned names are still exported for compatibility.

## Public Modules

### authentication

- Create DID-WBA documents for `e1`, `k1`, and `plain_legacy`
- Resolve DID documents
- Generate and verify legacy `DIDWba` authorization headers
- Generate and verify HTTP Message Signatures
- Verify requests with `DidWbaVerifier`

### proof

- Generate W3C Data Integrity / legacy secp256k1 proofs
- Verify proofs with domain / challenge / purpose constraints

### wns

- Validate handles and `wba://` URIs
- Resolve handles through `/.well-known/handle/{local-part}`
- Verify forward and reverse handle binding

## Development

```bash
npm install
npm run typecheck
npm test
npm run build
```

## Examples

```bash
node examples/authentication.mjs
node examples/proof.mjs
node examples/wns.mjs
```

## Validation

The current test suite includes:

- TypeScript unit tests
- Rust-generated interoperability fixtures for DID documents and proofs

## License

MIT
