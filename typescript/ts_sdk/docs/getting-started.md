# Getting Started with the ANP TypeScript SDK

This SDK now focuses on three stable modules:

- `authentication`
- `proof`
- `wns`

Runtime target: **Node 20+**

## Installation

```bash
npm install @anp/typescript-sdk
```

## Stable Public API

The recommended public API uses short, stable aliases and namespace objects:

```ts
import {
  authentication,
  createDidDocument,
  createLegacyAuthHeader,
  createProof,
  verifyProof,
  verifyBinding,
  wns,
} from '@anp/typescript-sdk';
```

You can choose either style:

- flat aliases such as `createDidDocument()`
- grouped namespaces such as `authentication.didDocuments.create()` or `wns.parseUri()`

## 1. Create a DID document

```ts
import { DidProfile, createDidDocument } from '@anp/typescript-sdk';

const bundle = createDidDocument('example.com', {
  pathSegments: ['agents', 'demo'],
  didProfile: DidProfile.K1,
});

console.log(bundle.didDocument.id);
console.log(bundle.keys['key-1'].privateKeyPem);
```

## 2. Create authentication headers

### Legacy DIDWba header

```ts
import { createLegacyAuthHeader } from '@anp/typescript-sdk';

const header = createLegacyAuthHeader(
  bundle.didDocument,
  'api.example.com',
  bundle.keys['key-1'].privateKeyPem
);
```

### HTTP Message Signatures

```ts
import { createSignatureHeaders } from '@anp/typescript-sdk';

const headers = createSignatureHeaders(
  bundle.didDocument,
  'https://api.example.com/orders',
  'POST',
  bundle.keys['key-1'].privateKeyPem,
  {},
  JSON.stringify({ item: 'book' })
);
```

## 3. Verify incoming requests

```ts
import { DidWbaVerifier } from '@anp/typescript-sdk';

const verifier = new DidWbaVerifier({
  jwtPrivateKey: 'demo-secret',
  jwtPublicKey: 'demo-secret',
  jwtAlgorithm: 'HS256',
});

const result = await verifier.verifyRequestWithDidDocument(
  'GET',
  'https://api.example.com/orders',
  { Authorization: header },
  bundle.didDocument
);
```

## 4. Create and verify proofs

```ts
import { createProof, verifyProof } from '@anp/typescript-sdk';

const signedDocument = createProof(
  {
    id: 'did:wba:example.com:credential:alice',
    type: 'VerifiableCredential',
  },
  bundle.keys['key-1'].privateKeyPem,
  `${bundle.didDocument.id}#key-1`
);

const valid = verifyProof(signedDocument, bundle.keys['key-1'].publicKeyPem);
```

## 5. Work with WNS handles

```ts
import { parseUri, validateHandle, verifyBinding } from '@anp/typescript-sdk';

const [localPart, domain] = validateHandle('Alice.Example.COM');
const parsed = parseUri('wba://alice.example.com');

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

## Examples

Build the SDK first, then run:

```bash
npm run build
node examples/authentication.mjs
node examples/proof.mjs
node examples/wns.mjs
```

## Next Steps

- Read the [API Reference](./api-reference.md)
- Review [Configuration](./configuration.md)
- Review [Error Handling](./errors.md)
