# API Reference Draft

This draft documents the stable public API for the current TypeScript SDK.

## Top-level stable exports

### Authentication aliases

| Export | Description |
|---|---|
| `createDidDocument()` | Create a DID-WBA document bundle |
| `createDidDocumentWithKeyBinding()` | Create a key-bound DID-WBA document bundle |
| `resolveDidDocument()` | Resolve a DID-WBA document over HTTP |
| `validateDidBinding()` | Validate DID binding, optionally including proof verification |
| `verifyDidBinding()` | Verify a single verification method against a DID suffix binding |
| `createLegacyAuthHeader()` | Create a legacy `DIDWba` Authorization header |
| `createLegacyAuthPayload()` | Create the JSON payload form of legacy DID authentication |
| `parseLegacyAuthHeader()` | Parse a legacy `DIDWba` header |
| `verifyLegacyAuthHeader()` | Verify a legacy `DIDWba` header against a DID document |
| `verifyLegacyAuthPayload()` | Verify the JSON payload form of legacy DID authentication |
| `createSignatureHeaders()` | Create HTTP Message Signature headers |
| `parseSignatureMetadata()` | Parse `Signature-Input` / `Signature` metadata |
| `verifySignatureHeaders()` | Verify HTTP Message Signatures |

### Proof aliases

| Export | Description |
|---|---|
| `createProof()` | Create a W3C proof document |
| `verifyProof()` | Verify a W3C proof |
| `verifyProofDetailed()` | Verify a W3C proof and throw detailed errors |

### WNS aliases

| Export | Description |
|---|---|
| `validateLocalPart()` | Validate a WNS local-part |
| `validateHandle()` | Validate and normalize a handle |
| `normalizeHandle()` | Normalize a handle to lowercase |
| `parseUri()` | Parse a `wba://` URI |
| `buildResolutionUrl()` | Build a `/.well-known/handle/{local-part}` URL |
| `buildUri()` | Build a `wba://` URI |
| `resolveHandle()` | Resolve a handle |
| `resolveUri()` | Resolve a `wba://` URI |
| `verifyBinding()` | Verify forward and reverse handle binding |
| `createHandleServiceEntry()` | Create a DID `ANPHandleService` entry |
| `extractHandleServices()` | Extract `ANPHandleService` entries from a DID document |

## Namespace objects

These namespace objects are recommended when you want a more stable import shape.

### `authentication`

```ts
authentication.didDocuments.create()
authentication.didDocuments.createWithKeyBinding()
authentication.didDocuments.resolve()
authentication.didDocuments.validateBinding()
authentication.didDocuments.verifyKeyBinding()

authentication.legacyAuth.createHeader()
authentication.legacyAuth.createPayload()
authentication.legacyAuth.parseHeader()
authentication.legacyAuth.verifyHeader()
authentication.legacyAuth.verifyPayload()

authentication.httpSignatures.buildContentDigest()
authentication.httpSignatures.verifyContentDigest()
authentication.httpSignatures.createHeaders()
authentication.httpSignatures.verifyMessage()
authentication.httpSignatures.parseMetadata()
```

### `proof`

```ts
proof.create()
proof.verify()
proof.verifyDetailed()
```

### `wns`

```ts
wns.validateLocalPart()
wns.validateHandle()
wns.normalizeHandle()
wns.parseUri()
wns.buildResolutionUrl()
wns.buildUri()
wns.resolveHandle()
wns.resolveUri()
wns.verifyBinding()
wns.createHandleServiceEntry()
wns.extractHandleServices()
```

## Main types

### `DidDocumentOptions`

```ts
interface DidDocumentOptions {
  port?: number;
  pathSegments?: string[];
  agentDescriptionUrl?: string;
  services?: Record<string, unknown>[];
  proofPurpose?: string;
  verificationMethod?: string;
  domain?: string;
  challenge?: string;
  created?: string;
  enableE2ee?: boolean;
  didProfile?: DidProfile;
}
```

### `DidResolutionOptions`

```ts
interface DidResolutionOptions {
  timeoutSeconds?: number;
  verifySsl?: boolean;
  baseUrlOverride?: string;
  headers?: Record<string, string>;
}
```

### `HttpSignatureOptions`

```ts
interface HttpSignatureOptions {
  keyid?: string;
  nonce?: string;
  created?: number;
  expires?: number;
  coveredComponents?: string[];
}
```

### `DidWbaVerifierConfig`

Key fields:

- `jwtPrivateKey?`
- `jwtPublicKey?`
- `jwtAlgorithm?`
- `accessTokenExpireMinutes?`
- `nonceExpirationMinutes?`
- `timestampExpirationMinutes?`
- `allowedDomains?`
- `allowHttpSignatures?`
- `allowLegacyDidwba?`
- `emitAuthenticationInfoHeader?`
- `emitLegacyAuthorizationHeader?`
- `requireNonceForHttpSignatures?`
- `didResolutionOptions?`
- `externalNonceValidator?`

### `ResolveHandleOptions`

```ts
interface ResolveHandleOptions {
  timeoutSeconds?: number;
  verifySsl?: boolean;
  baseUrlOverride?: string;
}
```

### `BindingVerificationOptions`

```ts
interface BindingVerificationOptions {
  didDocument?: DidDocument;
  resolutionOptions?: ResolveHandleOptions;
  didResolutionOptions?: DidResolutionOptions;
}
```

## Main classes

### `DidWbaVerifier`

Primary methods:

- `verifyRequest(method, url, headers, body?, domain?)`
- `verifyRequestWithDidDocument(method, url, headers, didDocument, body?, domain?)`

### `DidAuthHeaders`

Alias of `DIDWbaAuthHeader`.

Primary methods:

- `getAuthHeaders(serverUrl, forceNew?, method?, headers?, body?)`
- `updateToken(serverUrl, headers)`
- `clearToken(serverUrl)`
- `clearAllTokens()`

## Compatibility note

Low-level Rust-aligned names are still exported, for example:

- `createDidWbaDocument()`
- `resolveDidWbaDocument()`
- `generateAuthHeader()`
- `generateHttpSignatureHeaders()`
- `generateW3cProof()`
- `verifyHandleBinding()`

The shorter aliases and namespace objects are the recommended long-term public surface.
