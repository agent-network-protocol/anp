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

### AWiki IM

| Export | Description |
|---|---|
| `createAwikiImClient(options)` | Create one persistent high-level AWiki IM client |
| `AwikiImError` | Stable, sanitized failure type with `code` and optional HTTP `status` |

`createAwikiImClient()` is synchronous. Methods that load state or use the network are asynchronous.

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
- `didResolver?`
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

### `AwikiImClientOptions`

```ts
interface AwikiImClientOptions {
  userServiceUrl: string;
  userServiceDomain: string;
  messageServiceUrl: string;
  messageServicePublicUrl: string;
  messageServiceDid: string;
  allowedAttachmentOrigins: readonly string[];
  attachmentMaxBytes: number;
  allowInsecureLoopbackForTesting?: boolean;
  statePath: string;
  fetch?: typeof globalThis.fetch;
}
```

Service URLs must use HTTPS. Explicit test environments can set `allowInsecureLoopbackForTesting` to use HTTP loopback URLs. `userServiceDomain` is the handle domain and is independent of the User Service API host. `messageServiceUrl` is the callable Home API base, while `messageServicePublicUrl` is the base advertised in the identity DID document. `messageServiceDid` must be a bare-domain `did:wba` value such as `did:wba:messages.example`. `allowedAttachmentOrigins` is an exact origin allowlist for every trusted sender DID, attachment endpoint, upload, and object origin. `attachmentMaxBytes` is a positive safe integer enforced for uploads and streamed downloads. `fetch` is an optional dependency-injection point for tests and controlled runtimes.

## Main classes

### `DidWbaVerifier`

Primary methods:

- `verifyRequest(method, url, headers, body?, domain?)`
- `verifyRequestWithDidDocument(method, url, headers, didDocument, body?, domain?)`

`didResolver` can be supplied in the constructor config to resolve DID documents from
local storage, tests, or an application registry before falling back to network DID
resolution.

### `DidAuthHeaders`

Alias of `DIDWbaAuthHeader`.

Primary methods:

- `getAuthHeaders(serverUrl, forceNew?, method?, headers?, body?)`
- `updateToken(serverUrl, headers)`
- `clearToken(serverUrl)`
- `clearAllTokens()`

### `AwikiImClient`

Primary methods:

- `getIdentity()`
- `sendRegistrationOtp({ handle, phone })`
- `registerIdentity({ handle, phone, otp })`
- `listConversations({ cursor?, limit? })`
- `getHistory({ conversationId, cursor?, limit? })`
- `sendText({ target, text, idempotencyKey })`
- `sendAttachment({ target, attachment, caption?, idempotencyKey })`
- `downloadAttachment({ attachmentId, messageId })`
- `dispose()`

The client owns one Legacy single-device identity at `statePath`. Public identity values never contain the private key or access token. The identity document is created with E2EE disabled and does not advertise unused E2EE key agreement material. The legacy OTP request sends only `phone` to AWiki; `handle` is retained locally to bind the challenge to registration.

`dispose()` rejects new operations, aborts owned network requests, joins every operation that already entered the client, and is idempotent. Its promise does not settle while an entered registration, state mutation, message send, or attachment operation is still unwinding.

Direct targets accept a handle or DID. Group targets refer to an existing group ID or DID; this API does not create groups. Text and attachment sends require caller-provided idempotency keys. One attachment up to the configured `attachmentMaxBytes` is supported per message. Downloads require both IDs because an attachment ID is not globally unique across messages, and returned bytes have passed exact size and SHA-256 verification. Idempotency request fingerprints, fixed wire metadata, progress stages, and completed results survive restart; using one key for a different request fails with `conflict`.

`listConversations()` returns persisted known direct conversations plus senders present in the current unread inbox and current groups. A fresh Legacy client cannot recover every previously read direct conversation because there is no authoritative Legacy direct roster.

`getHistory()` returns messages in ascending time order within each page. No cursor means the newest page; `nextCursor` is opaque, bound to the conversation and direction, and requests an older page using the Legacy offset field. The final page has no cursor. New deliveries can shift offset pages, so clients merge and deduplicate by message ID. Calling without a cursor again refreshes the newest page; the history cursor is not an incremental high-water mark.

## Compatibility note

Low-level Rust-aligned names are still exported, for example:

- `createDidWbaDocument()`
- `resolveDidWbaDocument()`
- `generateAuthHeader()`
- `generateHttpSignatureHeaders()`
- `generateW3cProof()`
- `verifyHandleBinding()`

The shorter aliases and namespace objects are the recommended long-term public surface.
