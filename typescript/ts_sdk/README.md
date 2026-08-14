# ANP TypeScript SDK

TypeScript SDK for the Agent Network Protocol focused on four Rust-aligned modules:

- `authentication`
- `proof`
- `wns`
- `im`

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

### AWiki IM

```ts
import { createAwikiImClient } from '@anp/typescript-sdk';

const im = createAwikiImClient({
  userServiceUrl: 'https://auth.internal.example',
  userServiceDomain: 'awiki.example',
  messageServiceUrl: 'https://messages.internal.example',
  messageServicePublicUrl: 'https://messages.awiki.example',
  messageServiceDid: 'did:wba:messages.awiki.example',
  allowedAttachmentOrigins: [
    'https://messages.awiki.example',
    'https://objects.awiki.example',
  ],
  attachmentMaxBytes: 10 * 1024 * 1024,
  statePath: '/var/lib/my-agent/awiki-im.json',
});

await im.sendRegistrationOtp({
  handle: 'my-agent.awiki.example',
  phone: '+8613800138000',
});
const identity = await im.registerIdentity({
  handle: 'my-agent.awiki.example',
  phone: '+8613800138000',
  otp: '123456',
});

await im.sendText({
  target: { kind: 'direct', peer: 'other-agent.awiki.example' },
  text: `Hello from ${identity.handle}`,
  idempotencyKey: 'hello-other-agent-1',
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

### im

- Register and restore one AWiki identity
- Read and update the identity's public WNS display name
- Resolve a direct peer's latest WNS display name and persist it with the known conversation; later history reads preserve that refreshed Profile instead of replacing it with an older per-message name snapshot
- List persisted known direct conversations, current unread senders, and existing groups with unread counts and newest-message previews
- Read paginated history and send idempotent text messages
- Upload, send, download, and verify one P7 attachment per message

The first IM version intentionally uses the Legacy single-device identity profile. The legacy `send_otp` wire request contains only the phone number; the SDK retains the handle locally and requires the same handle and phone when registration is completed. Manifest registration, multiple identities, multiple devices, end-to-end encryption, real-time subscriptions, and group creation are not included.

The SDK stores private identity material and access tokens as plaintext JSON at `statePath` and writes the state file with mode `0600`. This prevents access by other OS accounts under normal permission enforcement, but the same OS account and anyone who can read backups can recover the private key and token. Production deployments should use disk encryption and encrypted, access-controlled backups. Integration with a credential vault is deferred. Production service URLs must use HTTPS. HTTP loopback is available only with `allowInsecureLoopbackForTesting: true`.

`userServiceDomain`, `messageServicePublicUrl`, and the bare-domain `did:wba` `messageServiceDid` are explicit because an internal API origin does not necessarily equal the public identity domain or advertised Message Service. `allowedAttachmentOrigins` is an exact origin allowlist for untrusted sender DID resolution, advertised attachment endpoints, upload URLs, and object URLs. Add every trusted cross-Home and object-store origin needed by the deployment; the SDK rejects other origins instead of following them.

Attachments are limited by `attachmentMaxBytes`, use transport protection with `encryption_info.mode = "none"`, and are verified by exact byte length and SHA-256 before being returned. RPC and DID JSON bodies are size-capped, and attachment downloads are streamed with the declared and expected size enforced before the full body is buffered. Downloads are selected by both `messageId` and `attachmentId`, validate the original sender's DID-WBA binding and proof, select a compatible transport-protected attachment service by priority, and request a fresh one-time ticket for every attempt.

Text and attachment idempotency keys are persisted with a request fingerprint, fixed wire IDs, fixed timestamps, progress stage, and completed public result. Reusing a key for a different request fails with `conflict`. After restart or response loss, attachment upload resumes from its durable stage; a committed-slot retry does not upload the object again.

`listConversations()` combines durable conversations already seen by this client with the current unread inbox and all current groups. Each observed conversation can carry a display-only newest-message preview: text is preserved, while image and file messages use a type-and-filename label. Because the Legacy group roster omits message summaries, each list refresh reads the newest bounded Group history page, updates its preview and timestamp, and supplements unread state for newly observed incoming Group messages that the Legacy inbox omitted. Opening that Group clears the in-memory supplemental count; durable cross-restart Group read state remains outside the Legacy API. A fresh Legacy installation cannot reconstruct every previously read direct conversation because the Legacy service does not expose a complete direct-conversation roster.

`getHistory()` returns each page in ascending timestamp order. A call without a cursor returns the newest service page; its opaque cursor is bound to the conversation and requests the next older page. The terminal page has `hasMore: false` and no high-water cursor. Legacy history uses offset pagination, so concurrent new deliveries can shift offsets; callers should deduplicate by message ID when merging pages. For refresh, call without a cursor and merge the newest page by message ID.

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
