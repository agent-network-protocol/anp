# Configuration Guide

This SDK no longer uses a single `ANPClient` configuration object. Configuration is passed directly to the specific function or class that needs it.

## DID document creation

Use `DidDocumentOptions` with `createDidDocument()` or `authentication.didDocuments.create()`.

Key fields:

- `port?`
- `pathSegments?`
- `agentDescriptionUrl?`
- `services?`
- `proofPurpose?`
- `verificationMethod?`
- `domain?`
- `challenge?`
- `created?`
- `enableE2ee?`
- `didProfile?`

## DID resolution

Use `DidResolutionOptions` with `resolveDidDocument()`.

```ts
const document = await resolveDidDocument('did:wba:example.com:agents:demo', true, {
  timeoutSeconds: 5,
  baseUrlOverride: 'http://127.0.0.1:8080',
});
```

## HTTP Message Signatures

Use `HttpSignatureOptions` with `createSignatureHeaders()`.

```ts
const headers = createSignatureHeaders(document, url, 'POST', privateKeyPem, {}, body, {
  created: Math.floor(Date.now() / 1000),
  expires: Math.floor(Date.now() / 1000) + 300,
});
```

## Request verifier

Use `DidWbaVerifierConfig` when constructing `DidWbaVerifier`.

```ts
const verifier = new DidWbaVerifier({
  jwtPrivateKey: 'secret',
  jwtPublicKey: 'secret',
  jwtAlgorithm: 'HS256',
  accessTokenExpireMinutes: 60,
  nonceExpirationMinutes: 6,
  timestampExpirationMinutes: 5,
  allowHttpSignatures: true,
  allowLegacyDidwba: true,
  didResolver: async (did) => localDidDocuments.get(did),
});
```

When `didResolver` is present, `verifyRequest()` uses it to load the client DID
document. This is useful for servers that keep partner DID documents in a local
registry or for offline interoperability examples.

## WNS resolution

Use `ResolveHandleOptions` with `resolveHandle()`.

```ts
const result = await resolveHandle('alice.example.com', {
  baseUrlOverride: 'http://127.0.0.1:8080',
  timeoutSeconds: 5,
});
```

## WNS binding verification

Use `BindingVerificationOptions` with `verifyBinding()`.

```ts
const result = await verifyBinding('alice.example.com', {
  didDocument,
  resolutionOptions: { baseUrlOverride: 'http://127.0.0.1:8080' },
});
```

## AWiki IM client

Use `AwikiImClientOptions` with `createAwikiImClient()`.

```ts
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
```

- `userServiceUrl` is the AWiki handle and DID-auth service origin.
- `userServiceDomain` is the handle and identity domain administered by that User Service. It does not need to equal the API origin host.
- `messageServiceUrl` is the internal or external base used by this SDK to call the Home Message Service.
- `messageServicePublicUrl` is the public base advertised as the identity's `ANPMessageService.serviceEndpoint`; the SDK appends `/anp-im/rpc`.
- `messageServiceDid` is the authoritative Home Service DID and must have the bare-domain form `did:wba:domain`.
- `allowedAttachmentOrigins` contains exact trusted HTTPS origins for sender DID documents, advertised attachment services, upload slots, and object downloads. Cross-Home messaging requires the remote DID and object origins to be listed explicitly.
- `attachmentMaxBytes` is a positive safe integer applied to both uploads and streamed downloads.
- `allowInsecureLoopbackForTesting` permits HTTP only for `localhost`, `127.0.0.1`, or `[::1]` in controlled tests. It defaults to `false`.
- `statePath` is the local identity state file. The SDK creates parent directories with mode `0700` when needed and writes the file with mode `0600`.
- `fetch` optionally supplies a compatible Fetch implementation.

Use HTTPS URLs in production. Keep `statePath` stable across restarts. It is plaintext JSON protected by mode `0600`, not at-rest encryption: the same OS account and backup readers can recover private keys and access tokens. Use disk encryption and encrypted, access-controlled backups; credential-vault integration is deferred. Changing `userServiceDomain` or `messageServiceDid` while reusing an existing state file fails with a conflict instead of silently reusing the identity under a different deployment.

The first version owns one Legacy single-device identity. It does not expose configuration for Manifest registration, multiple devices, end-to-end encryption, real-time subscriptions, or group creation.
