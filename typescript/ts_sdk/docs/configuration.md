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
});
```

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
