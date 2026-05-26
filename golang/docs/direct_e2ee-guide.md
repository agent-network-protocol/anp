# Direct E2EE Developer Guide

## Overview

`direct_e2ee` implements the ANP direct end-to-end encryption profile used by `anp.direct.e2ee.v1`.

For the cross-repo SDK/product boundary map, see [`../../docs/e2e/direct-e2ee-p5-sdk.md`](../../docs/e2e/direct-e2ee-p5-sdk.md) and the harness entry [`../../../../awiki-harness/features/direct-e2ee.md`](../../../../awiki-harness/features/direct-e2ee.md).

The current Go implementation provides:

- signed prekey publication helpers
- X3DH-style initial shared-secret derivation
- symmetric chain-step derivation for follow-up messages
- authenticated encryption with ChaCha20-Poly1305
- file-backed stores for session and prekey state
- a reference message-service client for end-to-end flows
- Rust/Python interoperability tests for fixture exchange and decryption validation

## Security and Compatibility Constraints

- Pure Go only
- No cgo
- Go 1.22+
- Uses pure-Go cryptographic dependencies only

## Core Data Model

### Prekey layer

- `SignedPrekey`
- `PrekeyBundle`

A prekey bundle contains:

- owner DID
- static key agreement verification method id
- signed prekey metadata
- W3C proof signed by the DID authentication key

### Session layer

- `DirectSessionState`
- `PendingOutboundRecord`

A session stores:

- peer DID
- local and peer key-agreement ids
- root key
- send/receive chain keys
- ratchet public key
- message counters

### Message layer

- `DirectEnvelopeMetadata`
- `DirectInitBody`
- `DirectCipherBody`
- `ApplicationPlaintext`

## End-to-End Flow

### 1. Recipient publishes a prekey bundle

Typical flow:

1. Generate a signed prekey with `PrekeyManager.GenerateSignedPrekey`
2. Build a bundle with `PrekeyManager.BuildPrekeyBundle`
3. Publish it through the RPC boundary with `PrekeyManager.PublishPrekeyBundle`

### 2. Sender starts a session

1. Fetch recipient bundle
2. Verify bundle against recipient DID document
3. Call `DirectE2eeSession.InitiateSession`
4. Send `application/anp-direct-init+json`

### 3. Recipient accepts init

1. Load local static X25519 key
2. Load referenced signed prekey private key
3. Call `DirectE2eeSession.AcceptIncomingInit`
4. Persist returned `DirectSessionState`

### 4. Sender sends follow-up ciphertext

1. Load session by peer DID or session id
2. Call `DirectE2eeSession.EncryptFollowUp`
3. Send `application/anp-direct-cipher+json`

### 5. Recipient decrypts follow-up ciphertext

1. Load session by session id
2. Call `DirectE2eeSession.DecryptFollowUp`
3. Persist updated session state

## Recommended Store Layout

The file-backed stores are reference implementations.

- `FileSignedPrekeyStore`
- `FileSessionStore`
- `FilePendingOutboundStore`

For production deployments, replacing them with database-backed implementations is recommended.

## Reference Client Usage

`MessageServiceDirectE2eeClient` is a convenience client that wires together:

- bundle retrieval
- bundle verification
- init-message creation
- follow-up encryption
- inbound processing
- pending message replay after init arrives

Use it when you already have:

- an RPC transport function
- a DID resolver
- persistent session/prekey stores

## Interoperability Coverage

Current integration tests validate:

- Rust fixture -> Go decrypts
- Python fixture -> Go decrypts
- Go fixture -> Python decrypts
- Go fixture -> Rust decrypts

Additional failure-path interoperability tests cover:

- tampered ciphertext rejection
- replay rejection
- skip-window overflow rejection

## Failure Modes

Expect errors in these situations:

- unsupported suite id
- missing verification method
- invalid base64url encoded key material
- modified ciphertext or AAD mismatch
- duplicate message number replay
- skip distance beyond `MaxSkip`

## Example

See:

- `examples/direct_e2ee/main.go`

That example demonstrates:

- DID creation for both peers
- prekey bundle creation
- init encryption/decryption
- follow-up encryption/decryption

## Validation Commands

Run the full Go SDK validation:

```bash
go test ./...
```

Run only interoperability tests:

```bash
go test ./integration
```

These integration tests require local tool availability:

- `cargo`
- `uv`
