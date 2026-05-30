# anp

Rust SDK for the Agent Network Protocol (ANP).

This crate provides the core Rust implementation for DID WBA authentication,
proof generation and verification, strict Appendix-B object proof helpers, and WNS helpers used by ANP-compatible
agents and services.

## Installation

```bash
cargo add anp
```

## Features

- DID WBA document creation and verification
- HTTP authentication helpers
- Proof generation and verification
- Appendix-B object proof helpers for `group_receipt`, `prekey_bundle`, and `did_wba_binding`
- RFC 9421 origin proof helpers for ANP request objects
- WNS models, validation, and resolver helpers
- `anp::group_e2ee::operations` one-shot group E2EE APIs for ANP-P6 real OpenMLS
  KeyPackage generation, group create/add/remove prepare, local leave terminal-state
  handling, commit notice processing, pending commit finalize/abort, welcome processing,
  message encrypt/decrypt, and local status operations. MLS state is kept behind
  `anp::group_e2ee::storage` store implementations rather than a subprocess or CLI JSON
  command surface.

## Compatibility Notes

- `create_did_wba_document_with_key_binding` is deprecated. Use `create_did_wba_document` with `DidDocumentOptions::with_profile(DidProfile::K1)` when you need a `k1_` DID.
- Group MLS operations are library calls, not `anp-mls` subprocess calls. Use
  `CompatDataDirStore` for the legacy `state.db` layout or `ImCoreSqliteGroupMlsStore`
  for owner/device-scoped MLS state managed from an im-core local-state root.
- MLS private material, KeyPackage state, group bindings, pending commits, and OpenMLS
  persistence stay local to the selected `GroupMlsStore` and are not emitted to
  service-facing P6 payloads.
- Message encrypt/decrypt rejects incoming group-state or cipher claims whose
  `crypto_group_id_b64u`/`openmls_group_id_b64u` or epoch does not match the local
  SQLite group binding before invoking OpenMLS.
- Decrypted plaintext is returned only as the typed `DecryptOutput` for the active library
  call; callers must not persist plaintext in diagnostics or operation logs.
- `remove_member_prepare` creates a durable OpenMLS pending commit and returns opaque
  commit, ratchet-tree/group-info-compatible public artifacts, from/to epochs, and
  `pending_commit_id`; local epoch remains unchanged until `finalize_commit`, while
  `abort_commit` clears the pending commit after deterministic service rejection.
- `leave_prepare` records a local terminal pending artifact because OpenMLS 0.8 rejects
  same-member self-remove commits; finalizing it marks the local binding `left` without
  advancing the local epoch. PR-B1 service/CLI integrations should use the hidden
  `group.e2ee.leave_request` control plane and process it through an authorized
  epoch-advancing remove commit for remaining members.

## Message Payload Notes

Plain text, ordinary JSON, and attachments use the same ANP message operations
defined by the protocol profiles. This crate does not add separate REST APIs or
high-level base-message senders for JSON. If a product constructs `direct.send` or
`group.send` requests for `text/plain` at the application layer, it should construct
ordinary JSON messages at the same layer by setting `meta.content_type` to
`application/json` and placing the JSON object directly in `body.payload`.

For Direct E2EE, use the existing plaintext model:

```rust
use anp::direct_e2ee::ApplicationPlaintext;
use serde_json::json;

let plaintext = ApplicationPlaintext::new_json(
    "application/json",
    json!({"type": "example", "data": {"hello": "world"}}),
);
```

The SDK treats the JSON object as an opaque application payload; command, status,
task, result, or other business meanings are defined by the caller above the ANP
SDK layer.

## Repository

- Source: <https://github.com/agent-network-protocol/AgentConnect>
- Protocol: <https://github.com/agent-network-protocol/AgentNetworkProtocol>
