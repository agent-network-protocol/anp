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
- `anp-mls` one-shot group E2EE helper for ANP-P6 real OpenMLS key-package, group create/add,
  welcome processing, message encrypt/decrypt, and local status operations backed by a
  `state.db` SQLite store plus `state.lock` mutation lock. Contract-test artifacts remain
  available only when explicitly enabled by request or `ANP_MLS_CONTRACT_TEST=1`. Packaging
  and doctor integrations can probe compatibility with `anp-mls system version --json-in -`.

## Compatibility Notes

- `create_did_wba_document_with_key_binding` is deprecated. Use `create_did_wba_document` with `DidDocumentOptions::with_profile(DidProfile::K1)` when you need a `k1_` DID.
- Real `anp-mls` mode requires `--data-dir DIR`; MLS private material, KeyPackage state,
  group bindings, operation idempotency records, and OpenMLS persistence are local to
  `DIR/state.db` and are not emitted to service-facing P6 payloads.
- `anp-mls system version --json-in -` does not require `--data-dir`; it returns
  `api_version`, `binary_name`, `binary_version`/`build_version`, and `supported_commands`.
- Message encrypt/decrypt rejects incoming group-state or cipher claims whose
  `crypto_group_id_b64u`/`openmls_group_id_b64u` or epoch does not match the local
  SQLite group binding before invoking OpenMLS.
- Decrypted plaintext is returned to stdout for the active request only and is redacted from
  the local operation idempotency table.

## Repository

- Source: <https://github.com/agent-network-protocol/AgentConnect>
- Protocol: <https://github.com/agent-network-protocol/AgentNetworkProtocol>
