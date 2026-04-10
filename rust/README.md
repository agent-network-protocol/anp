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

## Compatibility Notes

- `create_did_wba_document_with_key_binding` is deprecated. Use `create_did_wba_document` with `DidDocumentOptions::with_profile(DidProfile::K1)` when you need a `k1_` DID.

## Repository

- Source: <https://github.com/agent-network-protocol/AgentConnect>
- Protocol: <https://github.com/agent-network-protocol/AgentNetworkProtocol>
