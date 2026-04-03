# ANP Go SDK Release Notes

## Current Snapshot

This Go SDK snapshot delivers the first production-oriented pure-Go implementation of the ANP core SDK surface.

### Included

- DID WBA document generation and verification helpers
- legacy DIDWba request authentication
- HTTP Message Signatures helpers
- DID resolution for `did:wba` and `did:web`
- W3C Data Integrity proof helpers
- WNS validation, resolution, and binding checks
- direct E2EE primitives and reference client helpers
- Go unit tests for authentication, proof, WNS, and direct E2EE
- Rust/Python interoperability tests for request authentication flows
- Rust/Python interoperability tests for direct E2EE fixture decryption flows
- Direct E2EE failure-path interoperability checks for tampering, replay, and skip overflow

### Excluded

- Advanced multi-device key rotation workflows
- One-time prekey consumption lifecycle
- Full direct E2EE interoperability coverage against Python/Rust transport flows
- direct E2EE server-side RPC implementation examples

### Compatibility

- Pure Go only
- No cgo
- Go 1.22+

### Validation

Recommended validation commands:

```bash
go test ./...
```

Interop validation currently requires local tool availability:

- `cargo`
- `uv`

When those tools are installed, `go test ./integration` also exercises Rust/Python fixture compatibility.
