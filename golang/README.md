# ANP Go SDK

Pure Go implementation of the Agent Network Protocol (ANP) core SDK.

## Status

Implemented in this directory:

- `authentication`
  - DID WBA document generation
  - legacy DIDWba auth header generation and verification
  - HTTP Message Signatures generation and verification
  - DID resolver for `did:wba` and `did:web`
  - request verifier with bearer token issuance
  - federated request verification helpers
- `proof`
  - W3C Data Integrity proof generation and verification
  - strict Appendix-B object proof helpers
  - group receipt proof helpers
  - did:wba binding proof helpers
  - IM proof helpers
  - RFC 9421 origin proof helpers for ANP request objects
- `wns`
  - handle validation and URI parsing
  - handle resolution
  - handle binding verification
- `direct_e2ee`
  - prekey bundle helpers
  - X3DH-derived initial session setup
  - symmetric ratchet step derivation
  - direct init / cipher message processing
  - file-backed stores and reference client helpers

## Compatibility

- **Pure Go only**
- **No cgo**
- Go **1.22+**

## Module Path

```bash
go get github.com/agent-network-protocol/anp/golang
```

## Quick Start

### Generate a DID document

```go
package main

import (
  "fmt"
  "github.com/agent-network-protocol/anp/golang/authentication"
)

func main() {
  bundle, err := authentication.CreateDidWBADocument(
    "example.com",
    authentication.DidDocumentOptions{PathSegments: []string{"user", "alice"}},
  )
  if err != nil {
    panic(err)
  }
  fmt.Println(bundle.DidDocument["id"])
}
```

### Create HTTP signature headers

```go
privateKey, _ := anp.PrivateKeyFromPEM(bundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
headers, err := authentication.GenerateHTTPSignatureHeaders(
  bundle.DidDocument,
  "https://api.example.com/orders",
  "POST",
  privateKey,
  map[string]string{"Content-Type": "application/json"},
  []byte(`{"item":"book"}`),
  authentication.HttpSignatureOptions{},
)
```

## Examples

- `examples/create_did_document`
- `examples/direct_e2ee`
- `examples/proof`
- `examples/wns`

## Docs

- `docs/api.md`
- `docs/direct_e2ee-guide.md`
- `docs/release-notes.md`

## Test

```bash
go test ./...
```
