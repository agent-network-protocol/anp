<div align="center">
  
[English](README.md) | [中文](README.cn.md)

</div>

# DID-WBA Authentication Examples

This directory showcases how to build, validate, and verify `did:wba` identities with AgentConnect. All scripts operate locally—no HTTP services are required—making them ideal for learning or offline testing.

## Contents
- `create_did_document.py`: Generates a DID document and secp256k1 key pair.
- `validate_did_document.py`: Confirms the generated document matches DID-WBA requirements.
- `authenticate_and_verify.py`: Produces a DID authentication header, verifies it, and validates the issued bearer token using demo credentials.
- `generated/`: Output directory for DID documents and key files created by the examples.

## Prerequisites

### Environment
Install AgentConnect from PyPI or work from a local checkout:
```bash
pip install agent-connect
# or
uv venv .venv
uv pip install --python .venv/bin/python --editable .
```

### Sample Credentials
The end-to-end demo relies on bundled material:
- `docs/did_public/public-did-doc.json`
- `docs/did_public/public-private-key.pem`
- `docs/jwt_rs256/RS256-private.pem`
- `docs/jwt_rs256/RS256-public.pem`

## Walkthrough

### 1. Create a DID Document
```bash
uv run --python .venv/bin/python python examples/python/did_wba_examples/create_did_document.py
```
Expected output:
```
DID document saved to .../generated/did.json
Registered verification method key-1 → private key: key-1_private.pem public key: key-1_public.pem
Generated DID identifier: did:wba:demo.agent-network:agents:demo
```
Generated files:
- `generated/did.json`
- `generated/key-1_private.pem`
- `generated/key-1_public.pem`

### 2. Validate the DID Document
```bash
uv run --python .venv/bin/python python examples/python/did_wba_examples/validate_did_document.py
```
The script checks:
- Identifier format (`did:wba:` prefix)
- Required JSON-LD contexts
- Verification method wiring and JWK integrity
- Authentication entry referencing `key-1`
- Optional HTTPS service endpoint

Expected output:
```
DID document validation succeeded.
```

### 3. Authenticate and Verify
```bash
uv run --python .venv/bin/python python examples/python/did_wba_examples/authenticate_and_verify.py
```
Flow overview:
1. `DIDWbaAuthHeader` signs a DID header with the public demo credentials.
2. `DidWbaVerifier` resolves the local DID document, verifies the signature, and issues a bearer token (RS256).
3. The bearer token is validated to confirm the `did:wba` subject.

Expected output:
```
DID header verified. Issued bearer token.
Bearer token verified. Associated DID: did:wba:didhost.cc:public
```

## Troubleshooting
- **Missing files**: Run `create_did_document.py` before the other scripts, or confirm the sample files exist.
- **Invalid key format**: Ensure private keys remain PEM-encoded; regenerate with the create script if necessary.
- **DID mismatch**: Re-run `validate_did_document.py` to highlight structural issues.

## Next Steps
- Swap the sample credentials for your own DID material.
- Integrate `DIDWbaAuthHeader` into HTTP clients to call remote services that expect DID WBA headers.
- Pair the verifier with actual DID resolution logic once your documents are hosted publicly.
