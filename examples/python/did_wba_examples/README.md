<div align="center">
  
[English](README.md) | [中文](README.cn.md)

</div>

# DID-WBA Authentication Examples

This directory showcases how to build, validate, and verify `did:wba` identities with AgentConnect.

> **Current behavior summary**
>
> - Path-based DID creation now defaults to the `e1_` profile
> - The default client auth flow uses HTTP Message Signatures
> - Legacy compatibility mode is still available for older Authorization-header clients
> - `resolve_did_wba_document()` now always validates `e1_` / `k1_` DID binding
> - For `e1_`, DID Document proof is mandatory as part of strong binding validation

## Contents

### Offline Examples
- `create_did_document.py`: Generates a DID document; path DIDs now default to an `e1_` identifier and Ed25519 binding key.
- `create_e1_did_document.py`: Explicit e1 example.
- `create_k1_did_document.py`: Explicit k1 compatibility example.
- `validate_did_document.py`: Confirms the generated document matches DID-WBA requirements.
- `authenticate_and_verify.py`: Produces a DID authentication header, verifies it, and validates the issued bearer token using demo credentials.

### HTTP End-to-End Examples
- `http_server.py`: FastAPI HTTP server with DID WBA authentication middleware.
- `http_client.py`: HTTP client demonstrating the complete authentication flow.

### Generated Files
- `generated/`: Output directory for DID documents and key files created by the examples.

## Prerequisites

### Environment
Install AgentConnect from PyPI or work from a local checkout:
```bash
pip install anp
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
Generated DID identifier: did:wba:demo.agent-network:agents:demo:e1_<fingerprint>
```
Generated files:
- `generated/e1/did.json`
- `generated/e1/key-1_private.pem`
- `generated/e1/key-1_public.pem`

Explicit profile examples:

```bash
# Explicit e1 profile
uv run --python .venv/bin/python python examples/python/did_wba_examples/create_e1_did_document.py

# Explicit k1 compatibility profile
uv run --python .venv/bin/python python examples/python/did_wba_examples/create_k1_did_document.py
```

### 2. Validate the DID Document
```bash
uv run --python .venv/bin/python python examples/python/did_wba_examples/validate_did_document.py

# Validate an explicit k1 document
uv run --python .venv/bin/python python examples/python/did_wba_examples/validate_did_document.py --profile k1
```
The script checks:
- Identifier format (`did:wba:` prefix)
- Required JSON-LD contexts
- Verification method wiring and key integrity
- DID/document binding consistency
- For `e1_`, presence and validity of the DID Document proof
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
1. `DIDWbaAuthHeader` signs the request using the current default flow (HTTP Message Signatures unless legacy mode is requested).
2. `DidWbaVerifier` resolves the local DID document, validates DID binding and proof rules, verifies the request signature, and issues a bearer token (RS256).
3. The bearer token is validated to confirm the `did:wba` subject.

Expected output:
```
DID request verified. Auth scheme: http_signatures
Issued bearer token.
Bearer token verified. Associated DID: did:wba:didhost.cc:public
```

### 4. HTTP End-to-End Authentication

This example demonstrates a complete client-server authentication flow using actual HTTP requests.

#### Start the Server
```bash
uv run python examples/python/did_wba_examples/http_server.py
```
The server starts on `http://localhost:8080` with:
- `/health` - Health check (no auth required)
- `/api/protected` - Protected endpoint (requires DID auth)
- `/api/user-info` - User info endpoint (requires DID auth)

#### Run the Client (in another terminal)
```bash
uv run python examples/python/did_wba_examples/http_client.py
```

Expected output:
```
============================================================
Step 1: Access health endpoint (no authentication required)
============================================================
Status: 200
Response: {'status': 'healthy', 'service': 'did-wba-http-server'}

============================================================
Step 2: Access protected endpoint with DID authentication
============================================================
Auth header type: HTTP Message Signatures
Signature-Input: sig1=("...");created=...;keyid="did:wba:..."
Status: 200
Response: {'message': 'Authentication successful!', 'did': 'did:wba:didhost.cc:public', 'token_type': 'bearer'}
Received Bearer token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

============================================================
Step 3: Access protected endpoint with cached Bearer token
============================================================
Auth header type: Bearer
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Status: 200
Response: {'message': 'Authentication successful!', 'did': 'did:wba:didhost.cc:public', 'token_type': None}

============================================================
Step 4: Access user-info endpoint with Bearer token
============================================================
Status: 200
Response: {'did': 'did:wba:didhost.cc:public', 'authenticated': True, ...}

============================================================
Demo completed successfully!
============================================================
```

#### Authentication Flow
1. **First Request (DID Auth)**: Client sends HTTP Message Signatures by default
2. **Server Verification**: Server verifies DID binding, proof rules, request signature, then issues a JWT bearer token
3. **Token Caching**: Client caches the Bearer token for subsequent requests
4. **Subsequent Requests**: Client uses cached Bearer token (more efficient)

## Troubleshooting
- **Missing files**: Run `create_did_document.py` before the other scripts, or confirm the sample files exist.
- **Invalid key format**: Ensure private keys remain PEM-encoded; regenerate with the create script if necessary.
- **DID mismatch**: Re-run `validate_did_document.py` to highlight structural issues.

## Integration Guide

For a comprehensive guide on integrating DID WBA authentication into your own HTTP server (including authentication principles, full API reference, and copy-paste code snippets), see:

- **[DID WBA Auth Integration Guide (English)](DID_WBA_AUTH_GUIDE.en.md)**
- **[DID WBA 身份认证集成指南 (中文)](DID_WBA_AUTH_GUIDE.md)**

## Next Steps
- Swap the sample credentials for your own DID material.
- Integrate `DIDWbaAuthHeader` into HTTP clients to call remote services that expect DID-WBA authentication.
- Pair the verifier with actual DID resolution logic once your documents are hosted publicly.
