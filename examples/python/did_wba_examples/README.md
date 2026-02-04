<div align="center">
  
[English](README.md) | [中文](README.cn.md)

</div>

# DID-WBA Authentication Examples

This directory showcases how to build, validate, and verify `did:wba` identities with AgentConnect. All scripts operate locally—no HTTP services are required—making them ideal for learning or offline testing.

## Contents

### Offline Examples
- `create_did_document.py`: Generates a DID document and secp256k1 key pair.
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
Auth header type: DID WBA
Authorization: DID-WBA did="did:wba:didhost.cc:public", nonce="...", timestamp=...
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
1. **First Request (DID Auth)**: Client sends DID WBA authentication header
2. **Server Verification**: Server verifies signature, issues JWT Bearer token
3. **Token Caching**: Client caches the Bearer token for subsequent requests
4. **Subsequent Requests**: Client uses cached Bearer token (more efficient)

## Troubleshooting
- **Missing files**: Run `create_did_document.py` before the other scripts, or confirm the sample files exist.
- **Invalid key format**: Ensure private keys remain PEM-encoded; regenerate with the create script if necessary.
- **DID mismatch**: Re-run `validate_did_document.py` to highlight structural issues.

## Next Steps
- Swap the sample credentials for your own DID material.
- Integrate `DIDWbaAuthHeader` into HTTP clients to call remote services that expect DID WBA headers.
- Pair the verifier with actual DID resolution logic once your documents are hosted publicly.
