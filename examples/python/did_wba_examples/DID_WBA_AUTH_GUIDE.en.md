# DID WBA Authentication Integration Guide

> [中文版](DID_WBA_AUTH_GUIDE.md)

This guide explains how to integrate DID WBA authentication into a Python HTTP server using the ANP SDK (`anp` package). After reading this guide, you can quickly add decentralized identity verification to any Python HTTP service.

## 1. Authentication Principles

### 1.1 What is DID WBA

DID WBA (Web-Based Agent) is a decentralized identity authentication method based on the W3C DID standard. It allows clients to include a DID and signature in the first HTTP request, enabling servers to verify client identity without additional round-trips.

Key characteristics:
- Asymmetric cryptography: client holds private key, server obtains public key from the DID document to verify signatures
- After initial authentication, the server issues a JWT Bearer Token for subsequent requests without repeated signing
- Works with HTTPS: client verifies server via TLS certificate, server verifies client via DID signature

### 1.2 Authentication Flow

```
First Request:
Client                              Server                    Client DID Server
  |                                    |                            |
  |-- HTTP Request ------------------>|                            |
  |   Authorization: DIDWba           |                            |
  |   did="did:wba:...",              |-- GET /user/alice/did.json-->|
  |   nonce="random_string",          |                            |
  |   timestamp="2024-12-05T...",     |<-- DID Document -----------|
  |   verification_method="key-1",    |                            |
  |   signature="base64url(...)"      |                            |
  |                                   |                            |
  |                                   |  1. Verify timestamp not expired
  |                                   |  2. Verify nonce not replayed
  |                                   |  3. Get public key from DID document
  |                                   |  4. Verify signature with public key
  |                                   |  5. Valid → generate JWT
  |                                   |
  |<-- HTTP Response -----------------|
  |    Authorization: bearer <JWT>    |
  |                                   |

Subsequent Requests (using JWT, faster):
Client                              Server
  |                                    |
  |-- HTTP Request ------------------>|
  |   Authorization: Bearer <JWT>     |
  |                                   |  Verify JWT signature & expiry
  |<-- HTTP Response -----------------|
```

### 1.3 Authorization Header Format

For initial authentication, the client sends the following in the `Authorization` header:

```
Authorization: DIDWba did="did:wba:example.com:user:alice", nonce="abc123", timestamp="2024-12-05T12:34:56Z", verification_method="key-1", signature="base64url(signature_value)"
```

Field descriptions:
- `did`: Client's DID identifier
- `nonce`: Random string to prevent replay attacks (recommended: 16-byte random value)
- `timestamp`: Request time in ISO 8601 UTC format, accurate to seconds
- `verification_method`: Fragment of the verification method in the DID document (e.g., `key-1`)
- `signature`: Sign `{nonce, timestamp, aud, did}` → JCS canonicalization → SHA-256 hash → private key signature → base64url encoding

### 1.4 Signature Verification Process

Upon receiving a request, the server performs these steps:

1. Extract `did`, `nonce`, `timestamp`, `verification_method`, `signature` from the `Authorization` header
2. Verify `timestamp` is within the acceptable range (default: ±5 minutes)
3. Verify `nonce` has not been used before (anti-replay)
4. Resolve the DID document by fetching it from the HTTPS URL derived from the client's DID
5. Find the public key matching `verification_method` in the DID document
6. Verify the signature using the public key
7. On success, generate an RS256 JWT Token and return it to the client

## 2. Installation

```bash
pip install anp
# or using uv
uv add anp
```

For FastAPI support:

```bash
pip install anp[api]
# or
uv add anp --extra api
```

## 3. Server-Side Integration

### 3.1 Core Classes

The ANP SDK provides the following classes for server-side authentication:

| Class | Module | Purpose |
|-------|--------|---------|
| `DidWbaVerifierConfig` | `anp.authentication` | Verifier configuration (JWT keys, expiry, etc.) |
| `DidWbaVerifier` | `anp.authentication` | Core verifier for DID WBA headers and Bearer Tokens |
| `auth_middleware` | `anp.openanp.middleware` | FastAPI middleware that intercepts requests for authentication |
| `create_auth_middleware` | `anp.openanp.middleware` | Middleware factory for one-line setup |

### 3.2 Minimal Example: FastAPI + DID WBA Authentication

```python
"""Minimal example of adding DID WBA authentication to a FastAPI server."""

from fastapi import FastAPI, Request
from anp.authentication import DidWbaVerifier, DidWbaVerifierConfig
from anp.openanp.middleware import auth_middleware

# 1. Prepare JWT keys (RS256)
#    Generate with: openssl genrsa -out private.pem 2048
#                   openssl rsa -in private.pem -pubout -out public.pem
with open("private.pem") as f:
    jwt_private_key = f.read()
with open("public.pem") as f:
    jwt_public_key = f.read()

# 2. Create verifier
config = DidWbaVerifierConfig(
    jwt_private_key=jwt_private_key,
    jwt_public_key=jwt_public_key,
    jwt_algorithm="RS256",
    access_token_expire_minutes=60,
)
verifier = DidWbaVerifier(config)

# 3. Create FastAPI app and register middleware
app = FastAPI()

# Paths that bypass authentication
exempt_paths = ["/health", "/docs", "/openapi.json"]

@app.middleware("http")
async def did_wba_auth(request: Request, call_next):
    return await auth_middleware(
        request, call_next, verifier, exempt_paths=exempt_paths
    )

# 4. Define routes
@app.get("/health")
async def health():
    """Exempt endpoint, no authentication required."""
    return {"status": "healthy"}

@app.get("/api/protected")
async def protected(request: Request):
    """Protected endpoint, requires DID authentication."""
    did = request.state.did          # DID is auto-injected after authentication
    return {"message": "Authentication successful", "did": did}
```

### 3.3 DidWbaVerifierConfig Reference

```python
from anp.authentication import DidWbaVerifierConfig

config = DidWbaVerifierConfig(
    # JWT signing keys (PEM strings) for issuing and verifying Bearer Tokens
    jwt_private_key="-----BEGIN RSA PRIVATE KEY-----\n...",
    jwt_public_key="-----BEGIN PUBLIC KEY-----\n...",
    jwt_algorithm="RS256",            # JWT signing algorithm

    # Token lifetime
    access_token_expire_minutes=60,   # Bearer Token expiry in minutes

    # Security parameters
    nonce_expiration_minutes=6,       # Nonce record expiry (should be slightly > timestamp expiry)
    timestamp_expiration_minutes=5,   # Timestamp validity window in minutes

    # Optional: custom nonce validator (for distributed deployments sharing nonce state)
    # Signature: (did: str, nonce: str) -> bool (also supports async)
    external_nonce_validator=None,

    # Optional: domain whitelist to restrict authentication sources
    allowed_domains=["example.com", "localhost"],
)
```

### 3.4 How the Middleware Works

The `auth_middleware` workflow:

1. Check if the request path is in `exempt_paths` (supports wildcards like `*/ad.json`, `/info/*`)
2. If exempt, pass through directly
3. If authentication is required, extract the `Authorization` header
4. If it starts with `DIDWba`, perform DID WBA verification. On success:
   - Store auth result in `request.state.auth_result`
   - Store DID in `request.state.did`
   - Return `bearer <JWT>` in the response `Authorization` header
5. If it starts with `Bearer`, verify the JWT Token
6. On authentication failure, return a 401 or 403 JSON response

### 3.5 Shorthand: Using create_auth_middleware

```python
from fastapi import FastAPI
from anp.authentication import DidWbaVerifierConfig
from anp.openanp.middleware import create_auth_middleware

app = FastAPI()

config = DidWbaVerifierConfig(
    jwt_private_key=open("private.pem").read(),
    jwt_public_key=open("public.pem").read(),
    jwt_algorithm="RS256",
)

# One-line middleware registration
app.middleware("http")(
    create_auth_middleware(config, exempt_paths=["/health", "/docs"])
)
```

### 3.6 Accessing Authentication Data in Route Handlers

After middleware authentication succeeds, access auth data via `request.state`:

```python
@app.get("/api/data")
async def get_data(request: Request):
    # Get the authenticated DID
    did: str = request.state.did
    # e.g., did = "did:wba:example.com:user:alice"

    # Get the full authentication result
    auth_result: dict = request.state.auth_result
    # DID WBA first auth: {"access_token": "...", "token_type": "bearer", "did": "..."}
    # Bearer Token auth:  {"did": "..."}

    return {"did": did, "data": "..."}
```

### 3.7 Without Middleware: Using the Verifier Directly

If you're not using FastAPI or need finer-grained control, use `DidWbaVerifier` directly:

```python
from anp.authentication import DidWbaVerifier, DidWbaVerifierConfig, DidWbaVerifierError

config = DidWbaVerifierConfig(
    jwt_private_key=open("private.pem").read(),
    jwt_public_key=open("public.pem").read(),
)
verifier = DidWbaVerifier(config)

# Use in any HTTP framework
async def handle_request(authorization_header: str, server_domain: str):
    try:
        result = await verifier.verify_auth_header(authorization_header, server_domain)
        did = result["did"]
        access_token = result.get("access_token")  # Only present for first DID auth
        return did, access_token
    except DidWbaVerifierError as e:
        # e.status_code: 401 (auth failed), 403 (forbidden), 500 (internal error)
        return None, None
```

This works with aiohttp, Flask, Django, or any other Python HTTP framework.

## 4. Client-Side Integration

### 4.1 Using DIDWbaAuthHeader

The SDK provides `DIDWbaAuthHeader` to automatically manage auth headers and token caching:

```python
from anp.authentication import DIDWbaAuthHeader
import httpx

# 1. Create authentication client
authenticator = DIDWbaAuthHeader(
    did_document_path="path/to/did.json",       # Path to DID document
    private_key_path="path/to/private-key.pem",  # Corresponding private key
)

server_url = "https://example.com"

# 2. First request: auto-generates DID WBA auth header
headers = authenticator.get_auth_header(server_url, force_new=True)
# headers = {"Authorization": "DIDWba did=\"...\", nonce=\"...\", ..."}

with httpx.Client() as client:
    response = client.get(f"{server_url}/api/data", headers=headers)

    # 3. Extract and cache Bearer Token from response
    auth_header = response.headers.get("authorization")
    if auth_header:
        authenticator.update_token(server_url, {"Authorization": auth_header})

    # 4. Subsequent requests: automatically uses cached Bearer Token
    headers = authenticator.get_auth_header(server_url)
    # headers = {"Authorization": "Bearer eyJ..."}
    response = client.get(f"{server_url}/api/other", headers=headers)
```

### 4.2 DIDWbaAuthHeader Key Methods

| Method | Description |
|--------|-------------|
| `get_auth_header(server_url, force_new=False)` | Get auth header. Returns cached Bearer header if available, otherwise generates DID WBA header. `force_new=True` forces a new DID WBA header |
| `update_token(server_url, headers)` | Extract Bearer Token from response headers and cache it |
| `clear_token(server_url)` | Clear cached token for the specified domain |
| `clear_all_tokens()` | Clear all cached tokens |

### 4.3 Handling Token Expiry

```python
response = client.get(f"{server_url}/api/data", headers=headers)

if response.status_code == 401:
    # Token expired or invalid — clear cache and re-authenticate with DID
    authenticator.clear_token(server_url)
    headers = authenticator.get_auth_header(server_url, force_new=True)
    response = client.get(f"{server_url}/api/data", headers=headers)

    # Cache the new token
    auth_header = response.headers.get("authorization")
    if auth_header:
        authenticator.update_token(server_url, {"Authorization": auth_header})
```

## 5. DID Document and Key Preparation

### 5.1 Generate a DID Document

Use the SDK function to generate a DID document:

```python
from anp.authentication import create_did_wba_document

did_document, private_keys = create_did_wba_document(
    hostname="example.com",
    path_segments=["user", "alice"],
)
# did_document["id"] = "did:wba:example.com:user:alice"
# private_keys contains the generated private key objects

import json
with open("did.json", "w") as f:
    json.dump(did_document, f, indent=2)
```

Or use the command-line tool:

```bash
uv run python tools/did_generater/generate_did_doc.py "did:wba:example.com:user:alice"
```

### 5.2 Generate JWT RS256 Key Pair

The server needs an RS256 key pair for issuing and verifying Bearer Tokens (separate from DID document keys):

```bash
# Generate RSA private key
openssl genrsa -out RS256-private.pem 2048

# Export public key
openssl rsa -in RS256-private.pem -pubout -out RS256-public.pem
```

### 5.3 Deploy the DID Document

The DID document must be hosted at an HTTPS-accessible path:

```
did:wba:example.com              → https://example.com/.well-known/did.json
did:wba:example.com:user:alice   → https://example.com/user/alice/did.json
did:wba:example.com%3A3000       → https://example.com:3000/.well-known/did.json
```

During verification, the server automatically resolves the corresponding URL based on the client's DID to fetch the document.

## 6. Runnable Examples

This directory provides complete runnable examples:

- `http_server.py` — FastAPI server with DID WBA authentication middleware
- `http_client.py` — HTTP client demonstrating the full authentication and token reuse flow
- `authenticate_and_verify.py` — Offline demo, no server needed, shows the complete auth + verification flow
- `create_did_document.py` — DID document generation example

To run:

```bash
# Terminal 1: Start the server
uv run python examples/python/did_wba_examples/http_server.py

# Terminal 2: Run the client
uv run python examples/python/did_wba_examples/http_client.py
```

## 7. Custom DID Document Resolution

By default, the SDK resolves DID documents via HTTPS. For development/testing, you can replace this with a local resolver:

```python
from anp.authentication import did_wba_verifier as verifier_module

# Option 1: Replace the global resolution function (for testing)
async def local_resolver(did: str) -> dict:
    # Load DID document from local file or database
    return load_did_from_db(did)

verifier_module.resolve_did_wba_document = local_resolver

# Option 2: In production, just ensure the client's DID HTTPS path is accessible
# The SDK automatically fetches from https://<domain>/<path>/did.json
```

## 8. Security Considerations

1. **Private key management**: Both DID private keys and JWT private keys must be stored securely. Never commit them to source control.
2. **HTTPS**: Production environments must use HTTPS. DID document retrieval must also use HTTPS.
3. **Nonce anti-replay**: The built-in nonce validation is in-memory (single-process only). For distributed deployments, use `external_nonce_validator` to integrate Redis or another shared store.
4. **Clock skew**: The clock difference between server and client should not exceed `timestamp_expiration_minutes`.
5. **Token lifetime**: Adjust `access_token_expire_minutes` to suit your needs. Recommended: no more than 24 hours.
6. **Domain whitelist**: In production, configure `allowed_domains` to restrict authentication sources.

## 9. References

- [did:wba Method Specification](https://github.com/agent-network-protocol/AgentNetworkProtocol/blob/main/03-did-wba-method-design-specification.md)
- [W3C DID Core Specification](https://www.w3.org/TR/did-core/)
- [ANP SDK Repository](https://github.com/agent-network-protocol/AgentConnect)
- [JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785)
