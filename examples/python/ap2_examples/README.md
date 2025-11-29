# AP2 Protocol Examples

This directory contains examples demonstrating the AP2 (Agent Payment Protocol) implementation.

## Overview

AP2 is a protocol built on top of ANP (Agent Negotiation Protocol) for secure payment and transaction flows between agents. It supports multiple signing algorithms including RS256 and ES256K.

## Examples

### Complete Flow (single process)

**File**: `ap2_complete_flow.py`

Runs the merchant server and shopper client inside a single asyncio program. This is the quickest way to review the full AP2 handshake from mandate creation to receipt issuance.

**Run**:
```bash
uv run python examples/python/ap2_examples/ap2_complete_flow.py
```

### Standalone merchant & shopper (two processes)

**Files**: `merchant_server.py`, `shopper_client.py`

These scripts replicate the complete flow but split the responsibilities into two separate processes so you can inspect the HTTP APIs individually or run them on different machines.

**Run**:
1. Terminal A – start the merchant server (binds to your local IP by default):
   ```bash
   uv run python examples/python/ap2_examples/merchant_server.py
   ```
   Optional flags: `--host 0.0.0.0`, `--port 8889`

2. Terminal B – run the shopper client and point it at the merchant URL:
   ```bash
   uv run python examples/python/ap2_examples/shopper_client.py \
     --merchant-url http://<merchant-host>:<port> \
     --merchant-did did:wba:didhost.cc:public
   ```
   Both arguments default to the demo DID/document shipped in `docs/did_public/`, so you can usually omit them when testing locally.

### Agent building blocks

**Files**: `merchant_agent.py`, `shopper_agent.py`

Reusable helpers that focus on the mandate builders/verifiers without spinning up HTTP servers. Import these when embedding AP2 flows inside larger applications or tests.

## Supported Algorithms

| Algorithm | Description | Key Type | Signature Size | Use Case |
|-----------|-------------|----------|----------------|----------|
| **RS256** | RSASSA-PKCS1-v1_5 using SHA-256 | RSA (2048+ bits) | ~256 bytes | General purpose |
| **ES256K** | ECDSA using secp256k1 and SHA-256 | EC (secp256k1) | ~70 bytes | Blockchain/crypto |

## Key Components

### CartMandate
- Contains shopping cart information
- Signed by merchant using `merchant_authorization`
- Includes QR code payment data
- Verified by shopper

### PaymentMandate
- Contains payment confirmation
- Signed by user using `user_authorization`
- References CartMandate via `cart_hash`
- Verified by merchant

## Key resolution (travel-anp-agent pattern)

For local runs, both shopper and merchant can reuse the sample DID assets in `docs/did_public/`:
- Load the DID document (`public-did-doc.json`) to resolve the shopper public key (via `verificationMethod[0].publicKeyJwk`) — mirroring the `user_public_key_resolver` pattern in `travel_anp_agent/agents/ap2/services/mandate_service.py`.
- Use the same DID document as the merchant DID for demos; no need to derive public keys from private PEMs in production flows. Instead, resolve public keys from the DID document or your DID resolver, and only use the private key for signing.

## Dependencies

All examples require:
- `pyjwt` - JWT encoding/decoding
- `cryptography` - Cryptographic primitives
- `pydantic` - Data validation

These are already included in the project dependencies.

## Further Reading

- [ES256K Support Documentation](../../../docs/ap2/ES256K_SUPPORT.md)
- [AP2 Protocol Specification](../../../docs/ap2/流程整理.md)
- [ANP Protocol](../../../README.md)

## Contributing

When adding new examples:
1. Follow the existing code structure
2. Include comprehensive comments
3. Add error handling
4. Update this README
5. Test the example before committing
