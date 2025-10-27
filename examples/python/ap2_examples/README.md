# AP2 Protocol Examples

This directory contains examples demonstrating the AP2 (Agent Payment Protocol) implementation.

## Overview

AP2 is a protocol built on top of ANP (Agent Negotiation Protocol) for secure payment and transaction flows between agents. It supports multiple signing algorithms including RS256 and ES256K.

## Examples

### ES256K Example

**File**: `es256k_example.py`

Demonstrates how to use ES256K (ECDSA with secp256k1 curve) algorithm for signing CartMandate and PaymentMandate. This is particularly useful for blockchain and cryptocurrency applications.

**Run**:
```bash
uv run python examples/python/ap2_examples/es256k_example.py
```

**Features**:
- Generate ES256K (secp256k1) key pairs
- Build CartMandate with ES256K signatures
- Verify CartMandate with ES256K
- Build PaymentMandate with ES256K signatures
- Verify PaymentMandate with ES256K

**Use Cases**:
- Blockchain-based payment systems
- Cryptocurrency transactions
- Integration with Bitcoin/Ethereum ecosystems
- Applications requiring smaller signature sizes

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

