# ES256K Algorithm Support in AP2

## Overview

AP2 protocol now fully supports **ES256K** (ECDSA using secp256k1 curve with SHA-256) algorithm for signing CartMandate and PaymentMandate, in addition to the standard **RS256** algorithm.

ES256K is particularly important for blockchain and cryptocurrency applications, as it uses the same secp256k1 curve as Bitcoin and Ethereum.

## Dependencies

The ES256K support is provided by:

- **PyJWT** (v2.10.1+): JWT encoding/decoding library with ES256K support
- **cryptography** (v46.0.1+): Cryptographic primitives including secp256k1 curve

These dependencies are already included in the project and are compatible with Python 3.13+.

## Usage

### CartMandate with ES256K

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from anp.ap2.cart_mandate import CartMandateBuilder, CartMandateVerifier
from anp.ap2.models import CartContents, PaymentRequest, ...

# Generate ES256K (secp256k1) key pair
private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
public_key = private_key.public_key()

# Serialize to PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode('utf-8')

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# Create builder with ES256K algorithm
builder = CartMandateBuilder(
    merchant_private_key=private_pem,
    merchant_did="did:wba:didhost.cc:merchant",
    merchant_kid="merchant-es256k-key-001",
    algorithm="ES256K",  # Specify ES256K algorithm
    shopper_did="did:wba:didhost.cc:shopper"
)

# Build CartMandate
cart_mandate = builder.build(
    cart_contents=cart_contents,
    extensions=["anp.ap2.qr.v1", "anp.human_presence.v1"]
)

# Verify CartMandate
verifier = CartMandateVerifier(
    merchant_public_key=public_pem,
    algorithm="ES256K"  # Specify ES256K algorithm
)

payload = verifier.verify(
    cart_mandate=cart_mandate,
    expected_aud="did:wba:didhost.cc:shopper"
)
```

### PaymentMandate with ES256K

```python
from anp.ap2.payment_mandate import PaymentMandateBuilder, PaymentMandateVerifier
from anp.ap2.models import PaymentMandateContents, ...

# Generate user's ES256K key pair (same as above)
# ...

# Create builder with ES256K algorithm
builder = PaymentMandateBuilder(
    user_private_key=private_pem,
    user_did="did:wba:didhost.cc:shopper",
    user_kid="shopper-es256k-key-001",
    algorithm="ES256K",  # Specify ES256K algorithm
    merchant_did="did:wba:didhost.cc:merchant"
)

# Build PaymentMandate
payment_mandate = builder.build(
    payment_mandate_contents=payment_contents,
    cart_hash=cart_hash,
    extensions=["anp.ap2.qr.v1", "anp.human_presence.v1"]
)

# Verify PaymentMandate
verifier = PaymentMandateVerifier(
    user_public_key=public_pem,
    algorithm="ES256K"  # Specify ES256K algorithm
)

payload = verifier.verify(
    payment_mandate=payment_mandate,
    expected_cart_hash=cart_hash,
    expected_aud="did:wba:didhost.cc:merchant"
)
```

## Supported Algorithms

| Algorithm | Description | Key Type | Use Case |
|-----------|-------------|----------|----------|
| **RS256** | RSASSA-PKCS1-v1_5 using SHA-256 | RSA (2048+ bits) | General purpose, widely supported |
| **ES256K** | ECDSA using secp256k1 curve and SHA-256 | EC (secp256k1) | Blockchain/crypto applications |

## Key Generation

### ES256K (secp256k1) Keys

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Generate private key
private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())

# Get public key
public_key = private_key.public_key()

# Export private key to PEM
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Export public key to PEM
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
```

### RS256 (RSA) Keys

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Get public key
public_key = private_key.public_key()

# Export private key to PEM
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Export public key to PEM
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)
```

## JWT Header Format

### ES256K JWT Header

```json
{
  "alg": "ES256K",
  "kid": "merchant-es256k-key-001",
  "typ": "JWT"
}
```

### RS256 JWT Header

```json
{
  "alg": "RS256",
  "kid": "merchant-rsa-key-001",
  "typ": "JWT"
}
```

## Implementation Notes

1. **Unified Implementation**: Both RS256 and ES256K use the same PyJWT library, providing consistent API and behavior.

2. **No Legacy Dependencies**: The old `python-jose` dependency (which had compatibility issues with Python 3.13) has been removed.

3. **Algorithm Selection**: Simply pass `algorithm="ES256K"` or `algorithm="RS256"` to the builder/verifier constructors.

4. **Key Format**: Both algorithms use PEM format for keys, making them easy to store and exchange.

5. **Signature Size**: ES256K signatures are typically smaller (~70 bytes) compared to RS256 signatures (~256 bytes with 2048-bit keys).

## Security Considerations

- **Key Size**: 
  - ES256K uses 256-bit keys (secp256k1 curve)
  - RS256 should use at least 2048-bit keys (3072-bit recommended for long-term security)

- **Algorithm Choice**:
  - Use **ES256K** for blockchain/crypto integrations and when signature size matters
  - Use **RS256** for general purpose and maximum compatibility

- **Key Management**: Always protect private keys and use secure key storage mechanisms.

## Testing

To verify ES256K support in your environment:

```python
import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

# Generate test key
private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
public_key = private_key.public_key()

# Test encoding
token = jwt.encode({"test": "data"}, private_key, algorithm="ES256K")

# Test decoding
decoded = jwt.decode(token, public_key, algorithms=["ES256K"])
print("ES256K is supported:", decoded)
```

## References

- [RFC 8812: CBOR Object Signing and Encryption (COSE) and JSON Object Signing and Encryption (JOSE) Registrations for Web Authentication (WebAuthn) Algorithms](https://datatracker.ietf.org/doc/html/rfc8812)
- [PyJWT Documentation](https://pyjwt.readthedocs.io/)
- [secp256k1 Curve](https://en.bitcoin.it/wiki/Secp256k1)

