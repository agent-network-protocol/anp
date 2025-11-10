# Encrypted Communication Example

This example demonstrates end-to-end encryption between two agents.

## What This Example Shows

- ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) key exchange
- Symmetric encryption with AES-256-GCM
- Key derivation from shared secrets
- Authenticated encryption
- Bidirectional secure communication
- Key rotation

## Running the Example

```bash
npm install
npm start
```

## Encryption Flow

### 1. Identity Creation
- Both agents create DID identities
- Identities include keyAgreement keys for encryption

### 2. Public Key Exchange
- Agents resolve each other's DID documents
- Extract keyAgreement public keys
- Public keys can be shared openly

### 3. ECDHE Key Exchange
- Each agent generates ephemeral key pair
- Agents compute shared secret using:
  - Own private key
  - Other agent's public key
- Both arrive at same shared secret

### 4. Key Derivation
- Derive symmetric encryption key from shared secret
- Use HKDF (HMAC-based Key Derivation Function)
- Include salt and context information

### 5. Encryption
- Encrypt messages with AES-256-GCM
- Generate unique IV for each message
- Produce authentication tag

### 6. Decryption
- Decrypt ciphertext with shared key
- Verify authentication tag
- Reject if tag doesn't match

### 7. Key Rotation
- Periodically generate new ephemeral keys
- Perform new key exchange
- Securely destroy old keys

## Cryptographic Algorithms

### ECDHE (Key Exchange)
- **Algorithm**: Elliptic Curve Diffie-Hellman Ephemeral
- **Curve**: P-256 (secp256r1) or X25519
- **Purpose**: Establish shared secret
- **Property**: Forward secrecy

### AES-256-GCM (Encryption)
- **Algorithm**: Advanced Encryption Standard
- **Mode**: Galois/Counter Mode
- **Key Size**: 256 bits
- **Purpose**: Confidentiality and authenticity
- **Properties**: 
  - Authenticated encryption
  - Detects tampering
  - Fast performance

### HKDF (Key Derivation)
- **Algorithm**: HMAC-based Key Derivation Function
- **Hash**: SHA-256
- **Purpose**: Derive encryption keys from shared secret
- **Properties**:
  - Cryptographically strong
  - Separates key material

## Security Properties

### Confidentiality
Only the two agents can read the messages. Even if an intermediary intercepts the encrypted data, they cannot decrypt it without the shared secret.

### Authenticity
The authentication tag ensures messages come from the claimed sender and haven't been modified.

### Forward Secrecy
Using ephemeral keys means that even if long-term keys are compromised, past communications remain secure.

### Integrity
Any tampering with the ciphertext is detected when verifying the authentication tag.

## Best Practices

### Key Management
- Generate new ephemeral keys for each session
- Rotate keys regularly (e.g., every 1000 messages)
- Securely destroy old keys after rotation
- Never reuse IVs with the same key

### DID Verification
- Always verify DID documents before key exchange
- Check signatures on DID documents
- Validate key purposes (keyAgreement)
- Ensure keys are current and not revoked

### Message Handling
- Use unique IV for every message
- Include sequence numbers to prevent replay
- Implement message ordering
- Set maximum message age

### Error Handling
- Reject messages with invalid authentication tags
- Handle key exchange failures gracefully
- Implement retry logic with backoff
- Log security events

## Implementation Details

### Message Format
```
[IV (12 bytes)][Ciphertext (variable)][Auth Tag (16 bytes)]
```

### Key Derivation
```
encryption_key = HKDF(
  shared_secret,
  salt,
  info="ANP-encryption-key",
  length=32
)
```

### Encryption
```
ciphertext, tag = AES-256-GCM.encrypt(
  key=encryption_key,
  plaintext=message,
  iv=random_iv,
  additional_data=metadata
)
```

## Common Issues

### Key Exchange Fails
- Verify both agents have keyAgreement keys
- Check key formats are compatible
- Ensure DID documents are accessible

### Decryption Fails
- Verify both agents used same shared secret
- Check IV and tag are transmitted correctly
- Ensure key derivation parameters match

### Authentication Tag Invalid
- Message may have been tampered with
- Wrong key used for decryption
- Corrupted ciphertext

## Performance Considerations

### Key Exchange
- Expensive operation (1-5ms)
- Perform once per session
- Cache shared secrets appropriately

### Encryption/Decryption
- Fast operation (<1ms for typical messages)
- Hardware acceleration available
- Minimal overhead

### Key Rotation
- Balance security vs performance
- Rotate based on:
  - Message count (e.g., 1000 messages)
  - Time (e.g., every hour)
  - Data volume (e.g., every 100MB)

## Security Considerations

### Threat Model
- **Protected Against**:
  - Eavesdropping
  - Man-in-the-middle (with DID verification)
  - Message tampering
  - Replay attacks (with sequence numbers)

- **Not Protected Against**:
  - Endpoint compromise
  - Malicious agents with valid DIDs
  - Traffic analysis (message sizes/timing)

### Recommendations
- Use HTTPS for transport layer security
- Implement rate limiting
- Monitor for suspicious patterns
- Implement access controls
- Regular security audits

## Next Steps

- Implement message sequencing
- Add replay attack protection
- Implement key rotation policies
- Add metadata encryption
- Explore group encryption scenarios
