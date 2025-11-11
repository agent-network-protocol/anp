# Encrypted Communication Example

This example demonstrates end-to-end encryption between two agents using ECDHE key exchange and AES-256-GCM encryption.

## What This Example Shows

- Creating DID identities with X25519 keyAgreement keys
- Extracting keyAgreement keys from DID documents
- Performing ECDHE (Elliptic Curve Diffie-Hellman Ephemeral) key exchange
- Verifying both parties compute the same shared secret
- Deriving AES-256-GCM encryption keys using HKDF
- **Actually encrypting messages** with real plaintext
- **Actually decrypting messages** and verifying content
- Bidirectional encrypted communication (Alice ↔ Bob)
- Demonstrating tampering detection with authentication tags

## Running the Example

From the `ts_sdk` directory:

```bash
npm run build
npx tsx examples/encrypted-communication/index.ts
```

Or from this directory:

```bash
npm install
npm start
```

## Expected Output

```
=== Encrypted Communication Example ===

Step 1: Creating agent identities...
✓ Alice: did:wba:localhost:9000:alice
✓ Bob: did:wba:localhost:9001:bob

Step 2: Extracting keyAgreement keys...
✓ Alice keyAgreement: did:wba:localhost:9000:alice#key-agreement
✓ Bob keyAgreement: did:wba:localhost:9001:bob#key-agreement

Step 3: Performing ECDHE key exchange...
✓ Shared secret established: MATCH
  Shared secret length: 32 bytes

Step 4: Deriving encryption keys with HKDF...
✓ Encryption key derived (AES-256-GCM)
  Salt length: 32 bytes

Step 5: Alice encrypts message to Bob...
✓ Message encrypted
  Original message: Hello Bob! This is a secret message from Alice.
  Plaintext length: 47 bytes
  Ciphertext length: 47 bytes
  IV length: 12 bytes
  Auth tag length: 16 bytes

Step 6: Bob decrypts message from Alice...
✓ Message decrypted
  Decrypted message: Hello Bob! This is a secret message from Alice.
  Messages match: true

Step 7: Bob sends encrypted reply to Alice...
✓ Reply encrypted
  Reply message: Hi Alice! I received your message securely.

Step 8: Alice decrypts Bob's reply...
✓ Reply decrypted
  Decrypted reply: Hi Alice! I received your message securely.
  Messages match: true

Step 9: Demonstrating tampering detection...
✓ Tampering detected and rejected
  Error: Decryption failed: Authentication tag verification failed. Data may have been tampered with.

=== Example Complete ===

Security Properties Demonstrated:
✓ Confidentiality: Messages encrypted with AES-256-GCM
✓ Authenticity: Authentication tags verify message integrity
✓ Forward Secrecy: Ephemeral key exchange protects past sessions
✓ Integrity: Tampering is detected and rejected
✓ Bidirectional: Both parties can encrypt and decrypt
```

## Example Flow

### 1. Create Identities with Key Agreement Keys
```typescript
const aliceIdentity = await client.did.create({
  domain: 'alice.example.com',
  path: 'agent1',
});

const bobIdentity = await client.did.create({
  domain: 'bob.example.com',
  path: 'agent1',
});
```
- Both identities include X25519 keyAgreement keys
- Keys are used for ECDHE key exchange

### 2. Resolve DID Documents
```typescript
const aliceDoc = await client.did.resolve(aliceIdentity.did);
const bobDoc = await client.did.resolve(bobIdentity.did);
```
- Each agent resolves the other's DID document
- Extracts keyAgreement public keys
- Public keys can be shared openly (not secret)

### 3. Perform ECDHE Key Exchange
```typescript
const sharedSecretAlice = await performKeyExchange(
  alicePrivateKey,
  bobPublicKey
);

const sharedSecretBob = await performKeyExchange(
  bobPrivateKey,
  alicePublicKey
);
```
- Both agents compute the same shared secret
- Uses Elliptic Curve Diffie-Hellman
- Shared secret is never transmitted

### 4. Derive Encryption Keys
```typescript
const encryptionKey = await deriveKey(sharedSecret, salt);
```
- Use HKDF (HMAC-based Key Derivation Function)
- Derives AES-256 key from shared secret
- Includes salt for additional security

### 5. Encrypt Messages
```typescript
const encrypted = await encrypt(encryptionKey, plaintext);
// Returns: { ciphertext, iv, tag }
```
- Encrypts with AES-256-GCM
- Generates random IV (Initialization Vector)
- Produces authentication tag for integrity

### 6. Decrypt Messages
```typescript
const decrypted = await decrypt(encryptionKey, encrypted);
```
- Decrypts ciphertext with shared key
- Verifies authentication tag
- Throws error if tag is invalid (tampering detected)

### 7. Bidirectional Communication
- Alice encrypts message → Bob decrypts
- Bob encrypts response → Alice decrypts
- Both use the same shared secret

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

### Encrypted Message Format
```typescript
interface EncryptedData {
  ciphertext: Uint8Array;  // Encrypted message
  iv: Uint8Array;          // Initialization Vector (12 bytes)
  tag: Uint8Array;         // Authentication Tag (16 bytes)
}
```

### Key Derivation (HKDF)
```typescript
const encryptionKey = await crypto.subtle.deriveKey(
  {
    name: 'HKDF',
    hash: 'SHA-256',
    salt: salt,
    info: new TextEncoder().encode('ANP-encryption-key'),
  },
  sharedSecret,
  { name: 'AES-GCM', length: 256 },
  false,
  ['encrypt', 'decrypt']
);
```

### AES-256-GCM Encryption
```typescript
const ciphertext = await crypto.subtle.encrypt(
  {
    name: 'AES-GCM',
    iv: randomIV,
    tagLength: 128,  // 16 bytes
  },
  encryptionKey,
  plaintext
);
```

### Wire Format
```
[IV (12 bytes)] + [Ciphertext (variable)] + [Auth Tag (16 bytes)]
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
