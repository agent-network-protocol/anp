# Authentication Example

This example demonstrates DID:WBA authentication between two agents using cryptographic signatures.

## What This Example Shows

- Creating client and server DID identities
- Generating authentication headers with signatures
- Verifying DID-based authentication
- Resolving DID documents
- Signature verification with public keys
- Mutual authentication flow

## Running the Example

From the `ts_sdk` directory:

```bash
npm run build
npx tsx examples/authentication/index.ts
```

Or from this directory:

```bash
npm install
npm start
```

## Expected Output

```
=== Authentication Example ===

Creating identities...
✓ Client DID: did:wba:localhost:9000:client
✓ Server DID: did:wba:localhost:9001:server

Client signing request...
✓ Request signed

Preparing authentication...
✓ Authentication data signed
  DID: did:wba:localhost:9000:client
  Nonce: 68e0ec0a-5263-4f...
  Timestamp: 2025-11-11T04:03:06.715Z

Server granting access...
✓ Access token generated: token_5760c4f7-cb49-4e25-9956-...

Server signing response...
✓ Server response signed

=== Example Complete ===

Key Points:
- Both parties have signed their data
- Signatures prove ownership of DIDs
- Timestamps prevent replay attacks
- Nonces ensure request uniqueness

Note: In production, signatures would be verified by resolving DIDs
```

## Example Flow

1. **Create Identities**
   - Client creates DID: `did:wba:localhost:9000:client`
   - Server creates DID: `did:wba:localhost:9001:server`
   - Both generate ECDSA secp256k1 key pairs

2. **Client Authentication**
   - Client creates authentication data (nonce, timestamp, target)
   - Signs data with private key
   - Generates authentication header

3. **Server Verification**
   - Server receives authentication header
   - Resolves client's DID document
   - Extracts public key from verification method
   - Verifies signature
   - Grants access if valid

4. **Mutual Authentication**
   - Server creates response data
   - Signs with server's private key
   - Client verifies server's signature
   - Both parties authenticated

## Authentication Header Format

```
DIDWba did="did:wba:client.example.com:agent1",
       nonce="abc123...",
       timestamp="2024-01-15T10:30:00Z",
       verification_method="did:wba:client.example.com:agent1#key-1",
       signature="base64_signature..."
```

## Key Concepts

### Nonce
A unique value for each request to prevent replay attacks.

### Timestamp
Ensures requests are recent and prevents replay of old requests.

### Verification Method
Identifies which key was used for signing.

### Mutual Authentication
Both parties verify each other's identity for secure communication.

## Security Considerations

- Always verify timestamps are within acceptable range
- Use unique nonces for each request
- Implement token expiration
- Use HTTPS for all communications
- Validate DID documents before trusting signatures

## Next Steps

- Explore the encrypted communication example
- Implement token refresh mechanisms
- Add rate limiting and abuse prevention
- Integrate with your application's authorization system
