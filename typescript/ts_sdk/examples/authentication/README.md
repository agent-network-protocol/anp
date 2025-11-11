# Authentication Example

This example demonstrates DID:WBA authentication between two agents.

## What This Example Shows

- Creating client and server identities
- Signing authentication data
- Verifying signatures
- Mutual authentication
- Token-based access patterns

## Running the Example

```bash
npm install
npm start
```

## Authentication Flow

1. **Client Identity**: Client creates a DID identity
2. **Server Identity**: Server creates a DID identity
3. **Request Signing**: Client signs request data with its private key
4. **Signature Verification**: Server verifies the signature using client's public key
5. **Access Grant**: Server grants access and issues token
6. **Mutual Auth**: Server signs response, client verifies

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
