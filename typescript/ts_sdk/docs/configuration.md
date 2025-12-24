# Configuration Guide

This guide covers all configuration options available in the ANP TypeScript SDK.

## ANPConfig

The main configuration object passed to the ANPClient constructor.

```typescript
interface ANPConfig {
  did?: DIDManagerConfig;
  auth?: AuthConfig;
  http?: HTTPClientConfig;
  debug?: boolean;
}
```

## DID Configuration

Configure DID resolution and caching behavior.

```typescript
interface DIDManagerConfig {
  cacheTTL?: number;
  timeout?: number;
}
```

### Options

#### cacheTTL
- **Type:** `number`
- **Default:** `300000` (5 minutes)
- **Description:** Time-to-live for cached DID documents in milliseconds

**Example:**
```typescript
const client = new ANPClient({
  did: {
    cacheTTL: 600000 // Cache for 10 minutes
  }
});
```

#### timeout
- **Type:** `number`
- **Default:** `10000` (10 seconds)
- **Description:** Timeout for DID resolution requests in milliseconds

**Example:**
```typescript
const client = new ANPClient({
  did: {
    timeout: 5000 // 5 second timeout
  }
});
```

## Authentication Configuration

Configure DID:WBA authentication behavior.

```typescript
interface AuthConfig {
  maxTokenAge?: number;
  nonceLength?: number;
  clockSkewTolerance?: number;
}
```

### Options

#### maxTokenAge
- **Type:** `number`
- **Default:** `3600000` (1 hour)
- **Description:** Maximum age for access tokens in milliseconds

**Example:**
```typescript
const client = new ANPClient({
  auth: {
    maxTokenAge: 1800000 // 30 minutes
  }
});
```

#### nonceLength
- **Type:** `number`
- **Default:** `32`
- **Description:** Length of nonce in bytes for authentication

**Example:**
```typescript
const client = new ANPClient({
  auth: {
    nonceLength: 64 // 64 bytes
  }
});
```

#### clockSkewTolerance
- **Type:** `number`
- **Default:** `300` (5 minutes)
- **Description:** Tolerance for clock skew in seconds when verifying timestamps

**Example:**
```typescript
const client = new ANPClient({
  auth: {
    clockSkewTolerance: 600 // 10 minutes
  }
});
```

## HTTP Configuration

Configure HTTP client behavior including timeouts and retries.

```typescript
interface HTTPClientConfig {
  timeout?: number;
  maxRetries?: number;
  retryDelay?: number;
}
```

### Options

#### timeout
- **Type:** `number`
- **Default:** `10000` (10 seconds)
- **Description:** Timeout for HTTP requests in milliseconds

**Example:**
```typescript
const client = new ANPClient({
  http: {
    timeout: 30000 // 30 seconds
  }
});
```

#### maxRetries
- **Type:** `number`
- **Default:** `3`
- **Description:** Maximum number of retry attempts for failed requests

**Example:**
```typescript
const client = new ANPClient({
  http: {
    maxRetries: 5 // Retry up to 5 times
  }
});
```

#### retryDelay
- **Type:** `number`
- **Default:** `1000` (1 second)
- **Description:** Initial delay between retries in milliseconds (uses exponential backoff)

**Example:**
```typescript
const client = new ANPClient({
  http: {
    retryDelay: 2000 // Start with 2 second delay
  }
});
```

## Debug Mode

Enable debug logging for troubleshooting.

#### debug
- **Type:** `boolean`
- **Default:** `false`
- **Description:** Enable detailed debug logging

**Example:**
```typescript
const client = new ANPClient({
  debug: true
});
```

When enabled, the SDK will log:
- DID resolution attempts and results
- Authentication header generation and verification
- HTTP requests and responses
- Protocol negotiation state transitions
- Error details

## Complete Configuration Example

```typescript
import { ANPClient } from '@anp/typescript-sdk';

const client = new ANPClient({
  // DID configuration
  did: {
    cacheTTL: 600000,      // Cache DID documents for 10 minutes
    timeout: 15000,        // 15 second timeout for resolution
  },
  
  // Authentication configuration
  auth: {
    maxTokenAge: 1800000,  // Tokens valid for 30 minutes
    nonceLength: 64,       // 64-byte nonces
    clockSkewTolerance: 600, // 10 minute clock skew tolerance
  },
  
  // HTTP configuration
  http: {
    timeout: 30000,        // 30 second request timeout
    maxRetries: 5,         // Retry up to 5 times
    retryDelay: 2000,      // Start with 2 second delay
  },
  
  // Enable debug logging
  debug: process.env.NODE_ENV === 'development',
});
```

## Environment-Specific Configuration

### Development

```typescript
const devClient = new ANPClient({
  debug: true,
  http: {
    timeout: 60000,  // Longer timeout for debugging
    maxRetries: 1,   // Fewer retries to fail fast
  },
});
```

### Production

```typescript
const prodClient = new ANPClient({
  debug: false,
  did: {
    cacheTTL: 900000,  // Longer cache for performance
  },
  http: {
    timeout: 10000,
    maxRetries: 3,
    retryDelay: 1000,
  },
  auth: {
    maxTokenAge: 3600000,
    clockSkewTolerance: 300,
  },
});
```

### Testing

```typescript
const testClient = new ANPClient({
  debug: true,
  did: {
    cacheTTL: 0,  // No caching for tests
    timeout: 5000,
  },
  http: {
    timeout: 5000,
    maxRetries: 0,  // No retries in tests
  },
});
```

## Meta-Protocol Configuration

When creating a protocol negotiation state machine:

```typescript
interface MetaProtocolConfig {
  localIdentity: DIDIdentity;
  remoteDID: string;
  candidateProtocols: string;
  maxNegotiationRounds?: number;
  onStateChange?: (state: any) => void;
}
```

### Options

#### maxNegotiationRounds
- **Type:** `number`
- **Default:** `10`
- **Description:** Maximum number of negotiation rounds before timeout

**Example:**
```typescript
const machine = client.protocol.createNegotiationMachine({
  localIdentity: identity,
  remoteDID: 'did:wba:other.com:agent',
  candidateProtocols: 'JSON-RPC 2.0',
  maxNegotiationRounds: 5,
});
```

#### onStateChange
- **Type:** `(state: any) => void`
- **Description:** Callback function called on every state transition

**Example:**
```typescript
const machine = client.protocol.createNegotiationMachine({
  localIdentity: identity,
  remoteDID: 'did:wba:other.com:agent',
  candidateProtocols: 'JSON-RPC 2.0',
  onStateChange: (state) => {
    console.log('State changed to:', state.value);
    console.log('Context:', state.context);
  },
});
```

## Best Practices

### 1. Use Environment Variables

```typescript
const client = new ANPClient({
  debug: process.env.DEBUG === 'true',
  http: {
    timeout: parseInt(process.env.HTTP_TIMEOUT || '10000'),
    maxRetries: parseInt(process.env.HTTP_MAX_RETRIES || '3'),
  },
});
```

### 2. Adjust Timeouts Based on Network

For slow networks:
```typescript
const client = new ANPClient({
  http: { timeout: 30000 },
  did: { timeout: 20000 },
});
```

For fast, reliable networks:
```typescript
const client = new ANPClient({
  http: { timeout: 5000 },
  did: { timeout: 5000 },
});
```

### 3. Cache Configuration for Performance

For frequently accessed DIDs:
```typescript
const client = new ANPClient({
  did: {
    cacheTTL: 3600000,  // Cache for 1 hour
  },
});
```

For dynamic environments:
```typescript
const client = new ANPClient({
  did: {
    cacheTTL: 60000,  // Cache for 1 minute
  },
});
```

### 4. Security Considerations

For high-security applications:
```typescript
const client = new ANPClient({
  auth: {
    maxTokenAge: 900000,      // 15 minute tokens
    clockSkewTolerance: 60,   // 1 minute tolerance
    nonceLength: 64,          // Longer nonces
  },
});
```

## Troubleshooting Configuration Issues

### Timeouts Too Short

If you're experiencing timeout errors:
```typescript
const client = new ANPClient({
  http: { timeout: 30000 },
  did: { timeout: 20000 },
});
```

### Too Many Retries

If requests are taking too long due to retries:
```typescript
const client = new ANPClient({
  http: {
    maxRetries: 1,
    retryDelay: 500,
  },
});
```

### Authentication Failures

If experiencing clock skew issues:
```typescript
const client = new ANPClient({
  auth: {
    clockSkewTolerance: 600,  // Increase tolerance
  },
});
```

### Memory Issues with Caching

If caching is using too much memory:
```typescript
const client = new ANPClient({
  did: {
    cacheTTL: 60000,  // Reduce cache time
  },
});
```
