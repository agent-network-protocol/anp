# Error Handling

This guide covers error handling in the ANP TypeScript SDK.

## Error Hierarchy

All SDK errors extend from the base `ANPError` class:

```typescript
class ANPError extends Error {
  constructor(message: string, public code: string);
}
```

## Error Types

### DIDResolutionError

Thrown when DID resolution fails.

**Error Code:** `DID_RESOLUTION_ERROR`

**Common Causes:**
- DID document not found (404)
- Network connectivity issues
- Invalid DID format
- Malformed DID document

**Example:**
```typescript
try {
  const document = await client.did.resolve('did:wba:example.com:agent');
} catch (error) {
  if (error instanceof DIDResolutionError) {
    console.error('Failed to resolve DID:', error.message);
    console.error('Error code:', error.code);
  }
}
```

### AuthenticationError

Thrown when authentication fails.

**Error Code:** `AUTHENTICATION_ERROR`

**Common Causes:**
- Invalid signature
- Expired timestamp
- Invalid nonce
- Missing or malformed authentication header
- Token expired or invalid

**Example:**
```typescript
try {
  const response = await client.http.get('https://example.com/api', identity);
} catch (error) {
  if (error instanceof AuthenticationError) {
    console.error('Authentication failed:', error.message);
    // Re-authenticate or refresh token
  }
}
```

### ProtocolNegotiationError

Thrown when protocol negotiation fails.

**Error Code:** `PROTOCOL_NEGOTIATION_ERROR`

**Common Causes:**
- No compatible protocols found
- Maximum negotiation rounds exceeded
- Remote agent rejected negotiation
- Invalid protocol message format

**Example:**
```typescript
const machine = client.protocol.createNegotiationMachine({
  localIdentity: identity,
  remoteDID: 'did:wba:other.com:agent',
  candidateProtocols: 'JSON-RPC 2.0',
  onStateChange: (state) => {
    if (state.matches('rejected')) {
      console.error('Protocol negotiation failed');
    }
  },
});
```

### NetworkError

Thrown when network requests fail.

**Error Code:** `NETWORK_ERROR`

**Properties:**
- `statusCode`: HTTP status code (if available)

**Common Causes:**
- Connection timeout
- DNS resolution failure
- Server returned error status code
- Network connectivity issues

**Example:**
```typescript
try {
  const response = await client.http.get('https://example.com/api');
} catch (error) {
  if (error instanceof NetworkError) {
    console.error('Network error:', error.message);
    console.error('Status code:', error.statusCode);
    
    if (error.statusCode === 503) {
      // Service unavailable, retry later
    }
  }
}
```

### CryptoError

Thrown when cryptographic operations fail.

**Error Code:** `CRYPTO_ERROR`

**Common Causes:**
- Invalid key format
- Unsupported algorithm
- Encryption/decryption failure
- Key generation failure

**Example:**
```typescript
try {
  const signature = await client.did.sign(identity, data);
} catch (error) {
  if (error instanceof CryptoError) {
    console.error('Cryptographic operation failed:', error.message);
  }
}
```

## Error Handling Patterns

### Basic Try-Catch

```typescript
try {
  const identity = await client.did.create({
    domain: 'example.com',
    path: 'agent1'
  });
} catch (error) {
  if (error instanceof ANPError) {
    console.error(`ANP Error [${error.code}]:`, error.message);
  } else {
    console.error('Unexpected error:', error);
  }
}
```

### Type-Specific Handling

```typescript
try {
  const response = await client.http.get('https://example.com/api', identity);
  const data = await response.json();
} catch (error) {
  if (error instanceof AuthenticationError) {
    // Handle authentication failure
    console.error('Authentication failed, please re-authenticate');
  } else if (error instanceof NetworkError) {
    // Handle network failure
    if (error.statusCode === 503) {
      console.error('Service temporarily unavailable');
    } else {
      console.error('Network error:', error.message);
    }
  } else if (error instanceof ANPError) {
    // Handle other ANP errors
    console.error('ANP error:', error.code, error.message);
  } else {
    // Handle unexpected errors
    console.error('Unexpected error:', error);
  }
}
```

### Async Error Handling

```typescript
async function discoverAgents(domain: string) {
  try {
    const agents = await client.discovery.discoverAgents(domain);
    return agents;
  } catch (error) {
    if (error instanceof DIDResolutionError) {
      console.error('Failed to resolve agent DIDs');
      return [];
    } else if (error instanceof NetworkError) {
      console.error('Network error during discovery');
      throw error; // Re-throw for caller to handle
    } else {
      console.error('Unexpected error:', error);
      return [];
    }
  }
}
```

### Retry Logic

```typescript
async function fetchWithRetry(url: string, maxRetries = 3) {
  let lastError;
  
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await client.http.get(url);
    } catch (error) {
      lastError = error;
      
      if (error instanceof NetworkError && error.statusCode === 503) {
        // Service unavailable, wait and retry
        await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
        continue;
      }
      
      // Don't retry for other errors
      throw error;
    }
  }
  
  throw lastError;
}
```

### Promise.allSettled for Multiple Operations

```typescript
async function discoverMultipleDomains(domains: string[]) {
  const results = await Promise.allSettled(
    domains.map(domain => client.discovery.discoverAgents(domain))
  );
  
  const successful = results
    .filter(r => r.status === 'fulfilled')
    .map(r => r.value);
  
  const failed = results
    .filter(r => r.status === 'rejected')
    .map(r => r.reason);
  
  if (failed.length > 0) {
    console.warn(`${failed.length} domains failed to discover`);
    failed.forEach(error => {
      if (error instanceof ANPError) {
        console.error(`Error [${error.code}]:`, error.message);
      }
    });
  }
  
  return successful.flat();
}
```

## Error Recovery Strategies

### DID Resolution Failures

```typescript
async function resolveDIDWithFallback(did: string) {
  try {
    return await client.did.resolve(did);
  } catch (error) {
    if (error instanceof DIDResolutionError) {
      // Try alternative resolution method
      console.warn('Primary resolution failed, trying fallback');
      // Implement fallback logic
    }
    throw error;
  }
}
```

### Authentication Failures

```typescript
async function authenticatedRequest(url: string, identity: DIDIdentity) {
  try {
    return await client.http.get(url, identity);
  } catch (error) {
    if (error instanceof AuthenticationError) {
      // Token might be expired, create new identity or refresh
      console.log('Re-authenticating...');
      const newIdentity = await client.did.create({
        domain: identity.did.split(':')[2],
      });
      return await client.http.get(url, newIdentity);
    }
    throw error;
  }
}
```

### Network Failures

```typescript
async function robustRequest(url: string) {
  const maxRetries = 3;
  let delay = 1000;
  
  for (let i = 0; i < maxRetries; i++) {
    try {
      return await client.http.get(url);
    } catch (error) {
      if (error instanceof NetworkError) {
        if (i < maxRetries - 1) {
          console.log(`Retry ${i + 1}/${maxRetries} after ${delay}ms`);
          await new Promise(resolve => setTimeout(resolve, delay));
          delay *= 2; // Exponential backoff
          continue;
        }
      }
      throw error;
    }
  }
}
```

## Logging and Monitoring

### Structured Error Logging

```typescript
function logError(error: unknown, context: Record<string, any>) {
  if (error instanceof ANPError) {
    console.error({
      type: 'ANPError',
      code: error.code,
      message: error.message,
      stack: error.stack,
      ...context,
    });
  } else if (error instanceof Error) {
    console.error({
      type: 'Error',
      message: error.message,
      stack: error.stack,
      ...context,
    });
  } else {
    console.error({
      type: 'Unknown',
      error: String(error),
      ...context,
    });
  }
}

// Usage
try {
  await client.did.resolve(did);
} catch (error) {
  logError(error, { operation: 'did.resolve', did });
}
```

### Error Metrics

```typescript
class ErrorMetrics {
  private errorCounts = new Map<string, number>();
  
  recordError(error: unknown) {
    const code = error instanceof ANPError ? error.code : 'UNKNOWN';
    this.errorCounts.set(code, (this.errorCounts.get(code) || 0) + 1);
  }
  
  getMetrics() {
    return Object.fromEntries(this.errorCounts);
  }
}

const metrics = new ErrorMetrics();

try {
  await someOperation();
} catch (error) {
  metrics.recordError(error);
  throw error;
}
```

## Best Practices

### 1. Always Handle Specific Error Types

```typescript
// Good
try {
  await operation();
} catch (error) {
  if (error instanceof AuthenticationError) {
    // Handle auth error
  } else if (error instanceof NetworkError) {
    // Handle network error
  }
}

// Avoid
try {
  await operation();
} catch (error) {
  console.error(error); // Too generic
}
```

### 2. Provide Context in Error Messages

```typescript
try {
  await client.did.resolve(did);
} catch (error) {
  throw new Error(`Failed to resolve DID ${did}: ${error.message}`);
}
```

### 3. Don't Swallow Errors

```typescript
// Bad
try {
  await operation();
} catch (error) {
  // Silent failure
}

// Good
try {
  await operation();
} catch (error) {
  console.error('Operation failed:', error);
  // Or re-throw
  throw error;
}
```

### 4. Use Finally for Cleanup

```typescript
let resource;
try {
  resource = await acquireResource();
  await useResource(resource);
} catch (error) {
  console.error('Error using resource:', error);
  throw error;
} finally {
  if (resource) {
    await releaseResource(resource);
  }
}
```

### 5. Validate Inputs Early

```typescript
async function createAgent(domain: string) {
  if (!domain || typeof domain !== 'string') {
    throw new Error('Invalid domain: must be a non-empty string');
  }
  
  try {
    return await client.did.create({ domain });
  } catch (error) {
    // Handle error
  }
}
```

## Error Code Reference

| Error Code | Error Type | Description |
|------------|------------|-------------|
| `DID_RESOLUTION_ERROR` | DIDResolutionError | Failed to resolve DID document |
| `AUTHENTICATION_ERROR` | AuthenticationError | Authentication or authorization failed |
| `PROTOCOL_NEGOTIATION_ERROR` | ProtocolNegotiationError | Protocol negotiation failed |
| `NETWORK_ERROR` | NetworkError | Network request failed |
| `CRYPTO_ERROR` | CryptoError | Cryptographic operation failed |

## Debugging Tips

### Enable Debug Mode

```typescript
const client = new ANPClient({ debug: true });
```

### Check Error Details

```typescript
catch (error) {
  console.error('Error details:', {
    name: error.name,
    message: error.message,
    code: error.code,
    stack: error.stack,
    cause: error.cause,
  });
}
```

### Inspect Network Errors

```typescript
catch (error) {
  if (error instanceof NetworkError) {
    console.error('Status:', error.statusCode);
    console.error('Message:', error.message);
  }
}
```

### Test Error Scenarios

```typescript
// Test with invalid DID
try {
  await client.did.resolve('invalid-did');
} catch (error) {
  console.log('Expected error:', error.code);
}
```
