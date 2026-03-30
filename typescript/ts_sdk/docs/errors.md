# Error Handling

## Error hierarchy

All SDK-specific base errors extend `ANPError`.

### Core errors

- `ANPError`
- `CryptoError`
- `AuthenticationError`
- `ProofError`
- `NetworkError`
- `WnsError`

### WNS-specific errors

- `HandleValidationError`
- `HandleResolutionError`
- `HandleNotFoundError`
- `HandleGoneError`
- `HandleMovedError`
- `HandleBindingError`
- `WbaUriParseError`

### Verifier-specific error

- `DidWbaVerifierError`

## Example pattern

```ts
import {
  ANPError,
  AuthenticationError,
  HandleNotFoundError,
  NetworkError,
  ProofError,
} from '@anp/typescript-sdk';

try {
  // SDK call
} catch (error) {
  if (error instanceof HandleNotFoundError) {
    console.error('Handle not found:', error.message);
  } else if (error instanceof AuthenticationError) {
    console.error('Authentication failed:', error.message);
  } else if (error instanceof ProofError) {
    console.error('Proof verification failed:', error.message);
  } else if (error instanceof NetworkError) {
    console.error('Network error:', error.message, error.statusCode);
  } else if (error instanceof ANPError) {
    console.error('ANP error:', error.code, error.message);
  } else {
    console.error('Unexpected error:', error);
  }
}
```

## Notes

- DID resolution failures typically surface as `AuthenticationError` or `NetworkError`
- HTTP handle lookup failures surface as `HandleNotFoundError`, `HandleGoneError`, `HandleMovedError`, or `HandleResolutionError`
- `DidWbaVerifier` throws `DidWbaVerifierError` with `statusCode` and challenge headers when request verification fails
