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

### AWiki IM error

`AwikiImError` exposes a stable `code`, a sanitized `message`, and an optional HTTP `status`. Remote response bodies, access tokens, private keys, and protocol challenge details are not copied into public error messages. JSON-RPC responses require version `2.0`, the exact request ID, and exactly one non-null `result` or `error`; an explicit `error: null` on success or `result: null` on failure is accepted.

The stable codes are:

- `not-registered`
- `already-registered`
- `invalid-request`
- `invalid-otp`
- `challenge-expired`
- `handle-unavailable`
- `not-found`
- `forbidden`
- `conflict`
- `rate-limited`
- `network`
- `remote`

## Example pattern

```ts
import {
  ANPError,
  AuthenticationError,
  AwikiImError,
  HandleNotFoundError,
  NetworkError,
  ProofError,
} from '@anp/typescript-sdk';

try {
  // SDK call
} catch (error) {
  if (error instanceof AwikiImError) {
    console.error('AWiki IM error:', error.code, error.message, error.status);
  } else if (error instanceof HandleNotFoundError) {
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
