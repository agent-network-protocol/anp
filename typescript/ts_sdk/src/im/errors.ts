import type { AwikiImErrorCode } from './types.js';

/** A stable AWiki IM failure that does not expose credentials or private protocol fields. */
export class AwikiImError extends Error {
  /**
   * Create a normalized AWiki IM error.
   *
   * @param code Stable category for callers.
   * @param message Public diagnostic message.
   * @param options Optional transport status and underlying cause.
   */
  constructor(
    public readonly code: AwikiImErrorCode,
    message: string,
    public readonly status?: number,
    options?: { cause?: unknown }
  ) {
    super(message, options?.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'AwikiImError';
  }
}

/** Return an existing normalized error or convert an unknown failure to one. */
export function normalizeAwikiImError(error: unknown): AwikiImError {
  if (error instanceof AwikiImError) {
    return error;
  }
  if (error instanceof TypeError) {
    return new AwikiImError('network', 'AWiki service is unavailable', undefined, {
      cause: error,
    });
  }
  return new AwikiImError('remote', 'AWiki operation failed', undefined, { cause: error });
}

/** Convert a JSON-RPC or HTTP response failure to the stable public taxonomy. */
export function awikiImRemoteError(input: {
  readonly status?: number;
  readonly rpcCode?: number;
  readonly serviceCode?: string;
  readonly message?: string;
}): AwikiImError {
  const code = classifyRemoteError(input);
  return new AwikiImError(code, publicMessage(code), input.status);
}

function classifyRemoteError(input: {
  readonly status?: number;
  readonly rpcCode?: number;
  readonly serviceCode?: string;
  readonly message?: string;
}): AwikiImErrorCode {
  const serviceCode = input.serviceCode?.toLowerCase() ?? '';
  const message = input.message?.toLowerCase() ?? '';
  const combined = `${serviceCode} ${message}`;

  if (input.rpcCode === 1003) {
    return 'invalid-request';
  }
  if (input.rpcCode === 1403 || serviceCode === 'anp.forbidden') {
    return 'forbidden';
  }
  if (
    input.rpcCode === 1404 ||
    serviceCode === 'anp.target_not_found' ||
    serviceCode === 'target_not_found'
  ) {
    return 'not-found';
  }
  if (
    input.rpcCode === 1409 ||
    serviceCode === 'anp.idempotency_conflict' ||
    serviceCode === 'idempotency_conflict'
  ) {
    return 'conflict';
  }
  if (combined.includes('otp_rate_limited') || input.status === 429 || input.rpcCode === -32005) {
    return 'rate-limited';
  }
  if (combined.includes('invalid_otp') || combined.includes('otp_invalid')) {
    return 'invalid-otp';
  }
  if (combined.includes('otp_expired') || combined.includes('challenge_expired')) {
    return 'challenge-expired';
  }
  if (
    combined.includes('handle_unavailable') ||
    combined.includes('handle_exists') ||
    combined.includes('handle already')
  ) {
    return 'handle-unavailable';
  }
  if (combined.includes('already_registered') || combined.includes('did already')) {
    return 'already-registered';
  }
  if (input.status === 404 || input.rpcCode === -32002) {
    return 'not-found';
  }
  if (input.status === 401 || input.status === 403 || input.rpcCode === -32001) {
    return 'forbidden';
  }
  if (input.status === 409 || input.rpcCode === -32003) {
    return 'conflict';
  }
  if (input.rpcCode === -32600 || input.rpcCode === -32602 || input.rpcCode === -32004) {
    return combined.includes('otp') ? 'invalid-otp' : 'invalid-request';
  }
  if (input.status !== undefined && input.status >= 400 && input.status < 500) {
    return 'invalid-request';
  }
  return 'remote';
}

function publicMessage(code: AwikiImErrorCode): string {
  switch (code) {
    case 'not-registered':
      return 'AWiki identity is not registered';
    case 'already-registered':
      return 'AWiki identity is already registered';
    case 'invalid-request':
      return 'AWiki rejected the request';
    case 'invalid-otp':
      return 'AWiki verification code is invalid';
    case 'challenge-expired':
      return 'AWiki registration challenge has expired';
    case 'handle-unavailable':
      return 'AWiki handle is unavailable';
    case 'not-found':
      return 'AWiki resource was not found';
    case 'forbidden':
      return 'AWiki operation is not permitted';
    case 'conflict':
      return 'AWiki operation conflicts with existing state';
    case 'rate-limited':
      return 'AWiki request was rate limited';
    case 'network':
      return 'AWiki service is unavailable';
    case 'remote':
      return 'AWiki service returned an error';
  }
}
