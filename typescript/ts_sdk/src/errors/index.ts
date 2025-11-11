/**
 * Error classes for ANP SDK
 *
 * This module defines the error hierarchy for the SDK.
 */

/**
 * Base error class for all ANP SDK errors
 */
export class ANPError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly cause?: Error
  ) {
    super(message);
    this.name = 'ANPError';
    Object.setPrototypeOf(this, ANPError.prototype);
  }
}

/**
 * Error thrown when DID resolution fails
 */
export class DIDResolutionError extends ANPError {
  constructor(did: string, cause?: Error) {
    super(`Failed to resolve DID: ${did}`, 'DID_RESOLUTION_ERROR', cause);
    this.name = 'DIDResolutionError';
    Object.setPrototypeOf(this, DIDResolutionError.prototype);
  }
}

/**
 * Error thrown when authentication fails
 */
export class AuthenticationError extends ANPError {
  constructor(message: string, cause?: Error) {
    super(message, 'AUTHENTICATION_ERROR', cause);
    this.name = 'AuthenticationError';
    Object.setPrototypeOf(this, AuthenticationError.prototype);
  }
}

/**
 * Error thrown when protocol negotiation fails
 */
export class ProtocolNegotiationError extends ANPError {
  constructor(message: string, cause?: Error) {
    super(message, 'PROTOCOL_NEGOTIATION_ERROR', cause);
    this.name = 'ProtocolNegotiationError';
    Object.setPrototypeOf(this, ProtocolNegotiationError.prototype);
  }
}

/**
 * Error thrown when network operations fail
 */
export class NetworkError extends ANPError {
  constructor(
    message: string,
    public readonly statusCode?: number,
    cause?: Error
  ) {
    super(message, 'NETWORK_ERROR', cause);
    this.name = 'NetworkError';
    Object.setPrototypeOf(this, NetworkError.prototype);
  }
}

/**
 * Error thrown when cryptographic operations fail
 */
export class CryptoError extends ANPError {
  constructor(message: string, cause?: Error) {
    super(message, 'CRYPTO_ERROR', cause);
    this.name = 'CryptoError';
    Object.setPrototypeOf(this, CryptoError.prototype);
  }
}
