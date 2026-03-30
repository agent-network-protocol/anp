export class ANPError extends Error {
  constructor(message: string, public readonly code: string, cause?: Error) {
    super(message, { cause });
    this.name = 'ANPError';
  }
}

export class CryptoError extends ANPError {
  constructor(message: string, cause?: Error) {
    super(message, 'CRYPTO_ERROR', cause);
    this.name = 'CryptoError';
  }
}

export class AuthenticationError extends ANPError {
  constructor(message: string, cause?: Error) {
    super(message, 'AUTHENTICATION_ERROR', cause);
    this.name = 'AuthenticationError';
  }
}

export class ProofError extends ANPError {
  constructor(message: string, cause?: Error) {
    super(message, 'PROOF_ERROR', cause);
    this.name = 'ProofError';
  }
}

export class NetworkError extends ANPError {
  constructor(message: string, public readonly statusCode?: number, cause?: Error) {
    super(message, 'NETWORK_ERROR', cause);
    this.name = 'NetworkError';
  }
}

export class WnsError extends ANPError {
  constructor(message: string, code = 'WNS_ERROR', cause?: Error) {
    super(message, code, cause);
    this.name = 'WnsError';
  }
}

export class HandleValidationError extends WnsError {
  constructor(message: string) {
    super(message, 'HANDLE_VALIDATION_ERROR');
    this.name = 'HandleValidationError';
  }
}

export class HandleResolutionError extends WnsError {
  constructor(message: string, public readonly statusCode?: number, cause?: Error) {
    super(message, 'HANDLE_RESOLUTION_ERROR', cause);
    this.name = 'HandleResolutionError';
  }
}

export class HandleNotFoundError extends HandleResolutionError {
  constructor(message: string) {
    super(message, 404);
    this.name = 'HandleNotFoundError';
  }
}

export class HandleGoneError extends HandleResolutionError {
  constructor(message: string) {
    super(message, 410);
    this.name = 'HandleGoneError';
  }
}

export class HandleMovedError extends HandleResolutionError {
  constructor(message: string, public readonly redirectUrl = '') {
    super(message, 301);
    this.name = 'HandleMovedError';
  }
}

export class HandleBindingError extends WnsError {
  constructor(message: string) {
    super(message, 'HANDLE_BINDING_ERROR');
    this.name = 'HandleBindingError';
  }
}

export class WbaUriParseError extends WnsError {
  constructor(message: string) {
    super(message, 'WBA_URI_PARSE_ERROR');
    this.name = 'WbaUriParseError';
  }
}
