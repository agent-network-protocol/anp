import {
  SignJWT,
  importPKCS8,
  importSPKI,
  jwtVerify,
} from 'jose';
import {
  extractAuthHeaderParts,
  isAuthenticationAuthorized,
  resolveDidWbaDocument,
  validateDidDocumentBinding,
  verifyAuthHeaderSignature,
} from './did-wba.js';
import { extractSignatureMetadata, verifyHttpMessageSignature } from './http-signatures.js';
import type { DidDocument, DidResolutionOptions } from './types.js';

export interface DidWbaVerifierConfig {
  jwtPrivateKey?: string;
  jwtPublicKey?: string;
  jwtAlgorithm?: string;
  accessTokenExpireMinutes?: number;
  nonceExpirationMinutes?: number;
  timestampExpirationMinutes?: number;
  allowedDomains?: string[];
  allowHttpSignatures?: boolean;
  allowLegacyDidwba?: boolean;
  emitAuthenticationInfoHeader?: boolean;
  emitLegacyAuthorizationHeader?: boolean;
  requireNonceForHttpSignatures?: boolean;
  didResolutionOptions?: DidResolutionOptions;
  externalNonceValidator?: (did: string, nonce: string) => boolean | Promise<boolean>;
}

export interface VerificationSuccess {
  did: string;
  authScheme: string;
  responseHeaders: Record<string, string>;
  accessToken?: string;
  tokenType?: 'bearer';
}

export class DidWbaVerifierError extends Error {
  constructor(
    message: string,
    public readonly statusCode = 400,
    public readonly headers: Record<string, string> = {}
  ) {
    super(message);
    this.name = 'DidWbaVerifierError';
  }
}

const DEFAULT_CONFIG: Required<Omit<DidWbaVerifierConfig, 'jwtPrivateKey' | 'jwtPublicKey' | 'allowedDomains' | 'externalNonceValidator' | 'didResolutionOptions'>> = {
  jwtAlgorithm: 'RS256',
  accessTokenExpireMinutes: 60,
  nonceExpirationMinutes: 6,
  timestampExpirationMinutes: 5,
  allowHttpSignatures: true,
  allowLegacyDidwba: true,
  emitAuthenticationInfoHeader: true,
  emitLegacyAuthorizationHeader: true,
  requireNonceForHttpSignatures: true,
};

export class DidWbaVerifier {
  private readonly config: DidWbaVerifierConfig;

  private readonly usedNonces = new Map<string, Date>();

  constructor(config: DidWbaVerifierConfig = {}) {
    this.config = {
      ...DEFAULT_CONFIG,
      ...config,
    };
  }

  async verifyRequest(
    method: string,
    url: string,
    headers: Record<string, string>,
    body?: Uint8Array | string | null,
    domain?: string
  ): Promise<VerificationSuccess> {
    return this.verifyRequestWithOptionalDidDocument(method, url, headers, body, domain);
  }

  async verifyRequestWithDidDocument(
    method: string,
    url: string,
    headers: Record<string, string>,
    didDocument: DidDocument,
    body?: Uint8Array | string | null,
    domain?: string
  ): Promise<VerificationSuccess> {
    return this.verifyRequestWithOptionalDidDocument(method, url, headers, body, domain, didDocument);
  }

  private async verifyRequestWithOptionalDidDocument(
    method: string,
    url: string,
    headers: Record<string, string>,
    body?: Uint8Array | string | null,
    domain?: string,
    didDocument?: DidDocument
  ): Promise<VerificationSuccess> {
    const requestDomain = domain ?? extractDomainFromUrl(url);
    this.validateAllowedDomain(requestDomain);
    const authHeader = getHeaderCaseInsensitive(headers, 'Authorization');

    if (authHeader?.startsWith('Bearer ')) {
      return this.handleBearerAuth(authHeader);
    }

    if (
      getHeaderCaseInsensitive(headers, 'Signature-Input') ||
      getHeaderCaseInsensitive(headers, 'Signature')
    ) {
      if (!this.config.allowHttpSignatures) {
        throw this.challengeError(
          'HTTP Message Signatures authentication is disabled',
          401,
          requestDomain,
          'invalid_request'
        );
      }
      return this.handleHttpSignatureAuth(method, url, headers, body, requestDomain, didDocument);
    }

    if (authHeader) {
      if (!this.config.allowLegacyDidwba) {
        throw this.challengeError(
          'Legacy DIDWba authentication is disabled',
          401,
          requestDomain,
          'invalid_request'
        );
      }
      return this.handleLegacyDidAuth(authHeader, requestDomain, didDocument);
    }

    throw new DidWbaVerifierError('Missing authentication headers', 401);
  }

  private async handleHttpSignatureAuth(
    method: string,
    url: string,
    headers: Record<string, string>,
    body: Uint8Array | string | null | undefined,
    domain: string,
    providedDidDocument?: DidDocument
  ): Promise<VerificationSuccess> {
    const metadata = extractSignatureMetadata(headers);
    if (!metadata.keyid.includes('#')) {
      throw this.challengeError(
        'Invalid Signature-Input keyid',
        401,
        domain,
        'invalid_verification_method'
      );
    }

    const did = metadata.keyid.split('#', 1)[0];
    const didDocument =
      providedDidDocument ??
      (await resolveDidWbaDocument(did, false, this.config.didResolutionOptions));

    if (!validateDidDocumentBinding(didDocument, true)) {
      throw this.challengeError('DID binding verification failed', 401, domain, 'invalid_did');
    }
    if (!isAuthenticationAuthorized(didDocument, metadata.keyid)) {
      throw new DidWbaVerifierError(
        'Verification method is not authorized for authentication',
        403
      );
    }

    const verification = verifyHttpMessageSignature(didDocument, method, url, headers, body ?? undefined);
    if (!this.verifyHttpSignatureTimeWindow(verification.created, verification.expires)) {
      throw this.challengeError(
        'HTTP signature timestamp is expired or invalid',
        401,
        domain,
        'invalid_timestamp'
      );
    }
    if (this.config.requireNonceForHttpSignatures && !verification.nonce) {
      throw this.challengeError('HTTP signature nonce is required', 401, domain, 'invalid_nonce');
    }
    if (verification.nonce && !(await this.isValidServerNonce(did, verification.nonce))) {
      throw this.challengeError('Invalid or expired nonce', 401, domain, 'invalid_nonce');
    }

    const accessToken = await this.createAccessToken(did);
    return this.buildSuccessResult(did, 'http_signatures', accessToken);
  }

  private async handleLegacyDidAuth(
    authorization: string,
    domain: string,
    providedDidDocument?: DidDocument
  ): Promise<VerificationSuccess> {
    const parsed = extractAuthHeaderParts(authorization);
    if (!this.verifyLegacyTimestamp(parsed.timestamp)) {
      throw this.challengeError('Timestamp expired or invalid', 401, domain, 'invalid_timestamp');
    }
    if (!(await this.isValidServerNonce(parsed.did, parsed.nonce))) {
      throw this.challengeError('Invalid or expired nonce', 401, domain, 'invalid_nonce');
    }

    const didDocument =
      providedDidDocument ??
      (await resolveDidWbaDocument(parsed.did, false, this.config.didResolutionOptions));

    if (!validateDidDocumentBinding(didDocument, true)) {
      throw this.challengeError('DID binding verification failed', 401, domain, 'invalid_did');
    }

    const keyid = `${parsed.did}#${parsed.verificationMethod}`;
    if (!isAuthenticationAuthorized(didDocument, keyid)) {
      throw new DidWbaVerifierError(
        'Verification method is not authorized for authentication',
        403
      );
    }

    try {
      verifyAuthHeaderSignature(authorization, didDocument, domain);
    } catch (error) {
      throw this.challengeError(
        `Error verifying signature: ${(error as Error).message}`,
        401,
        domain,
        'invalid_signature'
      );
    }

    const accessToken = await this.createAccessToken(parsed.did);
    return this.buildSuccessResult(parsed.did, 'legacy_didwba', accessToken);
  }

  private async handleBearerAuth(authorization: string): Promise<VerificationSuccess> {
    if (!this.config.jwtPublicKey) {
      throw new DidWbaVerifierError(
        'Internal server error during token verification',
        500
      );
    }

    const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : authorization;
    const verifyKey = await importVerifyKey(this.config.jwtPublicKey, this.config.jwtAlgorithm ?? 'RS256');
    const result = await jwtVerify(token, verifyKey, {
      algorithms: [this.config.jwtAlgorithm ?? 'RS256'],
    }).catch(() => {
      throw new DidWbaVerifierError('Invalid token', 401);
    });

    const did = result.payload.sub;
    if (!did || !did.startsWith('did:wba:')) {
      throw new DidWbaVerifierError('Invalid DID format', 401);
    }

    return {
      did,
      authScheme: 'bearer',
      responseHeaders: {},
      accessToken: token,
      tokenType: 'bearer',
    };
  }

  private async createAccessToken(did: string): Promise<string | undefined> {
    if (!this.config.jwtPrivateKey) {
      return undefined;
    }

    const algorithm = this.config.jwtAlgorithm ?? 'RS256';
    const signingKey = await importSigningKey(this.config.jwtPrivateKey, algorithm);
    return new SignJWT({})
      .setProtectedHeader({ alg: algorithm })
      .setSubject(did)
      .setIssuedAt()
      .setExpirationTime(`${this.config.accessTokenExpireMinutes ?? 60}m`)
      .sign(signingKey);
  }

  private buildSuccessResult(
    did: string,
    authScheme: string,
    accessToken?: string
  ): VerificationSuccess {
    const responseHeaders: Record<string, string> = {};
    if (accessToken) {
      const expiresInSeconds = (this.config.accessTokenExpireMinutes ?? 60) * 60;
      if (this.config.emitAuthenticationInfoHeader !== false) {
        responseHeaders['Authentication-Info'] =
          `access_token="${accessToken}", token_type="Bearer", expires_in=${expiresInSeconds}`;
      }
      if (this.config.emitLegacyAuthorizationHeader !== false) {
        responseHeaders.Authorization = `Bearer ${accessToken}`;
      }
    }

    return {
      did,
      authScheme,
      responseHeaders,
      accessToken,
      tokenType: accessToken ? 'bearer' : undefined,
    };
  }

  private verifyLegacyTimestamp(timestamp: string): boolean {
    const requestTime = new Date(timestamp);
    if (Number.isNaN(requestTime.getTime())) {
      return false;
    }
    const now = Date.now();
    if (requestTime.getTime() - now > 60_000) {
      return false;
    }
    return now - requestTime.getTime() <= (this.config.timestampExpirationMinutes ?? 5) * 60_000;
  }

  private verifyHttpSignatureTimeWindow(created: number, expires?: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    if (created > now + 60) {
      return false;
    }
    if (now - created > (this.config.timestampExpirationMinutes ?? 5) * 60) {
      return false;
    }
    return expires === undefined || expires >= now;
  }

  private async isValidServerNonce(did: string, nonce: string): Promise<boolean> {
    if (this.config.externalNonceValidator) {
      return Boolean(await this.config.externalNonceValidator(did, nonce));
    }

    const expirationMs = (this.config.nonceExpirationMinutes ?? 6) * 60_000;
    const now = Date.now();
    for (const [key, createdAt] of this.usedNonces.entries()) {
      if (now - createdAt.getTime() > expirationMs) {
        this.usedNonces.delete(key);
      }
    }

    const cacheKey = `${did}:${nonce}`;
    if (this.usedNonces.has(cacheKey)) {
      return false;
    }
    this.usedNonces.set(cacheKey, new Date(now));
    return true;
  }

  private validateAllowedDomain(domain: string): void {
    if (this.config.allowedDomains && !this.config.allowedDomains.includes(domain)) {
      throw new DidWbaVerifierError('Domain is not allowed', 403);
    }
  }

  private challengeError(
    message: string,
    statusCode: number,
    domain: string,
    error: string
  ): DidWbaVerifierError {
    const headers: Record<string, string> = {
      'WWW-Authenticate': `DIDWba realm="${domain}", error="${error}", error_description="${message}"`,
    };
    if (this.config.allowHttpSignatures !== false) {
      headers['Accept-Signature'] =
        'sig1=("@method" "@target-uri" "@authority" "content-digest");created;expires;nonce;keyid';
    }
    return new DidWbaVerifierError(message, statusCode, headers);
  }
}

function getHeaderCaseInsensitive(headers: Record<string, string>, name: string): string | undefined {
  const target = name.toLowerCase();
  return Object.entries(headers).find(([key]) => key.toLowerCase() === target)?.[1];
}

function extractDomainFromUrl(url: string): string {
  return new URL(url).hostname;
}

async function importSigningKey(key: string, algorithm: string) {
  if (algorithm.startsWith('HS')) {
    return new TextEncoder().encode(key);
  }
  return importPKCS8(key, algorithm);
}

async function importVerifyKey(key: string, algorithm: string) {
  if (algorithm.startsWith('HS')) {
    return new TextEncoder().encode(key);
  }
  return importSPKI(key, algorithm);
}
