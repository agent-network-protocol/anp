import { SignJWT, importPKCS8, importSPKI, jwtVerify } from 'jose';
import {
  extractAuthHeaderParts,
  isAuthenticationAuthorized,
  validateDidDocumentBinding,
  verifyAuthHeaderSignature,
} from './did-wba.js';
import {
  extractSignatureMetadata,
  verifyHttpMessageSignature,
  httpSignatureReplayContext,
} from './http-signatures.js';
import type { DidDocument, DidResolutionOptions, DidResolver } from './types.js';
import { resolveDidDocument, validateDidDocumentMethod } from './did-resolver.js';
import {
  consumeHttpReplay,
  MemoryHttpReplayStore,
  replayDigest,
  defaultAuthClock,
  validateHttpSignatureTime,
  type HttpReplayStore,
  type HttpReplayConsumer,
  type HttpReplayContext,
  type HttpSignaturePolicy,
} from './http-auth-security.js';

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
  didResolver?: DidResolver;
  externalNonceValidator?: (did: string, nonce: string) => boolean | Promise<boolean>;
  replayStore?: HttpReplayStore | HttpReplayConsumer;
  verifierScope?: string;
  /** Epoch seconds. Configure before processing concurrent requests. */
  clock?: () => number;
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

const DEFAULT_CONFIG: Required<
  Omit<
    DidWbaVerifierConfig,
    | 'jwtPrivateKey'
    | 'jwtPublicKey'
    | 'allowedDomains'
    | 'externalNonceValidator'
    | 'didResolutionOptions'
    | 'didResolver'
    | 'replayStore'
    | 'verifierScope'
    | 'clock'
  >
> = {
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

  private readonly replayStore: HttpReplayStore | HttpReplayConsumer;

  constructor(config: DidWbaVerifierConfig = {}) {
    this.config = {
      ...DEFAULT_CONFIG,
      ...config,
    };
    this.replayStore = config.replayStore ?? new MemoryHttpReplayStore(10000, () => this.now());
  }

  private now(): number {
    return this.config.clock === undefined ? defaultAuthClock() : this.config.clock();
  }
  private httpPolicy(): HttpSignaturePolicy {
    return { maxAgeSeconds: (this.config.timestampExpirationMinutes ?? 5) * 60 };
  }
  private async consumeReplay(context: HttpReplayContext, nonce?: string): Promise<boolean> {
    try {
      if (
        this.config.replayStore === undefined &&
        this.config.externalNonceValidator &&
        nonce !== undefined
      ) {
        const result = await this.config.externalNonceValidator(context.signerDid, nonce);
        if (typeof result !== 'boolean') throw new Error('Invalid callback result');
        return result;
      }
      return await consumeHttpReplay(this.replayStore, context);
    } catch {
      throw new DidWbaVerifierError('Replay protection unavailable', 503);
    }
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
    return this.verifyRequestWithOptionalDidDocument(
      method,
      url,
      headers,
      body,
      domain,
      didDocument
    );
  }

  private async verifyRequestWithOptionalDidDocument(
    method: string,
    url: string,
    headers: Record<string, string>,
    body?: Uint8Array | string | null,
    domain?: string,
    didDocument?: DidDocument
  ): Promise<VerificationSuccess> {
    if (
      new Set(Object.keys(headers).map((key) => key.toLowerCase())).size !==
      Object.keys(headers).length
    )
      throw new DidWbaVerifierError('Ambiguous duplicate HTTP header', 401);
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

    throw this.challengeError(
      'Missing authentication headers',
      401,
      requestDomain,
      'invalid_request'
    );
  }

  private async handleHttpSignatureAuth(
    method: string,
    url: string,
    headers: Record<string, string>,
    body: Uint8Array | string | null | undefined,
    domain: string,
    providedDidDocument?: DidDocument
  ): Promise<VerificationSuccess> {
    let metadata: ReturnType<typeof extractSignatureMetadata>;
    try {
      metadata = extractSignatureMetadata(headers);
    } catch (error) {
      throw this.challengeError(
        `Invalid signature metadata: ${(error as Error).message}`,
        401,
        domain,
        'invalid_request'
      );
    }
    if (!metadata.keyid.includes('#')) {
      throw this.challengeError(
        'Invalid Signature-Input keyid',
        401,
        domain,
        'invalid_verification_method'
      );
    }

    if (!this.verifyHttpSignatureTimeWindow(metadata.created, metadata.expires))
      throw this.challengeError(
        'HTTP signature timestamp is expired or invalid',
        401,
        domain,
        'invalid_timestamp'
      );
    const did = metadata.keyid.split('#', 1)[0];
    const didDocument = providedDidDocument ?? (await this.resolveDidDocument(did, domain));

    if (
      didDocument.id !== did ||
      (did.startsWith('did:wba:')
        ? !validateDidDocumentBinding(didDocument, true)
        : !validateDidDocumentMethod(didDocument))
    ) {
      throw this.challengeError('DID binding verification failed', 401, domain, 'invalid_did');
    }
    if (!isAuthenticationAuthorized(didDocument, metadata.keyid)) {
      throw new DidWbaVerifierError(
        'Verification method is not authorized for authentication',
        403
      );
    }

    let verification: ReturnType<typeof verifyHttpMessageSignature>;
    try {
      verification = verifyHttpMessageSignature(
        didDocument,
        method,
        url,
        headers,
        body ?? undefined,
        { policy: this.httpPolicy(), now: this.now() }
      );
    } catch (error) {
      throw this.challengeError((error as Error).message, 401, domain, 'invalid_signature');
    }
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
    const replay = httpSignatureReplayContext(
      verification,
      method,
      url,
      headers,
      this.config.verifierScope,
      this.httpPolicy()
    );
    if (!(await this.consumeReplay(replay, verification.nonce))) {
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
    let parsed: ReturnType<typeof extractAuthHeaderParts>;
    try {
      parsed = extractAuthHeaderParts(authorization);
    } catch (error) {
      throw this.challengeError(
        `Invalid authorization header format: ${(error as Error).message}`,
        401,
        domain,
        'invalid_request'
      );
    }
    if (!this.verifyLegacyTimestamp(parsed.timestamp)) {
      throw this.challengeError('Timestamp expired or invalid', 401, domain, 'invalid_timestamp');
    }
    const didDocument = providedDidDocument ?? (await this.resolveDidDocument(parsed.did, domain));

    if (didDocument.id !== parsed.did || !validateDidDocumentBinding(didDocument, true)) {
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

    const scope = this.config.verifierScope ?? `legacy:${domain}`;
    const context: HttpReplayContext = {
      signerDid: parsed.did,
      verifierScope: scope,
      replayKey: replayDigest(['anp.legacy-auth.replay.v1', scope, parsed.did, parsed.nonce]),
      validUntil:
        Math.floor(new Date(parsed.timestamp).getTime() / 1000) +
        Math.max(
          this.config.nonceExpirationMinutes ?? 6,
          this.config.timestampExpirationMinutes ?? 5
        ) *
          60 +
        60,
    };
    if (!(await this.consumeReplay(context, parsed.nonce)))
      throw this.challengeError('Invalid or expired nonce', 401, domain, 'invalid_nonce');
    const accessToken = await this.createAccessToken(parsed.did);
    return this.buildSuccessResult(parsed.did, 'legacy_didwba', accessToken);
  }

  private async handleBearerAuth(authorization: string): Promise<VerificationSuccess> {
    if (!this.config.jwtPublicKey) {
      throw new DidWbaVerifierError('Internal server error during token verification', 500);
    }

    const token = authorization.startsWith('Bearer ') ? authorization.slice(7) : authorization;
    const verifyKey = await importVerifyKey(
      this.config.jwtPublicKey,
      this.config.jwtAlgorithm ?? 'RS256'
    );
    const result = await jwtVerify(token, verifyKey, {
      algorithms: [this.config.jwtAlgorithm ?? 'RS256'],
    }).catch(() => {
      throw new DidWbaVerifierError('Invalid token', 401);
    });

    const did = result.payload.sub;
    if (!did || !(did.startsWith('did:wba:') || did.startsWith('did:web:'))) {
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
    const now = this.now() * 1000;
    if (!Number.isSafeInteger(now) || now < 0) return false;
    if (requestTime.getTime() - now > 60_000) {
      return false;
    }
    return now - requestTime.getTime() <= (this.config.timestampExpirationMinutes ?? 5) * 60_000;
  }

  private verifyHttpSignatureTimeWindow(created: number, expires?: number): boolean {
    try {
      validateHttpSignatureTime(created, expires, this.httpPolicy(), this.now());
      return true;
    } catch {
      return false;
    }
  }

  private async resolveDidDocument(did: string, domain: string): Promise<DidDocument> {
    try {
      const resolved = this.config.didResolver
        ? await this.config.didResolver(did)
        : await resolveDidDocument(did, false, this.config.didResolutionOptions);
      if (!resolved) {
        throw this.challengeError('Failed to resolve DID document', 401, domain, 'invalid_did');
      }
      return resolved;
    } catch (error) {
      if (error instanceof DidWbaVerifierError) {
        throw error;
      }
      throw this.challengeError(
        `Failed to resolve DID document: ${(error as Error).message}`,
        401,
        domain,
        'invalid_did'
      );
    }
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

function getHeaderCaseInsensitive(
  headers: Record<string, string>,
  name: string
): string | undefined {
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
