import { authenticationOrigin } from './http-auth-security.js';
import { readFile } from 'node:fs/promises';

import { generateAuthHeader } from './did-wba.js';
import { generateHttpSignatureHeaders } from './http-signatures.js';
import { AuthMode, type DidDocument } from './types.js';

export class DIDWbaAuthHeader {
  private didDocumentCache?: DidDocument;

  private readonly tokens = new Map<string, string>();

  constructor(
    private readonly didDocumentPath: string,
    private readonly privateKeyPath: string,
    private readonly authMode: AuthMode = AuthMode.HttpSignatures
  ) {}

  async getAuthHeaders(
    serverUrl: string,
    forceNew = false,
    method = 'GET',
    headers?: Record<string, string>,
    body?: Uint8Array | string
  ): Promise<Record<string, string>> {
    const domain = extractDomain(serverUrl);
    const origin = authenticationOrigin(serverUrl);
    if (!forceNew) {
      const token = this.tokens.get(origin);
      if (token) {
        return { Authorization: `Bearer ${token}` };
      }
    }

    const [didDocument, privateKeyPem] = await Promise.all([
      this.loadDidDocument(),
      readFile(this.privateKeyPath, 'utf8'),
    ]);

    if (this.authMode === AuthMode.LegacyDidWba) {
      return {
        Authorization: generateAuthHeader(didDocument, domain, privateKeyPem, '1.1'),
      };
    }

    return generateHttpSignatureHeaders(
      didDocument,
      serverUrl,
      method,
      privateKeyPem,
      headers,
      body
    );
  }

  async getAuthHeader(
    serverUrl: string,
    forceNew = false,
    method = 'GET',
    headers?: Record<string, string>,
    body?: Uint8Array | string
  ): Promise<Record<string, string>> {
    return this.getAuthHeaders(serverUrl, forceNew, method, headers, body);
  }

  updateToken(serverUrl: string, headers: Record<string, string>): string | undefined {
    // The caller owns actual authenticated exchange provenance; not discovery.
    const origin = authenticationOrigin(serverUrl);
    if (!origin.startsWith('https://')) return undefined;
    const authenticationInfo = getHeaderCaseInsensitive(headers, 'Authentication-Info');
    if (authenticationInfo) {
      const parsed = parseAuthenticationInfo(authenticationInfo);
      const accessToken = parsed.access_token;
      const tokenType = parsed.token_type ?? 'Bearer';
      if (validBearerToken(accessToken) && tokenType.toLowerCase() === 'bearer') {
        this.tokens.set(origin, accessToken!);
        return accessToken;
      }
    }
    const authorization = getHeaderCaseInsensitive(headers, 'Authorization');
    if (authorization?.startsWith('Bearer ')) {
      const token = authorization.slice(7);
      if (!validBearerToken(token)) return undefined;
      this.tokens.set(origin, token);
      return token;
    }
    return undefined;
  }

  clearToken(serverUrl: string): void {
    this.tokens.delete(authenticationOrigin(serverUrl));
  }

  clearAllTokens(): void {
    this.tokens.clear();
  }

  shouldRetryAfter401(responseHeaders: Record<string, string>): boolean {
    const wwwAuthenticate = getHeaderCaseInsensitive(responseHeaders, 'WWW-Authenticate');
    if (!wwwAuthenticate) {
      return false;
    }
    const challenge = parseWwwAuthenticate(wwwAuthenticate);
    if (challenge.nonce) {
      return true;
    }
    return !['invalid_did', 'invalid_verification_method', 'forbidden_did'].includes(
      challenge.error ?? ''
    );
  }

  async getChallengeAuthHeaders(
    serverUrl: string,
    responseHeaders: Record<string, string>,
    method = 'GET',
    headers?: Record<string, string>,
    body?: Uint8Array | string
  ): Promise<Record<string, string>> {
    const wwwAuthenticate = getHeaderCaseInsensitive(responseHeaders, 'WWW-Authenticate');
    const acceptSignature = getHeaderCaseInsensitive(responseHeaders, 'Accept-Signature');
    const challenge = wwwAuthenticate ? parseWwwAuthenticate(wwwAuthenticate) : {};
    const coveredComponents = normalizeCoveredComponents(
      acceptSignature ? parseAcceptSignature(acceptSignature) : undefined,
      headers,
      body
    );

    const [didDocument, privateKeyPem] = await Promise.all([
      this.loadDidDocument(),
      readFile(this.privateKeyPath, 'utf8'),
    ]);

    if (this.authMode === AuthMode.LegacyDidWba) {
      return {
        Authorization: generateAuthHeader(
          didDocument,
          extractDomain(serverUrl),
          privateKeyPem,
          '1.1',
          {
            nonce: challenge.nonce,
          }
        ),
      };
    }

    return generateHttpSignatureHeaders(
      didDocument,
      serverUrl,
      method,
      privateKeyPem,
      headers,
      body,
      {
        nonce: challenge.nonce,
        coveredComponents,
      }
    );
  }

  async getChallengeAuthHeader(
    serverUrl: string,
    responseHeaders: Record<string, string>,
    method = 'GET',
    headers?: Record<string, string>,
    body?: Uint8Array | string
  ): Promise<Record<string, string>> {
    return this.getChallengeAuthHeaders(serverUrl, responseHeaders, method, headers, body);
  }

  private async loadDidDocument(): Promise<DidDocument> {
    if (!this.didDocumentCache) {
      this.didDocumentCache = JSON.parse(
        await readFile(this.didDocumentPath, 'utf8')
      ) as DidDocument;
    }
    return this.didDocumentCache;
  }
}

function extractDomain(serverUrl: string): string {
  try {
    return new URL(serverUrl).hostname;
  } catch {
    return serverUrl;
  }
}

function getHeaderCaseInsensitive(
  headers: Record<string, string>,
  name: string
): string | undefined {
  const target = name.toLowerCase();
  return Object.entries(headers).find(([key]) => key.toLowerCase() === target)?.[1];
}

function validBearerToken(token: string | undefined): token is string {
  return (
    typeof token === 'string' &&
    token.length > 0 &&
    token.length <= 16384 &&
    /^[A-Za-z0-9._~+/=-]+$/.test(token)
  );
}

function parseAuthenticationInfo(value: string): Record<string, string> {
  const result: Record<string, string> = Object.create(null) as Record<string, string>;
  if (value.length > 16384) return result;
  for (const item of value.split(',')) {
    const index = item.indexOf('=');
    if (index < 1) continue;
    const key = item.slice(0, index).trim().toLowerCase();
    if (Object.hasOwn(result, key)) return Object.create(null) as Record<string, string>;
    result[key] = item
      .slice(index + 1)
      .trim()
      .replace(/^"|"$/g, '');
  }
  return result;
}

function parseWwwAuthenticate(value: string): Record<string, string> {
  const normalized = value.replace(/^DIDWba\s+/i, '').trim();
  const matches = [...normalized.matchAll(/([\w-]+)=("[^"]*"|[^,]+)/g)];
  return matches.reduce<Record<string, string>>((result, match) => {
    result[match[1]] = match[2].trim().replace(/^"|"$/g, '');
    return result;
  }, {});
}

function parseAcceptSignature(value: string): string[] {
  return [...value.matchAll(/"([^"]+)"/g)].map((match) => match[1]);
}

function normalizeCoveredComponents(
  coveredComponents: string[] | undefined,
  headers: Record<string, string> | undefined,
  body: Uint8Array | string | undefined
): string[] | undefined {
  if (!coveredComponents) {
    return undefined;
  }
  const normalizedHeaders = Object.fromEntries(
    Object.entries(headers ?? {}).map(([key, value]) => [key.toLowerCase(), value])
  );
  const bodyPresent =
    body !== undefined &&
    !(
      (typeof body === 'string' && body.length === 0) ||
      (body instanceof Uint8Array && body.byteLength === 0)
    );

  const result = coveredComponents.filter((component) => {
    const normalized = component.toLowerCase();
    if (normalized === 'content-digest' && !bodyPresent) {
      return false;
    }
    if (
      normalized === 'content-length' &&
      !bodyPresent &&
      !('content-length' in normalizedHeaders)
    ) {
      return false;
    }
    if (normalized === 'content-type' && !('content-type' in normalizedHeaders)) {
      return false;
    }
    if (
      !normalized.startsWith('@') &&
      normalized !== 'content-length' &&
      normalized !== 'content-digest' &&
      !(normalized in normalizedHeaders)
    ) {
      return false;
    }
    return true;
  });
  for (const required of ['@method', '@target-uri'])
    if (!result.includes(required)) result.push(required);
  if (bodyPresent && !result.includes('content-digest')) result.push('content-digest');
  return result;
}
