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
    if (!forceNew) {
      const token = this.tokens.get(domain);
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

    return generateHttpSignatureHeaders(didDocument, serverUrl, method, privateKeyPem, headers, body);
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
    const domain = extractDomain(serverUrl);
    const authenticationInfo = getHeaderCaseInsensitive(headers, 'Authentication-Info');
    if (authenticationInfo) {
      const parsed = parseAuthenticationInfo(authenticationInfo);
      const accessToken = parsed.access_token;
      if (accessToken) {
        this.tokens.set(domain, accessToken);
        return accessToken;
      }
    }
    const authorization = getHeaderCaseInsensitive(headers, 'Authorization');
    if (authorization?.startsWith('Bearer ')) {
      const token = authorization.slice(7);
      this.tokens.set(domain, token);
      return token;
    }
    return undefined;
  }

  clearToken(serverUrl: string): void {
    this.tokens.delete(extractDomain(serverUrl));
  }

  clearAllTokens(): void {
    this.tokens.clear();
  }

  private async loadDidDocument(): Promise<DidDocument> {
    if (!this.didDocumentCache) {
      this.didDocumentCache = JSON.parse(await readFile(this.didDocumentPath, 'utf8')) as DidDocument;
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

function getHeaderCaseInsensitive(headers: Record<string, string>, name: string): string | undefined {
  const target = name.toLowerCase();
  return Object.entries(headers).find(([key]) => key.toLowerCase() === target)?.[1];
}

function parseAuthenticationInfo(value: string): Record<string, string> {
  return value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
    .reduce<Record<string, string>>((result, item) => {
      const [key, rawValue] = item.split('=', 2);
      if (key && rawValue) {
        result[key.trim()] = rawValue.trim().replace(/^"|"$/g, '');
      }
      return result;
    }, {});
}
