import { randomBytes, randomUUID } from 'node:crypto';

import { generateHttpSignatureHeaders } from '../authentication/http-signatures.js';
import type { DidDocument } from '../authentication/types.js';
import { buildImContentDigest, buildImSignatureInput, encodeImSignature } from '../proof/im.js';
import { canonicalizeJson } from '../internal/json.js';
import { normalizePrivateKeyMaterial, signMessage } from '../internal/keys.js';
import { AwikiImError, awikiImRemoteError, normalizeAwikiImError } from './errors.js';
import type { JsonRpcErrorValue } from './internal.js';

/** User Service handle RPC path used by the AWiki Core client. */
export const HANDLE_RPC_PATH = '/user-service/v1/handle/rpc';
/** User Service DID authentication RPC path used by the AWiki Core client. */
export const DID_AUTH_RPC_PATH = '/user-service/v1/did-auth/rpc';
/** User Service DID profile RPC path used for authenticated profile changes. */
export const DID_PROFILE_RPC_PATH = '/user-service/v1/did/profile/rpc';
/** Local Message Service RPC path used by the AWiki Core client. */
export const MESSAGE_RPC_PATH = '/im/rpc';

export interface RpcAuthentication {
  readonly accessToken?: string;
  readonly didDocument: DidDocument;
  readonly signingPrivateKeyPem: string;
  readonly signingKeyId: string;
}

export interface RpcResult {
  readonly value: Record<string, unknown>;
  readonly accessToken?: string;
}

interface AwikiImTransportOptions {
  readonly allowedAttachmentOrigins: readonly string[];
  readonly allowInsecureLoopback: boolean;
  readonly attachmentMaxBytes: number;
}

const MAX_RPC_RESPONSE_BYTES = 1024 * 1024;
const MAX_DID_DOCUMENT_BYTES = 512 * 1024;
const REQUEST_TIMEOUT_MS = 30_000;

/** Fetch transport with JSON-RPC validation, signed authentication, and disposal. */
export class AwikiImTransport {
  private readonly controllers = new Set<AbortController>();
  private readonly allowedAttachmentOrigins: ReadonlySet<string>;
  private disposed = false;

  public constructor(
    private readonly fetchImpl: typeof globalThis.fetch,
    private readonly options: AwikiImTransportOptions
  ) {
    this.allowedAttachmentOrigins = new Set(
      options.allowedAttachmentOrigins.map((value) =>
        normalizeAllowedOrigin(value, options.allowInsecureLoopback)
      )
    );
  }

  /** Execute an unsigned or bearer-authenticated JSON-RPC request. */
  public async rpc(
    baseUrl: string,
    path: string,
    method: string,
    params: Record<string, unknown>,
    accessToken?: string
  ): Promise<RpcResult> {
    const url = joinServiceUrl(baseUrl, path, this.options.allowInsecureLoopback);
    const request = encodeJsonRpc(method, params);
    const body = request.body;
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (accessToken) {
      headers.Authorization = `Bearer ${accessToken}`;
    }
    return this.executeRpc(url, body, headers, request.id);
  }

  /** Execute a DID HTTP-Signature-authenticated JSON-RPC request. */
  public async signedRpc(
    baseUrl: string,
    path: string,
    method: string,
    params: Record<string, unknown>,
    authentication: RpcAuthentication
  ): Promise<RpcResult> {
    const url = joinServiceUrl(baseUrl, path, this.options.allowInsecureLoopback);
    const request = encodeJsonRpc(method, params);
    const body = request.body;
    const baseHeaders = { 'Content-Type': 'application/json' };
    let headers = {
      ...baseHeaders,
      ...generateHttpSignatureHeaders(
        authentication.didDocument,
        url,
        'POST',
        authentication.signingPrivateKeyPem,
        baseHeaders,
        body,
        { keyid: authentication.signingKeyId }
      ),
    };
    const result = await this.withResponse(
      url,
      {
        method: 'POST',
        headers,
        body,
        redirect: 'error',
      },
      async (response) => {
        if (response.status !== 401) {
          return {
            kind: 'result' as const,
            value: await decodeRpcResponse(response, request.id),
          };
        }
        const nonce = parseAuthenticationParameter(
          response.headers.get('www-authenticate') ?? '',
          'nonce'
        );
        await response.body?.cancel();
        return { kind: 'challenge' as const, nonce };
      }
    );
    if (result.kind === 'challenge' && result.nonce) {
      headers = {
        ...baseHeaders,
        ...generateHttpSignatureHeaders(
          authentication.didDocument,
          url,
          'POST',
          authentication.signingPrivateKeyPem,
          baseHeaders,
          body,
          { keyid: authentication.signingKeyId, nonce: result.nonce }
        ),
      };
      return this.withResponse(
        url,
        {
          method: 'POST',
          headers,
          body,
          redirect: 'error',
        },
        (response) => decodeRpcResponse(response, request.id)
      );
    }
    if (result.kind === 'challenge') {
      throw awikiImRemoteError({ status: 401 });
    }
    return result.value;
  }

  /** Upload one object without following redirects. */
  public async putBytes(
    url: string,
    headers: Readonly<Record<string, string>>,
    bytes: Uint8Array
  ): Promise<void> {
    this.validateAttachmentUrl(url);
    await this.withResponse(
      url,
      {
        method: 'PUT',
        headers: { ...headers },
        body: Buffer.from(bytes),
        redirect: 'error',
      },
      async (response) => {
        if (!response.ok) {
          await response.body?.cancel();
          throw awikiImRemoteError({ status: response.status });
        }
        await response.body?.cancel();
      }
    );
  }

  /** Read one public JSON document without following redirects. */
  public async getJson(url: string): Promise<Record<string, unknown>> {
    this.validateAttachmentUrl(url);
    return this.withResponse(
      url,
      {
        method: 'GET',
        headers: { Accept: 'application/json' },
        redirect: 'error',
      },
      async (response) => {
        if (!response.ok) {
          await response.body?.cancel();
          throw awikiImRemoteError({ status: response.status });
        }
        const value = parseJson(await readCappedBody(response, MAX_DID_DOCUMENT_BYTES));
        if (!isRecord(value)) {
          throw new AwikiImError('remote', 'AWiki service returned an invalid response');
        }
        return value;
      }
    );
  }

  /** Download one object without following redirects. */
  public async getBytes(
    url: string,
    bearerToken: string,
    expectedSize: number
  ): Promise<Uint8Array> {
    if (
      !Number.isSafeInteger(expectedSize) ||
      expectedSize < 0 ||
      expectedSize > this.options.attachmentMaxBytes
    ) {
      throw new AwikiImError('invalid-request', 'AWiki attachment size is invalid');
    }
    this.validateAttachmentUrl(url);
    return this.withResponse(
      url,
      {
        method: 'GET',
        headers: { Authorization: `Bearer ${bearerToken}` },
        redirect: 'error',
      },
      async (response) => {
        if (!response.ok) {
          await response.body?.cancel();
          throw awikiImRemoteError({ status: response.status });
        }
        const declaredLength = contentLength(response.headers);
        if (declaredLength !== undefined && declaredLength !== expectedSize) {
          await response.body?.cancel();
          throw new AwikiImError('remote', 'AWiki attachment verification failed');
        }
        return readCappedBody(response, expectedSize);
      }
    );
  }

  /** Validate an untrusted DID, service, upload, or object URL against the operator allowlist. */
  public validateAttachmentUrl(value: string): URL {
    const url = validateServiceBaseUrl(value, this.options.allowInsecureLoopback);
    if (!this.allowedAttachmentOrigins.has(url.origin)) {
      throw new AwikiImError('forbidden', 'AWiki attachment origin is not permitted');
    }
    return url;
  }

  /** Abort every owned request and reject future work. */
  public dispose(): void {
    this.disposed = true;
    for (const controller of this.controllers) {
      controller.abort();
    }
    this.controllers.clear();
  }

  private async executeRpc(
    url: string,
    body: string,
    headers: Record<string, string>,
    requestId: string
  ): Promise<RpcResult> {
    return this.withResponse(
      url,
      {
        method: 'POST',
        headers,
        body,
        redirect: 'error',
      },
      (response) => decodeRpcResponse(response, requestId)
    );
  }

  private async withResponse<T>(
    input: string,
    init: RequestInit,
    consume: (response: Response) => Promise<T>
  ): Promise<T> {
    if (this.disposed) {
      throw new AwikiImError('remote', 'AWiki IM client has been disposed');
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    this.controllers.add(controller);
    try {
      const response = await this.fetchImpl(input, { ...init, signal: controller.signal });
      return await consume(response);
    } catch (error) {
      if (this.disposed) {
        throw new AwikiImError('remote', 'AWiki IM client has been disposed');
      }
      throw normalizeAwikiImError(error);
    } finally {
      clearTimeout(timeout);
      this.controllers.delete(controller);
    }
  }
}

/** Build the origin proof required by Direct and Group send operations. */
export function buildOriginAuthentication(input: {
  readonly method: string;
  readonly meta: Record<string, unknown>;
  readonly body: Record<string, unknown>;
  readonly signingPrivateKeyPem: string;
  readonly signingKeyId: string;
}): Record<string, unknown> {
  const target = input.meta.target;
  if (!isRecord(target)) {
    throw new AwikiImError('invalid-request', 'AWiki message target is invalid');
  }
  const kind = requiredString(target.kind, 'target kind');
  const did = requiredString(target.did, 'target DID');
  if (kind !== 'agent' && kind !== 'group' && kind !== 'service') {
    throw new AwikiImError('invalid-request', 'AWiki message target is invalid');
  }
  const canonicalRequest = canonicalizeJson({
    method: input.method,
    meta: input.meta,
    body: input.body,
  });
  const signatureInput = buildImSignatureInput(input.signingKeyId, {
    label: 'sig1',
    components: ['@method', '@target-uri', 'content-digest'],
  });
  const contentDigest = buildImContentDigest(canonicalRequest);
  const targetUri = `anp://${kind}/${encodeRfc3986(did)}`;
  const signatureParams = signatureInput.slice(signatureInput.indexOf('=') + 1);
  const signatureBase = [
    `"@method": ${input.method}`,
    `"@target-uri": ${targetUri}`,
    `"content-digest": ${contentDigest}`,
    `"@signature-params": ${signatureParams}`,
  ].join('\n');
  const signature = signMessage(
    normalizePrivateKeyMaterial(input.signingPrivateKeyPem),
    new TextEncoder().encode(signatureBase)
  );
  return {
    scheme: 'anp-rfc9421-origin-proof-v1',
    origin_proof: {
      contentDigest,
      signatureInput,
      signature: encodeImSignature(signature, 'sig1'),
    },
  };
}

export function joinServiceUrl(
  baseUrl: string,
  path: string,
  allowInsecureLoopback = false
): string {
  const base = validateServiceBaseUrl(baseUrl, allowInsecureLoopback);
  return new URL(`/${path.replace(/^\/+/, '')}`, base).toString();
}

export function validateServiceBaseUrl(value: string, allowInsecureLoopback = false): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch (error) {
    throw new AwikiImError('invalid-request', 'AWiki service URL is invalid', undefined, {
      cause: error,
    });
  }
  if (
    url.username ||
    url.password ||
    (url.protocol !== 'https:' &&
      !(allowInsecureLoopback && url.protocol === 'http:' && isLoopback(url.hostname)))
  ) {
    throw new AwikiImError('invalid-request', 'AWiki service URL is invalid');
  }
  return url;
}

export function operationId(prefix: 'op' | 'msg' | 'att'): string {
  return `${prefix}-${randomUUID()}`;
}

export function randomChallenge(): string {
  return randomBytes(16).toString('hex');
}

function encodeJsonRpc(
  method: string,
  params: Record<string, unknown>
): { readonly id: string; readonly body: string } {
  const id = randomUUID();
  return { id, body: JSON.stringify({ jsonrpc: '2.0', id, method, params }) };
}

async function decodeRpcResponse(response: Response, expectedId: string): Promise<RpcResult> {
  let decoded: unknown;
  try {
    decoded = parseJson(await readCappedBody(response, MAX_RPC_RESPONSE_BYTES));
  } catch (error) {
    if (!response.ok) {
      throw awikiImRemoteError({ status: response.status });
    }
    throw new AwikiImError(
      'remote',
      'AWiki service returned an invalid response',
      response.status,
      {
        cause: error,
      }
    );
  }
  if (!isRecord(decoded)) {
    throw new AwikiImError('remote', 'AWiki service returned an invalid response', response.status);
  }
  const hasResult = Object.hasOwn(decoded, 'result') && decoded.result !== null;
  const hasError = Object.hasOwn(decoded, 'error') && decoded.error !== null;
  if (decoded.jsonrpc !== '2.0' || decoded.id !== expectedId || hasResult === hasError) {
    throw new AwikiImError(
      'remote',
      'AWiki JSON-RPC response envelope is invalid',
      response.status
    );
  }
  if (hasError && !isRecord(decoded.error)) {
    throw new AwikiImError(
      'remote',
      'AWiki JSON-RPC response envelope is invalid',
      response.status
    );
  }
  const rpcError = hasError ? (decoded.error as JsonRpcErrorValue) : undefined;
  if (!response.ok || rpcError !== undefined) {
    throw awikiImRemoteError({
      status: response.status,
      rpcCode: numberValue(rpcError?.code),
      serviceCode: serviceErrorCode(rpcError?.data),
      message: stringValue(rpcError?.message),
    });
  }
  if (!isRecord(decoded.result)) {
    throw new AwikiImError('remote', 'AWiki service returned an invalid response', response.status);
  }
  return {
    value: decoded.result,
    accessToken: responseAccessToken(response.headers) ?? stringValue(decoded.result.access_token),
  };
}

function responseAccessToken(headers: Headers): string | undefined {
  const authenticationInfo = headers.get('authentication-info') ?? '';
  return parseAuthenticationParameter(authenticationInfo, 'access_token');
}

function parseAuthenticationParameter(value: string, key: string): string | undefined {
  const match = value.match(new RegExp(`(?:^|[,\\s])${key}=(?:"([^"]+)"|([^,\\s]+))`, 'i'));
  return (match?.[1] ?? match?.[2])?.trim() || undefined;
}

function serviceErrorCode(data: unknown): string | undefined {
  if (!isRecord(data)) {
    return undefined;
  }
  for (const key of ['awiki_code', 'anp_code', 'code']) {
    const value = stringValue(data[key]);
    if (value) {
      return value;
    }
  }
  return undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function requiredString(value: unknown, label: string): string {
  const result = stringValue(value);
  if (!result) {
    throw new AwikiImError('invalid-request', `AWiki ${label} is required`);
  }
  return result;
}

function normalizeAllowedOrigin(value: string, allowInsecureLoopback: boolean): string {
  const url = validateServiceBaseUrl(value, allowInsecureLoopback);
  if (url.pathname !== '/' || url.search || url.hash) {
    throw new AwikiImError('invalid-request', 'AWiki attachment origin is invalid');
  }
  return url.origin;
}

function isLoopback(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
}

async function readCappedBody(response: Response, maximumBytes: number): Promise<Uint8Array> {
  const declaredLength = contentLength(response.headers);
  if (declaredLength !== undefined && declaredLength > maximumBytes) {
    await response.body?.cancel();
    throw new AwikiImError('remote', 'AWiki response exceeds the permitted size');
  }
  if (!response.body) {
    return new Uint8Array();
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    let part = await reader.read();
    while (!part.done) {
      total += part.value.byteLength;
      if (total > maximumBytes) {
        await reader.cancel();
        throw new AwikiImError('remote', 'AWiki response exceeds the permitted size');
      }
      chunks.push(part.value);
      part = await reader.read();
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function contentLength(headers: Headers): number | undefined {
  const raw = headers.get('content-length');
  if (raw === null) {
    return undefined;
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new AwikiImError('remote', 'AWiki response has an invalid Content-Length');
  }
  return value;
}

function parseJson(bytes: Uint8Array): unknown {
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
  } catch (error) {
    throw new AwikiImError('remote', 'AWiki service returned an invalid response', undefined, {
      cause: error,
    });
  }
}

function encodeRfc3986(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}
