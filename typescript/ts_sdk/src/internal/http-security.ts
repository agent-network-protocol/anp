/** Node transport: checked connection DNS, TLS, no redirects/proxies, bounded bodies.
 * This is not a browser fetch SSRF guarantee; the SDK's Node transport is required.
 */
import { lookup, type LookupAddress } from 'node:dns';
import { isIP, type LookupFunction } from 'node:net';
import {
  Agent as HttpAgent,
  request as httpRequest,
  type ClientRequest,
  type IncomingMessage,
  type RequestOptions,
} from 'node:http';
import { Agent as HttpsAgent, request as httpsRequest } from 'node:https';
import { createBrotliDecompress, createGunzip, createInflate } from 'node:zlib';
import type { Readable } from 'node:stream';
import { NetworkError } from '../errors/index.js';
import { authenticationOrigin } from '../authentication/http-auth-security.js';
import type { DidResolutionOptions } from '../authentication/types.js';

export const MAX_DOCUMENT_BYTES = 1024 * 1024;
let activeRequests = 0;

export function isPublicAddress(raw: string): boolean {
  const v4 = (parts: number[]): boolean => {
    const [a, b, c] = parts;
    return !(
      a === 0 ||
      a === 10 ||
      a === 127 ||
      a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113)
    );
  };
  if (isIP(raw) === 4) return v4(raw.split('.').map(Number));
  if (isIP(raw) !== 6) return false;
  try {
    const normalized = new URL(`https://[${raw}]/`).hostname.slice(1, -1);
    const halves = normalized.split('::');
    const left = halves[0] ? halves[0].split(':').map((v) => parseInt(v, 16)) : [];
    const right = halves[1] ? halves[1].split(':').map((v) => parseInt(v, 16)) : [];
    const values =
      halves.length === 2
        ? [...left, ...Array<number>(8 - left.length - right.length).fill(0), ...right]
        : left;
    if (values.length !== 8) return false;
    if (values.slice(0, 5).every((v) => v === 0) && values[5] === 0xffff)
      return v4([values[6] >> 8, values[6] & 255, values[7] >> 8, values[7] & 255]);
    return (
      (values[0] & 0xe000) === 0x2000 &&
      !(values[0] === 0x2001 && (values[1] < 0x200 || values[1] === 0xdb8)) &&
      values[0] !== 0x2002 &&
      (values[0] & 0xfff0) !== 0x3ff0
    );
  } catch {
    return false;
  }
}

type LookupAll = (
  hostname: string,
  callback: (error: NodeJS.ErrnoException | null, addresses: LookupAddress[]) => void
) => void;
export function createPublicLookup(
  resolve: LookupAll = (host, callback) => lookup(host, { all: true, verbatim: true }, callback)
): LookupFunction {
  return (host, options, callback) =>
    resolve(host, (error, addresses) => {
      if (error) {
        callback(error, '', 0);
        return;
      }
      if (!addresses.length || addresses.some((item) => !isPublicAddress(item.address))) {
        callback(new Error('ANP resolved to a non-public destination'), '', 0);
        return;
      }
      const family = options.family === 'IPv4' ? 4 : options.family === 'IPv6' ? 6 : options.family;
      const matching = family ? addresses.filter((item) => item.family === family) : addresses;
      if (!matching.length) {
        callback(new Error('ANP DNS returned no matching addresses'), '', 0);
        return;
      }
      // Give Node the checked addresses themselves, never the hostname to resolve again.
      if (options.all) callback(null, matching);
      else callback(null, matching[0].address, matching[0].family);
    });
}

export function validatePublicUrl(raw: string, baseUrlOverride?: string): URL {
  authenticationOrigin(raw);
  const url = new URL(raw);
  if (baseUrlOverride !== undefined) {
    const base = new URL(baseUrlOverride);
    const prefix = base.pathname.replace(/\/+$/, '');
    if (
      base.search ||
      baseUrlOverride.includes('#') ||
      authenticationOrigin(baseUrlOverride) !== authenticationOrigin(raw) ||
      (prefix && url.pathname !== prefix && !url.pathname.startsWith(prefix + '/'))
    )
      throw new NetworkError('Invalid trusted resolution override');
    return url;
  }
  if (url.protocol !== 'https:') throw new NetworkError('Public ANP requests require HTTPS');
  const host = url.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (host === 'localhost' || host.endsWith('.localhost') || (isIP(host) && !isPublicAddress(host)))
    throw new NetworkError('Non-public ANP destination');
  return url;
}

export interface PublicHttpResponse {
  status: number;
  ok: boolean;
  headers: Headers;
  json(): Promise<unknown>;
}

type RequestFactory = (
  url: URL,
  options: RequestOptions,
  callback: (response: IncomingMessage) => void
) => ClientRequest;
/** Injectable only at this internal transport boundary for offline unit tests. */
export interface DocumentRequestDependencies {
  request?: RequestFactory;
  lookup?: LookupAll;
}

export async function publicDocumentRequest(
  raw: string,
  options: DidResolutionOptions = {},
  dependencies: DocumentRequestDependencies = {}
): Promise<PublicHttpResponse> {
  const url = validatePublicUrl(raw, options.baseUrlOverride);
  const timeout = (options.timeoutSeconds ?? 10) * 1000;
  if (!Number.isFinite(timeout) || timeout <= 0 || timeout > 2147483647)
    throw new NetworkError('Invalid ANP request timeout');
  const trusted = options.baseUrlOverride !== undefined;
  if (!trusted && options.verifySsl === false)
    throw new NetworkError('Public ANP requests require TLS verification');
  if (activeRequests >= 32) throw new NetworkError('ANP document concurrency budget exhausted');
  activeRequests++;
  const tls = url.protocol === 'https:';
  const agent = tls
    ? new HttpsAgent({
        lookup: trusted ? undefined : createPublicLookup(dependencies.lookup),
        rejectUnauthorized: options.verifySsl !== false,
        maxSockets: 1,
      })
    : new HttpAgent({ maxSockets: 1 });
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await new Promise<PublicHttpResponse>((resolve, reject) => {
      let settled = false;
      let responseStream: Readable | undefined;
      const fail = (error: Error): void => {
        if (settled) return;
        settled = true;
        responseStream?.destroy();
        request.destroy();
        reject(new NetworkError('ANP document request rejected', undefined, error));
      };
      const requestFactory = dependencies.request ?? (tls ? httpsRequest : httpRequest);
      const request = requestFactory(
        url,
        {
          agent,
          method: 'GET',
          headers: {
            Accept: 'application/json',
            'Accept-Encoding': 'gzip, deflate, br',
            ...(options.headers ?? {}),
          },
        },
        (response) => {
          responseStream = response;
          response.once('error', fail);
          const status = response.statusCode ?? 0;
          const headers = new Headers();
          for (const [name, value] of Object.entries(response.headers)) {
            if (Array.isArray(value)) for (const item of value) headers.append(name, item);
            else if (value !== undefined) headers.set(name, value);
          }
          const finish = (data: Uint8Array): void => {
            if (settled) return;
            settled = true;
            resolve({
              status,
              ok: status === 200,
              headers,
              json: async () =>
                JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data)) as unknown,
            });
          };
          if (status !== 200) {
            finish(new Uint8Array());
            response.destroy();
            return;
          }
          if (Number(response.headers['content-length']) > MAX_DOCUMENT_BYTES) {
            fail(new Error('ANP response exceeds size limit'));
            return;
          }
          const encoding = String(response.headers['content-encoding'] ?? 'identity').toLowerCase();
          const decoder =
            encoding === 'gzip'
              ? createGunzip()
              : encoding === 'deflate'
                ? createInflate()
                : encoding === 'br'
                  ? createBrotliDecompress()
                  : undefined;
          if (!decoder && encoding !== 'identity') {
            fail(new Error('Unsupported document content encoding'));
            return;
          }
          let wireBytes = 0,
            decodedBytes = 0;
          response.on('data', (chunk: Buffer) => {
            wireBytes += chunk.length;
            if (wireBytes > MAX_DOCUMENT_BYTES) fail(new Error('ANP response exceeds size limit'));
          });
          const stream = decoder ? response.pipe(decoder) : response;
          stream.once('error', fail);
          const chunks: Buffer[] = [];
          stream.on('data', (chunk: Buffer) => {
            decodedBytes += chunk.length;
            if (decodedBytes > MAX_DOCUMENT_BYTES) {
              fail(new Error('ANP decoded response exceeds size limit'));
              stream.destroy();
              return;
            }
            chunks.push(Buffer.from(chunk));
          });
          stream.once('end', () => finish(Buffer.concat(chunks)));
          response.once('aborted', () => fail(new Error('ANP response aborted')));
        }
      );
      request.once('error', fail);
      timer = setTimeout(() => fail(new Error('ANP document timeout')), timeout);
      timer.unref();
      request.end();
    });
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    agent.destroy();
    activeRequests--;
  }
}
