import { EventEmitter } from 'node:events';
import { Socket, type LookupFunction } from 'node:net';
import { Readable } from 'node:stream';
import { gzipSync } from 'node:zlib';
import type { ClientRequest, IncomingMessage, RequestOptions } from 'node:http';
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';
import * as transport from '../src/internal/http-security.js';
import { buildDidResolutionUrl } from '../src/authentication/did-resource.js';
import { resolveDidDocument } from '../src/authentication/did-resolver.js';
import { resolveDidWbaDocument } from '../src/authentication/did-wba.js';
import {
  AuthMode,
  DIDWbaAuthHeader,
  extractSignatureMetadata,
} from '../src/authentication/index.js';
import { resolveHandle } from '../src/wns/resolver.js';
import { join } from 'node:path';

type RequestFactory = NonNullable<transport.DocumentRequestDependencies['request']>;
function fakeRequest(
  body: Buffer,
  status = 200,
  headers: Record<string, string> = {},
  seen?: (options: RequestOptions) => void
): RequestFactory {
  return (_url, options, callback) => {
    seen?.(options);
    const request = new EventEmitter() as ClientRequest;
    request.destroy = () => request;
    request.end = (() => {
      queueMicrotask(() => {
        const response = Object.assign(Readable.from([body]), {
          statusCode: status,
          headers,
        }) as IncomingMessage;
        callback(response);
      });
      return request;
    }) as ClientRequest['end'];
    return request;
  };
}

beforeEach(() => {
  vi.spyOn(Socket.prototype, 'connect').mockImplementation(() => {
    throw new Error('Real network forbidden in unit tests');
  });
});
afterEach(() => {
  vi.restoreAllMocks();
});

describe('outbound security', () => {
  test('rejects private/ambiguous URLs before creating a request', async () => {
    const request = vi.fn(fakeRequest(Buffer.from('{}')));
    for (const url of [
      'https://127.0.0.1/',
      'https://169.254.169.254/',
      'https://[::1]/',
      'https://[::ffff:127.0.0.1]/',
      'https://localhost./',
      'http://example.com/',
      'https://user@example.com/',
      'https://example.com/#x',
    ]) {
      await expect(transport.publicDocumentRequest(url, {}, { request })).rejects.toThrow();
    }
    expect(request).not.toHaveBeenCalled();
    expect(() =>
      transport.validatePublicUrl('http://127.0.0.1/root/did.json', 'http://127.0.0.1/root')
    ).not.toThrow();
    expect(() =>
      transport.validatePublicUrl('http://127.0.0.2/root/did.json', 'http://127.0.0.1/root')
    ).toThrow();
    expect(() =>
      transport.validatePublicUrl('http://127.0.0.1/other/did.json', 'http://127.0.0.1/root')
    ).toThrow();
    await expect(
      transport.publicDocumentRequest('https://public.example/', { verifySsl: false }, { request })
    ).rejects.toThrow('TLS');
  });
  test('connection lookup rejects every private answer and returns checked IPs, not hostnames', () => {
    const resolved = vi.fn();
    const guard = transport.createPublicLookup((_host, callback) =>
      callback(null, [
        { address: '8.8.8.8', family: 4 },
        { address: '10.0.0.1', family: 4 },
      ])
    );
    guard('public.example', {}, resolved);
    expect(resolved.mock.calls[0][0]).toBeInstanceOf(Error);
    const allowed = transport.createPublicLookup((_host, callback) =>
      callback(null, [{ address: '8.8.8.8', family: 4 }])
    );
    const callback: Parameters<LookupFunction>[2] = vi.fn();
    allowed('public.example', {}, callback);
    expect(callback).toHaveBeenCalledWith(null, '8.8.8.8', 4);
    for (const ip of [
      '127.0.0.1',
      '10.0.0.1',
      '169.254.169.254',
      '::1',
      '::ffff:127.0.0.1',
      '2002:7f00:1::',
      '2001:db8::1',
    ])
      expect(transport.isPublicAddress(ip)).toBe(false);
  });
  test('TLS agent contains checked lookup and redirects are returned without another request', async () => {
    let options: RequestOptions | undefined;
    const request = vi.fn(
      fakeRequest(Buffer.from('ignored'), 302, { location: 'https://127.0.0.1/' }, (value) => {
        options = value;
      })
    );
    const response = await transport.publicDocumentRequest(
      'https://public.example/',
      {},
      { request }
    );
    expect(response.status).toBe(302);
    expect(request).toHaveBeenCalledTimes(1);
    expect(options?.agent).toBeTruthy();
  });
  test('bounds decoded gzip output and rejects oversized body before JSON', async () => {
    await expect(
      transport.publicDocumentRequest(
        'https://public.example/',
        {},
        { request: fakeRequest(Buffer.alloc(transport.MAX_DOCUMENT_BYTES + 1)) }
      )
    ).rejects.toThrow('rejected');
    const compressed = gzipSync(Buffer.alloc(transport.MAX_DOCUMENT_BYTES + 1, 32));
    await expect(
      transport.publicDocumentRequest(
        'https://public.example/',
        {},
        { request: fakeRequest(compressed, 200, { 'content-encoding': 'gzip' }) }
      )
    ).rejects.toThrow('rejected');
    const response = await transport.publicDocumentRequest(
      'https://public.example/',
      {},
      {
        request: fakeRequest(gzipSync(Buffer.from('{"ok":true}')), 200, {
          'content-encoding': 'gzip',
        }),
      }
    );
    expect(await response.json()).toEqual({ ok: true });
  });
  test('WBA and Web use the same transport and reject ambiguous resources', async () => {
    const response = {
      status: 200,
      ok: true,
      headers: new Headers(),
      json: async () => ({ id: 'did:web:example.com:alice' }),
    };
    const request = vi.spyOn(transport, 'publicDocumentRequest').mockResolvedValue(response);
    expect((await resolveDidDocument('did:web:example.com:alice', false)).id).toBe(
      'did:web:example.com:alice'
    );
    response.json = async () => ({ id: 'did:wba:example.com' });
    expect((await resolveDidWbaDocument('did:wba:example.com', false)).id).toBe(
      'did:wba:example.com'
    );
    expect(request).toHaveBeenCalledTimes(2);
    for (const did of [
      'did:wba:example.com%2fother:user',
      'did:wba:user%40example.com:alice',
      'did:web:example.com:..',
      'did:wba:example.com:%2fetc',
    ])
      expect(() => buildDidResolutionUrl(did)).toThrow();
  });
  test('WNS keeps moved/not-found/gone status semantics without real services', async () => {
    const request = vi.spyOn(transport, 'publicDocumentRequest');
    for (const status of [301, 404, 410]) {
      request.mockResolvedValue({
        status,
        ok: false,
        headers: new Headers({ Location: 'https://other.example/' }),
        json: async () => ({}),
      });
      await expect(resolveHandle('alice.example.com')).rejects.toThrow();
    }
    expect(request).toHaveBeenCalledTimes(3);
  });
  test('token origin isolation and malicious challenge retain target coverage', async () => {
    const dir = join(process.cwd(), 'tests/fixtures/rust/k1');
    const helper = new DIDWbaAuthHeader(
      join(dir, 'did.json'),
      join(dir, 'key-1_private.pem'),
      AuthMode.HttpSignatures
    );
    helper.updateToken('https://example.com:8443/', {
      'Authentication-Info': 'access_token="marker==", token_type="Bearer"',
    });
    expect((await helper.getAuthHeader('https://example.com:8443/a')).Authorization).toBe(
      'Bearer marker=='
    );
    expect((await helper.getAuthHeader('https://example.com/a')).Authorization).toBeUndefined();
    expect(
      helper.updateToken('http://example.com:8443/', { Authorization: 'Bearer marker' })
    ).toBeUndefined();
    const challenge = await helper.getChallengeAuthHeader('https://example.com/rpc', {
      'WWW-Authenticate': 'DIDWba nonce="unit"',
      'Accept-Signature': 'sig1=("@method");created;nonce;keyid',
    });
    expect(extractSignatureMetadata(challenge).components).toContain('@target-uri');
  });
});
