import { createServer } from 'node:http';

import { afterEach, describe, expect, test } from 'vitest';

import {
  HandleStatus,
  buildHandleServiceEntry,
  buildWbaUri,
  parseWbaUri,
  resolveHandle,
  validateHandle,
  verifyHandleBinding,
} from '../src/index.js';

describe('wns', () => {
  let server: ReturnType<typeof createServer> | undefined;

  afterEach(async () => {
    if (!server) {
      return;
    }
    await new Promise<void>((resolve) => server?.close(() => resolve()));
    server = undefined;
  });

  test('validates handles and parses WBA URIs', () => {
    const [localPart, domain] = validateHandle('Alice.Example.COM');
    expect(localPart).toBe('alice');
    expect(domain).toBe('example.com');
    expect(parseWbaUri(buildWbaUri(localPart, domain)).handle).toBe('alice.example.com');
  });

  test('resolves handles with a mock server', async () => {
    server = createServer((request, response) => {
      if (request.url === '/.well-known/handle/alice') {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(
          JSON.stringify({
            handle: 'alice.example.com',
            did: 'did:wba:example.com:user:alice',
            status: 'active',
            updated: '2025-01-01T00:00:00Z',
          })
        );
        return;
      }
      response.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', () => resolve()));
    const address = server.address();
    const baseUrl =
      typeof address === 'object' && address ? `http://127.0.0.1:${address.port}` : '';

    const result = await resolveHandle('alice.example.com', { baseUrlOverride: baseUrl });
    expect(result.did).toBe('did:wba:example.com:user:alice');
    expect(result.status).toBe(HandleStatus.Active);
  });

  test('verifies forward and reverse handle binding', async () => {
    server = createServer((request, response) => {
      if (request.url === '/.well-known/handle/alice') {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(
          JSON.stringify({
            handle: 'alice.example.com',
            did: 'did:wba:example.com:user:alice',
            status: 'active',
          })
        );
        return;
      }
      response.writeHead(404).end();
    });
    await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', () => resolve()));
    const address = server.address();
    const baseUrl =
      typeof address === 'object' && address ? `http://127.0.0.1:${address.port}` : '';

    const didDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: 'did:wba:example.com:user:alice',
      verificationMethod: [],
      authentication: [],
      service: [buildHandleServiceEntry('did:wba:example.com:user:alice', 'alice', 'example.com')],
    };

    const result = await verifyHandleBinding('alice.example.com', {
      didDocument,
      resolutionOptions: { baseUrlOverride: baseUrl },
    });
    expect(result.isValid).toBe(true);
    expect(result.forwardVerified).toBe(true);
    expect(result.reverseVerified).toBe(true);
  });
});
