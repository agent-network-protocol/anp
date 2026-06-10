import { createServer } from 'node:http';

import { afterEach, describe, expect, test } from 'vitest';

import {
  HandleStatus,
  SubjectType,
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
            versionId: '42',
            ttl: 300,
            profile: {
              type: 'DIDSubjectProfile',
              subject_did: 'did:wba:example.com:user:alice',
              subject_type: 'person',
              handle: 'alice.example.com',
              display_name: 'Alice',
              avatar_uri: 'https://example.com/avatars/alice.png',
              proof: { type: 'DataIntegrityProof' },
            },
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
    expect(result.versionId).toBe('42');
    expect(result.ttl).toBe(300);
    expect(result.profile?.subject_type).toBe(SubjectType.Person);
    expect(result.profile?.display_name).toBe('Alice');
    expect(result.profile?.proof?.type).toBe('DataIntegrityProof');
  });

  test('ignores profile subject DID mismatch during resolution', async () => {
    server = createServer((request, response) => {
      if (request.url === '/.well-known/handle/alice') {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(
          JSON.stringify({
            handle: 'alice.example.com',
            did: 'did:wba:example.com:user:alice',
            status: 'active',
            profile: {
              subject_did: 'did:wba:example.com:user:bob',
              display_name: 'Bob',
            },
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
    expect(result.profile).toBeUndefined();
  });

  test('ignores profile handle mismatch during resolution', async () => {
    server = createServer((request, response) => {
      if (request.url === '/.well-known/handle/alice') {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(
          JSON.stringify({
            handle: 'alice.example.com',
            did: 'did:wba:example.com:user:alice',
            status: 'active',
            profile: {
              subject_did: 'did:wba:example.com:user:alice',
              handle: 'bob.example.com',
              display_name: 'Bob',
            },
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
    expect(result.profile).toBeUndefined();
  });

  test('normalizes unknown profile subject type to unknown', async () => {
    server = createServer((request, response) => {
      if (request.url === '/.well-known/handle/alice') {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(
          JSON.stringify({
            handle: 'alice.example.com',
            did: 'did:wba:example.com:user:alice',
            status: 'active',
            profile: {
              subject_did: 'did:wba:example.com:user:alice',
              subject_type: 'custom-private-type',
              display_name: 'Alice',
            },
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
    expect(result.profile?.subject_type).toBe(SubjectType.Unknown);
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

  test('accepts ANPHandleService entries that only match by HTTPS domain', async () => {
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
      service: [
        {
          id: 'did:wba:example.com:user:alice#handle',
          type: 'ANPHandleService',
          serviceEndpoint: 'https://example.com/providers/wns',
        },
      ],
    };

    const result = await verifyHandleBinding('alice.example.com', {
      didDocument,
      resolutionOptions: { baseUrlOverride: baseUrl },
    });
    expect(result.isValid).toBe(true);
    expect(result.reverseVerified).toBe(true);
  });
});
