import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, test } from 'vitest';

import {
  AuthMode,
  DidProfile,
  DidWbaVerifier,
  DIDWbaAuthHeader,
  createDidWbaDocument,
  extractSignatureMetadata,
  extractAuthHeaderParts,
  generateAuthHeader,
  generateHttpSignatureHeaders,
  validateDidDocumentBinding,
  verifyAuthHeaderSignature,
  verifyHttpMessageSignature,
} from '../src/index.js';

describe('authentication', () => {
  test('creates DID documents for e1 and k1 profiles', () => {
    const e1 = createDidWbaDocument('example.com', {
      pathSegments: ['agents', 'demo'],
      didProfile: DidProfile.E1,
    });
    const k1 = createDidWbaDocument('example.com', {
      pathSegments: ['agents', 'demo'],
      didProfile: DidProfile.K1,
    });

    expect(e1.didDocument.id).toContain(':e1_');
    expect(k1.didDocument.id).toContain(':k1_');
    expect(validateDidDocumentBinding(e1.didDocument, true)).toBe(true);
    expect(validateDidDocumentBinding(k1.didDocument, true)).toBe(true);
  });

  test('generates and verifies legacy DIDWba headers', () => {
    const bundle = createDidWbaDocument('example.com', {
      pathSegments: ['agents', 'demo'],
      didProfile: DidProfile.K1,
    });
    const header = generateAuthHeader(
      bundle.didDocument,
      'api.example.com',
      bundle.keys['key-1'].privateKeyPem
    );

    expect(extractAuthHeaderParts(header).did).toBe(bundle.didDocument.id);
    expect(
      verifyAuthHeaderSignature(header, bundle.didDocument, 'api.example.com')
    ).toBe(true);
  });

  test('generates and verifies HTTP signatures', () => {
    const bundle = createDidWbaDocument('example.com', {
      pathSegments: ['agents', 'demo'],
      didProfile: DidProfile.K1,
    });
    const headers = generateHttpSignatureHeaders(
      bundle.didDocument,
      'https://api.example.com/orders',
      'POST',
      bundle.keys['key-1'].privateKeyPem,
      {},
      '{"item":"book"}'
    );

    expect(
      verifyHttpMessageSignature(
        bundle.didDocument,
        'POST',
        'https://api.example.com/orders',
        headers,
        '{"item":"book"}'
      ).keyid
    ).toContain('#key-1');

    expect(() =>
      verifyHttpMessageSignature(
        bundle.didDocument,
        'POST',
        'https://api.example.com/orders',
        headers,
        '{"item":"music"}'
      )
    ).toThrow();
  });

  test('verifier accepts legacy and HTTP signatures using provided DID document', async () => {
    const bundle = createDidWbaDocument('example.com', {
      pathSegments: ['agents', 'demo'],
      didProfile: DidProfile.K1,
    });
    const verifier = new DidWbaVerifier({
      jwtPrivateKey: 'test-secret',
      jwtPublicKey: 'test-secret',
      jwtAlgorithm: 'HS256',
    });

    const legacyHeader = generateAuthHeader(
      bundle.didDocument,
      'api.example.com',
      bundle.keys['key-1'].privateKeyPem
    );
    const legacyResult = await verifier.verifyRequestWithDidDocument(
      'GET',
      'https://api.example.com/orders',
      { Authorization: legacyHeader },
      bundle.didDocument
    );
    expect(legacyResult.authScheme).toBe('legacy_didwba');
    expect(legacyResult.accessToken).toBeDefined();

    const httpHeaders = generateHttpSignatureHeaders(
      bundle.didDocument,
      'https://api.example.com/orders',
      'GET',
      bundle.keys['key-1'].privateKeyPem
    );
    const httpResult = await verifier.verifyRequestWithDidDocument(
      'GET',
      'https://api.example.com/orders',
      httpHeaders,
      bundle.didDocument
    );
    expect(httpResult.authScheme).toBe('http_signatures');
    expect(httpResult.accessToken).toBeDefined();
  });

  test('file-based authenticator reuses bearer token', async () => {
    const fixtureDir = join(process.cwd(), 'tests/fixtures/rust/k1');
    const authHelper = new DIDWbaAuthHeader(
      join(fixtureDir, 'did.json'),
      join(fixtureDir, 'key-1_private.pem'),
      AuthMode.LegacyDidWba
    );

    const initialHeaders = await authHelper.getAuthHeaders('https://api.example.com/orders');
    expect(initialHeaders.Authorization?.startsWith('DIDWba')).toBe(true);

    authHelper.updateToken('https://api.example.com/orders', {
      Authorization: 'Bearer cached-token',
    });
    const cachedHeaders = await authHelper.getAuthHeaders('https://api.example.com/orders');
    expect(cachedHeaders.Authorization).toBe('Bearer cached-token');
  });

  test('file-based authenticator reuses server nonce for challenge headers', async () => {
    const fixtureDir = join(process.cwd(), 'tests/fixtures/rust/k1');
    const authHelper = new DIDWbaAuthHeader(
      join(fixtureDir, 'did.json'),
      join(fixtureDir, 'key-1_private.pem'),
      AuthMode.HttpSignatures
    );

    const headers = await authHelper.getChallengeAuthHeaders(
      'https://api.example.com/orders',
      {
        'WWW-Authenticate':
          'DIDWba realm="api.example.com", error="invalid_nonce", error_description="Retry", nonce="server-nonce-xyz"',
        'Accept-Signature':
          'sig1=("@method" "@target-uri" "@authority" "content-digest" "content-type");created;expires;nonce;keyid',
      },
      'POST',
      { 'Content-Type': 'application/json' },
      '{"item":"book"}'
    );

    const metadata = extractSignatureMetadata(headers);
    expect(metadata.nonce).toBe('server-nonce-xyz');
    expect(metadata.components).toContain('content-type');
    expect(headers['Content-Digest']).toBeDefined();
  });

  test('file-based authenticator skips retry for invalid DID challenge', async () => {
    const fixtureDir = join(process.cwd(), 'tests/fixtures/rust/k1');
    const authHelper = new DIDWbaAuthHeader(
      join(fixtureDir, 'did.json'),
      join(fixtureDir, 'key-1_private.pem'),
      AuthMode.HttpSignatures
    );

    expect(
      authHelper.shouldRetryAfter401({
        'WWW-Authenticate':
          'DIDWba realm="api.example.com", error="invalid_did", error_description="Unknown DID"',
      })
    ).toBe(false);
  });

  test('verifies Rust-generated fixtures', () => {
    const fixtureDir = join(process.cwd(), 'tests/fixtures/rust/e1');
    const didDocument = JSON.parse(readFileSync(join(fixtureDir, 'did.json'), 'utf8'));
    expect(validateDidDocumentBinding(didDocument, true)).toBe(true);
  });
});
