import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, test } from 'vitest';

import {
  AuthMode,
  buildAgentMessageService,
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
  verifyFederatedHttpRequest,
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

  test('creates a bare-domain did:wba document and verifies HTTP signatures', () => {
    const bundle = createDidWbaDocument('example.com');
    expect(bundle.didDocument.id).toBe('did:wba:example.com');

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
    ).toBe('did:wba:example.com#key-1');
  });

  test('builds ANPMessageService entries with serviceDid', () => {
    const service = buildAgentMessageService(
      'did:wba:example.com:agents:demo:e1_test',
      'https://example.com/anp',
      { serviceDid: 'did:wba:example.com' }
    );
    expect(service.type).toBe('ANPMessageService');
    expect(service.serviceDid).toBe('did:wba:example.com');
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

  test('verifies federated HTTP requests with did:wba serviceDid', async () => {
    const sender = createDidWbaDocument('a.example.com', {
      pathSegments: ['agents', 'alice'],
      didProfile: DidProfile.E1,
    });
    const serviceIdentity = createDidWbaDocument('a.example.com');
    sender.didDocument.service = [
      buildAgentMessageService(sender.didDocument.id, 'https://a.example.com/anp', {
        serviceDid: serviceIdentity.didDocument.id,
      }),
    ];

    const headers = generateHttpSignatureHeaders(
      serviceIdentity.didDocument,
      'https://b.example.com/anp',
      'POST',
      serviceIdentity.keys['key-1'].privateKeyPem,
      {},
      '{"message":"hello"}'
    );

    const result = await verifyFederatedHttpRequest(
      sender.didDocument.id,
      'POST',
      'https://b.example.com/anp',
      headers,
      '{"message":"hello"}',
      {
        senderDidDocument: sender.didDocument,
        serviceDidDocument: serviceIdentity.didDocument,
      }
    );

    expect(result.serviceDid).toBe('did:wba:a.example.com');
    expect(result.signatureMetadata.keyid).toBe('did:wba:a.example.com#key-1');
  });

  test('verifies federated HTTP requests with did:web serviceDid', async () => {
    const sender = createDidWbaDocument('a.example.com', {
      pathSegments: ['agents', 'alice'],
      didProfile: DidProfile.E1,
    });
    const serviceIdentity = createDidWbaDocument('a.example.com');
    const multikeyMethod = serviceIdentity.didDocument.verificationMethod[0];
    const serviceDidDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: 'did:web:a.example.com',
      verificationMethod: [
        {
          id: 'did:web:a.example.com#key-1',
          type: 'Ed25519VerificationKey2020',
          controller: 'did:web:a.example.com',
          publicKeyMultibase: multikeyMethod.publicKeyMultibase,
        },
      ],
      authentication: ['did:web:a.example.com#key-1'],
    };
    sender.didDocument.service = [
      buildAgentMessageService(sender.didDocument.id, 'https://a.example.com/anp', {
        serviceDid: serviceDidDocument.id,
      }),
    ];

    const headers = generateHttpSignatureHeaders(
      serviceDidDocument,
      'https://b.example.com/anp',
      'POST',
      serviceIdentity.keys['key-1'].privateKeyPem,
      {},
      '{"message":"hello"}'
    );

    const result = await verifyFederatedHttpRequest(
      sender.didDocument.id,
      'POST',
      'https://b.example.com/anp',
      headers,
      '{"message":"hello"}',
      {
        senderDidDocument: sender.didDocument,
        serviceDidDocument,
      }
    );

    expect(result.serviceDid).toBe('did:web:a.example.com');
    expect(result.signatureMetadata.keyid).toBe('did:web:a.example.com#key-1');
  });
});
