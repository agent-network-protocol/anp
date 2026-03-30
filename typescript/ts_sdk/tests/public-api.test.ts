import { describe, expect, test } from 'vitest';

import {
  DidProfile,
  authentication,
  createDidDocument,
  createLegacyAuthHeader,
  createProof,
  parseUri,
  proof,
  resolveUri,
  verifyProof,
  wns,
} from '../src/index.js';

describe('public API aliases', () => {
  test('exposes stable authentication aliases and namespace', () => {
    const bundle = createDidDocument('example.com', {
      pathSegments: ['agents', 'demo'],
      didProfile: DidProfile.K1,
    });

    const header = createLegacyAuthHeader(
      bundle.didDocument,
      'api.example.com',
      bundle.keys['key-1'].privateKeyPem
    );
    expect(header.startsWith('DIDWba')).toBe(true);
    expect(authentication.didDocuments.validateBinding(bundle.didDocument, true)).toBe(true);
  });

  test('exposes stable proof aliases and namespace', () => {
    const bundle = createDidDocument('example.com', {
      pathSegments: ['agents', 'demo'],
      didProfile: DidProfile.K1,
    });
    const signed = createProof(
      { id: 'did:wba:example.com:claim:alice', claim: 'hello' },
      bundle.keys['key-1'].privateKeyPem,
      `${bundle.didDocument.id}#key-1`
    );

    expect(verifyProof(signed, bundle.keys['key-1'].publicKeyPem)).toBe(true);
    expect(proof.verify(signed, bundle.keys['key-1'].publicKeyPem)).toBe(true);
  });

  test('exposes stable wns aliases and namespace', async () => {
    expect(parseUri('wba://alice.example.com').handle).toBe('alice.example.com');
    expect(wns.buildUri('alice', 'example.com')).toBe('wba://alice.example.com');
    expect(resolveUri).toBeTypeOf('function');
  });
});
