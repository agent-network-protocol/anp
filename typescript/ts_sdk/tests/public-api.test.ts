import { describe, expect, test } from 'vitest';

import {
  DidProfile,
  AwikiImError,
  authentication,
  buildVnextDidDocument,
  createDidDocument,
  createLegacyAuthHeader,
  createAwikiImClient,
  createProof,
  DeviceManifestEntry,
  generateRfc9421OriginProof,
  parseUri,
  proof,
  resolveUri,
  validateDeviceManifest,
  verifyProof,
  verifyRfc9421OriginProof,
  wns,
} from '../src/index.js';
import * as sdk from '../src/index.js';

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
    expect(proof.im.generateImProof).toBeTypeOf('function');
    expect(proof.im.verifyImProof).toBeTypeOf('function');
    expect(generateRfc9421OriginProof).toBeTypeOf('function');
    expect(verifyRfc9421OriginProof).toBeTypeOf('function');
    expect(proof.rfc9421.generateRfc9421OriginProof).toBeTypeOf('function');
    expect(DeviceManifestEntry).toBeTypeOf('function');
    expect(buildVnextDidDocument).toBeTypeOf('function');
    expect(validateDeviceManifest).toBeTypeOf('function');
    expect(authentication.deviceManifest.buildVnextDidDocument).toBeTypeOf('function');
    expect('buildOriginAuthentication' in sdk).toBe(false);
    expect((sdk as Record<string, unknown>).buildOriginAuthentication).toBeUndefined();
  });

  test('exposes stable wns aliases and namespace', async () => {
    expect(parseUri('wba://alice.example.com').handle).toBe('alice.example.com');
    expect(wns.buildUri('alice', 'example.com')).toBe('wba://alice.example.com');
    expect(resolveUri).toBeTypeOf('function');
  });

  test('exposes the AWiki IM factory and error value from the package root', () => {
    expect(createAwikiImClient).toBeTypeOf('function');
    expect(new AwikiImError('remote', 'test')).toMatchObject({
      name: 'AwikiImError',
      code: 'remote',
    });
  });
});
