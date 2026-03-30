import { describe, expect, test } from 'vitest';

import {
  DidProfile,
  createDidWbaDocument,
  generateW3cProof,
  verifyW3cProof,
} from '../src/index.js';

describe('proof', () => {
  test('generates and verifies secp256k1 proof', () => {
    const bundle = createDidWbaDocument('example.com', {
      pathSegments: ['agents', 'demo'],
      didProfile: DidProfile.K1,
    });
    const document = {
      id: 'did:wba:example.com:claim:alice',
      claim: 'test-data',
    };

    const signed = generateW3cProof(
      document,
      bundle.keys['key-1'].privateKeyPem,
      `${bundle.didDocument.id}#key-1`
    );
    expect(verifyW3cProof(signed, bundle.keys['key-1'].publicKeyPem)).toBe(true);
  });

  test('generates and verifies Ed25519 data integrity proof', () => {
    const bundle = createDidWbaDocument('example.com', {
      pathSegments: ['agents', 'demo'],
      didProfile: DidProfile.E1,
    });
    const document = {
      id: 'did:wba:example.com:credential:bob',
      type: 'VerifiableCredential',
    };

    const signed = generateW3cProof(
      document,
      bundle.keys['key-1'].privateKeyPem,
      `${bundle.didDocument.id}#key-1`,
      {
        proofType: 'DataIntegrityProof',
        cryptosuite: 'eddsa-jcs-2022',
      }
    );
    expect(verifyW3cProof(signed, bundle.keys['key-1'].publicKeyPem)).toBe(true);
  });

  test('fails proof verification after tampering', () => {
    const bundle = createDidWbaDocument('example.com', {
      pathSegments: ['agents', 'demo'],
      didProfile: DidProfile.K1,
    });
    const signed = generateW3cProof(
      { id: 'did:wba:example.com:claim:alice', claim: 'hello' },
      bundle.keys['key-1'].privateKeyPem,
      `${bundle.didDocument.id}#key-1`
    );

    const tampered = { ...signed, claim: 'tampered' };
    expect(verifyW3cProof(tampered, bundle.keys['key-1'].publicKeyPem)).toBe(false);
  });
});
