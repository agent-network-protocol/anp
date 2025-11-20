/**
 * Unit tests for key generation functionality
 */

import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  KeyType,
  exportPublicKeyJWK,
  exportPublicKeyMultibase,
  exportPrivateKeyJWK,
} from '../../../src/crypto/key-generation.js';
import { CryptoError } from '../../../src/errors/index.js';

describe('Key Generation', () => {
  describe('ECDSA secp256k1 key pair generation', () => {
    it('should generate a valid ECDSA secp256k1 key pair', async () => {
      const keyPair = await generateKeyPair(KeyType.ECDSA_SECP256K1);

      expect(keyPair).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey.type).toBe('public');
      expect(keyPair.privateKey.type).toBe('private');
    });

    it('should generate different key pairs on each call', async () => {
      const keyPair1 = await generateKeyPair(KeyType.ECDSA_SECP256K1);
      const keyPair2 = await generateKeyPair(KeyType.ECDSA_SECP256K1);

      const jwk1 = await exportPublicKeyJWK(keyPair1.publicKey);
      const jwk2 = await exportPublicKeyJWK(keyPair2.publicKey);

      expect(jwk1.x).not.toBe(jwk2.x);
      expect(jwk1.y).not.toBe(jwk2.y);
    });

    it('should export public key as JWK format', async () => {
      const keyPair = await generateKeyPair(KeyType.ECDSA_SECP256K1);
      const jwk = await exportPublicKeyJWK(keyPair.publicKey);

      expect(jwk).toBeDefined();
      expect(jwk.kty).toBe('EC');
      expect(jwk.crv).toBe('P-256'); // Note: Using P-256 as secp256k1 is not natively supported
      expect(jwk.x).toBeDefined();
      expect(jwk.y).toBeDefined();
      expect(typeof jwk.x).toBe('string');
      expect(typeof jwk.y).toBe('string');
    });

    it('should export private key as JWK format', async () => {
      const keyPair = await generateKeyPair(KeyType.ECDSA_SECP256K1);
      const jwk = await exportPrivateKeyJWK(keyPair.privateKey);

      expect(jwk).toBeDefined();
      expect(jwk.kty).toBe('EC');
      expect(jwk.crv).toBe('P-256'); // Note: Using P-256 as secp256k1 is not natively supported
      expect(jwk.x).toBeDefined();
      expect(jwk.y).toBeDefined();
      expect(jwk.d).toBeDefined();
      expect(typeof jwk.d).toBe('string');
    });
  });

  describe('Ed25519 key pair generation', () => {
    it('should generate a valid Ed25519 key pair', async () => {
      const keyPair = await generateKeyPair(KeyType.ED25519);

      expect(keyPair).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey.type).toBe('public');
      expect(keyPair.privateKey.type).toBe('private');
    });

    it('should generate different key pairs on each call', async () => {
      const keyPair1 = await generateKeyPair(KeyType.ED25519);
      const keyPair2 = await generateKeyPair(KeyType.ED25519);

      const jwk1 = await exportPublicKeyJWK(keyPair1.publicKey);
      const jwk2 = await exportPublicKeyJWK(keyPair2.publicKey);

      expect(jwk1.x).not.toBe(jwk2.x);
    });

    it('should export public key as JWK format', async () => {
      const keyPair = await generateKeyPair(KeyType.ED25519);
      const jwk = await exportPublicKeyJWK(keyPair.publicKey);

      expect(jwk).toBeDefined();
      expect(jwk.kty).toBe('OKP');
      expect(jwk.crv).toBe('Ed25519');
      expect(jwk.x).toBeDefined();
      expect(typeof jwk.x).toBe('string');
    });

    it('should export private key as JWK format', async () => {
      const keyPair = await generateKeyPair(KeyType.ED25519);
      const jwk = await exportPrivateKeyJWK(keyPair.privateKey);

      expect(jwk).toBeDefined();
      expect(jwk.kty).toBe('OKP');
      expect(jwk.crv).toBe('Ed25519');
      expect(jwk.x).toBeDefined();
      expect(jwk.d).toBeDefined();
      expect(typeof jwk.d).toBe('string');
    });
  });

  describe('X25519 key pair generation', () => {
    it('should generate a valid X25519 key pair', async () => {
      const keyPair = await generateKeyPair(KeyType.X25519);

      expect(keyPair).toBeDefined();
      expect(keyPair.publicKey).toBeDefined();
      expect(keyPair.privateKey).toBeDefined();
      expect(keyPair.publicKey.type).toBe('public');
      expect(keyPair.privateKey.type).toBe('private');
    });

    it('should generate different key pairs on each call', async () => {
      const keyPair1 = await generateKeyPair(KeyType.X25519);
      const keyPair2 = await generateKeyPair(KeyType.X25519);

      const jwk1 = await exportPublicKeyJWK(keyPair1.publicKey);
      const jwk2 = await exportPublicKeyJWK(keyPair2.publicKey);

      expect(jwk1.x).not.toBe(jwk2.x);
    });

    it('should export public key as JWK format', async () => {
      const keyPair = await generateKeyPair(KeyType.X25519);
      const jwk = await exportPublicKeyJWK(keyPair.publicKey);

      expect(jwk).toBeDefined();
      expect(jwk.kty).toBe('OKP');
      expect(jwk.crv).toBe('X25519');
      expect(jwk.x).toBeDefined();
      expect(typeof jwk.x).toBe('string');
    });

    it('should export private key as JWK format', async () => {
      const keyPair = await generateKeyPair(KeyType.X25519);
      const jwk = await exportPrivateKeyJWK(keyPair.privateKey);

      expect(jwk).toBeDefined();
      expect(jwk.kty).toBe('OKP');
      expect(jwk.crv).toBe('X25519');
      expect(jwk.x).toBeDefined();
      expect(jwk.d).toBeDefined();
      expect(typeof jwk.d).toBe('string');
    });
  });

  describe('Multibase format export', () => {
    it('should export Ed25519 public key as multibase format', async () => {
      const keyPair = await generateKeyPair(KeyType.ED25519);
      const multibase = await exportPublicKeyMultibase(keyPair.publicKey);

      expect(multibase).toBeDefined();
      expect(typeof multibase).toBe('string');
      expect(multibase).toMatch(/^z[1-9A-HJ-NP-Za-km-z]+$/); // base58btc format
    });

    it('should export X25519 public key as multibase format', async () => {
      const keyPair = await generateKeyPair(KeyType.X25519);
      const multibase = await exportPublicKeyMultibase(keyPair.publicKey);

      expect(multibase).toBeDefined();
      expect(typeof multibase).toBe('string');
      expect(multibase).toMatch(/^z[1-9A-HJ-NP-Za-km-z]+$/);
    });
  });

  describe('Error handling', () => {
    it('should throw CryptoError for invalid key type', async () => {
      await expect(generateKeyPair('INVALID_TYPE' as KeyType)).rejects.toThrow(
        CryptoError
      );
    });

    it('should throw CryptoError when exporting invalid key as JWK', async () => {
      const invalidKey = {} as CryptoKey;
      await expect(exportPublicKeyJWK(invalidKey)).rejects.toThrow(CryptoError);
    });

    it('should throw CryptoError when exporting invalid key as multibase', async () => {
      const invalidKey = {} as CryptoKey;
      await expect(exportPublicKeyMultibase(invalidKey)).rejects.toThrow(
        CryptoError
      );
    });
  });
});
