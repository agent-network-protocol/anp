/**
 * Unit tests for ECDHE key exchange functionality
 */

import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  KeyType,
} from '../../../src/crypto/key-generation.js';
import {
  performKeyExchange,
  deriveKey,
} from '../../../src/crypto/key-exchange.js';
import { CryptoError } from '../../../src/errors/index.js';

describe('ECDHE Key Exchange', () => {
  describe('X25519 key exchange', () => {
    it('should perform key exchange with X25519 keys', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);

      const aliceSharedSecret = await performKeyExchange(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      expect(aliceSharedSecret).toBeDefined();
      expect(aliceSharedSecret).toBeInstanceOf(Uint8Array);
      expect(aliceSharedSecret.length).toBe(32); // X25519 shared secrets are 32 bytes
    });

    it('should produce same shared secret for both parties', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);

      const aliceSharedSecret = await performKeyExchange(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const bobSharedSecret = await performKeyExchange(
        bobKeyPair.privateKey,
        aliceKeyPair.publicKey
      );

      expect(aliceSharedSecret).toEqual(bobSharedSecret);
    });

    it('should produce different shared secrets for different key pairs', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);
      const charlieKeyPair = await generateKeyPair(KeyType.X25519);

      const aliceBobSecret = await performKeyExchange(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const aliceCharlieSecret = await performKeyExchange(
        aliceKeyPair.privateKey,
        charlieKeyPair.publicKey
      );

      expect(aliceBobSecret).not.toEqual(aliceCharlieSecret);
    });
  });

  describe('Key derivation', () => {
    it('should derive encryption key from shared secret', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);

      const sharedSecret = await performKeyExchange(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const salt = crypto.getRandomValues(new Uint8Array(32));
      const derivedKey = await deriveKey(sharedSecret, salt);

      expect(derivedKey).toBeDefined();
      expect(derivedKey.type).toBe('secret');
      expect(derivedKey.algorithm.name).toBe('AES-GCM');
    });

    it('should derive same key with same inputs', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);

      const sharedSecret = await performKeyExchange(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const salt = crypto.getRandomValues(new Uint8Array(32));
      
      const key1 = await deriveKey(sharedSecret, salt);
      const key2 = await deriveKey(sharedSecret, salt);

      // Export both keys to compare
      const exported1 = await crypto.subtle.exportKey('raw', key1);
      const exported2 = await crypto.subtle.exportKey('raw', key2);

      expect(new Uint8Array(exported1)).toEqual(new Uint8Array(exported2));
    });

    it('should derive different keys with different salts', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);

      const sharedSecret = await performKeyExchange(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const salt1 = crypto.getRandomValues(new Uint8Array(32));
      const salt2 = crypto.getRandomValues(new Uint8Array(32));
      
      const key1 = await deriveKey(sharedSecret, salt1);
      const key2 = await deriveKey(sharedSecret, salt2);

      // Export both keys to compare
      const exported1 = await crypto.subtle.exportKey('raw', key1);
      const exported2 = await crypto.subtle.exportKey('raw', key2);

      expect(new Uint8Array(exported1)).not.toEqual(new Uint8Array(exported2));
    });

    it('should derive different keys from different shared secrets', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);
      const charlieKeyPair = await generateKeyPair(KeyType.X25519);

      const secret1 = await performKeyExchange(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const secret2 = await performKeyExchange(
        aliceKeyPair.privateKey,
        charlieKeyPair.publicKey
      );

      const salt = crypto.getRandomValues(new Uint8Array(32));
      
      const key1 = await deriveKey(secret1, salt);
      const key2 = await deriveKey(secret2, salt);

      // Export both keys to compare
      const exported1 = await crypto.subtle.exportKey('raw', key1);
      const exported2 = await crypto.subtle.exportKey('raw', key2);

      expect(new Uint8Array(exported1)).not.toEqual(new Uint8Array(exported2));
    });
  });

  describe('Error handling', () => {
    it('should throw CryptoError when using non-X25519 key for exchange', async () => {
      const ed25519KeyPair = await generateKeyPair(KeyType.ED25519);
      const x25519KeyPair = await generateKeyPair(KeyType.X25519);

      await expect(
        performKeyExchange(ed25519KeyPair.privateKey, x25519KeyPair.publicKey)
      ).rejects.toThrow(CryptoError);
    });

    it('should throw CryptoError when using public key as private key', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);

      await expect(
        performKeyExchange(aliceKeyPair.publicKey as any, bobKeyPair.publicKey)
      ).rejects.toThrow(CryptoError);
    });

    it('should throw CryptoError when using private key as public key', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);

      await expect(
        performKeyExchange(aliceKeyPair.privateKey, bobKeyPair.privateKey as any)
      ).rejects.toThrow(CryptoError);
    });

    it('should throw CryptoError when deriving key with invalid shared secret', async () => {
      const invalidSecret = new Uint8Array(16); // Wrong size
      const salt = crypto.getRandomValues(new Uint8Array(32));

      await expect(deriveKey(invalidSecret, salt)).rejects.toThrow(CryptoError);
    });

    it('should throw CryptoError when deriving key with invalid salt', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);

      const sharedSecret = await performKeyExchange(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const invalidSalt = new Uint8Array(0); // Empty salt

      await expect(deriveKey(sharedSecret, invalidSalt)).rejects.toThrow(
        CryptoError
      );
    });
  });
});
