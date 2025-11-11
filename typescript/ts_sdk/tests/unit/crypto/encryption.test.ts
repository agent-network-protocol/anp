/**
 * Unit tests for encryption and decryption functionality
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
import {
  encrypt,
  decrypt,
  generateIV,
} from '../../../src/crypto/encryption.js';
import { CryptoError } from '../../../src/errors/index.js';

describe('Encryption and Decryption', () => {
  describe('AES-GCM encryption', () => {
    it('should encrypt data with AES-GCM', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);

      const sharedSecret = await performKeyExchange(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const salt = crypto.getRandomValues(new Uint8Array(32));
      const key = await deriveKey(sharedSecret, salt);

      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypted = await encrypt(key, plaintext);

      expect(encrypted).toBeDefined();
      expect(encrypted.ciphertext).toBeInstanceOf(Uint8Array);
      expect(encrypted.iv).toBeInstanceOf(Uint8Array);
      expect(encrypted.tag).toBeInstanceOf(Uint8Array);
      expect(encrypted.ciphertext.length).toBeGreaterThan(0);
      expect(encrypted.iv.length).toBe(12); // Standard IV length for AES-GCM
      expect(encrypted.tag.length).toBe(16); // Standard tag length for AES-GCM
    });

    it('should decrypt encrypted data', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);

      const sharedSecret = await performKeyExchange(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const salt = crypto.getRandomValues(new Uint8Array(32));
      const key = await deriveKey(sharedSecret, salt);

      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypted = await encrypt(key, plaintext);
      const decrypted = await decrypt(key, encrypted);

      expect(decrypted).toEqual(plaintext);
      expect(new TextDecoder().decode(decrypted)).toBe('Hello, World!');
    });

    it('should produce different ciphertexts for same plaintext', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);

      const sharedSecret = await performKeyExchange(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const salt = crypto.getRandomValues(new Uint8Array(32));
      const key = await deriveKey(sharedSecret, salt);

      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypted1 = await encrypt(key, plaintext);
      const encrypted2 = await encrypt(key, plaintext);

      // IVs should be different
      expect(encrypted1.iv).not.toEqual(encrypted2.iv);
      // Ciphertexts should be different due to different IVs
      expect(encrypted1.ciphertext).not.toEqual(encrypted2.ciphertext);
    });

    it('should handle empty plaintext', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);

      const sharedSecret = await performKeyExchange(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const salt = crypto.getRandomValues(new Uint8Array(32));
      const key = await deriveKey(sharedSecret, salt);

      const plaintext = new Uint8Array(0);
      const encrypted = await encrypt(key, plaintext);
      const decrypted = await decrypt(key, encrypted);

      expect(decrypted).toEqual(plaintext);
      expect(decrypted.length).toBe(0);
    });

    it('should handle large plaintext', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);

      const sharedSecret = await performKeyExchange(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const salt = crypto.getRandomValues(new Uint8Array(32));
      const key = await deriveKey(sharedSecret, salt);

      // Create 64KB of data (max for crypto.getRandomValues)
      const plaintext = crypto.getRandomValues(new Uint8Array(65536));
      const encrypted = await encrypt(key, plaintext);
      const decrypted = await decrypt(key, encrypted);

      expect(decrypted).toEqual(plaintext);
    });
  });

  describe('IV generation', () => {
    it('should generate random IV', () => {
      const iv = generateIV();

      expect(iv).toBeDefined();
      expect(iv).toBeInstanceOf(Uint8Array);
      expect(iv.length).toBe(12);
    });

    it('should generate different IVs on each call', () => {
      const iv1 = generateIV();
      const iv2 = generateIV();

      expect(iv1).not.toEqual(iv2);
    });

    it('should generate cryptographically random IVs', () => {
      const ivs = new Set<string>();
      
      // Generate 100 IVs and check for uniqueness
      for (let i = 0; i < 100; i++) {
        const iv = generateIV();
        const ivStr = Array.from(iv).join(',');
        ivs.add(ivStr);
      }

      // All IVs should be unique
      expect(ivs.size).toBe(100);
    });
  });

  describe('Authentication tag validation', () => {
    it('should reject tampered ciphertext', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);

      const sharedSecret = await performKeyExchange(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const salt = crypto.getRandomValues(new Uint8Array(32));
      const key = await deriveKey(sharedSecret, salt);

      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypted = await encrypt(key, plaintext);

      // Tamper with ciphertext
      encrypted.ciphertext[0] ^= 0xff;

      await expect(decrypt(key, encrypted)).rejects.toThrow(CryptoError);
    });

    it('should reject tampered IV', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);

      const sharedSecret = await performKeyExchange(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const salt = crypto.getRandomValues(new Uint8Array(32));
      const key = await deriveKey(sharedSecret, salt);

      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypted = await encrypt(key, plaintext);

      // Tamper with IV
      encrypted.iv[0] ^= 0xff;

      await expect(decrypt(key, encrypted)).rejects.toThrow(CryptoError);
    });

    it('should reject tampered authentication tag', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);

      const sharedSecret = await performKeyExchange(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const salt = crypto.getRandomValues(new Uint8Array(32));
      const key = await deriveKey(sharedSecret, salt);

      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypted = await encrypt(key, plaintext);

      // Tamper with tag
      encrypted.tag[0] ^= 0xff;

      await expect(decrypt(key, encrypted)).rejects.toThrow(CryptoError);
    });
  });

  describe('Error handling', () => {
    it('should throw CryptoError when encrypting with invalid key', async () => {
      const invalidKey = {} as CryptoKey;
      const plaintext = new TextEncoder().encode('Hello, World!');

      await expect(encrypt(invalidKey, plaintext)).rejects.toThrow(CryptoError);
    });

    it('should throw CryptoError when decrypting with invalid key', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);

      const sharedSecret = await performKeyExchange(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const salt = crypto.getRandomValues(new Uint8Array(32));
      const key = await deriveKey(sharedSecret, salt);

      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypted = await encrypt(key, plaintext);

      const invalidKey = {} as CryptoKey;
      await expect(decrypt(invalidKey, encrypted)).rejects.toThrow(CryptoError);
    });

    it('should throw CryptoError when decrypting with wrong key', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);
      const charlieKeyPair = await generateKeyPair(KeyType.X25519);

      const sharedSecret1 = await performKeyExchange(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const sharedSecret2 = await performKeyExchange(
        aliceKeyPair.privateKey,
        charlieKeyPair.publicKey
      );

      const salt = crypto.getRandomValues(new Uint8Array(32));
      const key1 = await deriveKey(sharedSecret1, salt);
      const key2 = await deriveKey(sharedSecret2, salt);

      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypted = await encrypt(key1, plaintext);

      await expect(decrypt(key2, encrypted)).rejects.toThrow(CryptoError);
    });

    it('should throw CryptoError with invalid IV length', async () => {
      const aliceKeyPair = await generateKeyPair(KeyType.X25519);
      const bobKeyPair = await generateKeyPair(KeyType.X25519);

      const sharedSecret = await performKeyExchange(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
      );

      const salt = crypto.getRandomValues(new Uint8Array(32));
      const key = await deriveKey(sharedSecret, salt);

      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypted = await encrypt(key, plaintext);

      // Use invalid IV length
      encrypted.iv = new Uint8Array(8);

      await expect(decrypt(key, encrypted)).rejects.toThrow(CryptoError);
    });
  });
});
