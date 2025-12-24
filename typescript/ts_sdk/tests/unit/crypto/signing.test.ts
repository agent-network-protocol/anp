/**
 * Unit tests for signing and verification functionality
 */

import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  KeyType,
} from '../../../src/crypto/key-generation.js';
import { sign, verify } from '../../../src/crypto/signing.js';
import { CryptoError } from '../../../src/errors/index.js';

describe('Signing and Verification', () => {
  describe('ECDSA secp256k1 signing', () => {
    it('should sign data with ECDSA key', async () => {
      const keyPair = await generateKeyPair(KeyType.ECDSA_SECP256K1);
      const data = new TextEncoder().encode('test message');

      const signature = await sign(keyPair.privateKey, data, KeyType.ECDSA_SECP256K1);

      expect(signature).toBeDefined();
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBeGreaterThan(0);
    });

    it('should verify valid ECDSA signature', async () => {
      const keyPair = await generateKeyPair(KeyType.ECDSA_SECP256K1);
      const data = new TextEncoder().encode('test message');

      const signature = await sign(keyPair.privateKey, data, KeyType.ECDSA_SECP256K1);
      const isValid = await verify(
        keyPair.publicKey,
        data,
        signature,
        KeyType.ECDSA_SECP256K1
      );

      expect(isValid).toBe(true);
    });

    it('should reject invalid ECDSA signature', async () => {
      const keyPair = await generateKeyPair(KeyType.ECDSA_SECP256K1);
      const data = new TextEncoder().encode('test message');

      const signature = await sign(keyPair.privateKey, data, KeyType.ECDSA_SECP256K1);
      
      // Tamper with signature
      signature[0] ^= 0xff;

      const isValid = await verify(
        keyPair.publicKey,
        data,
        signature,
        KeyType.ECDSA_SECP256K1
      );

      expect(isValid).toBe(false);
    });

    it('should reject signature with wrong data', async () => {
      const keyPair = await generateKeyPair(KeyType.ECDSA_SECP256K1);
      const data = new TextEncoder().encode('test message');
      const wrongData = new TextEncoder().encode('wrong message');

      const signature = await sign(keyPair.privateKey, data, KeyType.ECDSA_SECP256K1);
      const isValid = await verify(
        keyPair.publicKey,
        wrongData,
        signature,
        KeyType.ECDSA_SECP256K1
      );

      expect(isValid).toBe(false);
    });

    it('should generate different signatures for different data', async () => {
      const keyPair = await generateKeyPair(KeyType.ECDSA_SECP256K1);
      const data1 = new TextEncoder().encode('message 1');
      const data2 = new TextEncoder().encode('message 2');

      const signature1 = await sign(keyPair.privateKey, data1, KeyType.ECDSA_SECP256K1);
      const signature2 = await sign(keyPair.privateKey, data2, KeyType.ECDSA_SECP256K1);

      expect(signature1).not.toEqual(signature2);
    });
  });

  describe('Ed25519 signing', () => {
    it('should sign data with Ed25519 key', async () => {
      const keyPair = await generateKeyPair(KeyType.ED25519);
      const data = new TextEncoder().encode('test message');

      const signature = await sign(keyPair.privateKey, data, KeyType.ED25519);

      expect(signature).toBeDefined();
      expect(signature).toBeInstanceOf(Uint8Array);
      expect(signature.length).toBe(64); // Ed25519 signatures are always 64 bytes
    });

    it('should verify valid Ed25519 signature', async () => {
      const keyPair = await generateKeyPair(KeyType.ED25519);
      const data = new TextEncoder().encode('test message');

      const signature = await sign(keyPair.privateKey, data, KeyType.ED25519);
      const isValid = await verify(
        keyPair.publicKey,
        data,
        signature,
        KeyType.ED25519
      );

      expect(isValid).toBe(true);
    });

    it('should reject invalid Ed25519 signature', async () => {
      const keyPair = await generateKeyPair(KeyType.ED25519);
      const data = new TextEncoder().encode('test message');

      const signature = await sign(keyPair.privateKey, data, KeyType.ED25519);
      
      // Tamper with signature
      signature[0] ^= 0xff;

      const isValid = await verify(
        keyPair.publicKey,
        data,
        signature,
        KeyType.ED25519
      );

      expect(isValid).toBe(false);
    });

    it('should reject signature with wrong data', async () => {
      const keyPair = await generateKeyPair(KeyType.ED25519);
      const data = new TextEncoder().encode('test message');
      const wrongData = new TextEncoder().encode('wrong message');

      const signature = await sign(keyPair.privateKey, data, KeyType.ED25519);
      const isValid = await verify(
        keyPair.publicKey,
        wrongData,
        signature,
        KeyType.ED25519
      );

      expect(isValid).toBe(false);
    });

    it('should generate deterministic signatures', async () => {
      const keyPair = await generateKeyPair(KeyType.ED25519);
      const data = new TextEncoder().encode('test message');

      const signature1 = await sign(keyPair.privateKey, data, KeyType.ED25519);
      const signature2 = await sign(keyPair.privateKey, data, KeyType.ED25519);

      // Ed25519 signatures are deterministic
      expect(signature1).toEqual(signature2);
    });
  });

  describe('Error handling', () => {
    it('should throw CryptoError when signing with mismatched key type', async () => {
      const keyPair = await generateKeyPair(KeyType.ED25519);
      const data = new TextEncoder().encode('test message');

      await expect(
        sign(keyPair.privateKey, data, KeyType.X25519)
      ).rejects.toThrow(CryptoError);
    });

    it('should throw CryptoError when verifying with mismatched key type', async () => {
      const keyPair = await generateKeyPair(KeyType.ED25519);
      const data = new TextEncoder().encode('test message');
      const signature = await sign(keyPair.privateKey, data, KeyType.ED25519);

      await expect(
        verify(keyPair.publicKey, data, signature, KeyType.X25519)
      ).rejects.toThrow(CryptoError);
    });

    it('should throw CryptoError when signing with public key', async () => {
      const keyPair = await generateKeyPair(KeyType.ED25519);
      const data = new TextEncoder().encode('test message');

      await expect(
        sign(keyPair.publicKey as any, data, KeyType.ED25519)
      ).rejects.toThrow(CryptoError);
    });

    it('should throw CryptoError when verifying with private key', async () => {
      const keyPair = await generateKeyPair(KeyType.ED25519);
      const data = new TextEncoder().encode('test message');
      const signature = await sign(keyPair.privateKey, data, KeyType.ED25519);

      await expect(
        verify(keyPair.privateKey as any, data, signature, KeyType.ED25519)
      ).rejects.toThrow(CryptoError);
    });

    it('should reject signature with wrong public key', async () => {
      const keyPair1 = await generateKeyPair(KeyType.ED25519);
      const keyPair2 = await generateKeyPair(KeyType.ED25519);
      const data = new TextEncoder().encode('test message');

      const signature = await sign(keyPair1.privateKey, data, KeyType.ED25519);
      const isValid = await verify(
        keyPair2.publicKey,
        data,
        signature,
        KeyType.ED25519
      );

      expect(isValid).toBe(false);
    });
  });
});
