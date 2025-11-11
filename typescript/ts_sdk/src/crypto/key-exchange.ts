/**
 * ECDHE key exchange and key derivation utilities
 */

import { CryptoError } from '../errors/index.js';

/**
 * Perform ECDHE key exchange using X25519
 *
 * @param privateKey - The local private key
 * @param publicKey - The remote public key
 * @returns A promise that resolves to the shared secret
 * @throws {CryptoError} If key exchange fails
 */
export async function performKeyExchange(
  privateKey: CryptoKey,
  publicKey: CryptoKey
): Promise<Uint8Array> {
  try {
    // Validate that keys are X25519
    if (privateKey.algorithm.name !== 'X25519') {
      throw new CryptoError(
        `Invalid private key algorithm: ${privateKey.algorithm.name}. Expected X25519`
      );
    }
    if (publicKey.algorithm.name !== 'X25519') {
      throw new CryptoError(
        `Invalid public key algorithm: ${publicKey.algorithm.name}. Expected X25519`
      );
    }

    // Validate key types
    if (privateKey.type !== 'private') {
      throw new CryptoError('First argument must be a private key');
    }
    if (publicKey.type !== 'public') {
      throw new CryptoError('Second argument must be a public key');
    }

    // Perform key exchange
    const sharedSecret = await crypto.subtle.deriveBits(
      {
        name: 'X25519',
        public: publicKey,
      },
      privateKey,
      256 // 256 bits = 32 bytes
    );

    return new Uint8Array(sharedSecret);
  } catch (error) {
    if (error instanceof CryptoError) {
      throw error;
    }
    throw new CryptoError('Failed to perform key exchange', error as Error);
  }
}

/**
 * Derive an encryption key from a shared secret using HKDF
 *
 * @param sharedSecret - The shared secret from key exchange
 * @param salt - Random salt for key derivation
 * @param info - Optional context information (default: 'ANP encryption key')
 * @returns A promise that resolves to a CryptoKey for AES-GCM encryption
 * @throws {CryptoError} If key derivation fails
 */
export async function deriveKey(
  sharedSecret: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array = new TextEncoder().encode('ANP encryption key')
): Promise<CryptoKey> {
  try {
    // Validate inputs
    if (sharedSecret.length !== 32) {
      throw new CryptoError(
        `Invalid shared secret length: ${sharedSecret.length}. Expected 32 bytes`
      );
    }
    if (salt.length === 0) {
      throw new CryptoError('Salt cannot be empty');
    }

    // Import shared secret as key material
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      sharedSecret as BufferSource,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );

    // Derive AES-GCM key using HKDF
    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt as BufferSource,
        info: info as BufferSource,
      },
      keyMaterial,
      {
        name: 'AES-GCM',
        length: 256,
      },
      true,
      ['encrypt', 'decrypt']
    );

    return derivedKey;
  } catch (error) {
    if (error instanceof CryptoError) {
      throw error;
    }
    throw new CryptoError('Failed to derive encryption key', error as Error);
  }
}

/**
 * Validate a shared secret
 *
 * @param sharedSecret - The shared secret to validate
 * @returns True if valid, false otherwise
 */
export function validateSharedSecret(sharedSecret: Uint8Array): boolean {
  // X25519 shared secrets should be 32 bytes
  if (sharedSecret.length !== 32) {
    return false;
  }

  // Check that it's not all zeros (invalid shared secret)
  const isAllZeros = sharedSecret.every((byte) => byte === 0);
  if (isAllZeros) {
    return false;
  }

  return true;
}
