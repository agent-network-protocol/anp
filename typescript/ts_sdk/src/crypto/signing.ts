/**
 * Signing and verification utilities
 */

import { CryptoError } from '../errors/index.js';
import { KeyType } from './key-generation.js';

/**
 * Sign data with a private key
 *
 * @param privateKey - The private key to sign with
 * @param data - The data to sign
 * @param keyType - The type of key being used
 * @returns A promise that resolves to the signature
 * @throws {CryptoError} If signing fails
 */
export async function sign(
  privateKey: CryptoKey,
  data: Uint8Array,
  keyType: KeyType
): Promise<Uint8Array> {
  try {
    const algorithm = getSignAlgorithm(keyType);
    const signature = await crypto.subtle.sign(algorithm, privateKey, data as BufferSource);
    return new Uint8Array(signature);
  } catch (error) {
    throw new CryptoError(
      `Failed to sign data with ${keyType}`,
      error as Error
    );
  }
}

/**
 * Verify a signature
 *
 * @param publicKey - The public key to verify with
 * @param data - The original data that was signed
 * @param signature - The signature to verify
 * @param keyType - The type of key being used
 * @returns A promise that resolves to true if valid, false otherwise
 * @throws {CryptoError} If verification fails due to an error (not invalid signature)
 */
export async function verify(
  publicKey: CryptoKey,
  data: Uint8Array,
  signature: Uint8Array,
  keyType: KeyType
): Promise<boolean> {
  try {
    const algorithm = getSignAlgorithm(keyType);
    return await crypto.subtle.verify(algorithm, publicKey, signature as BufferSource, data as BufferSource);
  } catch (error) {
    throw new CryptoError(
      `Failed to verify signature with ${keyType}`,
      error as Error
    );
  }
}

/**
 * Get the signing algorithm for a key type
 */
function getSignAlgorithm(keyType: KeyType): AlgorithmIdentifier | EcdsaParams {
  switch (keyType) {
    case KeyType.ECDSA_SECP256K1:
      return {
        name: 'ECDSA',
        hash: { name: 'SHA-256' },
      };
    case KeyType.ED25519:
      return { name: 'Ed25519' };
    case KeyType.X25519:
      throw new CryptoError('X25519 keys cannot be used for signing');
    default:
      throw new CryptoError(`Unsupported key type for signing: ${keyType}`);
  }
}

/**
 * Encode a signature to base64url format
 *
 * @param signature - The signature bytes
 * @returns The base64url-encoded signature
 */
export function encodeSignature(signature: Uint8Array): string {
  return base64UrlEncode(signature);
}

/**
 * Decode a signature from base64url format
 *
 * @param encoded - The base64url-encoded signature
 * @returns The signature bytes
 * @throws {CryptoError} If decoding fails
 */
export function decodeSignature(encoded: string): Uint8Array {
  try {
    return base64UrlDecode(encoded);
  } catch (error) {
    throw new CryptoError('Failed to decode signature', error as Error);
  }
}

/**
 * Encode bytes to base64url
 */
function base64UrlEncode(bytes: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Decode base64url to bytes
 */
function base64UrlDecode(str: string): Uint8Array {
  // Add padding if needed
  const padding = '='.repeat((4 - (str.length % 4)) % 4);
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/') + padding;
  
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
