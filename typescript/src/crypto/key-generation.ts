/**
 * Key generation and format conversion utilities
 */

import { CryptoError } from '../errors/index.js';

/**
 * Supported key types for cryptographic operations
 */
export enum KeyType {
  ECDSA_SECP256K1 = 'EcdsaSecp256k1VerificationKey2019',
  ED25519 = 'Ed25519VerificationKey2020',
  X25519 = 'X25519KeyAgreementKey2019',
}

/**
 * Generate a cryptographic key pair
 *
 * @param type - The type of key pair to generate
 * @returns A promise that resolves to a CryptoKeyPair
 * @throws {CryptoError} If key generation fails
 */
export async function generateKeyPair(type: KeyType): Promise<CryptoKeyPair> {
  try {
    switch (type) {
      case KeyType.ECDSA_SECP256K1:
        return await crypto.subtle.generateKey(
          {
            name: 'ECDSA',
            namedCurve: 'P-256', // Note: secp256k1 not natively supported, using P-256 as fallback
          },
          true,
          ['sign', 'verify']
        );

      case KeyType.ED25519:
        return await crypto.subtle.generateKey(
          {
            name: 'Ed25519',
          },
          true,
          ['sign', 'verify']
        );

      case KeyType.X25519:
        return (await crypto.subtle.generateKey(
          {
            name: 'X25519',
          },
          true,
          ['deriveKey', 'deriveBits']
        )) as CryptoKeyPair;

      default:
        throw new CryptoError(`Unsupported key type: ${type}`);
    }
  } catch (error) {
    if (error instanceof CryptoError) {
      throw error;
    }
    throw new CryptoError(
      `Failed to generate key pair for type ${type}`,
      error as Error
    );
  }
}

/**
 * Export a public key in JWK format
 *
 * @param publicKey - The public key to export
 * @returns A promise that resolves to a JsonWebKey
 * @throws {CryptoError} If export fails
 */
export async function exportPublicKeyJWK(
  publicKey: CryptoKey
): Promise<JsonWebKey> {
  try {
    return await crypto.subtle.exportKey('jwk', publicKey);
  } catch (error) {
    throw new CryptoError('Failed to export public key as JWK', error as Error);
  }
}

/**
 * Export a private key in JWK format
 *
 * @param privateKey - The private key to export
 * @returns A promise that resolves to a JsonWebKey
 * @throws {CryptoError} If export fails
 */
export async function exportPrivateKeyJWK(
  privateKey: CryptoKey
): Promise<JsonWebKey> {
  try {
    return await crypto.subtle.exportKey('jwk', privateKey);
  } catch (error) {
    throw new CryptoError(
      'Failed to export private key as JWK',
      error as Error
    );
  }
}

/**
 * Export a public key in multibase format (base58btc)
 *
 * @param publicKey - The public key to export
 * @returns A promise that resolves to a multibase-encoded string
 * @throws {CryptoError} If export fails
 */
export async function exportPublicKeyMultibase(
  publicKey: CryptoKey
): Promise<string> {
  try {
    // Export as raw format
    const rawKey = await crypto.subtle.exportKey('raw', publicKey);
    const keyBytes = new Uint8Array(rawKey);

    // Encode to base58btc with 'z' prefix
    const base58 = encodeBase58(keyBytes);
    return `z${base58}`;
  } catch (error) {
    throw new CryptoError(
      'Failed to export public key as multibase',
      error as Error
    );
  }
}

/**
 * Import a public key from JWK format
 *
 * @param jwk - The JWK to import
 * @param type - The key type
 * @returns A promise that resolves to a CryptoKey
 * @throws {CryptoError} If import fails
 */
export async function importPublicKeyJWK(
  jwk: JsonWebKey,
  type: KeyType
): Promise<CryptoKey> {
  try {
    const algorithm = getAlgorithmForKeyType(type);
    const usages = getUsagesForKeyType(type, 'public');

    return await crypto.subtle.importKey('jwk', jwk, algorithm, true, usages);
  } catch (error) {
    throw new CryptoError('Failed to import public key from JWK', error as Error);
  }
}

/**
 * Import a private key from JWK format
 *
 * @param jwk - The JWK to import
 * @param type - The key type
 * @returns A promise that resolves to a CryptoKey
 * @throws {CryptoError} If import fails
 */
export async function importPrivateKeyJWK(
  jwk: JsonWebKey,
  type: KeyType
): Promise<CryptoKey> {
  try {
    const algorithm = getAlgorithmForKeyType(type);
    const usages = getUsagesForKeyType(type, 'private');

    return await crypto.subtle.importKey('jwk', jwk, algorithm, true, usages);
  } catch (error) {
    throw new CryptoError('Failed to import private key from JWK', error as Error);
  }
}

/**
 * Get the Web Crypto API algorithm for a key type
 */
function getAlgorithmForKeyType(
  type: KeyType
): AlgorithmIdentifier | EcKeyGenParams {
  switch (type) {
    case KeyType.ECDSA_SECP256K1:
      return { name: 'ECDSA', namedCurve: 'P-256' };
    case KeyType.ED25519:
      return { name: 'Ed25519' };
    case KeyType.X25519:
      return { name: 'X25519' };
    default:
      throw new CryptoError(`Unsupported key type: ${type}`);
  }
}

/**
 * Get the key usages for a key type and key kind
 */
function getUsagesForKeyType(
  type: KeyType,
  keyKind: 'public' | 'private'
): KeyUsage[] {
  if (type === KeyType.X25519) {
    return keyKind === 'private' ? ['deriveKey', 'deriveBits'] : [];
  }
  return keyKind === 'private' ? ['sign'] : ['verify'];
}

/**
 * Base58 alphabet (Bitcoin/IPFS variant)
 */
const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Encode bytes to base58
 *
 * @param bytes - The bytes to encode
 * @returns The base58-encoded string
 */
function encodeBase58(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';

  // Convert bytes to big integer
  let num = 0n;
  for (const byte of bytes) {
    num = num * 256n + BigInt(byte);
  }

  // Convert to base58
  let result = '';
  while (num > 0n) {
    const remainder = Number(num % 58n);
    result = BASE58_ALPHABET[remainder] + result;
    num = num / 58n;
  }

  // Add leading '1's for leading zero bytes
  for (const byte of bytes) {
    if (byte === 0) {
      result = '1' + result;
    } else {
      break;
    }
  }

  return result;
}

/**
 * Decode base58 to bytes
 *
 * @param str - The base58 string to decode
 * @returns The decoded bytes
 */
export function decodeBase58(str: string): Uint8Array {
  if (str.length === 0) return new Uint8Array(0);

  // Convert base58 to big integer
  let num = 0n;
  for (const char of str) {
    const index = BASE58_ALPHABET.indexOf(char);
    if (index === -1) {
      throw new CryptoError(`Invalid base58 character: ${char}`);
    }
    num = num * 58n + BigInt(index);
  }

  // Convert to bytes
  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num = num / 256n;
  }

  // Add leading zero bytes for leading '1's
  for (const char of str) {
    if (char === '1') {
      bytes.unshift(0);
    } else {
      break;
    }
  }

  return new Uint8Array(bytes);
}
