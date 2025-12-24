/**
 * Encryption and decryption utilities using AES-GCM
 */

import { CryptoError } from '../errors/index.js';

/**
 * Encrypted data structure
 */
export interface EncryptedData {
  ciphertext: Uint8Array;
  iv: Uint8Array;
  tag: Uint8Array;
}

/**
 * Encrypt data using AES-GCM
 *
 * @param key - The encryption key (must be AES-GCM key)
 * @param plaintext - The data to encrypt
 * @returns A promise that resolves to the encrypted data
 * @throws {CryptoError} If encryption fails
 */
export async function encrypt(
  key: CryptoKey,
  plaintext: Uint8Array
): Promise<EncryptedData> {
  try {
    // Generate random IV
    const iv = generateIV();

    // Encrypt the data
    const ciphertextWithTag = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv as BufferSource,
        tagLength: 128, // 128-bit authentication tag
      },
      key,
      plaintext as BufferSource
    );

    // AES-GCM returns ciphertext with tag appended
    const ciphertextWithTagArray = new Uint8Array(ciphertextWithTag);
    
    // Split ciphertext and tag (tag is last 16 bytes)
    const ciphertext = ciphertextWithTagArray.slice(0, -16);
    const tag = ciphertextWithTagArray.slice(-16);

    return {
      ciphertext,
      iv,
      tag,
    };
  } catch (error) {
    throw new CryptoError('Failed to encrypt data', error as Error);
  }
}

/**
 * Decrypt data using AES-GCM
 *
 * @param key - The decryption key (must be AES-GCM key)
 * @param encrypted - The encrypted data
 * @returns A promise that resolves to the decrypted plaintext
 * @throws {CryptoError} If decryption fails
 */
export async function decrypt(
  key: CryptoKey,
  encrypted: EncryptedData
): Promise<Uint8Array> {
  try {
    // Validate inputs
    if (encrypted.iv.length !== 12) {
      throw new CryptoError(
        `Invalid IV length: ${encrypted.iv.length}. Expected 12 bytes`
      );
    }
    if (encrypted.tag.length !== 16) {
      throw new CryptoError(
        `Invalid tag length: ${encrypted.tag.length}. Expected 16 bytes`
      );
    }

    // Combine ciphertext and tag for Web Crypto API
    const ciphertextWithTag = new Uint8Array(
      encrypted.ciphertext.length + encrypted.tag.length
    );
    ciphertextWithTag.set(encrypted.ciphertext, 0);
    ciphertextWithTag.set(encrypted.tag, encrypted.ciphertext.length);

    // Decrypt the data
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: encrypted.iv as BufferSource,
        tagLength: 128,
      },
      key,
      ciphertextWithTag as BufferSource
    );

    return new Uint8Array(plaintext);
  } catch (error) {
    // Check if it's an authentication failure
    if (
      error instanceof Error &&
      (error.message.includes('authentication') ||
        error.message.includes('tag') ||
        error.name === 'OperationError')
    ) {
      throw new CryptoError(
        'Decryption failed: Authentication tag verification failed. Data may have been tampered with.',
        error
      );
    }
    throw new CryptoError('Failed to decrypt data', error as Error);
  }
}

/**
 * Generate a random initialization vector (IV) for AES-GCM
 *
 * @returns A 12-byte random IV
 */
export function generateIV(): Uint8Array {
  // AES-GCM standard IV length is 12 bytes (96 bits)
  return crypto.getRandomValues(new Uint8Array(12));
}

/**
 * Encrypt data with additional authenticated data (AAD)
 *
 * @param key - The encryption key
 * @param plaintext - The data to encrypt
 * @param additionalData - Additional data to authenticate but not encrypt
 * @returns A promise that resolves to the encrypted data
 * @throws {CryptoError} If encryption fails
 */
export async function encryptWithAAD(
  key: CryptoKey,
  plaintext: Uint8Array,
  additionalData: Uint8Array
): Promise<EncryptedData> {
  try {
    const iv = generateIV();

    const ciphertextWithTag = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv as BufferSource,
        additionalData: additionalData as BufferSource,
        tagLength: 128,
      },
      key,
      plaintext as BufferSource
    );

    const ciphertextWithTagArray = new Uint8Array(ciphertextWithTag);
    const ciphertext = ciphertextWithTagArray.slice(0, -16);
    const tag = ciphertextWithTagArray.slice(-16);

    return {
      ciphertext,
      iv,
      tag,
    };
  } catch (error) {
    throw new CryptoError(
      'Failed to encrypt data with AAD',
      error as Error
    );
  }
}

/**
 * Decrypt data with additional authenticated data (AAD)
 *
 * @param key - The decryption key
 * @param encrypted - The encrypted data
 * @param additionalData - Additional data that was authenticated
 * @returns A promise that resolves to the decrypted plaintext
 * @throws {CryptoError} If decryption fails
 */
export async function decryptWithAAD(
  key: CryptoKey,
  encrypted: EncryptedData,
  additionalData: Uint8Array
): Promise<Uint8Array> {
  try {
    if (encrypted.iv.length !== 12) {
      throw new CryptoError(
        `Invalid IV length: ${encrypted.iv.length}. Expected 12 bytes`
      );
    }
    if (encrypted.tag.length !== 16) {
      throw new CryptoError(
        `Invalid tag length: ${encrypted.tag.length}. Expected 16 bytes`
      );
    }

    const ciphertextWithTag = new Uint8Array(
      encrypted.ciphertext.length + encrypted.tag.length
    );
    ciphertextWithTag.set(encrypted.ciphertext, 0);
    ciphertextWithTag.set(encrypted.tag, encrypted.ciphertext.length);

    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: encrypted.iv as BufferSource,
        additionalData: additionalData as BufferSource,
        tagLength: 128,
      },
      key,
      ciphertextWithTag as BufferSource
    );

    return new Uint8Array(plaintext);
  } catch (error) {
    if (
      error instanceof Error &&
      (error.message.includes('authentication') ||
        error.message.includes('tag') ||
        error.name === 'OperationError')
    ) {
      throw new CryptoError(
        'Decryption failed: Authentication tag verification failed. Data may have been tampered with.',
        error
      );
    }
    throw new CryptoError('Failed to decrypt data with AAD', error as Error);
  }
}
