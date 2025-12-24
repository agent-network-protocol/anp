/**
 * Integration test for encrypted communication flow
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { DIDManager } from '../../src/core/did/did-manager.js';
import {
  performKeyExchange,
  deriveKey,
  validateSharedSecret,
} from '../../src/crypto/key-exchange.js';
import { encrypt, decrypt, generateIV } from '../../src/crypto/encryption.js';
import type { DIDIdentity } from '../../src/types/index.js';

describe('Encrypted Communication Integration', () => {
  let didManager: DIDManager;
  let aliceIdentity: DIDIdentity;
  let bobIdentity: DIDIdentity;

  beforeEach(async () => {
    // Initialize DID manager
    didManager = new DIDManager();

    // Create two agent identities with keyAgreement keys
    aliceIdentity = await didManager.createDID({
      domain: 'alice.example.com',
      path: 'agent',
    });

    bobIdentity = await didManager.createDID({
      domain: 'bob.example.com',
      path: 'agent',
    });
  });

  it('should establish encrypted channel and exchange messages', async () => {
    // Step 1: Extract key agreement keys from DID documents
    const aliceKeyAgreementMethod = aliceIdentity.document.verificationMethod.find(
      (vm) => vm.id.includes('#key-agreement')
    );
    const bobKeyAgreementMethod = bobIdentity.document.verificationMethod.find(
      (vm) => vm.id.includes('#key-agreement')
    );

    expect(aliceKeyAgreementMethod).toBeDefined();
    expect(bobKeyAgreementMethod).toBeDefined();

    // Step 2: Get private keys
    const alicePrivateKey = aliceIdentity.privateKeys.get(
      aliceKeyAgreementMethod!.id
    );
    const bobPrivateKey = bobIdentity.privateKeys.get(
      bobKeyAgreementMethod!.id
    );

    expect(alicePrivateKey).toBeDefined();
    expect(bobPrivateKey).toBeDefined();

    // Step 3: Import Bob's public key for Alice
    const bobPublicKey = await crypto.subtle.importKey(
      'jwk',
      bobKeyAgreementMethod!.publicKeyJwk!,
      {
        name: 'X25519',
      } as any,
      true,
      []
    );

    // Step 4: Import Alice's public key for Bob
    const alicePublicKey = await crypto.subtle.importKey(
      'jwk',
      aliceKeyAgreementMethod!.publicKeyJwk!,
      {
        name: 'X25519',
      } as any,
      true,
      []
    );

    // Step 5: Perform key exchange (Alice's side)
    const aliceSharedSecret = await performKeyExchange(
      alicePrivateKey!.key,
      bobPublicKey
    );

    // Step 6: Perform key exchange (Bob's side)
    const bobSharedSecret = await performKeyExchange(
      bobPrivateKey!.key,
      alicePublicKey
    );

    // Step 7: Verify shared secrets match
    expect(aliceSharedSecret).toEqual(bobSharedSecret);

    // Step 8: Validate shared secrets
    expect(validateSharedSecret(aliceSharedSecret)).toBe(true);
    expect(validateSharedSecret(bobSharedSecret)).toBe(true);

    // Step 9: Derive encryption keys
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const aliceEncryptionKey = await deriveKey(aliceSharedSecret, salt);
    const bobEncryptionKey = await deriveKey(bobSharedSecret, salt);

    // Step 10: Alice encrypts a message
    const message = new TextEncoder().encode('Hello Bob! This is a secret message.');
    const encryptedMessage = await encrypt(aliceEncryptionKey, message);

    expect(encryptedMessage.ciphertext).toBeDefined();
    expect(encryptedMessage.iv).toBeDefined();
    expect(encryptedMessage.tag).toBeDefined();
    expect(encryptedMessage.iv.length).toBe(12);
    expect(encryptedMessage.tag.length).toBe(16);

    // Step 11: Bob decrypts the message
    const decryptedMessage = await decrypt(bobEncryptionKey, encryptedMessage);

    // Step 12: Verify decrypted message matches original
    const decryptedText = new TextDecoder().decode(decryptedMessage);
    expect(decryptedText).toBe('Hello Bob! This is a secret message.');
  });

  it('should support bidirectional encrypted communication', async () => {
    // Setup: Establish shared secret
    const aliceKeyAgreementMethod = aliceIdentity.document.verificationMethod.find(
      (vm) => vm.id.includes('#key-agreement')
    )!;
    const bobKeyAgreementMethod = bobIdentity.document.verificationMethod.find(
      (vm) => vm.id.includes('#key-agreement')
    )!;

    const alicePrivateKey = aliceIdentity.privateKeys.get(
      aliceKeyAgreementMethod.id
    )!;
    const bobPrivateKey = bobIdentity.privateKeys.get(
      bobKeyAgreementMethod.id
    )!;

    const bobPublicKey = await crypto.subtle.importKey(
      'jwk',
      bobKeyAgreementMethod.publicKeyJwk!,
      { name: 'X25519' } as any,
      true,
      []
    );

    const alicePublicKey = await crypto.subtle.importKey(
      'jwk',
      aliceKeyAgreementMethod.publicKeyJwk!,
      { name: 'X25519' } as any,
      true,
      []
    );

    const aliceSharedSecret = await performKeyExchange(
      alicePrivateKey.key,
      bobPublicKey
    );
    const bobSharedSecret = await performKeyExchange(
      bobPrivateKey.key,
      alicePublicKey
    );

    const salt = crypto.getRandomValues(new Uint8Array(32));
    const aliceEncryptionKey = await deriveKey(aliceSharedSecret, salt);
    const bobEncryptionKey = await deriveKey(bobSharedSecret, salt);

    // Alice sends message to Bob
    const aliceMessage = new TextEncoder().encode('Hello Bob!');
    const encryptedAliceMessage = await encrypt(aliceEncryptionKey, aliceMessage);
    const decryptedAliceMessage = await decrypt(
      bobEncryptionKey,
      encryptedAliceMessage
    );
    expect(new TextDecoder().decode(decryptedAliceMessage)).toBe('Hello Bob!');

    // Bob sends message to Alice
    const bobMessage = new TextEncoder().encode('Hello Alice!');
    const encryptedBobMessage = await encrypt(bobEncryptionKey, bobMessage);
    const decryptedBobMessage = await decrypt(
      aliceEncryptionKey,
      encryptedBobMessage
    );
    expect(new TextDecoder().decode(decryptedBobMessage)).toBe('Hello Alice!');
  });

  it('should detect tampering with authentication tag', async () => {
    // Setup: Establish encrypted channel
    const aliceKeyAgreementMethod = aliceIdentity.document.verificationMethod.find(
      (vm) => vm.id.includes('#key-agreement')
    )!;
    const bobKeyAgreementMethod = bobIdentity.document.verificationMethod.find(
      (vm) => vm.id.includes('#key-agreement')
    )!;

    const alicePrivateKey = aliceIdentity.privateKeys.get(
      aliceKeyAgreementMethod.id
    )!;
    const bobPrivateKey = bobIdentity.privateKeys.get(
      bobKeyAgreementMethod.id
    )!;

    const bobPublicKey = await crypto.subtle.importKey(
      'jwk',
      bobKeyAgreementMethod.publicKeyJwk!,
      { name: 'X25519' } as any,
      true,
      []
    );

    const alicePublicKey = await crypto.subtle.importKey(
      'jwk',
      aliceKeyAgreementMethod.publicKeyJwk!,
      { name: 'X25519' } as any,
      true,
      []
    );

    const aliceSharedSecret = await performKeyExchange(
      alicePrivateKey.key,
      bobPublicKey
    );
    const bobSharedSecret = await performKeyExchange(
      bobPrivateKey.key,
      alicePublicKey
    );

    const salt = crypto.getRandomValues(new Uint8Array(32));
    const aliceEncryptionKey = await deriveKey(aliceSharedSecret, salt);
    const bobEncryptionKey = await deriveKey(bobSharedSecret, salt);

    // Encrypt message
    const message = new TextEncoder().encode('Secret message');
    const encryptedMessage = await encrypt(aliceEncryptionKey, message);

    // Tamper with the ciphertext
    encryptedMessage.ciphertext[0] ^= 0xff;

    // Decryption should fail
    await expect(decrypt(bobEncryptionKey, encryptedMessage)).rejects.toThrow();
  });

  it('should handle multiple messages with different IVs', async () => {
    // Setup: Establish encrypted channel
    const aliceKeyAgreementMethod = aliceIdentity.document.verificationMethod.find(
      (vm) => vm.id.includes('#key-agreement')
    )!;
    const bobKeyAgreementMethod = bobIdentity.document.verificationMethod.find(
      (vm) => vm.id.includes('#key-agreement')
    )!;

    const alicePrivateKey = aliceIdentity.privateKeys.get(
      aliceKeyAgreementMethod.id
    )!;
    const bobPrivateKey = bobIdentity.privateKeys.get(
      bobKeyAgreementMethod.id
    )!;

    const bobPublicKey = await crypto.subtle.importKey(
      'jwk',
      bobKeyAgreementMethod.publicKeyJwk!,
      { name: 'X25519' } as any,
      true,
      []
    );

    const alicePublicKey = await crypto.subtle.importKey(
      'jwk',
      aliceKeyAgreementMethod.publicKeyJwk!,
      { name: 'X25519' } as any,
      true,
      []
    );

    const aliceSharedSecret = await performKeyExchange(
      alicePrivateKey.key,
      bobPublicKey
    );
    const bobSharedSecret = await performKeyExchange(
      bobPrivateKey.key,
      alicePublicKey
    );

    const salt = crypto.getRandomValues(new Uint8Array(32));
    const aliceEncryptionKey = await deriveKey(aliceSharedSecret, salt);
    const bobEncryptionKey = await deriveKey(bobSharedSecret, salt);

    // Send multiple messages
    const messages = [
      'Message 1',
      'Message 2',
      'Message 3',
      'Message 4',
      'Message 5',
    ];

    const encryptedMessages = [];
    const ivs = new Set<string>();

    for (const msg of messages) {
      const plaintext = new TextEncoder().encode(msg);
      const encrypted = await encrypt(aliceEncryptionKey, plaintext);
      encryptedMessages.push(encrypted);

      // Verify each message has a unique IV
      const ivString = Array.from(encrypted.iv).join(',');
      expect(ivs.has(ivString)).toBe(false);
      ivs.add(ivString);
    }

    // Decrypt all messages
    for (let i = 0; i < messages.length; i++) {
      const decrypted = await decrypt(bobEncryptionKey, encryptedMessages[i]);
      const decryptedText = new TextDecoder().decode(decrypted);
      expect(decryptedText).toBe(messages[i]);
    }
  });

  it('should support large message encryption', async () => {
    // Setup: Establish encrypted channel
    const aliceKeyAgreementMethod = aliceIdentity.document.verificationMethod.find(
      (vm) => vm.id.includes('#key-agreement')
    )!;
    const bobKeyAgreementMethod = bobIdentity.document.verificationMethod.find(
      (vm) => vm.id.includes('#key-agreement')
    )!;

    const alicePrivateKey = aliceIdentity.privateKeys.get(
      aliceKeyAgreementMethod.id
    )!;
    const bobPrivateKey = bobIdentity.privateKeys.get(
      bobKeyAgreementMethod.id
    )!;

    const bobPublicKey = await crypto.subtle.importKey(
      'jwk',
      bobKeyAgreementMethod.publicKeyJwk!,
      { name: 'X25519' } as any,
      true,
      []
    );

    const alicePublicKey = await crypto.subtle.importKey(
      'jwk',
      aliceKeyAgreementMethod.publicKeyJwk!,
      { name: 'X25519' } as any,
      true,
      []
    );

    const aliceSharedSecret = await performKeyExchange(
      alicePrivateKey.key,
      bobPublicKey
    );
    const bobSharedSecret = await performKeyExchange(
      bobPrivateKey.key,
      alicePublicKey
    );

    const salt = crypto.getRandomValues(new Uint8Array(32));
    const aliceEncryptionKey = await deriveKey(aliceSharedSecret, salt);
    const bobEncryptionKey = await deriveKey(bobSharedSecret, salt);

    // Create a large message (64 KB - max for crypto.getRandomValues)
    // Fill in chunks to avoid quota exceeded error
    const largeMessage = new Uint8Array(64 * 1024);
    const chunkSize = 32 * 1024; // 32 KB chunks
    for (let i = 0; i < largeMessage.length; i += chunkSize) {
      const chunk = largeMessage.subarray(i, Math.min(i + chunkSize, largeMessage.length));
      crypto.getRandomValues(chunk);
    }

    // Encrypt large message
    const encryptedLargeMessage = await encrypt(
      aliceEncryptionKey,
      largeMessage
    );

    // Decrypt large message
    const decryptedLargeMessage = await decrypt(
      bobEncryptionKey,
      encryptedLargeMessage
    );

    // Verify decrypted message matches original
    expect(decryptedLargeMessage).toEqual(largeMessage);
  });

  it('should verify end-to-end encryption properties', async () => {
    // Setup: Establish encrypted channel
    const aliceKeyAgreementMethod = aliceIdentity.document.verificationMethod.find(
      (vm) => vm.id.includes('#key-agreement')
    )!;
    const bobKeyAgreementMethod = bobIdentity.document.verificationMethod.find(
      (vm) => vm.id.includes('#key-agreement')
    )!;

    const alicePrivateKey = aliceIdentity.privateKeys.get(
      aliceKeyAgreementMethod.id
    )!;
    const bobPrivateKey = bobIdentity.privateKeys.get(
      bobKeyAgreementMethod.id
    )!;

    const bobPublicKey = await crypto.subtle.importKey(
      'jwk',
      bobKeyAgreementMethod.publicKeyJwk!,
      { name: 'X25519' } as any,
      true,
      []
    );

    const alicePublicKey = await crypto.subtle.importKey(
      'jwk',
      aliceKeyAgreementMethod.publicKeyJwk!,
      { name: 'X25519' } as any,
      true,
      []
    );

    const aliceSharedSecret = await performKeyExchange(
      alicePrivateKey.key,
      bobPublicKey
    );
    const bobSharedSecret = await performKeyExchange(
      bobPrivateKey.key,
      alicePublicKey
    );

    const salt = crypto.getRandomValues(new Uint8Array(32));
    const aliceEncryptionKey = await deriveKey(aliceSharedSecret, salt);
    const bobEncryptionKey = await deriveKey(bobSharedSecret, salt);

    const message = new TextEncoder().encode('Confidential data');
    const encryptedMessage = await encrypt(aliceEncryptionKey, message);

    // Property 1: Ciphertext should not reveal plaintext
    const ciphertextString = new TextDecoder().decode(
      encryptedMessage.ciphertext
    );
    expect(ciphertextString).not.toContain('Confidential');
    expect(ciphertextString).not.toContain('data');

    // Property 2: Same plaintext with different IVs produces different ciphertext
    const encryptedMessage2 = await encrypt(aliceEncryptionKey, message);
    expect(encryptedMessage.ciphertext).not.toEqual(
      encryptedMessage2.ciphertext
    );
    expect(encryptedMessage.iv).not.toEqual(encryptedMessage2.iv);

    // Property 3: Both encrypted messages decrypt to same plaintext
    const decrypted1 = await decrypt(bobEncryptionKey, encryptedMessage);
    const decrypted2 = await decrypt(bobEncryptionKey, encryptedMessage2);
    expect(decrypted1).toEqual(message);
    expect(decrypted2).toEqual(message);

    // Property 4: Wrong key cannot decrypt
    const wrongSalt = crypto.getRandomValues(new Uint8Array(32));
    const wrongKey = await deriveKey(aliceSharedSecret, wrongSalt);
    await expect(decrypt(wrongKey, encryptedMessage)).rejects.toThrow();
  });

  it('should handle key derivation with different salts', async () => {
    // Setup: Get shared secret
    const aliceKeyAgreementMethod = aliceIdentity.document.verificationMethod.find(
      (vm) => vm.id.includes('#key-agreement')
    )!;
    const bobKeyAgreementMethod = bobIdentity.document.verificationMethod.find(
      (vm) => vm.id.includes('#key-agreement')
    )!;

    const alicePrivateKey = aliceIdentity.privateKeys.get(
      aliceKeyAgreementMethod.id
    )!;
    const bobPrivateKey = bobIdentity.privateKeys.get(
      bobKeyAgreementMethod.id
    )!;

    const bobPublicKey = await crypto.subtle.importKey(
      'jwk',
      bobKeyAgreementMethod.publicKeyJwk!,
      { name: 'X25519' } as any,
      true,
      []
    );

    const alicePublicKey = await crypto.subtle.importKey(
      'jwk',
      aliceKeyAgreementMethod.publicKeyJwk!,
      { name: 'X25519' } as any,
      true,
      []
    );

    const aliceSharedSecret = await performKeyExchange(
      alicePrivateKey.key,
      bobPublicKey
    );
    const bobSharedSecret = await performKeyExchange(
      bobPrivateKey.key,
      alicePublicKey
    );

    // Derive keys with different salts
    const salt1 = crypto.getRandomValues(new Uint8Array(32));
    const salt2 = crypto.getRandomValues(new Uint8Array(32));

    const key1Alice = await deriveKey(aliceSharedSecret, salt1);
    const key1Bob = await deriveKey(bobSharedSecret, salt1);

    const key2Alice = await deriveKey(aliceSharedSecret, salt2);
    const key2Bob = await deriveKey(bobSharedSecret, salt2);

    // Keys derived with same salt should work together
    const message = new TextEncoder().encode('Test message');
    const encrypted1 = await encrypt(key1Alice, message);
    const decrypted1 = await decrypt(key1Bob, encrypted1);
    expect(decrypted1).toEqual(message);

    const encrypted2 = await encrypt(key2Alice, message);
    const decrypted2 = await decrypt(key2Bob, encrypted2);
    expect(decrypted2).toEqual(message);

    // Keys derived with different salts should not work together
    await expect(decrypt(key2Bob, encrypted1)).rejects.toThrow();
    await expect(decrypt(key1Bob, encrypted2)).rejects.toThrow();
  });
});
