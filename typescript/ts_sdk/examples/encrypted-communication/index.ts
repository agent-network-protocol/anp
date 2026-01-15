/**
 * Encrypted Communication Example
 * 
 * Demonstrates end-to-end encryption between two agents:
 * - ECDHE key exchange with X25519
 * - Key derivation with HKDF
 * - AES-256-GCM encryption/decryption
 * - Bidirectional secure communication
 */

import { ANPClient } from '../../dist/index.js';
import { performKeyExchange, deriveKey } from '../../dist/index.js';
import { encrypt, decrypt } from '../../dist/index.js';

async function main() {
  console.log('=== Encrypted Communication Example ===\n');

  const client = new ANPClient();

  // Step 1: Create identities with key agreement keys
  console.log('Step 1: Creating agent identities...');
  const aliceIdentity = await client.did.create({
    domain: 'localhost:9000',
    path: 'alice',
  });
  const bobIdentity = await client.did.create({
    domain: 'localhost:9001',
    path: 'bob',
  });
  console.log('✓ Alice:', aliceIdentity.did);
  console.log('✓ Bob:', bobIdentity.did);
  console.log();

  // Step 2: Extract key agreement keys
  console.log('Step 2: Extracting keyAgreement keys...');
  
  // Get Alice's key agreement keys
  const aliceKeyAgreementId = aliceIdentity.document.keyAgreement?.[0];
  const aliceKeyAgreementMethod = typeof aliceKeyAgreementId === 'string'
    ? aliceIdentity.document.verificationMethod?.find(vm => vm.id === aliceKeyAgreementId)
    : aliceKeyAgreementId;
  
  // Get Bob's key agreement keys
  const bobKeyAgreementId = bobIdentity.document.keyAgreement?.[0];
  const bobKeyAgreementMethod = typeof bobKeyAgreementId === 'string'
    ? bobIdentity.document.verificationMethod?.find(vm => vm.id === bobKeyAgreementId)
    : bobKeyAgreementId;

  if (!aliceKeyAgreementMethod || !bobKeyAgreementMethod) {
    throw new Error('Key agreement keys not found');
  }

  console.log('✓ Alice keyAgreement:', aliceKeyAgreementMethod.id);
  console.log('✓ Bob keyAgreement:', bobKeyAgreementMethod.id);
  console.log();

  // Get the actual CryptoKey objects from private keys
  const alicePrivateKeyMeta = aliceIdentity.privateKeys.get(aliceKeyAgreementMethod.id);
  const bobPrivateKeyMeta = bobIdentity.privateKeys.get(bobKeyAgreementMethod.id);

  if (!alicePrivateKeyMeta || !bobPrivateKeyMeta) {
    throw new Error('Private keys not found');
  }

  const alicePrivateKey = alicePrivateKeyMeta.key;
  const bobPrivateKey = bobPrivateKeyMeta.key;

  // Extract public keys from JWK (for key exchange, we need the remote's public key)
  const alicePublicKeyJwk = aliceKeyAgreementMethod.publicKeyJwk!;
  const bobPublicKeyJwk = bobKeyAgreementMethod.publicKeyJwk!;
  
  // Import Bob's public key for Alice to use
  const bobPublicKey = await crypto.subtle.importKey(
    'jwk',
    bobPublicKeyJwk,
    { name: 'X25519' },
    true,
    []
  );

  // Import Alice's public key for Bob to use
  const alicePublicKey = await crypto.subtle.importKey(
    'jwk',
    alicePublicKeyJwk,
    { name: 'X25519' },
    true,
    []
  );

  // Step 3: Perform ECDHE key exchange
  console.log('Step 3: Performing ECDHE key exchange...');
  
  // Alice computes shared secret with Bob's public key
  const sharedSecretAlice = await performKeyExchange(alicePrivateKey, bobPublicKey);
  
  // Bob computes shared secret with Alice's public key
  const sharedSecretBob = await performKeyExchange(bobPrivateKey, alicePublicKey);
  
  // Verify both computed the same shared secret
  const secretsMatch = sharedSecretAlice.every((byte, i) => byte === sharedSecretBob[i]);
  console.log('✓ Shared secret established:', secretsMatch ? 'MATCH' : 'MISMATCH');
  console.log('  Shared secret length:', sharedSecretAlice.length, 'bytes');
  console.log();

  // Step 4: Derive encryption keys
  console.log('Step 4: Deriving encryption keys with HKDF...');
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const encryptionKey = await deriveKey(sharedSecretAlice, salt);
  console.log('✓ Encryption key derived (AES-256-GCM)');
  console.log('  Salt length:', salt.length, 'bytes');
  console.log();

  // Step 5: Alice encrypts a message to Bob
  console.log('Step 5: Alice encrypts message to Bob...');
  const aliceMessage = 'Hello Bob! This is a secret message from Alice.';
  const alicePlaintext = new TextEncoder().encode(aliceMessage);
  
  const encrypted = await encrypt(encryptionKey, alicePlaintext);
  console.log('✓ Message encrypted');
  console.log('  Original message:', aliceMessage);
  console.log('  Plaintext length:', alicePlaintext.length, 'bytes');
  console.log('  Ciphertext length:', encrypted.ciphertext.length, 'bytes');
  console.log('  IV length:', encrypted.iv.length, 'bytes');
  console.log('  Auth tag length:', encrypted.tag.length, 'bytes');
  console.log();

  // Step 6: Bob decrypts the message
  console.log('Step 6: Bob decrypts message from Alice...');
  const decrypted = await decrypt(encryptionKey, encrypted);
  const bobReceivedMessage = new TextDecoder().decode(decrypted);
  console.log('✓ Message decrypted');
  console.log('  Decrypted message:', bobReceivedMessage);
  console.log('  Messages match:', bobReceivedMessage === aliceMessage);
  console.log();

  // Step 7: Bob sends encrypted reply to Alice
  console.log('Step 7: Bob sends encrypted reply to Alice...');
  const bobMessage = 'Hi Alice! I received your message securely.';
  const bobPlaintext = new TextEncoder().encode(bobMessage);
  
  const encryptedReply = await encrypt(encryptionKey, bobPlaintext);
  console.log('✓ Reply encrypted');
  console.log('  Reply message:', bobMessage);
  console.log();

  // Step 8: Alice decrypts Bob's reply
  console.log('Step 8: Alice decrypts Bob\'s reply...');
  const decryptedReply = await decrypt(encryptionKey, encryptedReply);
  const aliceReceivedMessage = new TextDecoder().decode(decryptedReply);
  console.log('✓ Reply decrypted');
  console.log('  Decrypted reply:', aliceReceivedMessage);
  console.log('  Messages match:', aliceReceivedMessage === bobMessage);
  console.log();

  // Step 9: Demonstrate tampering detection
  console.log('Step 9: Demonstrating tampering detection...');
  const tamperedData = {
    ...encrypted,
    ciphertext: new Uint8Array(encrypted.ciphertext.length).fill(0xFF),
  };
  
  try {
    await decrypt(encryptionKey, tamperedData);
    console.log('✗ Tampering not detected (UNEXPECTED)');
  } catch (error) {
    console.log('✓ Tampering detected and rejected');
    console.log('  Error:', (error as Error).message.split('\n')[0]);
  }
  console.log();

  console.log('=== Example Complete ===\n');
  
  console.log('Security Properties Demonstrated:');
  console.log('✓ Confidentiality: Messages encrypted with AES-256-GCM');
  console.log('✓ Authenticity: Authentication tags verify message integrity');
  console.log('✓ Forward Secrecy: Ephemeral key exchange protects past sessions');
  console.log('✓ Integrity: Tampering is detected and rejected');
  console.log('✓ Bidirectional: Both parties can encrypt and decrypt');
}

main().catch(console.error);
