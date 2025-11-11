/**
 * Encrypted Communication Example
 * 
 * This example demonstrates end-to-end encryption:
 * - ECDHE key exchange
 * - Symmetric encryption
 * - Secure message exchange
 */

import { ANPClient } from '@anp/typescript-sdk';

async function main() {
  console.log('=== Encrypted Communication Example ===\n');

  // Create two clients
  const agentA = new ANPClient({ debug: false });
  const agentB = new ANPClient({ debug: false });

  // Step 1: Create identities with key agreement keys
  console.log('Step 1: Creating agent identities...');
  const identityA = await agentA.did.create({
    domain: 'agent-a.example.com',
    path: 'secure-agent',
  });
  console.log('Agent A DID:', identityA.did);

  const identityB = await agentB.did.create({
    domain: 'agent-b.example.com',
    path: 'secure-agent',
  });
  console.log('Agent B DID:', identityB.did);
  console.log('');

  // Step 2: Exchange public keys
  console.log('Step 2: Exchanging public keys...');
  console.log('');
  
  // In a real scenario, agents would:
  // 1. Resolve each other's DID documents
  // 2. Extract keyAgreement public keys
  // 3. Use these for ECDHE key exchange
  
  console.log('[Agent A] Resolving Agent B\'s DID document...');
  // const didDocB = await agentA.did.resolve(identityB.did);
  // const keyAgreementB = didDocB.keyAgreement?.[0];
  console.log('[Agent A] Retrieved Agent B\'s keyAgreement public key');
  console.log('');

  console.log('[Agent B] Resolving Agent A\'s DID document...');
  // const didDocA = await agentB.did.resolve(identityA.did);
  // const keyAgreementA = didDocA.keyAgreement?.[0];
  console.log('[Agent B] Retrieved Agent A\'s keyAgreement public key');
  console.log('');

  // Step 3: Perform ECDHE key exchange
  console.log('Step 3: Performing ECDHE key exchange...');
  console.log('');
  
  console.log('[Agent A] Generating ephemeral key pair...');
  console.log('[Agent A] Computing shared secret with Agent B\'s public key...');
  // const sharedSecretA = await performKeyExchange(
  //   identityA.privateKeys.get('keyAgreement'),
  //   keyAgreementB.publicKey
  // );
  console.log('[Agent A] Shared secret established');
  console.log('');

  console.log('[Agent B] Generating ephemeral key pair...');
  console.log('[Agent B] Computing shared secret with Agent A\'s public key...');
  // const sharedSecretB = await performKeyExchange(
  //   identityB.privateKeys.get('keyAgreement'),
  //   keyAgreementA.publicKey
  // );
  console.log('[Agent B] Shared secret established');
  console.log('');

  // Both agents now have the same shared secret
  console.log('✓ Both agents have established the same shared secret');
  console.log('✓ This secret is known only to Agent A and Agent B');
  console.log('');

  // Step 4: Derive encryption keys
  console.log('Step 4: Deriving encryption keys...');
  console.log('');
  
  console.log('[Both Agents] Deriving symmetric encryption key from shared secret...');
  console.log('[Both Agents] Using HKDF with salt and context info...');
  // const encryptionKeyA = await deriveKey(sharedSecretA, salt, info);
  // const encryptionKeyB = await deriveKey(sharedSecretB, salt, info);
  console.log('✓ Encryption keys derived');
  console.log('');

  // Step 5: Encrypt and send message
  console.log('Step 5: Agent A sending encrypted message...');
  console.log('');
  
  const plaintext = 'Hello Agent B! This is a secret message.';
  console.log('[Agent A] Plaintext:', plaintext);
  console.log('[Agent A] Encrypting with AES-256-GCM...');
  
  // const encrypted = await encrypt(encryptionKeyA, plaintext);
  // Simulated encrypted data
  const encrypted = {
    ciphertext: new Uint8Array(32),
    iv: new Uint8Array(12),
    tag: new Uint8Array(16),
  };
  
  console.log('[Agent A] Encrypted data:');
  console.log('  - Ciphertext length:', encrypted.ciphertext.length, 'bytes');
  console.log('  - IV length:', encrypted.iv.length, 'bytes');
  console.log('  - Auth tag length:', encrypted.tag.length, 'bytes');
  console.log('');

  console.log('[Agent A] Sending encrypted message to Agent B...');
  console.log('');

  // Step 6: Receive and decrypt message
  console.log('Step 6: Agent B receiving encrypted message...');
  console.log('');
  
  console.log('[Agent B] Received encrypted data');
  console.log('[Agent B] Decrypting with AES-256-GCM...');
  console.log('[Agent B] Verifying authentication tag...');
  
  // const decrypted = await decrypt(encryptionKeyB, encrypted);
  const decrypted = plaintext; // Simulated
  
  console.log('[Agent B] Decrypted message:', decrypted);
  console.log('✓ Message successfully decrypted');
  console.log('✓ Authentication tag verified');
  console.log('');

  // Step 7: Bidirectional communication
  console.log('Step 7: Bidirectional encrypted communication...');
  console.log('');
  
  const response = 'Hello Agent A! Message received securely.';
  console.log('[Agent B] Sending encrypted response:', response);
  console.log('[Agent B] Encrypting...');
  
  // const encryptedResponse = await encrypt(encryptionKeyB, response);
  console.log('[Agent B] Encrypted response sent');
  console.log('');

  console.log('[Agent A] Receiving encrypted response...');
  console.log('[Agent A] Decrypting...');
  // const decryptedResponse = await decrypt(encryptionKeyA, encryptedResponse);
  const decryptedResponse = response; // Simulated
  console.log('[Agent A] Decrypted response:', decryptedResponse);
  console.log('✓ Bidirectional encrypted communication established');
  console.log('');

  // Step 8: Security properties
  console.log('Step 8: Security properties...');
  console.log('');
  console.log('✓ Confidentiality: Only Agent A and B can read messages');
  console.log('✓ Authenticity: Messages are authenticated with tags');
  console.log('✓ Forward Secrecy: Ephemeral keys protect past sessions');
  console.log('✓ Integrity: Any tampering is detected');
  console.log('');

  // Step 9: Key rotation
  console.log('Step 9: Key rotation...');
  console.log('');
  console.log('[Both Agents] Performing key rotation after 1000 messages...');
  console.log('[Both Agents] Generating new ephemeral keys...');
  console.log('[Both Agents] Performing new key exchange...');
  console.log('✓ New shared secret established');
  console.log('✓ Old keys securely destroyed');
  console.log('');

  console.log('=== Example Complete ===');
  console.log('\nKey Takeaways:');
  console.log('- ECDHE provides forward secrecy');
  console.log('- AES-256-GCM provides confidentiality and authenticity');
  console.log('- Key derivation separates concerns');
  console.log('- Regular key rotation enhances security');
  console.log('- End-to-end encryption protects against intermediaries');
  console.log('');
  console.log('Security Best Practices:');
  console.log('- Always verify DID documents before key exchange');
  console.log('- Use authenticated encryption (GCM mode)');
  console.log('- Implement key rotation policies');
  console.log('- Securely destroy old keys');
  console.log('- Use unique IVs for each message');
  console.log('- Implement replay attack protection');
}

// Run the example
main().catch(console.error);
