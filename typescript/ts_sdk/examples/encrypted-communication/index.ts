/**
 * Encrypted Communication Example
 * 
 * Demonstrates cryptographic operations for secure communication:
 * - Key generation for encryption
 * - Understanding ECDHE key exchange
 * - Encryption/decryption concepts
 */

import { ANPClient } from '@anp/typescript-sdk';

async function main() {
  console.log('=== Encrypted Communication Example ===\n');

  const agentA = new ANPClient();
  const agentB = new ANPClient();

  // Create identities with key agreement keys
  console.log('Creating agent identities...');
  const identityA = await agentA.did.create({
    domain: 'localhost:9000',
    path: 'agent-a',
  });
  const identityB = await agentB.did.create({
    domain: 'localhost:9001',
    path: 'agent-b',
  });
  console.log('✓ Agent A:', identityA.did);
  console.log('✓ Agent B:', identityB.did);
  console.log();

  // Show key agreement keys
  console.log('Key Agreement Keys:');
  const keyAgreementA = identityA.document.keyAgreement?.[0];
  const keyAgreementB = identityB.document.keyAgreement?.[0];
  
  if (keyAgreementA && keyAgreementB) {
    console.log('✓ Agent A has keyAgreement key:', keyAgreementA.id);
    console.log('✓ Agent B has keyAgreement key:', keyAgreementB.id);
  }
  console.log();

  // Demonstrate encryption concept
  console.log('Encryption Flow:');
  console.log('1. Both agents have keyAgreement keys in their DID documents');
  console.log('2. Agents perform ECDHE key exchange to establish shared secret');
  console.log('3. Shared secret is used to derive encryption keys (HKDF)');
  console.log('4. Messages are encrypted with AES-256-GCM');
  console.log('5. Encrypted messages include IV and authentication tag');
  console.log();

  // Show what encrypted data looks like
  console.log('Example Encrypted Message Structure:');
  const exampleEncrypted = {
    ciphertext: new Uint8Array(32), // Encrypted message
    iv: new Uint8Array(12),          // Initialization vector
    tag: new Uint8Array(16),         // Authentication tag
  };
  console.log('  Ciphertext:', exampleEncrypted.ciphertext.length, 'bytes');
  console.log('  IV:', exampleEncrypted.iv.length, 'bytes');
  console.log('  Auth Tag:', exampleEncrypted.tag.length, 'bytes');
  console.log();

  // Security properties
  console.log('Security Properties:');
  console.log('✓ Confidentiality: Only intended recipients can decrypt');
  console.log('✓ Authenticity: Authentication tag verifies sender');
  console.log('✓ Forward Secrecy: Ephemeral keys protect past sessions');
  console.log('✓ Integrity: Tampering is detected via auth tag');
  console.log();

  console.log('=== Example Complete ===');
  console.log('\nTo implement encrypted communication:');
  console.log('1. Resolve remote agent\'s DID document');
  console.log('2. Extract keyAgreement public key');
  console.log('3. Perform ECDHE key exchange');
  console.log('4. Derive encryption keys using HKDF');
  console.log('5. Encrypt messages with AES-256-GCM');
  console.log('6. Include IV and auth tag with ciphertext');
  console.log('7. Rotate keys periodically for security');
}

main().catch(console.error);
