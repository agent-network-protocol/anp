/**
 * Simple Agent Example
 * 
 * Demonstrates basic ANP agent operations:
 * - Creating a DID identity
 * - Creating and signing an agent description
 * - Signing data
 */

import { ANPClient } from '@anp/typescript-sdk';

async function main() {
  console.log('=== Simple Agent Example ===\n');

  // Create ANP client
  const client = new ANPClient();

  // Create DID identity
  console.log('Creating DID identity...');
  const identity = await client.did.create({
    domain: 'localhost:9000',
    path: 'my-agent',
  });
  console.log('✓ Created DID:', identity.did);
  console.log('✓ DID Document ID:', identity.document.id);
  console.log('✓ Verification Methods:', identity.document.verificationMethod.length);
  console.log();

  // Create agent description
  console.log('Creating agent description...');
  let description = client.agent.createDescription({
    name: 'Simple Agent',
    description: 'A basic ANP agent',
    protocolVersion: '0.1.0',
    did: identity.did,
  });

  // Add interface
  description = client.agent.addInterface(description, {
    type: 'Interface',
    protocol: 'HTTP',
    version: '1.1',
    url: 'http://localhost:9000/api',
  });

  // Sign the description
  const signedDescription = await client.agent.signDescription(
    description,
    identity,
    'challenge-123',
    'localhost:9000'
  );
  console.log('✓ Agent description signed');
  console.log('✓ Proof type:', signedDescription.proof?.type);
  console.log();

  // Sign some data
  console.log('Signing data...');
  const message = 'Hello, ANP!';
  const data = new TextEncoder().encode(message);
  const signature = await client.did.sign(identity, data);
  console.log('✓ Data signed');
  console.log('✓ Verification method:', signature.verificationMethod);
  console.log();

  console.log('=== Example Complete ===');
  console.log('\nNote: To enable DID resolution, publish the DID document at:');
  console.log(`http://localhost:9000/.well-known/did.json`);
}

main().catch(console.error);
