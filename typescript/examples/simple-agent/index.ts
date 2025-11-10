/**
 * Simple Agent Example
 * 
 * This example demonstrates how to create a basic ANP agent with:
 * - DID identity creation
 * - Agent description
 * - Basic HTTP communication
 */

import { ANPClient } from '@anp/typescript-sdk';

async function main() {
  // Create ANP client
  const client = new ANPClient({
    debug: true,
  });

  console.log('=== Simple Agent Example ===\n');

  // Step 1: Create DID identity
  console.log('Step 1: Creating DID identity...');
  const identity = await client.did.create({
    domain: 'localhost:9000',
    path: 'agent1',
  });
  console.log('Created DID:', identity.did);
  console.log('');

  // Step 2: Create agent description
  console.log('Step 2: Creating agent description...');
  let description = client.agent.createDescription({
    name: 'Simple Agent',
    description: 'A basic ANP agent for demonstration',
    protocolVersion: '0.1.0',
    did: identity.did,
  });

  // Add information resource
  description = client.agent.addInformation(description, {
    type: 'Information',
    description: 'Agent documentation',
    url: 'http://localhost:9000/docs',
  });

  // Add interface
  description = client.agent.addInterface(description, {
    type: 'Interface',
    protocol: 'HTTP',
    version: '1.1',
    url: 'http://localhost:9000/api',
  });

  console.log('Agent description created:', description.name);
  console.log('');

  // Step 3: Sign the agent description
  console.log('Step 3: Signing agent description...');
  const signedDescription = await client.agent.signDescription(
    description,
    identity,
    'example-challenge',
    'localhost:9000'
  );
  console.log('Agent description signed');
  console.log('Proof type:', signedDescription.proof?.type);
  console.log('');

  // Step 4: Sign and verify data
  console.log('Step 4: Signing and verifying data...');
  const message = 'Hello, ANP!';
  const data = new TextEncoder().encode(message);
  
  const signature = await client.did.sign(identity, data);
  console.log('Message signed');
  console.log('Signature created with verification method:', signature.verificationMethod);
  
  // Note: Verification would work if DID document is published at the endpoint
  // For now, it will fail because localhost:9000 is not running
  console.log('(Verification requires DID document to be published at http://localhost:9000/.well-known/did.json)');
  console.log('');

  // Step 5: DID resolution (would work if published)
  console.log('Step 5: DID resolution...');
  console.log('To resolve this DID, publish the DID document at:');
  console.log(`http://${identity.did.split(':')[2]}/.well-known/did.json`);
  console.log('(Using localhost for testing - in production use HTTPS)');
  console.log('');

  console.log('=== Example Complete ===');
}

// Run the example
main().catch(console.error);
