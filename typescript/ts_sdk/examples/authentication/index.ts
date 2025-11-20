/**
 * Authentication Example
 * 
 * Demonstrates DID:WBA authentication between two agents:
 * - Creating client and server identities
 * - Signing authentication data
 * - Mutual authentication flow
 */

import { ANPClient } from '../../dist/index.js';

async function main() {
  console.log('=== Authentication Example ===\n');

  // Create two clients
  const clientAgent = new ANPClient();
  const serverAgent = new ANPClient();

  // Create identities
  console.log('Creating identities...');
  const clientIdentity = await clientAgent.did.create({
    domain: 'localhost:9000',
    path: 'client',
  });
  const serverIdentity = await serverAgent.did.create({
    domain: 'localhost:9001',
    path: 'server',
  });
  console.log('✓ Client DID:', clientIdentity.did);
  console.log('✓ Server DID:', serverIdentity.did);
  console.log();

  // Client signs a request
  console.log('Client signing request...');
  const requestData = {
    method: 'GET',
    path: '/api/data',
    timestamp: Date.now(),
  };
  const requestBytes = new TextEncoder().encode(JSON.stringify(requestData));
  const requestSignature = await clientAgent.did.sign(clientIdentity, requestBytes);
  console.log('✓ Request signed');
  console.log();

  // Prepare authentication data
  console.log('Preparing authentication...');
  const authData = {
    did: clientIdentity.did,
    nonce: crypto.randomUUID(),
    timestamp: Date.now(),
    verificationMethod: requestSignature.verificationMethod,
  };
  const authBytes = new TextEncoder().encode(JSON.stringify(authData));
  const authSignature = await clientAgent.did.sign(clientIdentity, authBytes);
  console.log('✓ Authentication data signed');
  console.log('  DID:', authData.did);
  console.log('  Nonce:', authData.nonce.substring(0, 16) + '...');
  console.log('  Timestamp:', new Date(authData.timestamp).toISOString());
  console.log();

  // Server generates access token (simulated)
  console.log('Server granting access...');
  const accessToken = `token_${crypto.randomUUID()}`;
  console.log('✓ Access token generated:', accessToken.substring(0, 30) + '...');
  console.log();

  // Mutual authentication: Server signs response
  console.log('Server signing response...');
  const responseData = {
    status: 'authenticated',
    serverDID: serverIdentity.did,
    timestamp: Date.now(),
  };
  const responseBytes = new TextEncoder().encode(JSON.stringify(responseData));
  const serverSignature = await serverAgent.did.sign(serverIdentity, responseBytes);
  console.log('✓ Server response signed');
  console.log();

  console.log('=== Example Complete ===');
  console.log('\nKey Points:');
  console.log('- Both parties have signed their data');
  console.log('- Signatures prove ownership of DIDs');
  console.log('- Timestamps prevent replay attacks');
  console.log('- Nonces ensure request uniqueness');
  console.log('\nNote: In production, signatures would be verified by resolving DIDs');
}

main().catch(console.error);
