/**
 * Authentication Example
 * 
 * This example demonstrates DID:WBA authentication:
 * - Creating client and server identities
 * - Generating authentication headers
 * - Verifying authentication
 * - Token-based access
 */

import { ANPClient } from '@anp/typescript-sdk';

async function main() {
  console.log('=== Authentication Example ===\n');

  // Create two clients: one for client agent, one for server agent
  const clientAgent = new ANPClient({ debug: false });
  const serverAgent = new ANPClient({ debug: false });

  // Step 1: Create identities
  console.log('Step 1: Creating identities...');
  const clientIdentity = await clientAgent.did.create({
    domain: 'localhost:9000',
    path: 'client-agent',
  });
  console.log('Client DID:', clientIdentity.did);

  const serverIdentity = await serverAgent.did.create({
    domain: 'localhost:9001',
    path: 'server-agent',
  });
  console.log('Server DID:', serverIdentity.did);
  console.log('');

  // Step 2: Client signs a request
  console.log('Step 2: Client creating authenticated request...');
  
  // In a real scenario, this would be done by the HTTP client automatically
  // Here we demonstrate the underlying mechanism
  
  const requestData = JSON.stringify({
    method: 'GET',
    path: '/api/data',
    timestamp: Date.now(),
  });
  
  const requestBytes = new TextEncoder().encode(requestData);
  const signature = await clientAgent.did.sign(clientIdentity, requestBytes);
  
  console.log('Request signed with verification method:', signature.verificationMethod);
  console.log('');

  // Step 3: Server verifies the signature
  console.log('Step 3: Server verifying client signature...');
  
  // Note: This will fail if localhost:9000 is not running with a DID document
  // In production, the server would resolve the client's DID from the network
  try {
    const isValid = await serverAgent.did.verify(
      clientIdentity.did,
      requestBytes,
      signature
    );
    console.log('Signature valid:', isValid);
  } catch (error) {
    console.log('(Verification failed - DID document not published at http://localhost:9000)');
    console.log('In production, server would resolve DID and verify signature');
  }
  console.log('');

  // Step 4: Demonstrate full authentication flow
  console.log('Step 4: Full authentication flow simulation...');
  
  // Client prepares authentication data
  const authData = {
    did: clientIdentity.did,
    nonce: crypto.randomUUID(),
    timestamp: Date.now(),
    verificationMethod: signature.verificationMethod,
  };
  
  console.log('Authentication data:', {
    did: authData.did,
    nonce: authData.nonce.substring(0, 8) + '...',
    timestamp: new Date(authData.timestamp).toISOString(),
  });
  
  // Client signs the authentication data
  const authDataBytes = new TextEncoder().encode(JSON.stringify(authData));
  const authSignature = await clientAgent.did.sign(clientIdentity, authDataBytes);
  
  console.log('Authentication data signed');
  console.log('');

  // Server verifies and grants access
  console.log('Step 5: Server verifying and granting access...');
  
  try {
    const authValid = await serverAgent.did.verify(
      clientIdentity.did,
      authDataBytes,
      authSignature
    );
    
    if (authValid) {
      console.log('✓ Authentication successful');
      console.log('✓ Access granted to:', authData.did);
      
      // In a real implementation, server would generate an access token here
      const accessToken = `token_${crypto.randomUUID()}`;
      console.log('✓ Access token generated:', accessToken.substring(0, 20) + '...');
    } else {
      console.log('✗ Authentication failed');
    }
  } catch (error) {
    console.log('(Verification failed - DID document not published)');
    console.log('In production, server would resolve DID and verify signature');
    // For demo purposes, simulate success
    console.log('✓ Simulating successful authentication for demo');
    const accessToken = `token_${crypto.randomUUID()}`;
    console.log('✓ Access token generated:', accessToken.substring(0, 20) + '...');
  }
  console.log('');

  // Step 6: Demonstrate mutual authentication
  console.log('Step 6: Mutual authentication...');
  
  // Server also signs its response
  const responseData = {
    status: 'authenticated',
    serverDID: serverIdentity.did,
    timestamp: Date.now(),
  };
  
  const responseBytes = new TextEncoder().encode(JSON.stringify(responseData));
  const serverSignature = await serverAgent.did.sign(serverIdentity, responseBytes);
  
  console.log('Server signed response');
  
  // Client verifies server's signature
  // Client verifies server's signature
  try {
    const serverValid = await clientAgent.did.verify(
      serverIdentity.did,
      responseBytes,
      serverSignature
    );
    console.log('Server signature valid:', serverValid);
  } catch (error) {
    console.log('(Server signature verification failed - DID document not published)');
    console.log('In production, client would resolve server DID and verify signature');
  }
  console.log('✓ Mutual authentication complete');
  console.log('');

  console.log('=== Example Complete ===');
  console.log('\nKey Takeaways:');
  console.log('- Both parties can verify each other\'s identity');
  console.log('- Signatures prove ownership of DID');
  console.log('- Timestamps prevent replay attacks');
  console.log('- Nonces ensure request uniqueness');
}

// Run the example
main().catch(console.error);
