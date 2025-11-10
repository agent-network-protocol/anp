/**
 * Protocol Negotiation Example
 * 
 * This example demonstrates meta-protocol negotiation:
 * - Creating negotiation state machines
 * - Proposing protocols
 * - Handling negotiation rounds
 * - Reaching agreement
 */

import { ANPClient } from '@anp/typescript-sdk';

async function main() {
  console.log('=== Protocol Negotiation Example ===\n');

  // Create two clients for two agents
  const agentA = new ANPClient({ debug: false });
  const agentB = new ANPClient({ debug: false });

  // Step 1: Create identities
  console.log('Step 1: Creating agent identities...');
  const identityA = await agentA.did.create({
    domain: 'agent-a.example.com',
    path: 'agent',
  });
  console.log('Agent A DID:', identityA.did);

  const identityB = await agentB.did.create({
    domain: 'agent-b.example.com',
    path: 'agent',
  });
  console.log('Agent B DID:', identityB.did);
  console.log('');

  // Step 2: Agent A initiates negotiation
  console.log('Step 2: Agent A initiating protocol negotiation...');
  console.log('');

  let currentState = 'idle';
  let negotiationRound = 0;

  const machineA = agentA.protocol.createNegotiationMachine({
    localIdentity: identityA,
    remoteDID: identityB.did,
    candidateProtocols: 'JSON-RPC 2.0, gRPC, GraphQL',
    maxNegotiationRounds: 5,
    onStateChange: (state) => {
      currentState = String(state.value);
      console.log(`[Agent A] State: ${state.value}`);
      if (state.context.sequenceId !== undefined) {
        console.log(`[Agent A] Round: ${state.context.sequenceId}`);
      }
    },
  });

  // Start machine A
  machineA.start();
  console.log('');

  // Step 3: Agent B creates its machine
  console.log('Step 3: Agent B creating negotiation machine...');
  console.log('');

  const machineB = agentB.protocol.createNegotiationMachine({
    localIdentity: identityB,
    remoteDID: identityA.did,
    candidateProtocols: 'REST, GraphQL, WebSocket',
    maxNegotiationRounds: 5,
    onStateChange: (state) => {
      console.log(`[Agent B] State: ${state.value}`);
      if (state.context.sequenceId !== undefined) {
        console.log(`[Agent B] Round: ${state.context.sequenceId}`);
      }
    },
  });

  machineB.start();
  console.log('');

  // Step 4: Simulate negotiation rounds
  console.log('Step 4: Negotiation rounds...');
  console.log('');

  // Round 1: Agent A proposes
  console.log('--- Round 1 ---');
  console.log('[Agent A] Proposes: JSON-RPC 2.0, gRPC, GraphQL');
  machineA.send({
    type: 'initiate',
    remoteDID: identityB.did,
    candidateProtocols: 'JSON-RPC 2.0, gRPC, GraphQL',
  });
  console.log('');

  // Agent B receives and responds
  console.log('[Agent B] Receives proposal');
  console.log('[Agent B] Supported: REST, GraphQL, WebSocket');
  console.log('[Agent B] Common protocol found: GraphQL');
  machineB.send({
    type: 'receive_request',
    message: {
      action: 'protocolNegotiation',
      sequenceId: 1,
      candidateProtocols: 'JSON-RPC 2.0, gRPC, GraphQL',
      status: 'negotiating',
    },
  });
  console.log('');

  // Round 2: Agent B counter-proposes
  console.log('--- Round 2 ---');
  console.log('[Agent B] Counter-proposes: GraphQL');
  machineB.send({
    type: 'negotiate',
    response: 'GraphQL',
  });
  console.log('');

  // Agent A receives and accepts
  console.log('[Agent A] Receives counter-proposal: GraphQL');
  console.log('[Agent A] GraphQL is acceptable');
  machineA.send({
    type: 'negotiate',
    response: 'GraphQL',
  });
  machineA.send({ type: 'accept' });
  console.log('[Agent A] Accepts GraphQL');
  console.log('');

  // Agent B also accepts
  console.log('[Agent B] Accepts GraphQL');
  machineB.send({ type: 'accept' });
  console.log('');

  // Step 5: Code generation phase
  console.log('Step 5: Code generation phase...');
  console.log('');
  console.log('[Both Agents] Generating protocol implementation code...');
  
  // Simulate code generation
  setTimeout(() => {
    console.log('[Agent A] Code generation complete');
    machineA.send({ type: 'code_ready' });
    
    console.log('[Agent B] Code generation complete');
    machineB.send({ type: 'code_ready' });
    console.log('');

    // Step 6: Test cases (optional)
    console.log('Step 6: Test cases phase...');
    console.log('');
    console.log('[Agent A] Proposes test cases');
    console.log('[Agent B] Agrees to test cases');
    
    machineA.send({
      type: 'tests_agreed',
      testCases: 'query { user { id name } }',
    });
    machineB.send({
      type: 'tests_agreed',
      testCases: 'query { user { id name } }',
    });
    console.log('');

    // Step 7: Testing phase
    console.log('Step 7: Testing phase...');
    console.log('');
    console.log('[Both Agents] Running test cases...');
    
    setTimeout(() => {
      console.log('[Agent A] All tests passed ✓');
      console.log('[Agent B] All tests passed ✓');
      
      machineA.send({ type: 'tests_passed' });
      machineB.send({ type: 'tests_passed' });
      console.log('');

      // Step 8: Ready for communication
      console.log('Step 8: Ready for communication...');
      console.log('');
      console.log('[Both Agents] Entering ready state');
      console.log('[Both Agents] Can now communicate using GraphQL');
      
      machineA.send({ type: 'start_communication' });
      machineB.send({ type: 'start_communication' });
      console.log('');

      // Step 9: Communication
      console.log('Step 9: Communication...');
      console.log('');
      console.log('[Agent A] Sends GraphQL query:');
      console.log('  query { user(id: "123") { name email } }');
      console.log('');
      console.log('[Agent B] Processes query and responds:');
      console.log('  { "data": { "user": { "name": "Alice", "email": "alice@example.com" } } }');
      console.log('');

      console.log('=== Example Complete ===');
      console.log('\nKey Takeaways:');
      console.log('- Agents negotiate protocols dynamically');
      console.log('- Multiple rounds allow finding common ground');
      console.log('- Code generation enables protocol implementation');
      console.log('- Test cases verify correct implementation');
      console.log('- State machine ensures predictable flow');

      // Stop machines
      machineA.stop();
      machineB.stop();
    }, 1000);
  }, 1000);
}

// Run the example
main().catch(console.error);
