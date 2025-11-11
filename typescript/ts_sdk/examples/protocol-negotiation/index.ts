/**
 * Protocol Negotiation Example
 * 
 * Demonstrates meta-protocol negotiation using XState:
 * - Creating negotiation state machines
 * - Simulating protocol negotiation flow
 * - Reaching protocol agreement
 */

import { ANPClient } from '../../dist/index.js';

async function main() {
  console.log('=== Protocol Negotiation Example ===\n');

  const agentA = new ANPClient();
  const agentB = new ANPClient();

  // Create identities
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

  // Create negotiation machines
  console.log('Creating negotiation state machines...');
  
  const machineA = agentA.protocol.createNegotiationMachine({
    localIdentity: identityA,
    remoteDID: identityB.did,
    candidateProtocols: 'JSON-RPC 2.0, gRPC, GraphQL',
    maxNegotiationRounds: 5,
    onStateChange: (state) => {
      console.log(`[Agent A] State: ${state.value}`);
    },
  });

  const machineB = agentB.protocol.createNegotiationMachine({
    localIdentity: identityB,
    remoteDID: identityA.did,
    candidateProtocols: 'REST, GraphQL, WebSocket',
    maxNegotiationRounds: 5,
    onStateChange: (state) => {
      console.log(`[Agent B] State: ${state.value}`);
    },
  });

  console.log('✓ State machines created');
  console.log();

  // Start machines
  console.log('Starting negotiation...');
  machineA.start();
  machineB.start();
  console.log();

  // Simulate negotiation
  console.log('Agent A proposes: JSON-RPC 2.0, gRPC, GraphQL');
  machineA.send({
    type: 'initiate',
    remoteDID: identityB.did,
    candidateProtocols: 'JSON-RPC 2.0, gRPC, GraphQL',
  });
  console.log();

  console.log('Agent B receives and finds common protocol: GraphQL');
  machineB.send({
    type: 'receive_request',
    message: {
      action: 'protocolNegotiation',
      sequenceId: 1,
      candidateProtocols: 'JSON-RPC 2.0, gRPC, GraphQL',
      status: 'negotiating',
    },
  });
  console.log();

  console.log('Both agents accept GraphQL');
  machineA.send({ type: 'negotiate', response: 'GraphQL' });
  machineA.send({ type: 'accept' });
  machineB.send({ type: 'accept' });
  console.log();

  // Simulate code generation
  setTimeout(() => {
    console.log('Generating protocol implementation...');
    machineA.send({ type: 'code_ready' });
    machineB.send({ type: 'code_ready' });
    console.log('✓ Code generation complete');
    console.log();

    // Skip to ready state
    machineA.send({ type: 'skip_tests' });
    machineB.send({ type: 'skip_tests' });
    machineA.send({ type: 'start_communication' });
    machineB.send({ type: 'start_communication' });

    console.log('=== Example Complete ===');
    console.log('\nNegotiation Result:');
    console.log('- Agreed Protocol: GraphQL');
    console.log('- Both agents ready to communicate');
    console.log('- State machines ensure predictable flow');

    machineA.stop();
    machineB.stop();
  }, 100);
}

main().catch(console.error);
