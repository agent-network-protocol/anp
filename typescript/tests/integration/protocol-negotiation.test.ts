/**
 * Integration test for protocol negotiation flow
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { DIDManager } from '../../src/core/did/did-manager.js';
import {
  createMetaProtocolMachine,
  createNegotiationMessage,
  createCodeGenerationMessage,
  createTestCasesMessage,
  encodeMetaProtocolMessage,
  processMessage,
  type MetaProtocolActor,
} from '../../src/protocol/meta-protocol-machine.js';
import type { DIDIdentity } from '../../src/types/index.js';

describe('Protocol Negotiation Integration', () => {
  let didManager: DIDManager;
  let aliceIdentity: DIDIdentity;
  let bobIdentity: DIDIdentity;
  let aliceActor: MetaProtocolActor;
  let bobActor: MetaProtocolActor;

  beforeEach(async () => {
    // Initialize DID manager
    didManager = new DIDManager();

    // Create two agent identities
    aliceIdentity = await didManager.createDID({
      domain: 'alice.example.com',
      path: 'agent',
    });

    bobIdentity = await didManager.createDID({
      domain: 'bob.example.com',
      path: 'agent',
    });

    // Create state machines for both agents
    aliceActor = createMetaProtocolMachine({
      localIdentity: aliceIdentity,
      remoteDID: bobIdentity.did,
      maxNegotiationRounds: 5,
    });

    bobActor = createMetaProtocolMachine({
      localIdentity: bobIdentity,
      remoteDID: aliceIdentity.did,
      maxNegotiationRounds: 5,
    });
  });

  it('should complete full protocol negotiation flow', async () => {
    // Step 1: Alice initiates negotiation
    aliceActor.send({
      type: 'initiate',
      candidateProtocols: 'REST API v1.0, GraphQL v1.0',
    });

    // Verify Alice is in Negotiating state
    let aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('Negotiating');
    expect(aliceSnapshot.context.candidateProtocols).toBe(
      'REST API v1.0, GraphQL v1.0'
    );

    // Step 2: Bob receives negotiation request
    const negotiationMessage = createNegotiationMessage(
      aliceSnapshot.context.sequenceId,
      'REST API v1.0, GraphQL v1.0',
      'negotiating'
    );

    const encodedMessage = encodeMetaProtocolMessage(negotiationMessage);
    processMessage(bobActor, encodedMessage);

    // Verify Bob is in Negotiating state
    let bobSnapshot = bobActor.getSnapshot();
    expect(bobSnapshot.value).toBe('Negotiating');
    expect(bobSnapshot.context.candidateProtocols).toBe(
      'REST API v1.0, GraphQL v1.0'
    );

    // Step 3: Bob accepts the protocol
    bobActor.send({
      type: 'accept',
      agreedProtocol: 'REST API v1.0',
    });

    // Verify Bob moved to CodeGeneration state
    bobSnapshot = bobActor.getSnapshot();
    expect(bobSnapshot.value).toBe('CodeGeneration');
    expect(bobSnapshot.context.agreedProtocol).toBe('REST API v1.0');

    // Step 4: Alice receives acceptance
    const acceptanceMessage = createNegotiationMessage(
      aliceSnapshot.context.sequenceId,
      'REST API v1.0',
      'accepted'
    );

    const encodedAcceptance = encodeMetaProtocolMessage(acceptanceMessage);
    processMessage(aliceActor, encodedAcceptance);

    // Verify Alice moved to CodeGeneration state
    aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('CodeGeneration');
    expect(aliceSnapshot.context.agreedProtocol).toBe('REST API v1.0');

    // Step 5: Code generation completes
    aliceActor.send({ type: 'code_ready', code: 'generated code' });
    bobActor.send({ type: 'code_ready', code: 'generated code' });

    // Verify both moved to TestCases state
    aliceSnapshot = aliceActor.getSnapshot();
    bobSnapshot = bobActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('TestCases');
    expect(bobSnapshot.value).toBe('TestCases');

    // Step 6: Skip tests and move to Ready
    aliceActor.send({ type: 'skip_tests' });
    bobActor.send({ type: 'skip_tests' });

    // Verify both are Ready
    aliceSnapshot = aliceActor.getSnapshot();
    bobSnapshot = bobActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('Ready');
    expect(bobSnapshot.value).toBe('Ready');

    // Step 7: Start communication
    aliceActor.send({ type: 'start_communication' });
    bobActor.send({ type: 'start_communication' });

    // Verify both are Communicating
    aliceSnapshot = aliceActor.getSnapshot();
    bobSnapshot = bobActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('Communicating');
    expect(bobSnapshot.value).toBe('Communicating');
  });

  it('should handle multiple negotiation rounds', async () => {
    // Round 1: Alice initiates
    aliceActor.send({
      type: 'initiate',
      candidateProtocols: 'REST API v1.0',
    });

    let aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('Negotiating');
    expect(aliceSnapshot.context.negotiationRound).toBe(0);

    // Round 2: Bob counter-proposes
    aliceActor.send({
      type: 'negotiate',
      response: 'GraphQL v1.0',
    });

    aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('Negotiating');
    expect(aliceSnapshot.context.negotiationRound).toBe(1);

    // Round 3: Alice counter-proposes again
    aliceActor.send({
      type: 'negotiate',
      response: 'REST API v2.0',
    });

    aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('Negotiating');
    expect(aliceSnapshot.context.negotiationRound).toBe(2);

    // Finally accept
    aliceActor.send({
      type: 'accept',
      agreedProtocol: 'REST API v2.0',
    });

    aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('CodeGeneration');
    expect(aliceSnapshot.context.agreedProtocol).toBe('REST API v2.0');
  });

  it('should reject negotiation after max rounds', async () => {
    // Initiate negotiation
    aliceActor.send({
      type: 'initiate',
      candidateProtocols: 'Protocol A',
    });

    // Negotiate up to max rounds (5)
    for (let i = 0; i < 5; i++) {
      aliceActor.send({
        type: 'negotiate',
        response: `Protocol ${i}`,
      });
    }

    // Next negotiation should move to Rejected
    aliceActor.send({
      type: 'negotiate',
      response: 'Protocol Final',
    });

    const aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('Rejected');
  });

  it('should handle test case negotiation and execution', async () => {
    // Setup: Get to TestCases state
    aliceActor.send({
      type: 'initiate',
      candidateProtocols: 'REST API v1.0',
    });
    aliceActor.send({
      type: 'accept',
      agreedProtocol: 'REST API v1.0',
    });
    aliceActor.send({ type: 'code_ready', code: 'code' });

    // Verify in TestCases state
    let aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('TestCases');

    // Agree on test cases
    const testCases = JSON.stringify([
      { name: 'test1', input: 'a', expected: 'b' },
      { name: 'test2', input: 'c', expected: 'd' },
    ]);

    aliceActor.send({
      type: 'tests_agreed',
      testCases,
    });

    // Verify moved to Testing state
    aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('Testing');
    expect(aliceSnapshot.context.testCases).toBe(testCases);

    // Tests pass
    aliceActor.send({ type: 'tests_passed' });

    // Verify moved to Ready state
    aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('Ready');
  });

  it('should handle test failures and error fixing', async () => {
    // Setup: Get to Testing state
    aliceActor.send({
      type: 'initiate',
      candidateProtocols: 'REST API v1.0',
    });
    aliceActor.send({
      type: 'accept',
      agreedProtocol: 'REST API v1.0',
    });
    aliceActor.send({ type: 'code_ready', code: 'code' });
    aliceActor.send({
      type: 'tests_agreed',
      testCases: 'test cases',
    });

    // Tests fail
    aliceActor.send({
      type: 'tests_failed',
      errors: 'Test 1 failed: expected b, got c',
    });

    // Verify moved to FixError state
    let aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('FixError');
    expect(aliceSnapshot.context.errors).toContain(
      'Test 1 failed: expected b, got c'
    );

    // Accept fix
    aliceActor.send({
      type: 'fix_accepted',
      fix: 'Fixed the bug',
    });

    // Verify moved back to CodeGeneration
    aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('CodeGeneration');

    // Code generation succeeds
    aliceActor.send({ type: 'code_ready', code: 'fixed code' });

    // Skip tests this time
    aliceActor.send({ type: 'skip_tests' });

    // Verify moved to Ready
    aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('Ready');
  });

  it('should handle code generation errors', async () => {
    // Setup: Get to CodeGeneration state
    aliceActor.send({
      type: 'initiate',
      candidateProtocols: 'REST API v1.0',
    });
    aliceActor.send({
      type: 'accept',
      agreedProtocol: 'REST API v1.0',
    });

    // Code generation fails
    aliceActor.send({
      type: 'code_error',
      error: 'Syntax error in generated code',
    });

    // Verify moved to Failed state
    const aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('Failed');
    expect(aliceSnapshot.context.errors).toContain(
      'Syntax error in generated code'
    );
  });

  it('should handle protocol errors during communication', async () => {
    // Setup: Get to Communicating state
    aliceActor.send({
      type: 'initiate',
      candidateProtocols: 'REST API v1.0',
    });
    aliceActor.send({
      type: 'accept',
      agreedProtocol: 'REST API v1.0',
    });
    aliceActor.send({ type: 'code_ready', code: 'code' });
    aliceActor.send({ type: 'skip_tests' });
    aliceActor.send({ type: 'start_communication' });

    // Verify in Communicating state
    let aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('Communicating');

    // Protocol error occurs
    aliceActor.send({
      type: 'protocol_error',
      error: 'Message format mismatch',
    });

    // Verify moved to FixError state
    aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('FixError');
    expect(aliceSnapshot.context.errors).toContain('Message format mismatch');
  });

  it('should handle explicit rejection', async () => {
    // Alice initiates
    aliceActor.send({
      type: 'initiate',
      candidateProtocols: 'Unsupported Protocol',
    });

    // Bob rejects
    aliceActor.send({
      type: 'reject',
      reason: 'Protocol not supported',
    });

    // Verify moved to Rejected state
    const aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('Rejected');
  });

  it('should handle timeout during negotiation', async () => {
    // Alice initiates
    aliceActor.send({
      type: 'initiate',
      candidateProtocols: 'REST API v1.0',
    });

    // Timeout occurs
    aliceActor.send({ type: 'timeout' });

    // Verify moved to Rejected state
    const aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('Rejected');
  });

  it('should complete communication and end gracefully', async () => {
    // Setup: Get to Communicating state
    aliceActor.send({
      type: 'initiate',
      candidateProtocols: 'REST API v1.0',
    });
    aliceActor.send({
      type: 'accept',
      agreedProtocol: 'REST API v1.0',
    });
    aliceActor.send({ type: 'code_ready', code: 'code' });
    aliceActor.send({ type: 'skip_tests' });
    aliceActor.send({ type: 'start_communication' });

    // End communication
    aliceActor.send({ type: 'end' });

    // Verify moved to Completed state
    const aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.value).toBe('Completed');
  });

  it('should maintain sequence ID throughout negotiation', async () => {
    // Initiate
    aliceActor.send({
      type: 'initiate',
      candidateProtocols: 'Protocol A',
    });

    let aliceSnapshot = aliceActor.getSnapshot();
    const initialSequenceId = aliceSnapshot.context.sequenceId;

    // Negotiate (should increment sequence ID)
    aliceActor.send({
      type: 'negotiate',
      response: 'Protocol B',
    });

    aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.context.sequenceId).toBe(initialSequenceId + 1);

    // Negotiate again
    aliceActor.send({
      type: 'negotiate',
      response: 'Protocol C',
    });

    aliceSnapshot = aliceActor.getSnapshot();
    expect(aliceSnapshot.context.sequenceId).toBe(initialSequenceId + 2);
  });

  it('should handle bidirectional message exchange', async () => {
    // Alice initiates
    aliceActor.send({
      type: 'initiate',
      candidateProtocols: 'REST API v1.0, GraphQL v1.0',
    });

    const aliceSnapshot1 = aliceActor.getSnapshot();

    // Create and send message to Bob
    const aliceMessage = createNegotiationMessage(
      aliceSnapshot1.context.sequenceId,
      'REST API v1.0, GraphQL v1.0',
      'negotiating'
    );

    const encodedAliceMessage = encodeMetaProtocolMessage(aliceMessage);
    processMessage(bobActor, encodedAliceMessage);

    // Bob counter-proposes
    bobActor.send({
      type: 'negotiate',
      response: 'GraphQL v1.0',
    });

    const bobSnapshot1 = bobActor.getSnapshot();

    // Send Bob's counter-proposal to Alice
    const bobMessage = createNegotiationMessage(
      bobSnapshot1.context.sequenceId,
      'GraphQL v1.0',
      'negotiating',
      'Prefer GraphQL for flexibility'
    );

    const encodedBobMessage = encodeMetaProtocolMessage(bobMessage);
    processMessage(aliceActor, encodedBobMessage);

    // Alice accepts
    aliceActor.send({
      type: 'accept',
      agreedProtocol: 'GraphQL v1.0',
    });

    const aliceSnapshot2 = aliceActor.getSnapshot();
    expect(aliceSnapshot2.value).toBe('CodeGeneration');
    expect(aliceSnapshot2.context.agreedProtocol).toBe('GraphQL v1.0');

    // Send acceptance to Bob
    const acceptMessage = createNegotiationMessage(
      aliceSnapshot2.context.sequenceId,
      'GraphQL v1.0',
      'accepted'
    );

    const encodedAcceptMessage = encodeMetaProtocolMessage(acceptMessage);
    processMessage(bobActor, encodedAcceptMessage);

    const bobSnapshot2 = bobActor.getSnapshot();
    expect(bobSnapshot2.value).toBe('CodeGeneration');
    expect(bobSnapshot2.context.agreedProtocol).toBe('GraphQL v1.0');
  });
});
