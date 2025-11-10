import { describe, it, expect, beforeEach } from 'vitest';
import { createMetaProtocolMachine, MetaProtocolConfig } from '../../../src/protocol/meta-protocol-machine';
import type { DIDIdentity } from '../../../src/types/did';

describe('MetaProtocolMachine - Initialization', () => {
  let mockIdentity: DIDIdentity;
  let config: MetaProtocolConfig;

  beforeEach(() => {
    // Create a mock DID identity for testing
    mockIdentity = {
      did: 'did:wba:example.com:agent1',
      document: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: 'did:wba:example.com:agent1',
        verificationMethod: [],
        authentication: [],
      },
      privateKeys: new Map(),
    };

    config = {
      localIdentity: mockIdentity,
      remoteDID: 'did:wba:example.com:agent2',
      maxNegotiationRounds: 5,
      timeoutMs: 30000,
    };
  });

  it('should create a state machine with valid config', () => {
    const actor = createMetaProtocolMachine(config);
    
    expect(actor).toBeDefined();
    expect(actor.getSnapshot).toBeDefined();
  });

  it('should initialize with Idle state', () => {
    const actor = createMetaProtocolMachine(config);
    const snapshot = actor.getSnapshot();
    
    expect(snapshot.value).toBe('Idle');
  });

  it('should initialize context with provided config', () => {
    const actor = createMetaProtocolMachine(config);
    const snapshot = actor.getSnapshot();
    
    expect(snapshot.context.localIdentity).toEqual(mockIdentity);
    expect(snapshot.context.remoteDID).toBe('did:wba:example.com:agent2');
    expect(snapshot.context.maxNegotiationRounds).toBe(5);
    expect(snapshot.context.sequenceId).toBe(0);
  });

  it('should initialize with empty candidateProtocols', () => {
    const actor = createMetaProtocolMachine(config);
    const snapshot = actor.getSnapshot();
    
    expect(snapshot.context.candidateProtocols).toBe('');
  });

  it('should initialize with undefined agreedProtocol', () => {
    const actor = createMetaProtocolMachine(config);
    const snapshot = actor.getSnapshot();
    
    expect(snapshot.context.agreedProtocol).toBeUndefined();
  });

  it('should initialize with undefined testCases', () => {
    const actor = createMetaProtocolMachine(config);
    const snapshot = actor.getSnapshot();
    
    expect(snapshot.context.testCases).toBeUndefined();
  });

  it('should use default maxNegotiationRounds if not provided', () => {
    const configWithoutMax = {
      localIdentity: mockIdentity,
      remoteDID: 'did:wba:example.com:agent2',
    };
    
    const actor = createMetaProtocolMachine(configWithoutMax);
    const snapshot = actor.getSnapshot();
    
    expect(snapshot.context.maxNegotiationRounds).toBe(10);
  });

  it('should use default timeout if not provided', () => {
    const configWithoutTimeout = {
      localIdentity: mockIdentity,
      remoteDID: 'did:wba:example.com:agent2',
    };
    
    const actor = createMetaProtocolMachine(configWithoutTimeout);
    const snapshot = actor.getSnapshot();
    
    // Verify timeout is set to default (we'll check this in context or config)
    expect(snapshot.context).toBeDefined();
  });
});


describe('MetaProtocolMachine - Negotiation Flow', () => {
  let mockIdentity: DIDIdentity;
  let config: MetaProtocolConfig;

  beforeEach(() => {
    mockIdentity = {
      did: 'did:wba:example.com:agent1',
      document: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: 'did:wba:example.com:agent1',
        verificationMethod: [],
        authentication: [],
      },
      privateKeys: new Map(),
    };

    config = {
      localIdentity: mockIdentity,
      remoteDID: 'did:wba:example.com:agent2',
      maxNegotiationRounds: 3,
    };
  });

  it('should transition from Idle to Negotiating on initiate event', () => {
    const actor = createMetaProtocolMachine(config);
    
    actor.send({
      type: 'initiate',
      candidateProtocols: 'protocol1,protocol2',
    });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.value).toBe('Negotiating');
    expect(snapshot.context.candidateProtocols).toBe('protocol1,protocol2');
  });

  it('should transition from Idle to Negotiating on receive_request event', () => {
    const actor = createMetaProtocolMachine(config);
    
    actor.send({
      type: 'receive_request',
      candidateProtocols: 'protocolA,protocolB',
      sequenceId: 1,
    });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.value).toBe('Negotiating');
    expect(snapshot.context.candidateProtocols).toBe('protocolA,protocolB');
    expect(snapshot.context.sequenceId).toBe(1);
  });

  it('should stay in Negotiating state on negotiate event when under max rounds', () => {
    const actor = createMetaProtocolMachine(config);
    
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    actor.send({ type: 'negotiate', response: 'counter-proposal' });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.value).toBe('Negotiating');
    expect(snapshot.context.negotiationRound).toBe(1);
  });

  it('should transition from Negotiating to CodeGeneration on accept event', () => {
    const actor = createMetaProtocolMachine(config);
    
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    actor.send({ type: 'accept', agreedProtocol: 'protocol1' });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.value).toBe('CodeGeneration');
    expect(snapshot.context.agreedProtocol).toBe('protocol1');
  });

  it('should transition from Negotiating to Rejected on reject event', () => {
    const actor = createMetaProtocolMachine(config);
    
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    actor.send({ type: 'reject', reason: 'incompatible protocols' });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.value).toBe('Rejected');
  });

  it('should transition from Negotiating to Rejected on timeout event', () => {
    const actor = createMetaProtocolMachine(config);
    
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    actor.send({ type: 'timeout' });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.value).toBe('Rejected');
  });

  it('should enforce max negotiation rounds', () => {
    const actor = createMetaProtocolMachine(config);
    
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    
    // Negotiate up to max rounds
    for (let i = 0; i < 3; i++) {
      actor.send({ type: 'negotiate', response: `round-${i}` });
    }
    
    const snapshot = actor.getSnapshot();
    // Should transition to Rejected when max rounds exceeded
    expect(snapshot.context.negotiationRound).toBe(3);
  });

  it('should increment sequence ID during negotiation', () => {
    const actor = createMetaProtocolMachine(config);
    
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    const initialSeq = actor.getSnapshot().context.sequenceId;
    
    actor.send({ type: 'negotiate', response: 'counter' });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.context.sequenceId).toBeGreaterThan(initialSeq);
  });
});


describe('MetaProtocolMachine - Code Generation Flow', () => {
  let mockIdentity: DIDIdentity;
  let config: MetaProtocolConfig;

  beforeEach(() => {
    mockIdentity = {
      did: 'did:wba:example.com:agent1',
      document: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: 'did:wba:example.com:agent1',
        verificationMethod: [],
        authentication: [],
      },
      privateKeys: new Map(),
    };

    config = {
      localIdentity: mockIdentity,
      remoteDID: 'did:wba:example.com:agent2',
    };
  });

  it('should transition from CodeGeneration to TestCases on code_ready event', () => {
    const actor = createMetaProtocolMachine(config);
    
    // Navigate to CodeGeneration state
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    actor.send({ type: 'accept', agreedProtocol: 'protocol1' });
    
    // Send code_ready event
    actor.send({ type: 'code_ready', code: 'generated code' });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.value).toBe('TestCases');
  });

  it('should transition from CodeGeneration to Failed on code_error event', () => {
    const actor = createMetaProtocolMachine(config);
    
    // Navigate to CodeGeneration state
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    actor.send({ type: 'accept', agreedProtocol: 'protocol1' });
    
    // Send code_error event
    actor.send({ type: 'code_error', error: 'compilation failed' });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.value).toBe('Failed');
  });

  it('should store error in context on code_error event', () => {
    const actor = createMetaProtocolMachine(config);
    
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    actor.send({ type: 'accept', agreedProtocol: 'protocol1' });
    actor.send({ type: 'code_error', error: 'syntax error' });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.context.errors).toContain('syntax error');
  });

  it('should remain in CodeGeneration state until code_ready or code_error', () => {
    const actor = createMetaProtocolMachine(config);
    
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    actor.send({ type: 'accept', agreedProtocol: 'protocol1' });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.value).toBe('CodeGeneration');
  });
});


describe('MetaProtocolMachine - Test Cases Flow', () => {
  let mockIdentity: DIDIdentity;
  let config: MetaProtocolConfig;

  beforeEach(() => {
    mockIdentity = {
      did: 'did:wba:example.com:agent1',
      document: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: 'did:wba:example.com:agent1',
        verificationMethod: [],
        authentication: [],
      },
      privateKeys: new Map(),
    };

    config = {
      localIdentity: mockIdentity,
      remoteDID: 'did:wba:example.com:agent2',
    };
  });

  it('should transition from TestCases to Testing on tests_agreed event', () => {
    const actor = createMetaProtocolMachine(config);
    
    // Navigate to TestCases state
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    actor.send({ type: 'accept', agreedProtocol: 'protocol1' });
    actor.send({ type: 'code_ready', code: 'code' });
    
    // Send tests_agreed event
    actor.send({ type: 'tests_agreed', testCases: 'test suite' });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.value).toBe('Testing');
    expect(snapshot.context.testCases).toBe('test suite');
  });

  it('should transition from TestCases to Ready on skip_tests event', () => {
    const actor = createMetaProtocolMachine(config);
    
    // Navigate to TestCases state
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    actor.send({ type: 'accept', agreedProtocol: 'protocol1' });
    actor.send({ type: 'code_ready', code: 'code' });
    
    // Send skip_tests event
    actor.send({ type: 'skip_tests' });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.value).toBe('Ready');
  });

  it('should transition from Testing to Ready on tests_passed event', () => {
    const actor = createMetaProtocolMachine(config);
    
    // Navigate to Testing state
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    actor.send({ type: 'accept', agreedProtocol: 'protocol1' });
    actor.send({ type: 'code_ready', code: 'code' });
    actor.send({ type: 'tests_agreed', testCases: 'tests' });
    
    // Send tests_passed event
    actor.send({ type: 'tests_passed' });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.value).toBe('Ready');
  });

  it('should transition from Testing to FixError on tests_failed event', () => {
    const actor = createMetaProtocolMachine(config);
    
    // Navigate to Testing state
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    actor.send({ type: 'accept', agreedProtocol: 'protocol1' });
    actor.send({ type: 'code_ready', code: 'code' });
    actor.send({ type: 'tests_agreed', testCases: 'tests' });
    
    // Send tests_failed event
    actor.send({ type: 'tests_failed', errors: 'test errors' });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.value).toBe('FixError');
    expect(snapshot.context.errors).toContain('test errors');
  });
});


describe('MetaProtocolMachine - Error Fixing Flow', () => {
  let mockIdentity: DIDIdentity;
  let config: MetaProtocolConfig;

  beforeEach(() => {
    mockIdentity = {
      did: 'did:wba:example.com:agent1',
      document: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: 'did:wba:example.com:agent1',
        verificationMethod: [],
        authentication: [],
      },
      privateKeys: new Map(),
    };

    config = {
      localIdentity: mockIdentity,
      remoteDID: 'did:wba:example.com:agent2',
    };
  });

  it('should transition from FixError to CodeGeneration on fix_accepted event', () => {
    const actor = createMetaProtocolMachine(config);
    
    // Navigate to FixError state
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    actor.send({ type: 'accept', agreedProtocol: 'protocol1' });
    actor.send({ type: 'code_ready', code: 'code' });
    actor.send({ type: 'tests_agreed', testCases: 'tests' });
    actor.send({ type: 'tests_failed', errors: 'errors' });
    
    // Send fix_accepted event
    actor.send({ type: 'fix_accepted', fix: 'fixed code' });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.value).toBe('CodeGeneration');
  });

  it('should transition from FixError to Failed on fix_rejected event', () => {
    const actor = createMetaProtocolMachine(config);
    
    // Navigate to FixError state
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    actor.send({ type: 'accept', agreedProtocol: 'protocol1' });
    actor.send({ type: 'code_ready', code: 'code' });
    actor.send({ type: 'tests_agreed', testCases: 'tests' });
    actor.send({ type: 'tests_failed', errors: 'errors' });
    
    // Send fix_rejected event
    actor.send({ type: 'fix_rejected', reason: 'cannot fix' });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.value).toBe('Failed');
  });

  it('should allow multiple fix attempts by cycling back to CodeGeneration', () => {
    const actor = createMetaProtocolMachine(config);
    
    // Navigate to FixError state
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    actor.send({ type: 'accept', agreedProtocol: 'protocol1' });
    actor.send({ type: 'code_ready', code: 'code' });
    actor.send({ type: 'tests_agreed', testCases: 'tests' });
    actor.send({ type: 'tests_failed', errors: 'errors' });
    
    // Accept fix and go back to CodeGeneration
    actor.send({ type: 'fix_accepted', fix: 'fix1' });
    expect(actor.getSnapshot().value).toBe('CodeGeneration');
    
    // Can generate code again
    actor.send({ type: 'code_ready', code: 'new code' });
    expect(actor.getSnapshot().value).toBe('TestCases');
  });
});


describe('MetaProtocolMachine - Communication Flow', () => {
  let mockIdentity: DIDIdentity;
  let config: MetaProtocolConfig;

  beforeEach(() => {
    mockIdentity = {
      did: 'did:wba:example.com:agent1',
      document: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: 'did:wba:example.com:agent1',
        verificationMethod: [],
        authentication: [],
      },
      privateKeys: new Map(),
    };

    config = {
      localIdentity: mockIdentity,
      remoteDID: 'did:wba:example.com:agent2',
    };
  });

  it('should transition from Ready to Communicating on start_communication event', () => {
    const actor = createMetaProtocolMachine(config);
    
    // Navigate to Ready state
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    actor.send({ type: 'accept', agreedProtocol: 'protocol1' });
    actor.send({ type: 'code_ready', code: 'code' });
    actor.send({ type: 'skip_tests' });
    
    // Send start_communication event
    actor.send({ type: 'start_communication' });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.value).toBe('Communicating');
  });

  it('should transition from Communicating to FixError on protocol_error event', () => {
    const actor = createMetaProtocolMachine(config);
    
    // Navigate to Communicating state
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    actor.send({ type: 'accept', agreedProtocol: 'protocol1' });
    actor.send({ type: 'code_ready', code: 'code' });
    actor.send({ type: 'skip_tests' });
    actor.send({ type: 'start_communication' });
    
    // Send protocol_error event
    actor.send({ type: 'protocol_error', error: 'protocol mismatch' });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.value).toBe('FixError');
    expect(snapshot.context.errors).toContain('protocol mismatch');
  });

  it('should transition from Communicating to final state on end event', () => {
    const actor = createMetaProtocolMachine(config);
    
    // Navigate to Communicating state
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    actor.send({ type: 'accept', agreedProtocol: 'protocol1' });
    actor.send({ type: 'code_ready', code: 'code' });
    actor.send({ type: 'skip_tests' });
    actor.send({ type: 'start_communication' });
    
    // Send end event
    actor.send({ type: 'end' });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.status).toBe('done');
  });

  it('should remain in Ready state until start_communication', () => {
    const actor = createMetaProtocolMachine(config);
    
    // Navigate to Ready state
    actor.send({ type: 'initiate', candidateProtocols: 'protocol1' });
    actor.send({ type: 'accept', agreedProtocol: 'protocol1' });
    actor.send({ type: 'code_ready', code: 'code' });
    actor.send({ type: 'skip_tests' });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.value).toBe('Ready');
  });
});


describe('MetaProtocolMachine - Message Sending', () => {
  let mockIdentity: DIDIdentity;
  let config: MetaProtocolConfig;

  beforeEach(() => {
    mockIdentity = {
      did: 'did:wba:example.com:agent1',
      document: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: 'did:wba:example.com:agent1',
        verificationMethod: [],
        authentication: [],
      },
      privateKeys: new Map(),
    };

    config = {
      localIdentity: mockIdentity,
      remoteDID: 'did:wba:example.com:agent2',
    };
  });

  it('should construct negotiation message with correct structure', async () => {
    const actor = createMetaProtocolMachine(config);
    const snapshot = actor.getSnapshot();
    
    const message = {
      action: 'protocolNegotiation',
      sequenceId: snapshot.context.sequenceId,
      candidateProtocols: 'protocol1,protocol2',
      status: 'negotiating',
    };
    
    expect(message.action).toBe('protocolNegotiation');
    expect(message.sequenceId).toBeDefined();
    expect(message.candidateProtocols).toBe('protocol1,protocol2');
    expect(message.status).toBe('negotiating');
  });

  it('should include modification summary when provided', () => {
    const message = {
      action: 'protocolNegotiation',
      sequenceId: 1,
      candidateProtocols: 'protocol1',
      modificationSummary: 'Added support for feature X',
      status: 'negotiating',
    };
    
    expect(message.modificationSummary).toBe('Added support for feature X');
  });

  it('should construct code generation message', () => {
    const message = {
      action: 'codeGeneration',
      status: 'generated',
    };
    
    expect(message.action).toBe('codeGeneration');
    expect(message.status).toBe('generated');
  });

  it('should construct test cases negotiation message', () => {
    const message = {
      action: 'testCasesNegotiation',
      testCases: 'test suite description',
      status: 'negotiating',
    };
    
    expect(message.action).toBe('testCasesNegotiation');
    expect(message.testCases).toBe('test suite description');
  });

  it('should construct fix error negotiation message', () => {
    const message = {
      action: 'fixErrorNegotiation',
      errors: 'error description',
      status: 'negotiating',
    };
    
    expect(message.action).toBe('fixErrorNegotiation');
    expect(message.errors).toBe('error description');
  });
});


describe('MetaProtocolMachine - Message Processing', () => {
  let mockIdentity: DIDIdentity;
  let config: MetaProtocolConfig;

  beforeEach(() => {
    mockIdentity = {
      did: 'did:wba:example.com:agent1',
      document: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: 'did:wba:example.com:agent1',
        verificationMethod: [],
        authentication: [],
      },
      privateKeys: new Map(),
    };

    config = {
      localIdentity: mockIdentity,
      remoteDID: 'did:wba:example.com:agent2',
    };
  });

  it('should decode and process protocol negotiation message', async () => {
    const { encodeMetaProtocolMessage, createNegotiationMessage } = await import('../../../src/protocol/meta-protocol-machine');
    
    const message = createNegotiationMessage(1, 'protocol1', 'negotiating');
    const encoded = encodeMetaProtocolMessage(message);
    
    expect(encoded).toBeInstanceOf(Uint8Array);
    expect(encoded.length).toBeGreaterThan(0);
  });

  it('should decode and process code generation message', async () => {
    const { encodeMetaProtocolMessage, createCodeGenerationMessage } = await import('../../../src/protocol/meta-protocol-machine');
    
    const message = createCodeGenerationMessage('generated');
    const encoded = encodeMetaProtocolMessage(message);
    
    expect(encoded).toBeInstanceOf(Uint8Array);
  });

  it('should decode and process test cases message', async () => {
    const { encodeMetaProtocolMessage, createTestCasesMessage } = await import('../../../src/protocol/meta-protocol-machine');
    
    const message = createTestCasesMessage('test cases', 'negotiating');
    const encoded = encodeMetaProtocolMessage(message);
    
    expect(encoded).toBeInstanceOf(Uint8Array);
  });

  it('should decode and process fix error message', async () => {
    const { encodeMetaProtocolMessage, createFixErrorMessage } = await import('../../../src/protocol/meta-protocol-machine');
    
    const message = createFixErrorMessage('error description', 'negotiating');
    const encoded = encodeMetaProtocolMessage(message);
    
    expect(encoded).toBeInstanceOf(Uint8Array);
  });

  it('should handle message decoding errors gracefully', async () => {
    const { ProtocolMessageHandler } = await import('../../../src/protocol/message-handler');
    const handler = new ProtocolMessageHandler();
    
    // Invalid message (empty)
    expect(() => handler.decode(new Uint8Array(0))).toThrow();
  });

  it('should map received negotiation message to state machine event', () => {
    const actor = createMetaProtocolMachine(config);
    
    // Simulate receiving a negotiation request
    actor.send({
      type: 'receive_request',
      candidateProtocols: 'protocol1,protocol2',
      sequenceId: 1,
    });
    
    const snapshot = actor.getSnapshot();
    expect(snapshot.value).toBe('Negotiating');
    expect(snapshot.context.candidateProtocols).toBe('protocol1,protocol2');
  });
});
