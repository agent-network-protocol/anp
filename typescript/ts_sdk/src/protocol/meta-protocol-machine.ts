import { setup, createActor, type ActorRefFrom } from 'xstate';
import type { DIDIdentity } from '../types/did';

// Context type definition
export interface MetaProtocolContext {
  sequenceId: number;
  candidateProtocols: string;
  agreedProtocol?: string;
  testCases?: string;
  maxNegotiationRounds: number;
  remoteDID: string;
  localIdentity: DIDIdentity;
  negotiationRound: number;
  errors?: string[];
}

// Event type definitions
export type MetaProtocolEvent =
  | { type: 'initiate'; candidateProtocols: string }
  | { type: 'receive_request'; candidateProtocols: string; sequenceId: number }
  | { type: 'negotiate'; response: string }
  | { type: 'accept'; agreedProtocol: string }
  | { type: 'reject'; reason: string }
  | { type: 'timeout' }
  | { type: 'code_ready'; code: string }
  | { type: 'code_error'; error: string }
  | { type: 'tests_agreed'; testCases: string }
  | { type: 'skip_tests' }
  | { type: 'tests_passed' }
  | { type: 'tests_failed'; errors: string }
  | { type: 'fix_accepted'; fix: string }
  | { type: 'fix_rejected'; reason: string }
  | { type: 'start_communication' }
  | { type: 'protocol_error'; error: string }
  | { type: 'end' };

// Configuration for creating the machine
export interface MetaProtocolConfig {
  localIdentity: DIDIdentity;
  remoteDID: string;
  maxNegotiationRounds?: number;
  timeoutMs?: number;
}

// Define the state machine
const metaProtocolMachine = setup({
  types: {
    context: {} as MetaProtocolContext,
    events: {} as MetaProtocolEvent,
    input: {} as MetaProtocolConfig,
  },
  guards: {
    canContinueNegotiation: ({ context }) => {
      return context.negotiationRound < context.maxNegotiationRounds;
    },
    maxRoundsExceeded: ({ context }) => {
      return context.negotiationRound >= context.maxNegotiationRounds;
    },
  },
  actions: {
    incrementSequenceId: ({ context }) => {
      context.sequenceId += 1;
    },
    incrementNegotiationRound: ({ context }) => {
      context.negotiationRound += 1;
    },
    setAgreedProtocol: ({ context, event }) => {
      if (event.type === 'accept') {
        context.agreedProtocol = event.agreedProtocol;
      }
    },
    setCandidateProtocols: ({ context, event }) => {
      if (event.type === 'initiate') {
        context.candidateProtocols = event.candidateProtocols;
      } else if (event.type === 'receive_request') {
        context.candidateProtocols = event.candidateProtocols;
        context.sequenceId = event.sequenceId;
      }
    },
    setTestCases: ({ context, event }) => {
      if (event.type === 'tests_agreed') {
        context.testCases = event.testCases;
      }
    },
    addError: ({ context, event }) => {
      if (!context.errors) {
        context.errors = [];
      }
      if (event.type === 'code_error') {
        context.errors.push(event.error);
      } else if (event.type === 'tests_failed') {
        context.errors.push(event.errors);
      } else if (event.type === 'protocol_error') {
        context.errors.push(event.error);
      }
    },
  },
}).createMachine({
  id: 'metaProtocol',
  initial: 'Idle',
  context: ({ input }: { input: MetaProtocolConfig }) => ({
    sequenceId: 0,
    candidateProtocols: '',
    agreedProtocol: undefined,
    testCases: undefined,
    maxNegotiationRounds: input.maxNegotiationRounds ?? 10,
    remoteDID: input.remoteDID,
    localIdentity: input.localIdentity,
    negotiationRound: 0,
    errors: undefined,
  }),
  states: {
    Idle: {
      on: {
        initiate: {
          target: 'Negotiating',
          actions: ['setCandidateProtocols'],
        },
        receive_request: {
          target: 'Negotiating',
          actions: ['setCandidateProtocols'],
        },
      },
    },
    Negotiating: {
      on: {
        negotiate: [
          {
            guard: 'maxRoundsExceeded',
            target: 'Rejected',
          },
          {
            guard: 'canContinueNegotiation',
            target: 'Negotiating',
            actions: ['incrementNegotiationRound', 'incrementSequenceId'],
          },
        ],
        accept: {
          target: 'CodeGeneration',
          actions: ['setAgreedProtocol'],
        },
        reject: {
          target: 'Rejected',
        },
        timeout: {
          target: 'Rejected',
        },
      },
    },
    CodeGeneration: {
      on: {
        code_ready: {
          target: 'TestCases',
        },
        code_error: {
          target: 'Failed',
          actions: ['addError'],
        },
      },
    },
    TestCases: {
      on: {
        tests_agreed: {
          target: 'Testing',
          actions: ['setTestCases'],
        },
        skip_tests: {
          target: 'Ready',
        },
      },
    },
    Testing: {
      on: {
        tests_passed: {
          target: 'Ready',
        },
        tests_failed: {
          target: 'FixError',
          actions: ['addError'],
        },
      },
    },
    FixError: {
      on: {
        fix_accepted: {
          target: 'CodeGeneration',
        },
        fix_rejected: {
          target: 'Failed',
        },
      },
    },
    Ready: {
      on: {
        start_communication: {
          target: 'Communicating',
        },
      },
    },
    Communicating: {
      on: {
        protocol_error: {
          target: 'FixError',
          actions: ['addError'],
        },
        end: {
          target: 'Completed',
        },
      },
    },
    Rejected: {
      type: 'final',
    },
    Failed: {
      type: 'final',
    },
    Completed: {
      type: 'final',
    },
  },
});

// Factory function to create state machine actor
export function createMetaProtocolMachine(
  config: MetaProtocolConfig
): ActorRefFrom<typeof metaProtocolMachine> {
  const actor = createActor(metaProtocolMachine, {
    input: config,
  });
  
  actor.start();
  
  return actor;
}

// Export the machine type for use in other modules
export type MetaProtocolMachine = typeof metaProtocolMachine;
export type MetaProtocolActor = ActorRefFrom<typeof metaProtocolMachine>;


// Message sending helper functions
import { ProtocolMessageHandler, ProtocolType, type MetaProtocolMessage } from './message-handler';

/**
 * Create a protocol negotiation message
 */
export function createNegotiationMessage(
  sequenceId: number,
  candidateProtocols: string,
  status: 'negotiating' | 'rejected' | 'accepted' | 'timeout',
  modificationSummary?: string
): MetaProtocolMessage {
  const message: any = {
    action: 'protocolNegotiation',
    sequenceId,
    candidateProtocols,
    status,
  };
  
  if (modificationSummary) {
    message.modificationSummary = modificationSummary;
  }
  
  return message;
}

/**
 * Create a code generation message
 */
export function createCodeGenerationMessage(
  status: 'generated' | 'error'
): MetaProtocolMessage {
  return {
    action: 'codeGeneration',
    status,
  };
}

/**
 * Create a test cases negotiation message
 */
export function createTestCasesMessage(
  testCases: string,
  status: 'negotiating' | 'rejected' | 'accepted',
  modificationSummary?: string
): MetaProtocolMessage {
  const message: any = {
    action: 'testCasesNegotiation',
    testCases,
    status,
  };
  
  if (modificationSummary) {
    message.modificationSummary = modificationSummary;
  }
  
  return message;
}

/**
 * Create a fix error negotiation message
 */
export function createFixErrorMessage(
  errorDescription: string,
  status: 'negotiating' | 'rejected' | 'accepted'
): MetaProtocolMessage {
  return {
    action: 'fixErrorNegotiation',
    errorDescription,
    status,
  };
}

/**
 * Encode a meta-protocol message for transmission
 */
export function encodeMetaProtocolMessage(message: MetaProtocolMessage): Uint8Array {
  const handler = new ProtocolMessageHandler();
  const jsonString = JSON.stringify(message);
  const data = new TextEncoder().encode(jsonString);
  return handler.encode(ProtocolType.META, data);
}

/**
 * Send a negotiation message
 * This is a helper function that can be used with the state machine
 */
export async function sendNegotiation(
  actor: MetaProtocolActor,
  candidateProtocols: string,
  modificationSummary?: string
): Promise<Uint8Array> {
  const snapshot = actor.getSnapshot();
  const message = createNegotiationMessage(
    snapshot.context.sequenceId,
    candidateProtocols,
    'negotiating',
    modificationSummary
  );
  
  return encodeMetaProtocolMessage(message);
}


/**
 * Process a received meta-protocol message and dispatch appropriate event to state machine
 */
export function processMessage(
  actor: MetaProtocolActor,
  encodedMessage: Uint8Array
): void {
  const handler = new ProtocolMessageHandler();
  
  // Decode the message
  const decoded = handler.decode(encodedMessage);
  
  // Verify it's a meta-protocol message
  if (decoded.protocolType !== ProtocolType.META) {
    throw new Error(`Expected META protocol type, got ${decoded.protocolType}`);
  }
  
  // Parse the meta-protocol message
  const message = handler.parseMetaProtocol(decoded.data);
  
  // Map message to state machine event
  switch (message.action) {
    case 'protocolNegotiation':
      if (message.status === 'negotiating') {
        actor.send({
          type: 'receive_request',
          candidateProtocols: message.candidateProtocols,
          sequenceId: message.sequenceId,
        });
      } else if (message.status === 'accepted') {
        actor.send({
          type: 'accept',
          agreedProtocol: message.candidateProtocols,
        });
      } else if (message.status === 'rejected') {
        actor.send({
          type: 'reject',
          reason: 'Remote agent rejected negotiation',
        });
      } else if (message.status === 'timeout') {
        actor.send({ type: 'timeout' });
      }
      break;
    
    case 'codeGeneration':
      if (message.status === 'generated') {
        actor.send({ type: 'code_ready', code: 'generated' });
      } else if (message.status === 'error') {
        actor.send({ type: 'code_error', error: 'Code generation failed' });
      }
      break;
    
    case 'testCasesNegotiation':
      if (message.status === 'accepted') {
        actor.send({ type: 'tests_agreed', testCases: message.testCases });
      } else if (message.status === 'rejected') {
        actor.send({ type: 'skip_tests' });
      }
      break;
    
    case 'fixErrorNegotiation':
      if (message.status === 'accepted') {
        actor.send({ type: 'fix_accepted', fix: 'fix applied' });
      } else if (message.status === 'rejected') {
        actor.send({ type: 'fix_rejected', reason: 'Fix rejected' });
      }
      break;
    
    default:
      throw new Error(`Unhandled meta-protocol action: ${(message as any).action}`);
  }
}
