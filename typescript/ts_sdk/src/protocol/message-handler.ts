/**
 * Protocol Message Handler
 * 
 * Handles encoding and decoding of ANP protocol messages according to the
 * meta-protocol specification.
 */

/**
 * Protocol Type enumeration
 * Represents the 2-bit protocol type field in the message header
 */
export enum ProtocolType {
  META = 0b00,              // Meta-protocol for negotiation
  APPLICATION = 0b01,       // Application protocol for data transmission
  NATURAL_LANGUAGE = 0b10,  // Natural language protocol
  VERIFICATION = 0b11       // Verification protocol for testing
}

/**
 * Decoded protocol message
 */
export interface ProtocolMessage {
  protocolType: ProtocolType;
  data: Uint8Array;
}

/**
 * Protocol Negotiation Message
 */
export interface ProtocolNegotiationMessage {
  action: 'protocolNegotiation';
  sequenceId: number;
  candidateProtocols: string;
  modificationSummary?: string;
  status: 'negotiating' | 'rejected' | 'accepted' | 'timeout';
}

/**
 * Code Generation Message
 */
export interface CodeGenerationMessage {
  action: 'codeGeneration';
  status: 'generated' | 'error';
}

/**
 * Test Cases Negotiation Message
 */
export interface TestCasesNegotiationMessage {
  action: 'testCasesNegotiation';
  testCases: string;
  modificationSummary?: string;
  status: 'negotiating' | 'rejected' | 'accepted';
}

/**
 * Fix Error Negotiation Message
 */
export interface FixErrorNegotiationMessage {
  action: 'fixErrorNegotiation';
  errorDescription: string;
  status: 'negotiating' | 'rejected' | 'accepted';
}

/**
 * Natural Language Negotiation Message
 */
export interface NaturalLanguageNegotiationMessage {
  action: 'naturalLanguageNegotiation';
  type: 'REQUEST' | 'RESPONSE';
  messageId: string;
  message: string;
}

/**
 * Union type for all meta-protocol messages
 */
export type MetaProtocolMessage =
  | ProtocolNegotiationMessage
  | CodeGenerationMessage
  | TestCasesNegotiationMessage
  | FixErrorNegotiationMessage
  | NaturalLanguageNegotiationMessage;

/**
 * Protocol Message Handler
 * 
 * Encodes and decodes protocol messages according to ANP specification:
 * - 1 byte header: [PT(2 bits) | Reserved(6 bits)]
 * - Variable length protocol data
 */
export class ProtocolMessageHandler {
  /**
   * Encode a protocol message
   * 
   * Creates a binary message with:
   * - Header byte with protocol type in bits 7-6
   * - Reserved bits 5-0 set to 0
   * - Protocol data following the header
   * 
   * @param type - Protocol type (META, APPLICATION, NATURAL_LANGUAGE, or VERIFICATION)
   * @param data - Protocol data as Uint8Array
   * @returns Encoded message with header and data
   */
  encode(type: ProtocolType, data: Uint8Array): Uint8Array {
    // Create new array with space for header + data
    const encoded = new Uint8Array(1 + data.length);
    
    // Construct header byte:
    // - Protocol type in bits 7-6 (shift left by 6)
    // - Reserved bits 5-0 are 0 (default)
    const header = (type << 6) & 0b11000000;
    encoded[0] = header;
    
    // Copy protocol data after header
    encoded.set(data, 1);
    
    return encoded;
  }

  /**
   * Decode a protocol message
   * 
   * Extracts the protocol type and data from an encoded message:
   * - Reads protocol type from bits 7-6 of header byte
   * - Extracts protocol data from remaining bytes
   * 
   * @param message - Encoded message with header and data
   * @returns Decoded protocol message with type and data
   * @throws Error if message is invalid or too short
   */
  decode(message: Uint8Array): ProtocolMessage {
    // Validate input
    if (!message || message.length === 0) {
      throw new Error('Message is too short: must contain at least a header byte');
    }

    // Extract protocol type from bits 7-6 of header byte
    const header = message[0];
    const protocolType = (header >> 6) & 0b11;

    // Extract protocol data (everything after header byte)
    const data = message.slice(1);

    return {
      protocolType,
      data
    };
  }

  /**
   * Parse meta-protocol message
   * 
   * Parses JSON-encoded meta-protocol messages and validates the structure.
   * Supports all meta-protocol message types:
   * - protocolNegotiation
   * - codeGeneration
   * - testCasesNegotiation
   * - fixErrorNegotiation
   * - naturalLanguageNegotiation
   * 
   * @param data - UTF-8 encoded JSON data
   * @returns Parsed meta-protocol message
   * @throws Error if JSON is invalid or message structure is incorrect
   */
  parseMetaProtocol(data: Uint8Array): MetaProtocolMessage {
    // Decode UTF-8 data to string
    const jsonString = new TextDecoder().decode(data);
    
    // Parse JSON
    let parsed: any;
    try {
      parsed = JSON.parse(jsonString);
    } catch (error) {
      throw new Error(`Failed to parse meta-protocol message: ${error instanceof Error ? error.message : 'Invalid JSON'}`);
    }

    // Validate action field exists
    if (!parsed.action || typeof parsed.action !== 'string') {
      throw new Error('Invalid meta-protocol message: missing action field');
    }

    // Discriminate message type based on action field
    switch (parsed.action) {
      case 'protocolNegotiation':
        return this.validateProtocolNegotiationMessage(parsed);
      
      case 'codeGeneration':
        return this.validateCodeGenerationMessage(parsed);
      
      case 'testCasesNegotiation':
        return this.validateTestCasesNegotiationMessage(parsed);
      
      case 'fixErrorNegotiation':
        return this.validateFixErrorNegotiationMessage(parsed);
      
      case 'naturalLanguageNegotiation':
        return this.validateNaturalLanguageNegotiationMessage(parsed);
      
      default:
        throw new Error(`Unknown meta-protocol action: ${parsed.action}`);
    }
  }

  /**
   * Validate protocol negotiation message structure
   */
  private validateProtocolNegotiationMessage(parsed: any): ProtocolNegotiationMessage {
    if (typeof parsed.sequenceId !== 'number') {
      throw new Error('Invalid protocolNegotiation message: sequenceId must be a number');
    }
    if (typeof parsed.candidateProtocols !== 'string') {
      throw new Error('Invalid protocolNegotiation message: candidateProtocols must be a string');
    }
    if (typeof parsed.status !== 'string') {
      throw new Error('Invalid protocolNegotiation message: status must be a string');
    }
    
    return parsed as ProtocolNegotiationMessage;
  }

  /**
   * Validate code generation message structure
   */
  private validateCodeGenerationMessage(parsed: any): CodeGenerationMessage {
    if (typeof parsed.status !== 'string') {
      throw new Error('Invalid codeGeneration message: status must be a string');
    }
    
    return parsed as CodeGenerationMessage;
  }

  /**
   * Validate test cases negotiation message structure
   */
  private validateTestCasesNegotiationMessage(parsed: any): TestCasesNegotiationMessage {
    if (typeof parsed.testCases !== 'string') {
      throw new Error('Invalid testCasesNegotiation message: testCases must be a string');
    }
    if (typeof parsed.status !== 'string') {
      throw new Error('Invalid testCasesNegotiation message: status must be a string');
    }
    
    return parsed as TestCasesNegotiationMessage;
  }

  /**
   * Validate fix error negotiation message structure
   */
  private validateFixErrorNegotiationMessage(parsed: any): FixErrorNegotiationMessage {
    if (typeof parsed.errorDescription !== 'string') {
      throw new Error('Invalid fixErrorNegotiation message: errorDescription must be a string');
    }
    if (typeof parsed.status !== 'string') {
      throw new Error('Invalid fixErrorNegotiation message: status must be a string');
    }
    
    return parsed as FixErrorNegotiationMessage;
  }

  /**
   * Validate natural language negotiation message structure
   */
  private validateNaturalLanguageNegotiationMessage(parsed: any): NaturalLanguageNegotiationMessage {
    if (typeof parsed.type !== 'string') {
      throw new Error('Invalid naturalLanguageNegotiation message: type must be a string');
    }
    if (typeof parsed.messageId !== 'string') {
      throw new Error('Invalid naturalLanguageNegotiation message: messageId must be a string');
    }
    if (typeof parsed.message !== 'string') {
      throw new Error('Invalid naturalLanguageNegotiation message: message must be a string');
    }
    
    return parsed as NaturalLanguageNegotiationMessage;
  }
}
