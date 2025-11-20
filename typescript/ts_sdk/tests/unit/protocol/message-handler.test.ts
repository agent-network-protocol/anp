import { describe, it, expect } from 'vitest';
import { ProtocolMessageHandler, ProtocolType } from '../../../src/protocol/message-handler';

describe('ProtocolMessageHandler - Message Encoding', () => {
  const handler = new ProtocolMessageHandler();

  describe('encode', () => {
    it('should encode meta-protocol message with correct header', () => {
      const data = new TextEncoder().encode('{"action":"protocolNegotiation"}');
      const encoded = handler.encode(ProtocolType.META, data);

      // Check header byte (first byte should be 0b00000000 for META protocol)
      expect(encoded[0]).toBe(0b00000000);
      // Check data follows header
      expect(encoded.length).toBe(data.length + 1);
      expect(encoded.slice(1)).toEqual(data);
    });

    it('should encode application protocol message with correct header', () => {
      const data = new TextEncoder().encode('{"messageId":"123","data":"test"}');
      const encoded = handler.encode(ProtocolType.APPLICATION, data);

      // Check header byte (first byte should be 0b01000000 for APPLICATION protocol)
      expect(encoded[0]).toBe(0b01000000);
      // Check data follows header
      expect(encoded.length).toBe(data.length + 1);
      expect(encoded.slice(1)).toEqual(data);
    });

    it('should encode natural language message with correct header', () => {
      const text = 'Hello, this is a natural language message';
      const data = new TextEncoder().encode(text);
      const encoded = handler.encode(ProtocolType.NATURAL_LANGUAGE, data);

      // Check header byte (first byte should be 0b10000000 for NATURAL_LANGUAGE protocol)
      expect(encoded[0]).toBe(0b10000000);
      // Check data follows header
      expect(encoded.length).toBe(data.length + 1);
      expect(encoded.slice(1)).toEqual(data);
    });

    it('should encode verification protocol message with correct header', () => {
      const data = new TextEncoder().encode('{"testCase":"1","expected":"success"}');
      const encoded = handler.encode(ProtocolType.VERIFICATION, data);

      // Check header byte (first byte should be 0b11000000 for VERIFICATION protocol)
      expect(encoded[0]).toBe(0b11000000);
      // Check data follows header
      expect(encoded.length).toBe(data.length + 1);
      expect(encoded.slice(1)).toEqual(data);
    });

    it('should handle empty data', () => {
      const data = new Uint8Array(0);
      const encoded = handler.encode(ProtocolType.META, data);

      // Should still have header byte
      expect(encoded.length).toBe(1);
      expect(encoded[0]).toBe(0b00000000);
    });

    it('should handle large data payloads', () => {
      const largeData = new Uint8Array(10000).fill(42);
      const encoded = handler.encode(ProtocolType.APPLICATION, largeData);

      expect(encoded.length).toBe(10001);
      expect(encoded[0]).toBe(0b01000000);
      expect(encoded.slice(1)).toEqual(largeData);
    });

    it('should preserve binary data integrity', () => {
      const binaryData = new Uint8Array([0, 1, 2, 255, 254, 253]);
      const encoded = handler.encode(ProtocolType.META, binaryData);

      expect(encoded[0]).toBe(0b00000000);
      expect(encoded.slice(1)).toEqual(binaryData);
    });
  });

  describe('binary format correctness', () => {
    it('should set protocol type bits correctly in header', () => {
      const data = new Uint8Array([1, 2, 3]);

      // META: 00 in bits 7-6
      const metaEncoded = handler.encode(ProtocolType.META, data);
      expect((metaEncoded[0] >> 6) & 0b11).toBe(0b00);

      // APPLICATION: 01 in bits 7-6
      const appEncoded = handler.encode(ProtocolType.APPLICATION, data);
      expect((appEncoded[0] >> 6) & 0b11).toBe(0b01);

      // NATURAL_LANGUAGE: 10 in bits 7-6
      const nlEncoded = handler.encode(ProtocolType.NATURAL_LANGUAGE, data);
      expect((nlEncoded[0] >> 6) & 0b11).toBe(0b10);

      // VERIFICATION: 11 in bits 7-6
      const verEncoded = handler.encode(ProtocolType.VERIFICATION, data);
      expect((verEncoded[0] >> 6) & 0b11).toBe(0b11);
    });

    it('should set reserved bits to zero', () => {
      const data = new Uint8Array([1, 2, 3]);
      const encoded = handler.encode(ProtocolType.META, data);

      // Reserved bits (bits 5-0) should be 0
      expect(encoded[0] & 0b00111111).toBe(0);
    });

    it('should create new Uint8Array without modifying input', () => {
      const data = new Uint8Array([1, 2, 3]);
      const originalData = new Uint8Array(data);
      
      handler.encode(ProtocolType.META, data);

      // Original data should not be modified
      expect(data).toEqual(originalData);
    });
  });
});

describe('ProtocolMessageHandler - Message Decoding', () => {
  const handler = new ProtocolMessageHandler();

  describe('decode', () => {
    it('should decode meta-protocol message correctly', () => {
      const data = new TextEncoder().encode('{"action":"protocolNegotiation"}');
      const encoded = handler.encode(ProtocolType.META, data);
      
      const decoded = handler.decode(encoded);
      
      expect(decoded.protocolType).toBe(ProtocolType.META);
      expect(decoded.data).toEqual(data);
    });

    it('should decode application protocol message correctly', () => {
      const data = new TextEncoder().encode('{"messageId":"123","data":"test"}');
      const encoded = handler.encode(ProtocolType.APPLICATION, data);
      
      const decoded = handler.decode(encoded);
      
      expect(decoded.protocolType).toBe(ProtocolType.APPLICATION);
      expect(decoded.data).toEqual(data);
    });

    it('should decode natural language message correctly', () => {
      const text = 'Hello, this is a natural language message';
      const data = new TextEncoder().encode(text);
      const encoded = handler.encode(ProtocolType.NATURAL_LANGUAGE, data);
      
      const decoded = handler.decode(encoded);
      
      expect(decoded.protocolType).toBe(ProtocolType.NATURAL_LANGUAGE);
      expect(decoded.data).toEqual(data);
      expect(new TextDecoder().decode(decoded.data)).toBe(text);
    });

    it('should decode verification protocol message correctly', () => {
      const data = new TextEncoder().encode('{"testCase":"1","expected":"success"}');
      const encoded = handler.encode(ProtocolType.VERIFICATION, data);
      
      const decoded = handler.decode(encoded);
      
      expect(decoded.protocolType).toBe(ProtocolType.VERIFICATION);
      expect(decoded.data).toEqual(data);
    });

    it('should handle message with empty data', () => {
      const data = new Uint8Array(0);
      const encoded = handler.encode(ProtocolType.META, data);
      
      const decoded = handler.decode(encoded);
      
      expect(decoded.protocolType).toBe(ProtocolType.META);
      expect(decoded.data.length).toBe(0);
    });

    it('should handle large data payloads', () => {
      const largeData = new Uint8Array(10000).fill(42);
      const encoded = handler.encode(ProtocolType.APPLICATION, largeData);
      
      const decoded = handler.decode(encoded);
      
      expect(decoded.protocolType).toBe(ProtocolType.APPLICATION);
      expect(decoded.data).toEqual(largeData);
    });

    it('should preserve binary data integrity', () => {
      const binaryData = new Uint8Array([0, 1, 2, 255, 254, 253]);
      const encoded = handler.encode(ProtocolType.META, binaryData);
      
      const decoded = handler.decode(encoded);
      
      expect(decoded.protocolType).toBe(ProtocolType.META);
      expect(decoded.data).toEqual(binaryData);
    });

    it('should correctly extract protocol type from header', () => {
      const data = new Uint8Array([1, 2, 3]);
      
      // Test all protocol types
      const metaEncoded = handler.encode(ProtocolType.META, data);
      expect(handler.decode(metaEncoded).protocolType).toBe(ProtocolType.META);
      
      const appEncoded = handler.encode(ProtocolType.APPLICATION, data);
      expect(handler.decode(appEncoded).protocolType).toBe(ProtocolType.APPLICATION);
      
      const nlEncoded = handler.encode(ProtocolType.NATURAL_LANGUAGE, data);
      expect(handler.decode(nlEncoded).protocolType).toBe(ProtocolType.NATURAL_LANGUAGE);
      
      const verEncoded = handler.encode(ProtocolType.VERIFICATION, data);
      expect(handler.decode(verEncoded).protocolType).toBe(ProtocolType.VERIFICATION);
    });
  });

  describe('error handling for malformed messages', () => {
    it('should throw error for empty message', () => {
      const emptyMessage = new Uint8Array(0);
      
      expect(() => handler.decode(emptyMessage)).toThrow('Message is too short');
    });

    it('should throw error for message with only header and no data', () => {
      // This is actually valid - a message can have just a header with no data
      const headerOnly = new Uint8Array([0b00000000]);
      
      const decoded = handler.decode(headerOnly);
      expect(decoded.protocolType).toBe(ProtocolType.META);
      expect(decoded.data.length).toBe(0);
    });

    it('should handle messages with reserved bits set (should ignore them)', () => {
      // Create a message with reserved bits set (should still decode correctly)
      const message = new Uint8Array([0b00111111, 1, 2, 3]); // META type with reserved bits set
      
      const decoded = handler.decode(message);
      
      // Should still extract protocol type correctly
      expect(decoded.protocolType).toBe(ProtocolType.META);
      expect(decoded.data).toEqual(new Uint8Array([1, 2, 3]));
    });

    it('should throw error for null or undefined input', () => {
      expect(() => handler.decode(null as any)).toThrow();
      expect(() => handler.decode(undefined as any)).toThrow();
    });
  });

  describe('encode-decode round trip', () => {
    it('should maintain data integrity through encode-decode cycle', () => {
      const testCases = [
        { type: ProtocolType.META, data: new TextEncoder().encode('{"action":"test"}') },
        { type: ProtocolType.APPLICATION, data: new TextEncoder().encode('application data') },
        { type: ProtocolType.NATURAL_LANGUAGE, data: new TextEncoder().encode('natural language') },
        { type: ProtocolType.VERIFICATION, data: new TextEncoder().encode('verification data') },
      ];

      testCases.forEach(({ type, data }) => {
        const encoded = handler.encode(type, data);
        const decoded = handler.decode(encoded);
        
        expect(decoded.protocolType).toBe(type);
        expect(decoded.data).toEqual(data);
      });
    });
  });
});

describe('ProtocolMessageHandler - Meta-Protocol Message Parsing', () => {
  const handler = new ProtocolMessageHandler();

  describe('parseMetaProtocol - protocolNegotiation', () => {
    it('should parse protocolNegotiation message with all fields', () => {
      const message = {
        action: 'protocolNegotiation',
        sequenceId: 0,
        candidateProtocols: '# Requirements\nRetrieve product information',
        modificationSummary: 'Initial proposal',
        status: 'negotiating'
      };
      const data = new TextEncoder().encode(JSON.stringify(message));
      
      const parsed = handler.parseMetaProtocol(data);
      
      expect(parsed.action).toBe('protocolNegotiation');
      expect(parsed.sequenceId).toBe(0);
      expect(parsed.candidateProtocols).toBe('# Requirements\nRetrieve product information');
      expect(parsed.modificationSummary).toBe('Initial proposal');
      expect(parsed.status).toBe('negotiating');
    });

    it('should parse protocolNegotiation message without modificationSummary', () => {
      const message = {
        action: 'protocolNegotiation',
        sequenceId: 0,
        candidateProtocols: '# Requirements\nRetrieve product information',
        status: 'negotiating'
      };
      const data = new TextEncoder().encode(JSON.stringify(message));
      
      const parsed = handler.parseMetaProtocol(data);
      
      expect(parsed.action).toBe('protocolNegotiation');
      expect(parsed.sequenceId).toBe(0);
      expect(parsed.modificationSummary).toBeUndefined();
    });

    it('should parse protocolNegotiation with status accepted', () => {
      const message = {
        action: 'protocolNegotiation',
        sequenceId: 2,
        candidateProtocols: '# Final protocol',
        status: 'accepted'
      };
      const data = new TextEncoder().encode(JSON.stringify(message));
      
      const parsed = handler.parseMetaProtocol(data);
      
      expect(parsed.status).toBe('accepted');
    });

    it('should parse protocolNegotiation with status rejected', () => {
      const message = {
        action: 'protocolNegotiation',
        sequenceId: 1,
        candidateProtocols: '# Protocol',
        status: 'rejected'
      };
      const data = new TextEncoder().encode(JSON.stringify(message));
      
      const parsed = handler.parseMetaProtocol(data);
      
      expect(parsed.status).toBe('rejected');
    });

    it('should parse protocolNegotiation with status timeout', () => {
      const message = {
        action: 'protocolNegotiation',
        sequenceId: 5,
        candidateProtocols: '# Protocol',
        status: 'timeout'
      };
      const data = new TextEncoder().encode(JSON.stringify(message));
      
      const parsed = handler.parseMetaProtocol(data);
      
      expect(parsed.status).toBe('timeout');
    });
  });

  describe('parseMetaProtocol - codeGeneration', () => {
    it('should parse codeGeneration message with status generated', () => {
      const message = {
        action: 'codeGeneration',
        status: 'generated'
      };
      const data = new TextEncoder().encode(JSON.stringify(message));
      
      const parsed = handler.parseMetaProtocol(data);
      
      expect(parsed.action).toBe('codeGeneration');
      expect(parsed.status).toBe('generated');
    });

    it('should parse codeGeneration message with status error', () => {
      const message = {
        action: 'codeGeneration',
        status: 'error'
      };
      const data = new TextEncoder().encode(JSON.stringify(message));
      
      const parsed = handler.parseMetaProtocol(data);
      
      expect(parsed.action).toBe('codeGeneration');
      expect(parsed.status).toBe('error');
    });
  });

  describe('parseMetaProtocol - testCasesNegotiation', () => {
    it('should parse testCasesNegotiation message with all fields', () => {
      const message = {
        action: 'testCasesNegotiation',
        testCases: '# Test Case 1\n- Test request data\n- Expected result',
        modificationSummary: 'Added edge cases',
        status: 'negotiating'
      };
      const data = new TextEncoder().encode(JSON.stringify(message));
      
      const parsed = handler.parseMetaProtocol(data);
      
      expect(parsed.action).toBe('testCasesNegotiation');
      expect(parsed.testCases).toBe('# Test Case 1\n- Test request data\n- Expected result');
      expect(parsed.modificationSummary).toBe('Added edge cases');
      expect(parsed.status).toBe('negotiating');
    });

    it('should parse testCasesNegotiation message without modificationSummary', () => {
      const message = {
        action: 'testCasesNegotiation',
        testCases: '# Test Case 1',
        status: 'accepted'
      };
      const data = new TextEncoder().encode(JSON.stringify(message));
      
      const parsed = handler.parseMetaProtocol(data);
      
      expect(parsed.action).toBe('testCasesNegotiation');
      expect(parsed.modificationSummary).toBeUndefined();
      expect(parsed.status).toBe('accepted');
    });

    it('should parse testCasesNegotiation with status rejected', () => {
      const message = {
        action: 'testCasesNegotiation',
        testCases: '# Test cases',
        status: 'rejected'
      };
      const data = new TextEncoder().encode(JSON.stringify(message));
      
      const parsed = handler.parseMetaProtocol(data);
      
      expect(parsed.status).toBe('rejected');
    });
  });

  describe('parseMetaProtocol - fixErrorNegotiation', () => {
    it('should parse fixErrorNegotiation message with all fields', () => {
      const message = {
        action: 'fixErrorNegotiation',
        errorDescription: '# Error Description\n- The status field is missing',
        status: 'negotiating'
      };
      const data = new TextEncoder().encode(JSON.stringify(message));
      
      const parsed = handler.parseMetaProtocol(data);
      
      expect(parsed.action).toBe('fixErrorNegotiation');
      expect(parsed.errorDescription).toBe('# Error Description\n- The status field is missing');
      expect(parsed.status).toBe('negotiating');
    });

    it('should parse fixErrorNegotiation with status accepted', () => {
      const message = {
        action: 'fixErrorNegotiation',
        errorDescription: 'Error details',
        status: 'accepted'
      };
      const data = new TextEncoder().encode(JSON.stringify(message));
      
      const parsed = handler.parseMetaProtocol(data);
      
      expect(parsed.status).toBe('accepted');
    });

    it('should parse fixErrorNegotiation with status rejected', () => {
      const message = {
        action: 'fixErrorNegotiation',
        errorDescription: 'Error details',
        status: 'rejected'
      };
      const data = new TextEncoder().encode(JSON.stringify(message));
      
      const parsed = handler.parseMetaProtocol(data);
      
      expect(parsed.status).toBe('rejected');
    });
  });

  describe('parseMetaProtocol - naturalLanguageNegotiation', () => {
    it('should parse naturalLanguageNegotiation REQUEST message', () => {
      const message = {
        action: 'naturalLanguageNegotiation',
        type: 'REQUEST',
        messageId: 'abc123def4567890',
        message: 'Can we use a custom timeout of 30 seconds?'
      };
      const data = new TextEncoder().encode(JSON.stringify(message));
      
      const parsed = handler.parseMetaProtocol(data);
      
      expect(parsed.action).toBe('naturalLanguageNegotiation');
      expect(parsed.type).toBe('REQUEST');
      expect(parsed.messageId).toBe('abc123def4567890');
      expect(parsed.message).toBe('Can we use a custom timeout of 30 seconds?');
    });

    it('should parse naturalLanguageNegotiation RESPONSE message', () => {
      const message = {
        action: 'naturalLanguageNegotiation',
        type: 'RESPONSE',
        messageId: 'abc123def4567890',
        message: 'Yes, 30 seconds timeout is acceptable.'
      };
      const data = new TextEncoder().encode(JSON.stringify(message));
      
      const parsed = handler.parseMetaProtocol(data);
      
      expect(parsed.action).toBe('naturalLanguageNegotiation');
      expect(parsed.type).toBe('RESPONSE');
      expect(parsed.messageId).toBe('abc123def4567890');
      expect(parsed.message).toBe('Yes, 30 seconds timeout is acceptable.');
    });
  });

  describe('parseMetaProtocol - error handling', () => {
    it('should throw error for invalid JSON', () => {
      const invalidJson = new TextEncoder().encode('{ invalid json }');
      
      expect(() => handler.parseMetaProtocol(invalidJson)).toThrow();
    });

    it('should throw error for missing action field', () => {
      const message = {
        sequenceId: 0,
        status: 'negotiating'
      };
      const data = new TextEncoder().encode(JSON.stringify(message));
      
      expect(() => handler.parseMetaProtocol(data)).toThrow('Invalid meta-protocol message: missing action field');
    });

    it('should throw error for unknown action type', () => {
      const message = {
        action: 'unknownAction',
        data: 'some data'
      };
      const data = new TextEncoder().encode(JSON.stringify(message));
      
      expect(() => handler.parseMetaProtocol(data)).toThrow('Unknown meta-protocol action: unknownAction');
    });

    it('should throw error for empty data', () => {
      const emptyData = new Uint8Array(0);
      
      expect(() => handler.parseMetaProtocol(emptyData)).toThrow();
    });
  });

  describe('parseMetaProtocol - message type discrimination', () => {
    it('should correctly discriminate between different message types', () => {
      const messages = [
        { action: 'protocolNegotiation', sequenceId: 0, candidateProtocols: 'test', status: 'negotiating' },
        { action: 'codeGeneration', status: 'generated' },
        { action: 'testCasesNegotiation', testCases: 'test', status: 'negotiating' },
        { action: 'fixErrorNegotiation', errorDescription: 'error', status: 'negotiating' },
        { action: 'naturalLanguageNegotiation', type: 'REQUEST', messageId: '123', message: 'test' }
      ];

      messages.forEach(message => {
        const data = new TextEncoder().encode(JSON.stringify(message));
        const parsed = handler.parseMetaProtocol(data);
        
        expect(parsed.action).toBe(message.action);
      });
    });
  });
});
