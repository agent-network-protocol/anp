/**
 * Unit tests for Agent Description Manager
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { AgentDescriptionManager } from '../../../../src/core/agent-description/agent-description-manager.js';
import type {
  AgentMetadata,
  Information,
  Interface,
} from '../../../../src/types/index.js';

describe('AgentDescriptionManager - Description Creation', () => {
  let manager: AgentDescriptionManager;

  beforeEach(() => {
    manager = new AgentDescriptionManager();
  });

  describe('createDescription', () => {
    it('should create a valid agent description with required fields', () => {
      const metadata: AgentMetadata = {
        name: 'Test Agent',
        description: 'A test agent for unit testing',
      };

      const description = manager.createDescription(metadata);

      expect(description.protocolType).toBe('ANP');
      expect(description.type).toBe('AgentDescription');
      expect(description.name).toBe('Test Agent');
      expect(description.description).toBe('A test agent for unit testing');
      expect(description.protocolVersion).toBeDefined();
      expect(description.securityDefinitions).toBeDefined();
      expect(description.security).toBeDefined();
    });

    it('should include DID if provided', () => {
      const metadata: AgentMetadata = {
        name: 'Test Agent',
        did: 'did:wba:example.com',
      };

      const description = manager.createDescription(metadata);

      expect(description.did).toBe('did:wba:example.com');
    });

    it('should include owner information if provided', () => {
      const metadata: AgentMetadata = {
        name: 'Test Agent',
        owner: {
          name: 'Test Organization',
          url: 'https://example.com',
          email: 'contact@example.com',
        },
      };

      const description = manager.createDescription(metadata);

      expect(description.owner).toBeDefined();
      expect(description.owner?.name).toBe('Test Organization');
      expect(description.owner?.url).toBe('https://example.com');
      expect(description.owner?.email).toBe('contact@example.com');
    });

    it('should include URL if provided', () => {
      const metadata: AgentMetadata = {
        name: 'Test Agent',
        url: 'https://example.com/agent',
      };

      const description = manager.createDescription(metadata);

      expect(description.url).toBe('https://example.com/agent');
    });

    it('should set created timestamp', () => {
      const metadata: AgentMetadata = {
        name: 'Test Agent',
      };

      const description = manager.createDescription(metadata);

      expect(description.created).toBeDefined();
      expect(new Date(description.created!).getTime()).toBeLessThanOrEqual(
        Date.now()
      );
    });

    it('should use custom protocol version if provided', () => {
      const metadata: AgentMetadata = {
        name: 'Test Agent',
        protocolVersion: '2.0.0',
      };

      const description = manager.createDescription(metadata);

      expect(description.protocolVersion).toBe('2.0.0');
    });

    it('should use default protocol version if not provided', () => {
      const metadata: AgentMetadata = {
        name: 'Test Agent',
      };

      const description = manager.createDescription(metadata);

      expect(description.protocolVersion).toBe('1.0.0');
    });

    it('should set up security definitions with did_wba scheme', () => {
      const metadata: AgentMetadata = {
        name: 'Test Agent',
      };

      const description = manager.createDescription(metadata);

      expect(description.securityDefinitions).toHaveProperty('did_wba');
      expect(description.securityDefinitions.did_wba.scheme).toBe('did_wba');
      expect(description.securityDefinitions.did_wba.type).toBe('http');
      expect(description.security).toBe('did_wba');
    });

    it('should initialize empty Infomations array', () => {
      const metadata: AgentMetadata = {
        name: 'Test Agent',
      };

      const description = manager.createDescription(metadata);

      expect(description.Infomations).toBeDefined();
      expect(Array.isArray(description.Infomations)).toBe(true);
      expect(description.Infomations).toHaveLength(0);
    });

    it('should initialize empty interfaces array', () => {
      const metadata: AgentMetadata = {
        name: 'Test Agent',
      };

      const description = manager.createDescription(metadata);

      expect(description.interfaces).toBeDefined();
      expect(Array.isArray(description.interfaces)).toBe(true);
      expect(description.interfaces).toHaveLength(0);
    });

    it('should throw error if name is empty', () => {
      const metadata: AgentMetadata = {
        name: '',
      };

      expect(() => manager.createDescription(metadata)).toThrow(
        'Agent name is required'
      );
    });

    it('should throw error if name is only whitespace', () => {
      const metadata: AgentMetadata = {
        name: '   ',
      };

      expect(() => manager.createDescription(metadata)).toThrow(
        'Agent name is required'
      );
    });
  });
});

describe('AgentDescriptionManager - Adding Resources', () => {
  let manager: AgentDescriptionManager;

  beforeEach(() => {
    manager = new AgentDescriptionManager();
  });

  describe('addInformation', () => {
    it('should add information resource to description', () => {
      const description = manager.createDescription({
        name: 'Test Agent',
      });

      const info: Information = {
        type: 'documentation',
        description: 'API documentation',
        url: 'https://example.com/docs',
      };

      const updated = manager.addInformation(description, info);

      expect(updated.Infomations).toHaveLength(1);
      expect(updated.Infomations![0]).toEqual(info);
    });

    it('should add multiple information resources', () => {
      const description = manager.createDescription({
        name: 'Test Agent',
      });

      const info1: Information = {
        type: 'documentation',
        description: 'API documentation',
        url: 'https://example.com/docs',
      };

      const info2: Information = {
        type: 'schema',
        description: 'Data schema',
        url: 'https://example.com/schema',
      };

      let updated = manager.addInformation(description, info1);
      updated = manager.addInformation(updated, info2);

      expect(updated.Infomations).toHaveLength(2);
      expect(updated.Infomations![0]).toEqual(info1);
      expect(updated.Infomations![1]).toEqual(info2);
    });

    it('should validate information resource has required fields', () => {
      const description = manager.createDescription({
        name: 'Test Agent',
      });

      const invalidInfo = {
        type: 'documentation',
        description: 'API documentation',
      } as Information;

      expect(() => manager.addInformation(description, invalidInfo)).toThrow(
        'Information resource must have type, description, and url'
      );
    });

    it('should prevent duplicate information URLs', () => {
      const description = manager.createDescription({
        name: 'Test Agent',
      });

      const info: Information = {
        type: 'documentation',
        description: 'API documentation',
        url: 'https://example.com/docs',
      };

      const updated = manager.addInformation(description, info);

      expect(() => manager.addInformation(updated, info)).toThrow(
        'Information resource with URL https://example.com/docs already exists'
      );
    });
  });

  describe('addInterface', () => {
    it('should add interface to description', () => {
      const description = manager.createDescription({
        name: 'Test Agent',
      });

      const iface: Interface = {
        type: 'REST',
        protocol: 'HTTP',
        version: '1.0',
        url: 'https://example.com/api',
      };

      const updated = manager.addInterface(description, iface);

      expect(updated.interfaces).toHaveLength(1);
      expect(updated.interfaces![0]).toEqual(iface);
    });

    it('should add multiple interfaces', () => {
      const description = manager.createDescription({
        name: 'Test Agent',
      });

      const iface1: Interface = {
        type: 'REST',
        protocol: 'HTTP',
        version: '1.0',
        url: 'https://example.com/api',
      };

      const iface2: Interface = {
        type: 'GraphQL',
        protocol: 'HTTP',
        version: '1.0',
        url: 'https://example.com/graphql',
        description: 'GraphQL API',
      };

      let updated = manager.addInterface(description, iface1);
      updated = manager.addInterface(updated, iface2);

      expect(updated.interfaces).toHaveLength(2);
      expect(updated.interfaces![0]).toEqual(iface1);
      expect(updated.interfaces![1]).toEqual(iface2);
    });

    it('should validate interface has required fields', () => {
      const description = manager.createDescription({
        name: 'Test Agent',
      });

      const invalidInterface = {
        type: 'REST',
        protocol: 'HTTP',
        version: '1.0',
      } as Interface;

      expect(() => manager.addInterface(description, invalidInterface)).toThrow(
        'Interface must have type, protocol, version, and url'
      );
    });

    it('should prevent duplicate interface URLs', () => {
      const description = manager.createDescription({
        name: 'Test Agent',
      });

      const iface: Interface = {
        type: 'REST',
        protocol: 'HTTP',
        version: '1.0',
        url: 'https://example.com/api',
      };

      const updated = manager.addInterface(description, iface);

      expect(() => manager.addInterface(updated, iface)).toThrow(
        'Interface with URL https://example.com/api already exists'
      );
    });
  });
});

describe('AgentDescriptionManager - Description Signing', () => {
  let manager: AgentDescriptionManager;

  beforeEach(() => {
    manager = new AgentDescriptionManager();
  });

  describe('signDescription', () => {
    it('should sign agent description and add proof', async () => {
      const { DIDManager } = await import(
        '../../../../src/core/did/did-manager.js'
      );
      const didManager = new DIDManager();

      const identity = await didManager.createDID({
        domain: 'example.com',
      });

      const description = manager.createDescription({
        name: 'Test Agent',
        did: identity.did,
      });

      const challenge = 'test-challenge-123';
      const domain = 'example.com';

      const signed = await manager.signDescription(
        description,
        identity,
        challenge,
        domain
      );

      expect(signed.proof).toBeDefined();
      expect(signed.proof!.type).toBe('Ed25519Signature2020');
      expect(signed.proof!.verificationMethod).toBe(`${identity.did}#auth-key`);
      expect(signed.proof!.proofPurpose).toBe('authentication');
      expect(signed.proof!.challenge).toBe(challenge);
      expect(signed.proof!.domain).toBe(domain);
      expect(signed.proof!.created).toBeDefined();
      expect(signed.proof!.proofValue).toBeDefined();
    });

    it('should use JCS canonicalization before signing', async () => {
      const { DIDManager } = await import(
        '../../../../src/core/did/did-manager.js'
      );
      const didManager = new DIDManager();

      const identity = await didManager.createDID({
        domain: 'example.com',
      });

      const description = manager.createDescription({
        name: 'Test Agent',
        did: identity.did,
      });

      const challenge = 'test-challenge';
      const domain = 'example.com';

      const signed = await manager.signDescription(
        description,
        identity,
        challenge,
        domain
      );

      // Verify that proof exists and has a value
      expect(signed.proof).toBeDefined();
      expect(signed.proof!.proofValue).toBeDefined();
      expect(signed.proof!.proofValue.length).toBeGreaterThan(0);
    });

    it('should verify signed description', async () => {
      const { DIDManager } = await import(
        '../../../../src/core/did/did-manager.js'
      );
      const didManager = new DIDManager();

      const identity = await didManager.createDID({
        domain: 'example.com',
      });

      const description = manager.createDescription({
        name: 'Test Agent',
        did: identity.did,
      });

      const challenge = 'test-challenge';
      const domain = 'example.com';

      const signed = await manager.signDescription(
        description,
        identity,
        challenge,
        domain
      );

      const isValid = await manager.verifyDescription(
        signed,
        didManager,
        identity.document
      );

      expect(isValid).toBe(true);
    });

    it('should fail verification with tampered description', async () => {
      const { DIDManager } = await import(
        '../../../../src/core/did/did-manager.js'
      );
      const didManager = new DIDManager();

      const identity = await didManager.createDID({
        domain: 'example.com',
      });

      const description = manager.createDescription({
        name: 'Test Agent',
        did: identity.did,
      });

      const challenge = 'test-challenge';
      const domain = 'example.com';

      const signed = await manager.signDescription(
        description,
        identity,
        challenge,
        domain
      );

      // Tamper with the description
      const tampered = {
        ...signed,
        name: 'Tampered Agent',
      };

      const isValid = await manager.verifyDescription(
        tampered,
        didManager,
        identity.document
      );

      expect(isValid).toBe(false);
    });

    it('should throw error if description has no DID', async () => {
      const { DIDManager } = await import(
        '../../../../src/core/did/did-manager.js'
      );
      const didManager = new DIDManager();

      const identity = await didManager.createDID({
        domain: 'example.com',
      });

      const description = manager.createDescription({
        name: 'Test Agent',
      });

      const challenge = 'test-challenge';
      const domain = 'example.com';

      await expect(
        manager.signDescription(description, identity, challenge, domain)
      ).rejects.toThrow('Agent description must have a DID to be signed');
    });
  });
});

describe('AgentDescriptionManager - Description Fetching', () => {
  let manager: AgentDescriptionManager;

  beforeEach(() => {
    manager = new AgentDescriptionManager();
  });

  describe('fetchDescription', () => {
    it('should fetch and parse agent description from URL', async () => {
      const mockDescription = {
        protocolType: 'ANP',
        protocolVersion: '1.0.0',
        type: 'AgentDescription',
        name: 'Remote Agent',
        did: 'did:wba:example.com',
        securityDefinitions: {
          did_wba: {
            scheme: 'did_wba',
            type: 'http',
          },
        },
        security: 'did_wba',
        Infomations: [],
        interfaces: [],
      };

      // Mock fetch
      global.fetch = async (url: string) => {
        return {
          ok: true,
          status: 200,
          json: async () => mockDescription,
        } as Response;
      };

      const description = await manager.fetchDescription(
        'https://example.com/agent-description'
      );

      expect(description).toEqual(mockDescription);
    });

    it('should throw error on HTTP error', async () => {
      // Mock fetch with error
      global.fetch = async (url: string) => {
        return {
          ok: false,
          status: 404,
          statusText: 'Not Found',
        } as Response;
      };

      await expect(
        manager.fetchDescription('https://example.com/agent-description')
      ).rejects.toThrow('Failed to fetch agent description');
    });

    it('should throw error on invalid JSON', async () => {
      // Mock fetch with invalid JSON
      global.fetch = async (url: string) => {
        return {
          ok: true,
          status: 200,
          json: async () => {
            throw new Error('Invalid JSON');
          },
        } as Response;
      };

      await expect(
        manager.fetchDescription('https://example.com/agent-description')
      ).rejects.toThrow('Failed to parse agent description');
    });

    it('should validate fetched description has required fields', async () => {
      const invalidDescription = {
        protocolType: 'ANP',
        // Missing required fields
      };

      // Mock fetch
      global.fetch = async (url: string) => {
        return {
          ok: true,
          status: 200,
          json: async () => invalidDescription,
        } as Response;
      };

      await expect(
        manager.fetchDescription('https://example.com/agent-description')
      ).rejects.toThrow('Invalid agent description');
    });
  });
});

describe('AgentDescriptionManager - Description Verification', () => {
  let manager: AgentDescriptionManager;

  beforeEach(() => {
    manager = new AgentDescriptionManager();
  });

  describe('verifyDescription', () => {
    it('should return false if description has no proof', async () => {
      const { DIDManager } = await import(
        '../../../../src/core/did/did-manager.js'
      );
      const didManager = new DIDManager();

      const description = manager.createDescription({
        name: 'Test Agent',
        did: 'did:wba:example.com',
      });

      const isValid = await manager.verifyDescription(description, didManager);

      expect(isValid).toBe(false);
    });

    it('should return false if description has no DID', async () => {
      const { DIDManager } = await import(
        '../../../../src/core/did/did-manager.js'
      );
      const didManager = new DIDManager();

      const description = manager.createDescription({
        name: 'Test Agent',
      });

      // Add a fake proof
      const descriptionWithProof = {
        ...description,
        proof: {
          type: 'Ed25519Signature2020',
          created: new Date().toISOString(),
          verificationMethod: 'did:wba:example.com#auth-key',
          proofPurpose: 'authentication',
          challenge: 'test',
          domain: 'example.com',
          proofValue: 'fake-signature',
        },
      };

      const isValid = await manager.verifyDescription(
        descriptionWithProof,
        didManager
      );

      expect(isValid).toBe(false);
    });

    it('should validate domain in proof', async () => {
      const { DIDManager } = await import(
        '../../../../src/core/did/did-manager.js'
      );
      const didManager = new DIDManager();

      const identity = await didManager.createDID({
        domain: 'example.com',
      });

      const description = manager.createDescription({
        name: 'Test Agent',
        did: identity.did,
      });

      const challenge = 'test-challenge';
      const domain = 'example.com';

      const signed = await manager.signDescription(
        description,
        identity,
        challenge,
        domain
      );

      // Verify with correct domain
      const isValid = await manager.verifyDescriptionWithDomain(
        signed,
        didManager,
        domain,
        identity.document
      );

      expect(isValid).toBe(true);

      // Verify with wrong domain
      const isInvalid = await manager.verifyDescriptionWithDomain(
        signed,
        didManager,
        'wrong-domain.com',
        identity.document
      );

      expect(isInvalid).toBe(false);
    });

    it('should validate challenge in proof', async () => {
      const { DIDManager } = await import(
        '../../../../src/core/did/did-manager.js'
      );
      const didManager = new DIDManager();

      const identity = await didManager.createDID({
        domain: 'example.com',
      });

      const description = manager.createDescription({
        name: 'Test Agent',
        did: identity.did,
      });

      const challenge = 'test-challenge';
      const domain = 'example.com';

      const signed = await manager.signDescription(
        description,
        identity,
        challenge,
        domain
      );

      // Verify with correct challenge
      const isValid = await manager.verifyDescriptionWithChallenge(
        signed,
        didManager,
        challenge,
        identity.document
      );

      expect(isValid).toBe(true);

      // Verify with wrong challenge
      const isInvalid = await manager.verifyDescriptionWithChallenge(
        signed,
        didManager,
        'wrong-challenge',
        identity.document
      );

      expect(isInvalid).toBe(false);
    });
  });
});
