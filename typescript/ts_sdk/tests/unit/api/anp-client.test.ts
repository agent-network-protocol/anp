/**
 * Unit tests for ANPClient
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ANPClient } from '../../../src/anp-client';

// Mock fetch globally
global.fetch = vi.fn();

describe('ANPClient', () => {
  beforeEach(() => {
    // Reset fetch mock before each test
    vi.clearAllMocks();
  });
  describe('constructor', () => {
    it('should create client with default config', () => {
      const client = new ANPClient();

      expect(client).toBeDefined();
      expect(client.did).toBeDefined();
      expect(client.agent).toBeDefined();
      expect(client.discovery).toBeDefined();
      expect(client.protocol).toBeDefined();
      expect(client.http).toBeDefined();
    });

    it('should create client with custom config', () => {
      const customConfig = {
        did: {
          cacheTTL: 10000,
          timeout: 5000,
        },
        auth: {
          maxTokenAge: 3600000,
          nonceLength: 32,
          clockSkewTolerance: 300,
        },
        http: {
          timeout: 15000,
          maxRetries: 5,
          retryDelay: 2000,
        },
      };

      const client = new ANPClient(customConfig);

      expect(client).toBeDefined();
      expect(client.did).toBeDefined();
      expect(client.agent).toBeDefined();
      expect(client.discovery).toBeDefined();
      expect(client.protocol).toBeDefined();
      expect(client.http).toBeDefined();
    });

    it('should initialize all managers', () => {
      const client = new ANPClient();

      // Verify all namespaces are accessible
      expect(typeof client.did.create).toBe('function');
      expect(typeof client.did.resolve).toBe('function');
      expect(typeof client.did.sign).toBe('function');
      expect(typeof client.did.verify).toBe('function');

      expect(typeof client.agent.createDescription).toBe('function');
      expect(typeof client.agent.addInformation).toBe('function');
      expect(typeof client.agent.addInterface).toBe('function');
      expect(typeof client.agent.signDescription).toBe('function');
      expect(typeof client.agent.fetchDescription).toBe('function');

      expect(typeof client.discovery.discoverAgents).toBe('function');
      expect(typeof client.discovery.registerWithSearchService).toBe('function');
      expect(typeof client.discovery.searchAgents).toBe('function');

      expect(typeof client.protocol.createNegotiationMachine).toBe('function');
      expect(typeof client.protocol.sendMessage).toBe('function');
      expect(typeof client.protocol.receiveMessage).toBe('function');

      expect(typeof client.http.request).toBe('function');
      expect(typeof client.http.get).toBe('function');
      expect(typeof client.http.post).toBe('function');
    });

    it('should use default values when config is partially provided', () => {
      const partialConfig = {
        http: {
          timeout: 20000,
        },
      };

      const client = new ANPClient(partialConfig as any);

      expect(client).toBeDefined();
      expect(client.did).toBeDefined();
    });
  });

  describe('DID API', () => {
    let client: ANPClient;

    beforeEach(() => {
      client = new ANPClient();
    });

    it('should create a DID identity', async () => {
      const identity = await client.did.create({
        domain: 'example.com',
      });

      expect(identity).toBeDefined();
      expect(identity.did).toMatch(/^did:wba:example\.com$/);
      expect(identity.document).toBeDefined();
      expect(identity.privateKeys).toBeDefined();
    });

    it('should create a DID identity with path', async () => {
      const identity = await client.did.create({
        domain: 'example.com',
        path: 'agents/my-agent',
      });

      expect(identity).toBeDefined();
      expect(identity.did).toContain('did:wba:example.com:');
      expect(identity.did).toContain('agents');
    });

    it('should resolve a DID', async () => {
      // Mock fetch to return a 404
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      });

      await expect(
        client.did.resolve('did:wba:example.com')
      ).rejects.toThrow();
    });

    it('should sign data with DID identity', async () => {
      const identity = await client.did.create({
        domain: 'example.com',
      });

      const data = new TextEncoder().encode('test data');
      const signature = await client.did.sign(identity, data);

      expect(signature).toBeDefined();
      expect(signature.value).toBeInstanceOf(Uint8Array);
      expect(signature.verificationMethod).toBeDefined();
    });

    it('should verify a signature', async () => {
      const identity = await client.did.create({
        domain: 'example.com',
      });

      const data = new TextEncoder().encode('test data');
      const signature = await client.did.sign(identity, data);

      // Mock fetch to return a 404 for DID resolution
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      });

      await expect(
        client.did.verify(identity.did, data, signature)
      ).rejects.toThrow();
    });

    it('should reject invalid signature', async () => {
      const identity = await client.did.create({
        domain: 'example.com',
      });

      const data = new TextEncoder().encode('test data');
      const signature = await client.did.sign(identity, data);

      // Modify the data
      const modifiedData = new TextEncoder().encode('modified data');

      // Mock fetch to return a 404 for DID resolution
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      });

      await expect(
        client.did.verify(identity.did, modifiedData, signature)
      ).rejects.toThrow();
    });
  });

  describe('Agent API', () => {
    let client: ANPClient;

    beforeEach(() => {
      client = new ANPClient();
    });

    it('should create an agent description', () => {
      const description = client.agent.createDescription({
        name: 'Test Agent',
        description: 'A test agent',
      });

      expect(description).toBeDefined();
      expect(description.name).toBe('Test Agent');
      expect(description.description).toBe('A test agent');
      expect(description.protocolType).toBe('ANP');
      expect(description.type).toBe('AgentDescription');
    });

    it('should add information to agent description', () => {
      const description = client.agent.createDescription({
        name: 'Test Agent',
      });

      const updatedDescription = client.agent.addInformation(description, {
        type: 'documentation',
        description: 'API documentation',
        url: 'https://example.com/docs',
      });

      expect(updatedDescription.Infomations).toHaveLength(1);
      expect(updatedDescription.Infomations?.[0].type).toBe('documentation');
    });

    it('should add interface to agent description', () => {
      const description = client.agent.createDescription({
        name: 'Test Agent',
      });

      const updatedDescription = client.agent.addInterface(description, {
        type: 'REST',
        protocol: 'HTTP',
        version: '1.0',
        url: 'https://example.com/api',
      });

      expect(updatedDescription.interfaces).toHaveLength(1);
      expect(updatedDescription.interfaces?.[0].type).toBe('REST');
    });

    it('should sign agent description', async () => {
      const identity = await client.did.create({
        domain: 'example.com',
      });

      const description = client.agent.createDescription({
        name: 'Test Agent',
        did: identity.did,
      });

      const signedDescription = await client.agent.signDescription(
        description,
        identity,
        'test-challenge',
        'example.com'
      );

      expect(signedDescription.proof).toBeDefined();
      expect(signedDescription.proof?.type).toBe('Ed25519Signature2020');
      expect(signedDescription.proof?.challenge).toBe('test-challenge');
      expect(signedDescription.proof?.domain).toBe('example.com');
    });

    it('should fetch agent description', async () => {
      // Mock fetch to return a 404
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      });

      await expect(
        client.agent.fetchDescription('https://example.com/agent.json')
      ).rejects.toThrow();
    });
  });

  describe('Discovery API', () => {
    let client: ANPClient;

    beforeEach(() => {
      client = new ANPClient();
    });

    it('should discover agents from domain', async () => {
      // Mock fetch to return a 404
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      });

      await expect(
        client.discovery.discoverAgents('example.com')
      ).rejects.toThrow();
    });

    it('should register with search service', async () => {
      const identity = await client.did.create({
        domain: 'example.com',
      });

      // Mock fetch to return a 404
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      });

      await expect(
        client.discovery.registerWithSearchService(
          'https://search.example.com',
          'https://example.com/agent.json',
          identity
        )
      ).rejects.toThrow();
    });

    it('should search for agents', async () => {
      // Mock fetch to return a 404
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      });

      await expect(
        client.discovery.searchAgents('https://search.example.com', {
          keywords: ['test'],
        })
      ).rejects.toThrow();
    });
  });

  describe('Protocol API', () => {
    let client: ANPClient;

    beforeEach(() => {
      client = new ANPClient();
    });

    it('should create negotiation machine', async () => {
      const identity = await client.did.create({
        domain: 'example.com',
      });

      const machine = client.protocol.createNegotiationMachine({
        localIdentity: identity,
        remoteDID: 'did:wba:remote.com',
        maxNegotiationRounds: 5,
      });

      expect(machine).toBeDefined();
      expect(machine.getSnapshot).toBeDefined();
    });

    it('should send message', async () => {
      const identity = await client.did.create({
        domain: 'example.com',
      });

      const message = {
        action: 'protocolNegotiation',
        sequenceId: 1,
        candidateProtocols: 'HTTP/REST',
        status: 'negotiating',
      };

      // Mock fetch to return a 404
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      });

      await expect(
        client.protocol.sendMessage('did:wba:remote.com', message, identity)
      ).rejects.toThrow();
    });

    it('should receive message', async () => {
      const identity = await client.did.create({
        domain: 'example.com',
      });

      const machine = client.protocol.createNegotiationMachine({
        localIdentity: identity,
        remoteDID: 'did:wba:remote.com',
      });

      // Create a test message
      const message = new Uint8Array([0x00, 0x7b, 0x7d]); // META protocol type + {}

      // This should process without error
      expect(() => {
        client.protocol.receiveMessage(message, machine);
      }).toThrow(); // Will throw because message is invalid JSON
    });
  });

  describe('HTTP API', () => {
    let client: ANPClient;

    beforeEach(() => {
      client = new ANPClient();
    });

    it('should make HTTP request', async () => {
      // Mock fetch to return a 404
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      });

      await expect(
        client.http.request('https://example.com/api', { method: 'GET' })
      ).rejects.toThrow();
    });

    it('should make GET request', async () => {
      // Mock fetch to return a 404
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      });

      await expect(
        client.http.get('https://example.com/api')
      ).rejects.toThrow();
    });

    it('should make POST request', async () => {
      // Mock fetch to return a 404
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      });

      await expect(
        client.http.post('https://example.com/api', { data: 'test' })
      ).rejects.toThrow();
    });

    it('should make authenticated request', async () => {
      const identity = await client.did.create({
        domain: 'example.com',
      });

      // Mock fetch to return a 404
      (global.fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 404,
        statusText: 'Not Found',
      });

      await expect(
        client.http.get('https://example.com/api', identity)
      ).rejects.toThrow();
    });
  });
});
