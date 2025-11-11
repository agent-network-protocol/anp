/**
 * Integration test for agent discovery flow
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { DIDManager } from '../../src/core/did/did-manager.js';
import { AuthenticationManager } from '../../src/core/auth/authentication-manager.js';
import { AgentDescriptionManager } from '../../src/core/agent-description/agent-description-manager.js';
import { AgentDiscoveryManager } from '../../src/core/agent-discovery/agent-discovery-manager.js';
import { HTTPClient } from '../../src/transport/http-client.js';
import type {
  DIDIdentity,
  AgentDescription,
  DiscoveryDocument,
  AgentDescriptionItem,
} from '../../src/types/index.js';

describe('Agent Discovery Integration', () => {
  let didManager: DIDManager;
  let authManager: AuthenticationManager;
  let descriptionManager: AgentDescriptionManager;
  let httpClient: HTTPClient;
  let discoveryManager: AgentDiscoveryManager;
  let agentIdentity: DIDIdentity;
  let agentDescription: AgentDescription;

  beforeEach(async () => {
    // Initialize managers
    didManager = new DIDManager();
    authManager = new AuthenticationManager(didManager, {
      maxTokenAge: 3600000,
      nonceLength: 32,
      clockSkewTolerance: 60,
    });
    descriptionManager = new AgentDescriptionManager();
    httpClient = new HTTPClient(authManager, {
      timeout: 10000,
      maxRetries: 3,
      retryDelay: 1000,
    });
    discoveryManager = new AgentDiscoveryManager(httpClient);

    // Create agent identity
    agentIdentity = await didManager.createDID({
      domain: 'myagent.example.com',
      path: 'agent1',
    });

    // Create agent description
    agentDescription = descriptionManager.createDescription({
      name: 'My Test Agent',
      description: 'A test agent for integration testing',
      did: agentIdentity.did,
      protocolVersion: '1.0.0',
      owner: {
        name: 'Test Organization',
        url: 'https://example.com',
      },
    });

    // Add information resources
    agentDescription = descriptionManager.addInformation(agentDescription, {
      type: 'documentation',
      description: 'Agent API documentation',
      url: 'https://myagent.example.com/docs',
    });

    // Add interfaces
    agentDescription = descriptionManager.addInterface(agentDescription, {
      type: 'api',
      protocol: 'REST',
      version: '1.0',
      url: 'https://myagent.example.com/api/v1',
    });

    // Sign the description
    agentDescription = await descriptionManager.signDescription(
      agentDescription,
      agentIdentity,
      'test-challenge',
      'myagent.example.com'
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should complete full agent discovery flow', async () => {
    // Step 1: Mock publishing agent description to a server
    const publishUrl = 'https://myagent.example.com/agent-description.json';

    // Mock fetch for publishing (in real scenario, this would be an actual HTTP POST)
    const mockPublishResponse = new Response(
      JSON.stringify({ success: true, url: publishUrl }),
      {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }
    );

    // Step 2: Mock discovery document from domain
    const mockDiscoveryDoc: DiscoveryDocument = {
      '@context': {
        ad: 'https://anp.org/agent-description/',
      },
      '@type': 'CollectionPage',
      url: 'https://example.com/.well-known/agent-descriptions',
      items: [
        {
          '@type': 'ad:AgentDescription',
          name: 'My Test Agent',
          '@id': publishUrl,
        },
        {
          '@type': 'ad:AgentDescription',
          name: 'Another Agent',
          '@id': 'https://another.example.com/agent-description.json',
        },
      ],
    };

    // Mock fetch for discovery
    global.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(mockDiscoveryDoc), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );

    // Step 3: Discover agents from domain
    const discoveredAgents = await discoveryManager.discoverAgents(
      'example.com'
    );

    expect(discoveredAgents).toHaveLength(2);
    expect(discoveredAgents[0].name).toBe('My Test Agent');
    expect(discoveredAgents[0]['@id']).toBe(publishUrl);
    expect(discoveredAgents[1].name).toBe('Another Agent');

    // Verify correct URL was called
    expect(global.fetch).toHaveBeenCalledWith(
      'https://example.com/.well-known/agent-descriptions',
      expect.any(Object)
    );
  });

  it('should handle paginated discovery results', async () => {
    // Mock first page
    const page1: DiscoveryDocument = {
      '@context': { ad: 'https://anp.org/agent-description/' },
      '@type': 'CollectionPage',
      url: 'https://example.com/.well-known/agent-descriptions',
      items: [
        {
          '@type': 'ad:AgentDescription',
          name: 'Agent 1',
          '@id': 'https://example.com/agent1.json',
        },
        {
          '@type': 'ad:AgentDescription',
          name: 'Agent 2',
          '@id': 'https://example.com/agent2.json',
        },
      ],
      next: 'https://example.com/.well-known/agent-descriptions?page=2',
    };

    // Mock second page
    const page2: DiscoveryDocument = {
      '@context': { ad: 'https://anp.org/agent-description/' },
      '@type': 'CollectionPage',
      url: 'https://example.com/.well-known/agent-descriptions?page=2',
      items: [
        {
          '@type': 'ad:AgentDescription',
          name: 'Agent 3',
          '@id': 'https://example.com/agent3.json',
        },
      ],
    };

    // Mock fetch to return different pages
    global.fetch = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(JSON.stringify(page1), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify(page2), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );

    // Discover agents
    const discoveredAgents = await discoveryManager.discoverAgents(
      'example.com'
    );

    // Should have all agents from both pages
    expect(discoveredAgents).toHaveLength(3);
    expect(discoveredAgents[0].name).toBe('Agent 1');
    expect(discoveredAgents[1].name).toBe('Agent 2');
    expect(discoveredAgents[2].name).toBe('Agent 3');

    // Verify both pages were fetched
    expect(global.fetch).toHaveBeenCalledTimes(2);
  });

  it('should register with search service', async () => {
    const searchServiceUrl = 'https://search.example.com/register';
    const agentDescriptionUrl =
      'https://myagent.example.com/agent-description.json';

    // Mock successful registration
    global.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );

    // Register with search service
    await discoveryManager.registerWithSearchService(
      searchServiceUrl,
      agentDescriptionUrl,
      agentIdentity
    );

    // Verify registration request was made
    expect(global.fetch).toHaveBeenCalled();

    // Get the call arguments
    const callArgs = (global.fetch as any).mock.calls[0];
    expect(callArgs[0]).toBe(searchServiceUrl);

    // Verify request includes authentication header
    const requestInit = callArgs[1];
    expect(requestInit.headers.Authorization).toBeDefined();
    expect(requestInit.headers.Authorization).toMatch(/^DIDWba /);
  });

  it('should search for agents', async () => {
    const searchServiceUrl = 'https://search.example.com/search';
    const searchQuery = {
      keywords: ['weather', 'forecast'],
      capabilities: ['temperature', 'precipitation'],
    };

    // Mock search results
    const searchResults = {
      items: [
        {
          '@type': 'ad:AgentDescription',
          name: 'Weather Agent',
          '@id': 'https://weather.example.com/agent-description.json',
        },
        {
          '@type': 'ad:AgentDescription',
          name: 'Climate Agent',
          '@id': 'https://climate.example.com/agent-description.json',
        },
      ],
    };

    global.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(searchResults), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );

    // Search for agents
    const results = await discoveryManager.searchAgents(
      searchServiceUrl,
      searchQuery
    );

    expect(results).toHaveLength(2);
    expect(results[0].name).toBe('Weather Agent');
    expect(results[1].name).toBe('Climate Agent');

    // Verify search request was made
    expect(global.fetch).toHaveBeenCalledWith(
      searchServiceUrl,
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify(searchQuery),
      })
    );
  });

  it('should fetch and verify agent description', async () => {
    const descriptionUrl =
      'https://myagent.example.com/agent-description.json';

    // Mock fetch for agent description
    global.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(agentDescription), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );

    // Fetch the description
    const fetchedDescription =
      await descriptionManager.fetchDescription(descriptionUrl);

    expect(fetchedDescription).toBeDefined();
    expect(fetchedDescription.name).toBe('My Test Agent');
    expect(fetchedDescription.did).toBe(agentIdentity.did);
    expect(fetchedDescription.proof).toBeDefined();

    // Verify the signature
    const isValid = await descriptionManager.verifyDescription(
      fetchedDescription,
      didManager,
      agentIdentity.document
    );

    expect(isValid).toBe(true);
  });

  it('should handle discovery errors gracefully', async () => {
    // Mock 404 response
    global.fetch = vi.fn().mockResolvedValue(
      new Response('Not Found', {
        status: 404,
        statusText: 'Not Found',
      })
    );

    // Discovery should throw error
    await expect(
      discoveryManager.discoverAgents('nonexistent.example.com')
    ).rejects.toThrow();
  });

  it('should validate discovery document structure', async () => {
    // Mock invalid discovery document (missing required fields)
    const invalidDoc = {
      '@context': { ad: 'https://anp.org/agent-description/' },
      // Missing @type
      url: 'https://example.com/.well-known/agent-descriptions',
      items: [],
    };

    global.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(invalidDoc), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );

    // Should throw validation error
    await expect(
      discoveryManager.discoverAgents('example.com')
    ).rejects.toThrow();
  });

  it('should support authenticated discovery', async () => {
    const mockDiscoveryDoc: DiscoveryDocument = {
      '@context': { ad: 'https://anp.org/agent-description/' },
      '@type': 'CollectionPage',
      url: 'https://private.example.com/.well-known/agent-descriptions',
      items: [
        {
          '@type': 'ad:AgentDescription',
          name: 'Private Agent',
          '@id': 'https://private.example.com/agent.json',
        },
      ],
    };

    global.fetch = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(mockDiscoveryDoc), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );

    // Discover with authentication
    const discoveredAgents = await discoveryManager.discoverAgents(
      'private.example.com',
      agentIdentity
    );

    expect(discoveredAgents).toHaveLength(1);
    expect(discoveredAgents[0].name).toBe('Private Agent');

    // Verify authentication header was included
    const callArgs = (global.fetch as any).mock.calls[0];
    const requestInit = callArgs[1];
    expect(requestInit.headers.Authorization).toBeDefined();
  });

  it('should handle complete discovery and verification workflow', async () => {
    // Step 1: Create and sign agent description
    const myDescription = descriptionManager.createDescription({
      name: 'Workflow Test Agent',
      description: 'Testing complete workflow',
      did: agentIdentity.did,
      protocolVersion: '1.0.0',
    });

    const signedDescription = await descriptionManager.signDescription(
      myDescription,
      agentIdentity,
      'workflow-challenge',
      'workflow.example.com'
    );

    // Step 2: Mock discovery that returns this agent
    const discoveryDoc: DiscoveryDocument = {
      '@context': { ad: 'https://anp.org/agent-description/' },
      '@type': 'CollectionPage',
      url: 'https://workflow.example.com/.well-known/agent-descriptions',
      items: [
        {
          '@type': 'ad:AgentDescription',
          name: 'Workflow Test Agent',
          '@id': 'https://workflow.example.com/agent.json',
        },
      ],
    };

    global.fetch = vi
      .fn()
      // First call: discovery
      .mockResolvedValueOnce(
        new Response(JSON.stringify(discoveryDoc), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      )
      // Second call: fetch agent description
      .mockResolvedValueOnce(
        new Response(JSON.stringify(signedDescription), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        })
      );

    // Step 3: Discover agents
    const discovered = await discoveryManager.discoverAgents(
      'workflow.example.com'
    );

    expect(discovered).toHaveLength(1);
    expect(discovered[0].name).toBe('Workflow Test Agent');

    // Step 4: Fetch full description
    const fullDescription = await descriptionManager.fetchDescription(
      discovered[0]['@id']
    );

    expect(fullDescription.name).toBe('Workflow Test Agent');
    expect(fullDescription.proof).toBeDefined();

    // Step 5: Verify signature
    const isValid = await descriptionManager.verifyDescription(
      fullDescription,
      didManager,
      agentIdentity.document
    );

    expect(isValid).toBe(true);

    // Step 6: Verify domain
    const isDomainValid =
      await descriptionManager.verifyDescriptionWithDomain(
        fullDescription,
        didManager,
        'workflow.example.com',
        agentIdentity.document
      );

    expect(isDomainValid).toBe(true);
  });
});
