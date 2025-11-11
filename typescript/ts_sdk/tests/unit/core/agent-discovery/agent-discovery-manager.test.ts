/**
 * Unit tests for Agent Discovery Manager
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { AgentDiscoveryManager } from '../../../../src/core/agent-discovery/agent-discovery-manager.js';
import { HTTPClient } from '../../../../src/transport/http-client.js';
import type {
  DiscoveryDocument,
  AgentDescriptionItem,
} from '../../../../src/types/index.js';
import { NetworkError } from '../../../../src/errors/index.js';

describe('AgentDiscoveryManager - Active Discovery', () => {
  let discoveryManager: AgentDiscoveryManager;
  let mockHttpClient: HTTPClient;

  beforeEach(() => {
    // Create mock HTTP client
    mockHttpClient = {
      get: vi.fn(),
      post: vi.fn(),
      request: vi.fn(),
    } as any;

    discoveryManager = new AgentDiscoveryManager(mockHttpClient);
  });

  describe('discoverAgents', () => {
    it('should construct correct .well-known URL from domain', async () => {
      const domain = 'example.com';
      const expectedUrl = 'https://example.com/.well-known/agent-descriptions';

      const mockDocument: DiscoveryDocument = {
        '@context': { ad: 'https://anp.org/ad#' },
        '@type': 'CollectionPage',
        url: expectedUrl,
        items: [],
      };

      vi.mocked(mockHttpClient.get).mockResolvedValue({
        ok: true,
        json: async () => mockDocument,
      } as Response);

      await discoveryManager.discoverAgents(domain);

      expect(mockHttpClient.get).toHaveBeenCalledWith(expectedUrl, undefined);
    });

    it('should parse discovery document and return agent items', async () => {
      const domain = 'example.com';
      const mockItems: AgentDescriptionItem[] = [
        {
          '@type': 'ad:AgentDescription',
          name: 'Agent 1',
          '@id': 'https://example.com/agents/agent1',
        },
        {
          '@type': 'ad:AgentDescription',
          name: 'Agent 2',
          '@id': 'https://example.com/agents/agent2',
        },
      ];

      const mockDocument: DiscoveryDocument = {
        '@context': { ad: 'https://anp.org/ad#' },
        '@type': 'CollectionPage',
        url: 'https://example.com/.well-known/agent-descriptions',
        items: mockItems,
      };

      vi.mocked(mockHttpClient.get).mockResolvedValue({
        ok: true,
        json: async () => mockDocument,
      } as Response);

      const result = await discoveryManager.discoverAgents(domain);

      expect(result).toEqual(mockItems);
      expect(result).toHaveLength(2);
      expect(result[0].name).toBe('Agent 1');
      expect(result[1].name).toBe('Agent 2');
    });

    it('should handle pagination by recursively fetching all pages', async () => {
      const domain = 'example.com';

      // First page
      const page1Items: AgentDescriptionItem[] = [
        {
          '@type': 'ad:AgentDescription',
          name: 'Agent 1',
          '@id': 'https://example.com/agents/agent1',
        },
      ];

      const page1: DiscoveryDocument = {
        '@context': { ad: 'https://anp.org/ad#' },
        '@type': 'CollectionPage',
        url: 'https://example.com/.well-known/agent-descriptions',
        items: page1Items,
        next: 'https://example.com/.well-known/agent-descriptions?page=2',
      };

      // Second page
      const page2Items: AgentDescriptionItem[] = [
        {
          '@type': 'ad:AgentDescription',
          name: 'Agent 2',
          '@id': 'https://example.com/agents/agent2',
        },
      ];

      const page2: DiscoveryDocument = {
        '@context': { ad: 'https://anp.org/ad#' },
        '@type': 'CollectionPage',
        url: 'https://example.com/.well-known/agent-descriptions?page=2',
        items: page2Items,
        next: 'https://example.com/.well-known/agent-descriptions?page=3',
      };

      // Third page (last)
      const page3Items: AgentDescriptionItem[] = [
        {
          '@type': 'ad:AgentDescription',
          name: 'Agent 3',
          '@id': 'https://example.com/agents/agent3',
        },
      ];

      const page3: DiscoveryDocument = {
        '@context': { ad: 'https://anp.org/ad#' },
        '@type': 'CollectionPage',
        url: 'https://example.com/.well-known/agent-descriptions?page=3',
        items: page3Items,
        // No next property - last page
      };

      vi.mocked(mockHttpClient.get)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => page1,
        } as Response)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => page2,
        } as Response)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => page3,
        } as Response);

      const result = await discoveryManager.discoverAgents(domain);

      expect(result).toHaveLength(3);
      expect(result[0].name).toBe('Agent 1');
      expect(result[1].name).toBe('Agent 2');
      expect(result[2].name).toBe('Agent 3');
      expect(mockHttpClient.get).toHaveBeenCalledTimes(3);
    });

    it('should handle empty discovery document', async () => {
      const domain = 'example.com';

      const mockDocument: DiscoveryDocument = {
        '@context': { ad: 'https://anp.org/ad#' },
        '@type': 'CollectionPage',
        url: 'https://example.com/.well-known/agent-descriptions',
        items: [],
      };

      vi.mocked(mockHttpClient.get).mockResolvedValue({
        ok: true,
        json: async () => mockDocument,
      } as Response);

      const result = await discoveryManager.discoverAgents(domain);

      expect(result).toEqual([]);
      expect(result).toHaveLength(0);
    });

    it('should handle 404 error gracefully', async () => {
      const domain = 'example.com';

      vi.mocked(mockHttpClient.get).mockRejectedValue(
        new NetworkError('HTTP 404: Not Found', 404)
      );

      await expect(discoveryManager.discoverAgents(domain)).rejects.toThrow(
        NetworkError
      );
      await expect(discoveryManager.discoverAgents(domain)).rejects.toThrow(
        'HTTP 404: Not Found'
      );
    });

    it('should handle network errors gracefully', async () => {
      const domain = 'example.com';

      vi.mocked(mockHttpClient.get).mockRejectedValue(
        new NetworkError('Network request failed')
      );

      await expect(discoveryManager.discoverAgents(domain)).rejects.toThrow(
        NetworkError
      );
    });

    it('should handle invalid JSON response', async () => {
      const domain = 'example.com';

      vi.mocked(mockHttpClient.get).mockResolvedValue({
        ok: true,
        json: async () => {
          throw new Error('Invalid JSON');
        },
      } as unknown as Response);

      await expect(discoveryManager.discoverAgents(domain)).rejects.toThrow();
    });

    it('should handle malformed discovery document', async () => {
      const domain = 'example.com';

      // Missing required fields
      const malformedDocument = {
        '@context': { ad: 'https://anp.org/ad#' },
        // Missing @type, url, items
      };

      vi.mocked(mockHttpClient.get).mockResolvedValue({
        ok: true,
        json: async () => malformedDocument,
      } as Response);

      await expect(discoveryManager.discoverAgents(domain)).rejects.toThrow();
    });
  });

  describe('registerWithSearchService', () => {
    it('should construct registration request with agent description URL', async () => {
      const searchServiceUrl = 'https://search.example.com/register';
      const agentDescriptionUrl = 'https://agent.example.com/description';

      const mockIdentity = {
        did: 'did:wba:example.com:agent1',
        document: {} as any,
        privateKeys: new Map(),
      };

      vi.mocked(mockHttpClient.post).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      } as Response);

      await discoveryManager.registerWithSearchService(
        searchServiceUrl,
        agentDescriptionUrl,
        mockIdentity
      );

      expect(mockHttpClient.post).toHaveBeenCalledWith(
        searchServiceUrl,
        { agentDescriptionUrl },
        mockIdentity
      );
    });

    it('should use authentication when registering', async () => {
      const searchServiceUrl = 'https://search.example.com/register';
      const agentDescriptionUrl = 'https://agent.example.com/description';

      const mockIdentity = {
        did: 'did:wba:example.com:agent1',
        document: {} as any,
        privateKeys: new Map(),
      };

      vi.mocked(mockHttpClient.post).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      } as Response);

      await discoveryManager.registerWithSearchService(
        searchServiceUrl,
        agentDescriptionUrl,
        mockIdentity
      );

      // Verify that identity was passed for authentication
      expect(mockHttpClient.post).toHaveBeenCalledWith(
        searchServiceUrl,
        expect.any(Object),
        mockIdentity
      );
    });

    it('should handle registration success', async () => {
      const searchServiceUrl = 'https://search.example.com/register';
      const agentDescriptionUrl = 'https://agent.example.com/description';

      const mockIdentity = {
        did: 'did:wba:example.com:agent1',
        document: {} as any,
        privateKeys: new Map(),
      };

      vi.mocked(mockHttpClient.post).mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ success: true }),
      } as Response);

      await expect(
        discoveryManager.registerWithSearchService(
          searchServiceUrl,
          agentDescriptionUrl,
          mockIdentity
        )
      ).resolves.not.toThrow();
    });

    it('should handle registration failure with 4xx error', async () => {
      const searchServiceUrl = 'https://search.example.com/register';
      const agentDescriptionUrl = 'https://agent.example.com/description';

      const mockIdentity = {
        did: 'did:wba:example.com:agent1',
        document: {} as any,
        privateKeys: new Map(),
      };

      vi.mocked(mockHttpClient.post).mockRejectedValue(
        new NetworkError('HTTP 400: Bad Request', 400)
      );

      await expect(
        discoveryManager.registerWithSearchService(
          searchServiceUrl,
          agentDescriptionUrl,
          mockIdentity
        )
      ).rejects.toThrow(NetworkError);
      await expect(
        discoveryManager.registerWithSearchService(
          searchServiceUrl,
          agentDescriptionUrl,
          mockIdentity
        )
      ).rejects.toThrow('HTTP 400: Bad Request');
    });

    it('should handle network errors during registration', async () => {
      const searchServiceUrl = 'https://search.example.com/register';
      const agentDescriptionUrl = 'https://agent.example.com/description';

      const mockIdentity = {
        did: 'did:wba:example.com:agent1',
        document: {} as any,
        privateKeys: new Map(),
      };

      vi.mocked(mockHttpClient.post).mockRejectedValue(
        new NetworkError('Network request failed')
      );

      await expect(
        discoveryManager.registerWithSearchService(
          searchServiceUrl,
          agentDescriptionUrl,
          mockIdentity
        )
      ).rejects.toThrow(NetworkError);
    });

    it('should handle authentication errors during registration', async () => {
      const searchServiceUrl = 'https://search.example.com/register';
      const agentDescriptionUrl = 'https://agent.example.com/description';

      const mockIdentity = {
        did: 'did:wba:example.com:agent1',
        document: {} as any,
        privateKeys: new Map(),
      };

      vi.mocked(mockHttpClient.post).mockRejectedValue(
        new NetworkError('HTTP 401: Unauthorized', 401)
      );

      await expect(
        discoveryManager.registerWithSearchService(
          searchServiceUrl,
          agentDescriptionUrl,
          mockIdentity
        )
      ).rejects.toThrow(NetworkError);
      await expect(
        discoveryManager.registerWithSearchService(
          searchServiceUrl,
          agentDescriptionUrl,
          mockIdentity
        )
      ).rejects.toThrow('HTTP 401: Unauthorized');
    });
  });

  describe('searchAgents', () => {
    it('should construct search query with keywords', async () => {
      const searchServiceUrl = 'https://search.example.com/search';
      const query = {
        keywords: ['weather', 'forecast'],
      };

      const mockResults: AgentDescriptionItem[] = [
        {
          '@type': 'ad:AgentDescription',
          name: 'Weather Agent',
          '@id': 'https://weather.example.com/description',
        },
      ];

      vi.mocked(mockHttpClient.post).mockResolvedValue({
        ok: true,
        json: async () => ({ items: mockResults }),
      } as Response);

      const results = await discoveryManager.searchAgents(
        searchServiceUrl,
        query
      );

      expect(mockHttpClient.post).toHaveBeenCalledWith(
        searchServiceUrl,
        query,
        undefined
      );
      expect(results).toEqual(mockResults);
    });

    it('should construct search query with capabilities', async () => {
      const searchServiceUrl = 'https://search.example.com/search';
      const query = {
        capabilities: ['weather-api', 'forecast'],
      };

      const mockResults: AgentDescriptionItem[] = [
        {
          '@type': 'ad:AgentDescription',
          name: 'Weather Agent',
          '@id': 'https://weather.example.com/description',
        },
      ];

      vi.mocked(mockHttpClient.post).mockResolvedValue({
        ok: true,
        json: async () => ({ items: mockResults }),
      } as Response);

      const results = await discoveryManager.searchAgents(
        searchServiceUrl,
        query
      );

      expect(mockHttpClient.post).toHaveBeenCalledWith(
        searchServiceUrl,
        query,
        undefined
      );
      expect(results).toEqual(mockResults);
    });

    it('should construct search query with limit and offset', async () => {
      const searchServiceUrl = 'https://search.example.com/search';
      const query = {
        keywords: ['weather'],
        limit: 10,
        offset: 20,
      };

      const mockResults: AgentDescriptionItem[] = [];

      vi.mocked(mockHttpClient.post).mockResolvedValue({
        ok: true,
        json: async () => ({ items: mockResults }),
      } as Response);

      await discoveryManager.searchAgents(searchServiceUrl, query);

      expect(mockHttpClient.post).toHaveBeenCalledWith(
        searchServiceUrl,
        query,
        undefined
      );
    });

    it('should parse search results correctly', async () => {
      const searchServiceUrl = 'https://search.example.com/search';
      const query = {
        keywords: ['agent'],
      };

      const mockResults: AgentDescriptionItem[] = [
        {
          '@type': 'ad:AgentDescription',
          name: 'Agent 1',
          '@id': 'https://agent1.example.com/description',
        },
        {
          '@type': 'ad:AgentDescription',
          name: 'Agent 2',
          '@id': 'https://agent2.example.com/description',
        },
      ];

      vi.mocked(mockHttpClient.post).mockResolvedValue({
        ok: true,
        json: async () => ({ items: mockResults, total: 2 }),
      } as Response);

      const results = await discoveryManager.searchAgents(
        searchServiceUrl,
        query
      );

      expect(results).toEqual(mockResults);
      expect(results).toHaveLength(2);
      expect(results[0].name).toBe('Agent 1');
      expect(results[1].name).toBe('Agent 2');
    });

    it('should handle empty search results', async () => {
      const searchServiceUrl = 'https://search.example.com/search';
      const query = {
        keywords: ['nonexistent'],
      };

      vi.mocked(mockHttpClient.post).mockResolvedValue({
        ok: true,
        json: async () => ({ items: [] }),
      } as Response);

      const results = await discoveryManager.searchAgents(
        searchServiceUrl,
        query
      );

      expect(results).toEqual([]);
      expect(results).toHaveLength(0);
    });

    it('should use authentication when provided', async () => {
      const searchServiceUrl = 'https://search.example.com/search';
      const query = {
        keywords: ['weather'],
      };

      const mockIdentity = {
        did: 'did:wba:example.com:agent1',
        document: {} as any,
        privateKeys: new Map(),
      };

      const mockResults: AgentDescriptionItem[] = [];

      vi.mocked(mockHttpClient.post).mockResolvedValue({
        ok: true,
        json: async () => ({ items: mockResults }),
      } as Response);

      await discoveryManager.searchAgents(
        searchServiceUrl,
        query,
        mockIdentity
      );

      expect(mockHttpClient.post).toHaveBeenCalledWith(
        searchServiceUrl,
        query,
        mockIdentity
      );
    });

    it('should handle search errors gracefully', async () => {
      const searchServiceUrl = 'https://search.example.com/search';
      const query = {
        keywords: ['weather'],
      };

      vi.mocked(mockHttpClient.post).mockRejectedValue(
        new NetworkError('HTTP 500: Internal Server Error', 500)
      );

      await expect(
        discoveryManager.searchAgents(searchServiceUrl, query)
      ).rejects.toThrow(NetworkError);
    });

    it('should handle invalid search response', async () => {
      const searchServiceUrl = 'https://search.example.com/search';
      const query = {
        keywords: ['weather'],
      };

      vi.mocked(mockHttpClient.post).mockResolvedValue({
        ok: true,
        json: async () => {
          throw new Error('Invalid JSON');
        },
      } as unknown as Response);

      await expect(
        discoveryManager.searchAgents(searchServiceUrl, query)
      ).rejects.toThrow();
    });

    it('should handle malformed search response', async () => {
      const searchServiceUrl = 'https://search.example.com/search';
      const query = {
        keywords: ['weather'],
      };

      // Missing items array
      vi.mocked(mockHttpClient.post).mockResolvedValue({
        ok: true,
        json: async () => ({ total: 0 }),
      } as Response);

      await expect(
        discoveryManager.searchAgents(searchServiceUrl, query)
      ).rejects.toThrow();
    });
  });
});
