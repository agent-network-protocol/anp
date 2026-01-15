/**
 * Agent Discovery Manager
 *
 * Manages agent discovery through active and passive mechanisms.
 */

import { HTTPClient } from '../../transport/http-client.js';
import { NetworkError } from '../../errors/index.js';
import type {
  DiscoveryDocument,
  AgentDescriptionItem,
  SearchQuery,
  DIDIdentity,
} from '../../types/index.js';

/**
 * Agent Discovery Manager class
 */
export class AgentDiscoveryManager {
  private readonly httpClient: HTTPClient;

  constructor(httpClient: HTTPClient) {
    this.httpClient = httpClient;
  }

  /**
   * Discover agents from a domain using active discovery
   *
   * Fetches the agent discovery document from the .well-known/agent-descriptions endpoint
   * and recursively fetches all pages if pagination is present.
   *
   * @param domain - The domain to discover agents from
   * @param identity - Optional DID identity for authentication
   * @returns Array of agent description items
   */
  async discoverAgents(
    domain: string,
    identity?: DIDIdentity
  ): Promise<AgentDescriptionItem[]> {
    // Construct .well-known URL
    const url = this.constructWellKnownUrl(domain);

    // Fetch all pages recursively
    return this.fetchAllPages(url, identity);
  }

  /**
   * Register with a search service using passive discovery
   *
   * @param searchServiceUrl - The URL of the search service
   * @param agentDescriptionUrl - The URL of the agent description to register
   * @param identity - DID identity for authentication
   */
  async registerWithSearchService(
    searchServiceUrl: string,
    agentDescriptionUrl: string,
    identity: DIDIdentity
  ): Promise<void> {
    // Construct registration request
    const registrationRequest = {
      agentDescriptionUrl,
    };

    // Send POST request with authentication
    await this.httpClient.post(
      searchServiceUrl,
      registrationRequest,
      identity
    );
  }

  /**
   * Search for agents using a search service
   *
   * @param searchServiceUrl - The URL of the search service
   * @param query - Search query parameters
   * @param identity - Optional DID identity for authentication
   * @returns Array of matching agent description items
   */
  async searchAgents(
    searchServiceUrl: string,
    query: SearchQuery,
    identity?: DIDIdentity
  ): Promise<AgentDescriptionItem[]> {
    // Send POST request with search query
    const response = await this.httpClient.post(
      searchServiceUrl,
      query,
      identity
    );

    // Parse search results
    const results = await this.parseSearchResults(response);

    return results;
  }

  /**
   * Construct .well-known URL from domain
   *
   * @param domain - The domain
   * @returns The .well-known URL
   */
  private constructWellKnownUrl(domain: string): string {
    // Remove protocol if present
    const cleanDomain = domain.replace(/^https?:\/\//, '');

    // Use http:// for localhost, https:// for everything else
    const domainWithoutPort = cleanDomain.split(':')[0];
    const protocol = domainWithoutPort === 'localhost' || domainWithoutPort === '127.0.0.1' ? 'http://' : 'https://';

    // Construct URL
    return `${protocol}${cleanDomain}/.well-known/agent-descriptions`;
  }

  /**
   * Fetch all pages recursively
   *
   * @param url - The URL to fetch
   * @param identity - Optional DID identity for authentication
   * @returns Array of all agent description items from all pages
   */
  private async fetchAllPages(
    url: string,
    identity?: DIDIdentity
  ): Promise<AgentDescriptionItem[]> {
    const allItems: AgentDescriptionItem[] = [];

    let currentUrl: string | undefined = url;

    while (currentUrl) {
      // Fetch the current page
      const response = await this.httpClient.get(currentUrl, identity);

      // Parse JSON response
      const document = await this.parseDiscoveryDocument(response);

      // Validate document structure
      this.validateDiscoveryDocument(document);

      // Add items from this page
      allItems.push(...document.items);

      // Move to next page if it exists
      currentUrl = document.next;
    }

    return allItems;
  }

  /**
   * Parse discovery document from response
   *
   * @param response - The HTTP response
   * @returns The parsed discovery document
   */
  private async parseDiscoveryDocument(
    response: Response
  ): Promise<DiscoveryDocument> {
    try {
      const document = await response.json();
      return document as DiscoveryDocument;
    } catch (error) {
      throw new NetworkError(
        'Failed to parse discovery document',
        undefined,
        error as Error
      );
    }
  }

  /**
   * Validate discovery document structure
   *
   * @param document - The discovery document to validate
   */
  private validateDiscoveryDocument(document: DiscoveryDocument): void {
    if (!document['@type'] || document['@type'] !== 'CollectionPage') {
      throw new NetworkError(
        'Invalid discovery document: missing or invalid @type'
      );
    }

    if (!document.url) {
      throw new NetworkError('Invalid discovery document: missing url');
    }

    if (!Array.isArray(document.items)) {
      throw new NetworkError('Invalid discovery document: missing or invalid items array');
    }
  }

  /**
   * Parse search results from response
   *
   * @param response - The HTTP response
   * @returns Array of agent description items
   */
  private async parseSearchResults(
    response: Response
  ): Promise<AgentDescriptionItem[]> {
    try {
      const data = await response.json();

      // Handle both SearchResult format and direct array format for backwards compatibility
      if (Array.isArray(data)) {
        return data as AgentDescriptionItem[];
      }

      // Validate that items array exists in SearchResult format
      if (!Array.isArray(data.items)) {
        throw new NetworkError(
          'Invalid search results: missing or invalid items array'
        );
      }

      return data.items as AgentDescriptionItem[];
    } catch (error) {
      if (error instanceof NetworkError) {
        throw error;
      }
      throw new NetworkError(
        'Failed to parse search results',
        undefined,
        error as Error
      );
    }
  }
}
