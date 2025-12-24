/**
 * Type definitions for Agent Discovery Service Protocol (ADSP)
 */

/**
 * Agent description item in discovery document
 */
export interface AgentDescriptionItem {
  '@type': 'ad:AgentDescription';
  name: string;
  '@id': string; // URL to agent description
}

/**
 * Discovery document (CollectionPage)
 */
export interface DiscoveryDocument {
  '@context': Record<string, string>;
  '@type': 'CollectionPage';
  url: string;
  items: AgentDescriptionItem[];
  next?: string; // URL to next page
}

/**
 * Search query for agent discovery
 */
export interface SearchQuery {
  keywords?: string[];
  capabilities?: string[];
  limit?: number;
  offset?: number;
}

/**
 * Search result from discovery service
 */
export interface SearchResult {
  items: AgentDescriptionItem[];
  total?: number;
  hasMore?: boolean;
}
