/**
 * ANP Client - Main entry point for the ANP TypeScript SDK
 */

import { DIDManager, type DIDManagerConfig, type Signature } from './core/did/did-manager.js';
import { AuthenticationManager, type AuthConfig } from './core/auth/authentication-manager.js';
import { AgentDescriptionManager } from './core/agent-description/agent-description-manager.js';
import { AgentDiscoveryManager } from './core/agent-discovery/agent-discovery-manager.js';
import { HTTPClient, type HTTPClientConfig } from './transport/http-client.js';
import {
  createMetaProtocolMachine,
  type MetaProtocolConfig,
  type MetaProtocolActor,
  encodeMetaProtocolMessage,
  processMessage,
} from './protocol/meta-protocol-machine.js';
import type {
  DIDIdentity,
  DIDDocument,
  CreateDIDOptions,
  AgentDescription,
  AgentMetadata,
  Information,
  Interface,
  AgentDescriptionItem,
  SearchQuery,
} from './types/index.js';

/**
 * Configuration for ANP Client
 */
export interface ANPConfig {
  did?: DIDManagerConfig;
  auth?: AuthConfig;
  http?: HTTPClientConfig;
  debug?: boolean;
}

/**
 * Request options for HTTP requests
 */
export interface RequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

/**
 * ANP Client class - Main SDK interface
 */
export class ANPClient {
  private readonly didManager: DIDManager;
  private readonly authManager: AuthenticationManager;
  private readonly agentDescriptionManager: AgentDescriptionManager;
  private readonly agentDiscoveryManager: AgentDiscoveryManager;
  private readonly httpClient: HTTPClient;
  private readonly debug: boolean;

  constructor(config: ANPConfig = {}) {
    // Validate and set defaults for config
    const didConfig: DIDManagerConfig = {
      cacheTTL: config.did?.cacheTTL ?? 5 * 60 * 1000,
      timeout: config.did?.timeout ?? 10000,
    };

    const authConfig: AuthConfig = {
      maxTokenAge: config.auth?.maxTokenAge ?? 3600000,
      nonceLength: config.auth?.nonceLength ?? 32,
      clockSkewTolerance: config.auth?.clockSkewTolerance ?? 300,
    };

    const httpConfig: HTTPClientConfig = {
      timeout: config.http?.timeout ?? 10000,
      maxRetries: config.http?.maxRetries ?? 3,
      retryDelay: config.http?.retryDelay ?? 1000,
    };

    this.debug = config.debug ?? false;

    // Initialize managers
    this.didManager = new DIDManager(didConfig);
    this.authManager = new AuthenticationManager(this.didManager, authConfig);
    this.httpClient = new HTTPClient(this.authManager, httpConfig);
    this.agentDescriptionManager = new AgentDescriptionManager();
    this.agentDiscoveryManager = new AgentDiscoveryManager(this.httpClient);

    if (this.debug) {
      console.log('[ANPClient] Initialized with config:', {
        did: didConfig,
        auth: authConfig,
        http: httpConfig,
      });
    }
  }

  /**
   * DID operations namespace
   */
  readonly did = {
    /**
     * Create a new DID:WBA identity
     */
    create: async (options: CreateDIDOptions): Promise<DIDIdentity> => {
      try {
        return await this.didManager.createDID(options);
      } catch (error) {
        if (this.debug) {
          console.error('[ANPClient.did.create] Error:', error);
        }
        throw error;
      }
    },

    /**
     * Resolve a DID to its document
     */
    resolve: async (did: string): Promise<DIDDocument> => {
      try {
        return await this.didManager.resolveDID(did);
      } catch (error) {
        if (this.debug) {
          console.error('[ANPClient.did.resolve] Error:', error);
        }
        throw error;
      }
    },

    /**
     * Sign data with a DID identity
     */
    sign: async (identity: DIDIdentity, data: Uint8Array): Promise<Signature> => {
      try {
        return await this.didManager.sign(identity, data);
      } catch (error) {
        if (this.debug) {
          console.error('[ANPClient.did.sign] Error:', error);
        }
        throw error;
      }
    },

    /**
     * Verify a signature
     */
    verify: async (
      did: string,
      data: Uint8Array,
      signature: Signature
    ): Promise<boolean> => {
      try {
        return await this.didManager.verify(did, data, signature);
      } catch (error) {
        if (this.debug) {
          console.error('[ANPClient.did.verify] Error:', error);
        }
        throw error;
      }
    },
  };

  /**
   * Agent description operations namespace
   */
  readonly agent = {
    /**
     * Create a new agent description
     */
    createDescription: (metadata: AgentMetadata): AgentDescription => {
      try {
        return this.agentDescriptionManager.createDescription(metadata);
      } catch (error) {
        if (this.debug) {
          console.error('[ANPClient.agent.createDescription] Error:', error);
        }
        throw error;
      }
    },

    /**
     * Add information resource to agent description
     */
    addInformation: (
      description: AgentDescription,
      info: Information
    ): AgentDescription => {
      try {
        return this.agentDescriptionManager.addInformation(description, info);
      } catch (error) {
        if (this.debug) {
          console.error('[ANPClient.agent.addInformation] Error:', error);
        }
        throw error;
      }
    },

    /**
     * Add interface to agent description
     */
    addInterface: (
      description: AgentDescription,
      iface: Interface
    ): AgentDescription => {
      try {
        return this.agentDescriptionManager.addInterface(description, iface);
      } catch (error) {
        if (this.debug) {
          console.error('[ANPClient.agent.addInterface] Error:', error);
        }
        throw error;
      }
    },

    /**
     * Sign agent description
     */
    signDescription: async (
      description: AgentDescription,
      identity: DIDIdentity,
      challenge: string,
      domain: string
    ): Promise<AgentDescription> => {
      try {
        return await this.agentDescriptionManager.signDescription(
          description,
          identity,
          challenge,
          domain
        );
      } catch (error) {
        if (this.debug) {
          console.error('[ANPClient.agent.signDescription] Error:', error);
        }
        throw error;
      }
    },

    /**
     * Fetch agent description from URL
     */
    fetchDescription: async (url: string): Promise<AgentDescription> => {
      try {
        return await this.agentDescriptionManager.fetchDescription(url);
      } catch (error) {
        if (this.debug) {
          console.error('[ANPClient.agent.fetchDescription] Error:', error);
        }
        throw error;
      }
    },
  };

  /**
   * Agent discovery operations namespace
   */
  readonly discovery = {
    /**
     * Discover agents from a domain
     */
    discoverAgents: async (
      domain: string,
      identity?: DIDIdentity
    ): Promise<AgentDescriptionItem[]> => {
      try {
        return await this.agentDiscoveryManager.discoverAgents(domain, identity);
      } catch (error) {
        if (this.debug) {
          console.error('[ANPClient.discovery.discoverAgents] Error:', error);
        }
        throw error;
      }
    },

    /**
     * Register with a search service
     */
    registerWithSearchService: async (
      searchServiceUrl: string,
      agentDescriptionUrl: string,
      identity: DIDIdentity
    ): Promise<void> => {
      try {
        return await this.agentDiscoveryManager.registerWithSearchService(
          searchServiceUrl,
          agentDescriptionUrl,
          identity
        );
      } catch (error) {
        if (this.debug) {
          console.error('[ANPClient.discovery.registerWithSearchService] Error:', error);
        }
        throw error;
      }
    },

    /**
     * Search for agents
     */
    searchAgents: async (
      searchServiceUrl: string,
      query: SearchQuery,
      identity?: DIDIdentity
    ): Promise<AgentDescriptionItem[]> => {
      try {
        return await this.agentDiscoveryManager.searchAgents(
          searchServiceUrl,
          query,
          identity
        );
      } catch (error) {
        if (this.debug) {
          console.error('[ANPClient.discovery.searchAgents] Error:', error);
        }
        throw error;
      }
    },
  };

  /**
   * Protocol operations namespace
   */
  readonly protocol = {
    /**
     * Create a meta-protocol negotiation state machine
     */
    createNegotiationMachine: (config: MetaProtocolConfig): MetaProtocolActor => {
      try {
        return createMetaProtocolMachine(config);
      } catch (error) {
        if (this.debug) {
          console.error('[ANPClient.protocol.createNegotiationMachine] Error:', error);
        }
        throw error;
      }
    },

    /**
     * Send a protocol message
     */
    sendMessage: async (
      remoteDID: string,
      message: any,
      identity: DIDIdentity
    ): Promise<void> => {
      try {
        // Encode the message
        const encodedMessage = encodeMetaProtocolMessage(message);

        // Extract domain from remote DID
        const domain = this.extractDomainFromDID(remoteDID);

        // Send via HTTP
        await this.httpClient.post(
          `https://${domain}/anp/message`,
          { message: Array.from(encodedMessage) },
          identity
        );
      } catch (error) {
        if (this.debug) {
          console.error('[ANPClient.protocol.sendMessage] Error:', error);
        }
        throw error;
      }
    },

    /**
     * Receive and process a protocol message
     */
    receiveMessage: (
      encryptedMessage: Uint8Array,
      actor: MetaProtocolActor
    ): void => {
      try {
        processMessage(actor, encryptedMessage);
      } catch (error) {
        if (this.debug) {
          console.error('[ANPClient.protocol.receiveMessage] Error:', error);
        }
        throw error;
      }
    },
  };

  /**
   * HTTP operations namespace
   */
  readonly http = {
    /**
     * Make an HTTP request
     */
    request: async (
      url: string,
      options: RequestOptions,
      identity?: DIDIdentity
    ): Promise<Response> => {
      try {
        return await this.httpClient.request(url, options, identity);
      } catch (error) {
        if (this.debug) {
          console.error('[ANPClient.http.request] Error:', error);
        }
        throw error;
      }
    },

    /**
     * Make a GET request
     */
    get: async (url: string, identity?: DIDIdentity): Promise<Response> => {
      try {
        return await this.httpClient.get(url, identity);
      } catch (error) {
        if (this.debug) {
          console.error('[ANPClient.http.get] Error:', error);
        }
        throw error;
      }
    },

    /**
     * Make a POST request
     */
    post: async (
      url: string,
      body: any,
      identity?: DIDIdentity
    ): Promise<Response> => {
      try {
        return await this.httpClient.post(url, body, identity);
      } catch (error) {
        if (this.debug) {
          console.error('[ANPClient.http.post] Error:', error);
        }
        throw error;
      }
    },
  };

  /**
   * Extract domain from DID identifier
   */
  private extractDomainFromDID(did: string): string {
    // Parse DID: did:wba:domain[:port][:path]
    if (!did.startsWith('did:wba:')) {
      throw new Error('Invalid DID: must start with did:wba:');
    }

    const parts = did.substring(8).split(':');
    const domainPart = decodeURIComponent(parts[0]);

    // Extract domain (may include port)
    return domainPart;
  }
}
