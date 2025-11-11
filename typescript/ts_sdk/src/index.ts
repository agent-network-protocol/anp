/**
 * ANP TypeScript SDK
 *
 * Main entry point for the Agent Network Protocol TypeScript SDK
 */

// SDK version
export const VERSION = '0.1.0';

// Export main client
export { ANPClient, type ANPConfig, type RequestOptions } from './anp-client.js';

// Export core types
export type {
  DIDDocument,
  DIDIdentity,
  CreateDIDOptions,
  ResolveDIDOptions,
  VerificationMethod,
  ServiceEndpoint,
} from './types/did.js';

export type {
  AgentDescription,
  AgentMetadata,
  Information,
  Interface,
  Organization,
  SecurityScheme,
  Proof,
} from './types/agent-description.js';

export type {
  DiscoveryDocument,
  AgentDescriptionItem,
  SearchQuery,
} from './types/agent-discovery.js';

// Export managers for advanced use cases
export { DIDManager, type DIDManagerConfig, type Signature } from './core/did/did-manager.js';
export {
  AuthenticationManager,
  type AuthConfig,
  type VerificationResult,
  type TokenVerificationResult,
} from './core/auth/authentication-manager.js';
export { AgentDescriptionManager } from './core/agent-description/agent-description-manager.js';
export { AgentDiscoveryManager } from './core/agent-discovery/agent-discovery-manager.js';
export { HTTPClient, type HTTPClientConfig } from './transport/http-client.js';

// Export protocol types and utilities
export {
  createMetaProtocolMachine,
  type MetaProtocolConfig,
  type MetaProtocolContext,
  type MetaProtocolEvent,
  type MetaProtocolActor,
  createNegotiationMessage,
  createCodeGenerationMessage,
  createTestCasesMessage,
  createFixErrorMessage,
  encodeMetaProtocolMessage,
  sendNegotiation,
  processMessage,
} from './protocol/meta-protocol-machine.js';

export {
  ProtocolMessageHandler,
  ProtocolType,
  type ProtocolMessage,
  type MetaProtocolMessage,
  type ProtocolNegotiationMessage,
  type CodeGenerationMessage,
  type TestCasesNegotiationMessage,
  type FixErrorNegotiationMessage,
  type NaturalLanguageNegotiationMessage,
} from './protocol/message-handler.js';

// Export crypto utilities
export {
  generateKeyPair,
  exportPublicKeyJWK,
  exportPrivateKeyJWK,
  KeyType,
} from './crypto/key-generation.js';

export {
  sign,
  verify,
  encodeSignature,
  decodeSignature,
} from './crypto/signing.js';

export {
  performKeyExchange,
  deriveKey,
} from './crypto/key-exchange.js';

export {
  encrypt,
  decrypt,
  type EncryptedData,
} from './crypto/encryption.js';

// Export error classes
export {
  ANPError,
  DIDResolutionError,
  AuthenticationError,
  ProtocolNegotiationError,
  NetworkError,
  CryptoError,
} from './errors/index.js';
