/**
 * Type definitions for DID (Decentralized Identifier) functionality
 */

/**
 * Verification method for DID documents
 */
export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk?: JsonWebKey;
  publicKeyMultibase?: string;
}

/**
 * Service endpoint for DID documents
 */
export interface ServiceEndpoint {
  id: string;
  type: string;
  serviceEndpoint: string;
}

/**
 * DID Document structure following W3C DID specification
 */
export interface DIDDocument {
  '@context': string[];
  id: string;
  verificationMethod: VerificationMethod[];
  authentication: (string | VerificationMethod)[];
  keyAgreement?: (string | VerificationMethod)[];
  humanAuthorization?: (string | VerificationMethod)[];
  service?: ServiceEndpoint[];
}

/**
 * Key metadata for tracking key types
 */
export interface KeyMetadata {
  key: CryptoKey;
  type: string; // KeyType enum value as string
}

/**
 * DID Identity containing the DID, document, and private keys
 */
export interface DIDIdentity {
  did: string;
  document: DIDDocument;
  privateKeys: Map<string, KeyMetadata>;
}

/**
 * Options for creating a DID
 */
export interface CreateDIDOptions {
  domain: string;
  path?: string;
  port?: number;
}

/**
 * Options for resolving a DID
 */
export interface ResolveDIDOptions {
  cache?: boolean;
  cacheTTL?: number;
}
