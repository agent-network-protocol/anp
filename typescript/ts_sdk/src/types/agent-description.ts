/**
 * Type definitions for Agent Description Protocol (ADP)
 */

/**
 * Organization information
 */
export interface Organization {
  name: string;
  url?: string;
  email?: string;
}

/**
 * Security scheme definition
 */
export interface SecurityScheme {
  scheme: string;
  type?: string;
  description?: string;
}

/**
 * Information resource
 */
export interface Information {
  type: string;
  description: string;
  url: string;
}

/**
 * Interface definition
 */
export interface Interface {
  type: string;
  protocol: string;
  version: string;
  url: string;
  description?: string;
}

/**
 * Proof object for digital signatures
 */
export interface Proof {
  type: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  challenge?: string;
  domain?: string;
  proofValue: string;
}

/**
 * Agent Description document
 */
export interface AgentDescription {
  protocolType: 'ANP';
  protocolVersion: string;
  type: 'AgentDescription';
  url?: string;
  name: string;
  did?: string;
  owner?: Organization;
  description?: string;
  created?: string;
  securityDefinitions: Record<string, SecurityScheme>;
  security: string;
  Infomations?: Information[];
  interfaces?: Interface[];
  proof?: Proof;
}

/**
 * Metadata for creating an agent description
 */
export interface AgentMetadata {
  name: string;
  did?: string;
  owner?: Organization;
  description?: string;
  url?: string;
  protocolVersion?: string;
}
