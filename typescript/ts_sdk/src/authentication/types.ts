import type { GeneratedKeyPairPem } from '../internal/keys.js';
import type { JsonObject } from '../internal/json.js';

export enum DidProfile {
  E1 = 'e1',
  K1 = 'k1',
  PlainLegacy = 'plain_legacy',
}

export enum AuthMode {
  HttpSignatures = 'http_signatures',
  LegacyDidWba = 'legacy_didwba',
  Auto = 'auto',
}

export interface ProofRecord {
  type: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue: string;
  cryptosuite?: string;
  domain?: string;
  challenge?: string;
}

export interface VerificationMethodRecord {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk?: JsonWebKey;
  publicKeyMultibase?: string;
  publicKeyBase58?: string;
}

export interface ServiceRecord {
  id: string;
  type: string;
  serviceEndpoint: unknown;
}

export interface DidDocument {
  '@context': string[];
  id: string;
  verificationMethod: VerificationMethodRecord[];
  authentication: Array<string | VerificationMethodRecord>;
  assertionMethod?: Array<string | VerificationMethodRecord>;
  keyAgreement?: Array<string | VerificationMethodRecord>;
  service?: ServiceRecord[];
  proof?: ProofRecord;
}

export interface DidDocumentOptions {
  port?: number;
  pathSegments?: string[];
  agentDescriptionUrl?: string;
  services?: JsonObject[];
  proofPurpose?: string;
  verificationMethod?: string;
  domain?: string;
  challenge?: string;
  created?: string;
  enableE2ee?: boolean;
  didProfile?: DidProfile;
}

export interface DidDocumentBundle {
  didDocument: DidDocument;
  keys: Record<string, GeneratedKeyPairPem>;
}

export interface ParsedAuthHeader {
  did: string;
  nonce: string;
  timestamp: string;
  verificationMethod: string;
  signature: string;
  version: string;
}

export interface LegacyAuthOptions {
  nonce?: string;
  timestamp?: string;
}

export interface DidResolutionOptions {
  timeoutSeconds?: number;
  verifySsl?: boolean;
  baseUrlOverride?: string;
  headers?: Record<string, string>;
}

export interface HttpSignatureOptions {
  keyid?: string;
  nonce?: string;
  created?: number;
  expires?: number;
  coveredComponents?: string[];
}

export interface SignatureMetadata {
  label: string;
  components: string[];
  keyid: string;
  nonce?: string;
  created: number;
  expires?: number;
}
