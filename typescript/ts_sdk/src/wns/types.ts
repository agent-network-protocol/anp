import type { DidResolutionOptions } from '../authentication/types.js';
import type { DidDocument } from '../authentication/types.js';

export const ANP_HANDLE_SERVICE_TYPE = 'ANPHandleService';

export enum HandleStatus {
  Active = 'active',
  Suspended = 'suspended',
  Revoked = 'revoked',
}

export enum SubjectType {
  Person = 'person',
  Agent = 'agent',
  Group = 'group',
  Organization = 'organization',
  Service = 'service',
  Application = 'application',
  Unknown = 'unknown',
}

export interface DIDSubjectProfile {
  type?: string;
  subject_did: string;
  subject_type?: SubjectType;
  handle?: string;
  display_name?: string;
  description?: string;
  avatar_uri?: string;
  profile_uri?: string;
  discoverability?: string;
  labels?: Record<string, unknown>;
  updated?: string;
  versionId?: string;
  ttl?: number;
  proof?: Record<string, unknown>;
}

export interface HandleResolutionDocument {
  handle: string;
  did: string;
  status: HandleStatus;
  updated?: string;
  versionId?: string;
  ttl?: number;
  profile?: DIDSubjectProfile;
}

export interface HandleServiceEntry {
  id: string;
  type: string;
  serviceEndpoint: string;
}

export interface ParsedWbaUri {
  localPart: string;
  domain: string;
  handle: string;
  originalUri: string;
}

export interface ResolveHandleOptions {
  timeoutSeconds?: number;
  verifySsl?: boolean;
  baseUrlOverride?: string;
}

export interface BindingVerificationOptions {
  didDocument?: DidDocument;
  resolutionOptions?: ResolveHandleOptions;
  didResolutionOptions?: DidResolutionOptions;
}

export interface BindingVerificationResult {
  isValid: boolean;
  handle: string;
  did: string;
  forwardVerified: boolean;
  reverseVerified: boolean;
  errorMessage?: string;
}
