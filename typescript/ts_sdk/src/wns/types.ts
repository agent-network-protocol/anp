import type { DidResolutionOptions } from '../authentication/types.js';
import type { DidDocument } from '../authentication/types.js';

export enum HandleStatus {
  Active = 'active',
  Suspended = 'suspended',
  Revoked = 'revoked',
}

export interface HandleResolutionDocument {
  handle: string;
  did: string;
  status: HandleStatus;
  updated?: string;
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
