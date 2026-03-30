export * from './types.js';
export * from './verification-methods.js';
export * from './did-wba.js';
export * from './http-signatures.js';
export * from './did-wba-authenticator.js';
export * from './did-wba-verifier.js';

export {
  createDidWbaDocument as createDidDocument,
  createDidWbaDocumentWithKeyBinding as createDidDocumentWithKeyBinding,
  resolveDidWbaDocument as resolveDidDocument,
  validateDidDocumentBinding as validateDidBinding,
  verifyDidKeyBinding as verifyDidBinding,
  generateAuthHeader as createLegacyAuthHeader,
  generateAuthJson as createLegacyAuthPayload,
  extractAuthHeaderParts as parseLegacyAuthHeader,
  verifyAuthHeaderSignature as verifyLegacyAuthHeader,
  verifyAuthJsonSignature as verifyLegacyAuthPayload,
} from './did-wba.js';

export {
  generateHttpSignatureHeaders as createSignatureHeaders,
  verifyHttpMessageSignature as verifySignatureHeaders,
  extractSignatureMetadata as parseSignatureMetadata,
} from './http-signatures.js';

export {
  DIDWbaAuthHeader as DidAuthHeaders,
} from './did-wba-authenticator.js';

export {
  DidWbaVerifier as RequestVerifier,
  DidWbaVerifierError as RequestVerifierError,
} from './did-wba-verifier.js';

import {
  createDidWbaDocument,
  createDidWbaDocumentWithKeyBinding,
  resolveDidWbaDocument,
  validateDidDocumentBinding,
  verifyDidKeyBinding,
  generateAuthHeader,
  generateAuthJson,
  extractAuthHeaderParts,
  verifyAuthHeaderSignature,
  verifyAuthJsonSignature,
} from './did-wba.js';
import {
  buildContentDigest,
  verifyContentDigest,
  generateHttpSignatureHeaders,
  verifyHttpMessageSignature,
  extractSignatureMetadata,
} from './http-signatures.js';
import { DIDWbaAuthHeader } from './did-wba-authenticator.js';
import { DidWbaVerifier } from './did-wba-verifier.js';

export const didDocuments = {
  create: createDidWbaDocument,
  createWithKeyBinding: createDidWbaDocumentWithKeyBinding,
  resolve: resolveDidWbaDocument,
  validateBinding: validateDidDocumentBinding,
  verifyKeyBinding: verifyDidKeyBinding,
};

export const legacyAuth = {
  createHeader: generateAuthHeader,
  createPayload: generateAuthJson,
  parseHeader: extractAuthHeaderParts,
  verifyHeader: verifyAuthHeaderSignature,
  verifyPayload: verifyAuthJsonSignature,
};

export const httpSignatures = {
  buildContentDigest,
  verifyContentDigest,
  createHeaders: generateHttpSignatureHeaders,
  verifyMessage: verifyHttpMessageSignature,
  parseMetadata: extractSignatureMetadata,
};

export const authentication = {
  didDocuments,
  legacyAuth,
  httpSignatures,
  DidAuthHeaders: DIDWbaAuthHeader,
  RequestVerifier: DidWbaVerifier,
};
