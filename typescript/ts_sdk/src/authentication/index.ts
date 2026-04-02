export * from './types.js';
export * from './verification-methods.js';
export * from './did-wba.js';
export * from './did-resolver.js';
export * from './http-signatures.js';
export * from './did-wba-authenticator.js';
export * from './did-wba-verifier.js';
export * from './federation.js';

export {
  createDidWbaDocument as createDidDocument,
  createDidWbaDocumentWithKeyBinding as createDidDocumentWithKeyBinding,
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
  ANP_MESSAGE_SERVICE_TYPE,
  buildAgentMessageService,
  buildAnpMessageService,
  buildGroupMessageService,
  createDidWbaDocument,
  createDidWbaDocumentWithKeyBinding,
  validateDidDocumentBinding,
  verifyDidKeyBinding,
  generateAuthHeader,
  generateAuthJson,
  extractAuthHeaderParts,
  verifyAuthHeaderSignature,
  verifyAuthJsonSignature,
} from './did-wba.js';
import { resolveDidDocument } from './did-resolver.js';
import {
  buildContentDigest,
  verifyContentDigest,
  generateHttpSignatureHeaders,
  verifyHttpMessageSignature,
  extractSignatureMetadata,
} from './http-signatures.js';
import { DIDWbaAuthHeader } from './did-wba-authenticator.js';
import { DidWbaVerifier } from './did-wba-verifier.js';
import { verifyFederatedHttpRequest } from './federation.js';

export const didDocuments = {
  ANP_MESSAGE_SERVICE_TYPE,
  buildAnpMessageService,
  buildAgentMessageService,
  buildGroupMessageService,
  create: createDidWbaDocument,
  createWithKeyBinding: createDidWbaDocumentWithKeyBinding,
  resolve: resolveDidDocument,
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
  federation: {
    verifyRequest: verifyFederatedHttpRequest,
  },
  DidAuthHeaders: DIDWbaAuthHeader,
  RequestVerifier: DidWbaVerifier,
};
