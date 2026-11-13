import { publicDocumentRequest } from '../internal/http-security.js';
import { AuthenticationError, NetworkError } from '../errors/index.js';
import { verifyW3cProof } from '../proof/proof.js';
import type { DidDocument, DidResolutionOptions } from './types.js';
import {
  findVerificationMethod,
  resolveDidWbaDocument,
  validateDidDocumentBinding,
} from './did-wba.js';
import { extractPublicKey } from './verification-methods.js';
import { buildDidResolutionUrl } from './did-resource.js';

export async function resolveDidDocument(
  did: string,
  verifyProof = true,
  options: DidResolutionOptions = {}
): Promise<DidDocument> {
  if (did.startsWith('did:wba:')) {
    return resolveDidWbaDocument(did, verifyProof, options);
  }
  if (!did.startsWith('did:web:')) {
    throw new AuthenticationError('Unsupported DID method');
  }

  const url = buildDidResolutionUrl(did, options.baseUrlOverride);
  const response = await publicDocumentRequest(url, options);

  if (!response.ok) {
    throw new NetworkError('Network failure during DID resolution', response.status);
  }

  const document = (await response.json()) as DidDocument;
  if (document.id !== did) {
    throw new AuthenticationError('Invalid DID document');
  }
  if (verifyProof && document.proof) {
    const verificationMethodId = document.proof.verificationMethod;
    const method = findVerificationMethod(document, verificationMethodId);
    if (!method) {
      throw new AuthenticationError('Verification method not found');
    }
    const publicKey = extractPublicKey(method);
    if (!verifyW3cProof(document, publicKey)) {
      throw new AuthenticationError('Verification failed');
    }
  }
  return document;
}

/** Structural method validation after host-trusted resolution, not authorization. */
export function validateDidDocumentMethod(document: DidDocument): boolean {
  if (
    typeof document.id !== 'string' ||
    !Array.isArray(document.verificationMethod) ||
    !Array.isArray(document.authentication)
  )
    return false;
  if (document.id.startsWith('did:wba:')) return validateDidDocumentBinding(document, false);
  if (!document.id.startsWith('did:web:')) return false;
  try {
    buildDidResolutionUrl(document.id);
    return true;
  } catch {
    return false;
  }
}
