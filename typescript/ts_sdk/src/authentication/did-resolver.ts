import { AuthenticationError, NetworkError } from '../errors/index.js';
import { verifyW3cProof } from '../proof/proof.js';
import type { DidDocument, DidResolutionOptions } from './types.js';
import {
  findVerificationMethod,
  resolveDidWbaDocument,
} from './did-wba.js';
import { extractPublicKey } from './verification-methods.js';

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

  void options.verifySsl;
  const url = buildDidResolutionUrl(did, options.baseUrlOverride);
  const timeoutMs = Math.round((options.timeoutSeconds ?? 10) * 1000);
  const response = await fetch(url, {
    headers: {
      Accept: 'application/json',
      ...(options.headers ?? {}),
    },
    signal: AbortSignal.timeout(timeoutMs),
  }).catch((error) => {
    throw new NetworkError('Network failure during DID resolution', undefined, error as Error);
  });

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

function buildDidResolutionUrl(did: string, baseUrlOverride?: string): string {
  const parts = did.split(':');
  if (parts.length < 3) {
    throw new AuthenticationError('Invalid DID format');
  }
  const domain = decodeURIComponent(parts[2]);
  const pathSegments = parts.slice(3).map((segment) => decodeURIComponent(segment));
  const baseUrl = (baseUrlOverride ?? `https://${domain}`).replace(/\/$/, '');
  if (pathSegments.length === 0) {
    return `${baseUrl}/.well-known/did.json`;
  }
  return `${baseUrl}/${pathSegments.join('/')}/did.json`;
}
