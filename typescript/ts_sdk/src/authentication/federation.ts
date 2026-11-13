import { AuthenticationError } from '../errors/index.js';
import { ANP_MESSAGE_SERVICE_TYPE, isAuthenticationAuthorized } from './did-wba.js';
import { resolveDidDocument } from './did-resolver.js';
import {
  extractSignatureMetadata,
  verifyHttpMessageSignature,
  httpSignatureReplayContext,
} from './http-signatures.js';
import type {
  DidDocument,
  FederatedVerificationOptions,
  FederatedVerificationResult,
  ServiceRecord,
} from './types.js';

import {
  consumeHttpReplay,
  MemoryHttpReplayStore,
  validateHttpSignatureTime,
  type HttpSignatureVerificationOptions,
  type HttpReplayStore,
  type HttpReplayConsumer,
} from './http-auth-security.js';

export interface FederatedHttpSecurity extends HttpSignatureVerificationOptions {
  replayStore?: HttpReplayStore | HttpReplayConsumer;
  verifierScope?: string;
}
const processReplayStore = new MemoryHttpReplayStore();

export async function verifyFederatedHttpRequest(
  senderDid: string,
  requestMethod: string,
  requestUrl: string,
  headers: Record<string, string>,
  body?: Uint8Array | string,
  options: FederatedVerificationOptions = {},
  security: FederatedHttpSecurity = {}
): Promise<FederatedVerificationResult> {
  if (security.policy?.cryptoOnly)
    throw new AuthenticationError('Federated authentication requires time validation');
  const preflight = extractSignatureMetadata(headers);
  validateHttpSignatureTime(preflight.created, preflight.expires, security.policy, security.now);
  const senderDidDocument =
    options.senderDidDocument ??
    (await resolveDidDocument(
      senderDid,
      options.verifySenderDidProof ?? false,
      options.didResolutionOptions ?? {}
    ));
  if (senderDidDocument.id !== senderDid) {
    throw new AuthenticationError('Sender DID document ID mismatch');
  }

  const service = selectAnpMessageService(
    senderDidDocument,
    options.serviceId,
    options.serviceEndpoint
  );
  if (!service.serviceDid) {
    throw new AuthenticationError('Selected ANPMessageService is missing serviceDid');
  }

  const signatureMetadata = extractSignatureMetadata(headers);
  const keyidDid = signatureMetadata.keyid.split('#', 1)[0];
  if (keyidDid !== service.serviceDid) {
    throw new AuthenticationError('Signature keyid DID does not match serviceDid');
  }

  const serviceDidDocument =
    options.serviceDidDocument ??
    (await resolveDidDocument(
      service.serviceDid,
      options.verifyServiceDidProof ?? false,
      options.didResolutionOptions ?? {}
    ));
  if (serviceDidDocument.id !== service.serviceDid) {
    throw new AuthenticationError('serviceDid document ID mismatch');
  }
  if (!isAuthenticationAuthorized(serviceDidDocument, signatureMetadata.keyid)) {
    throw new AuthenticationError('Verification method is not authorized for authentication');
  }

  const verifiedMetadata = verifyHttpMessageSignature(
    serviceDidDocument,
    requestMethod,
    requestUrl,
    headers,
    body,
    security
  );
  const replay = httpSignatureReplayContext(
    verifiedMetadata,
    requestMethod,
    requestUrl,
    headers,
    security.verifierScope,
    security.policy
  );
  let accepted: boolean;
  try {
    accepted = await consumeHttpReplay(security.replayStore ?? processReplayStore, replay);
  } catch {
    throw new AuthenticationError('Replay protection unavailable');
  }
  if (!accepted) throw new AuthenticationError('HTTP signature replay detected');
  return {
    senderDid,
    serviceDid: service.serviceDid,
    serviceId: service.id,
    signatureMetadata: verifiedMetadata,
  };
}

function selectAnpMessageService(
  didDocument: DidDocument,
  serviceId?: string,
  serviceEndpoint?: string
): ServiceRecord {
  const candidates = (didDocument.service ?? []).filter(
    (service) => service.type === ANP_MESSAGE_SERVICE_TYPE
  );
  if (candidates.length === 0) {
    throw new AuthenticationError('No ANPMessageService found in DID document');
  }

  if (serviceId) {
    const matched = candidates.find((service) => service.id === serviceId);
    if (!matched) {
      throw new AuthenticationError(`ANPMessageService not found for serviceId=${serviceId}`);
    }
    return matched;
  }

  if (serviceEndpoint) {
    const matched = candidates.find((service) => service.serviceEndpoint === serviceEndpoint);
    if (!matched) {
      throw new AuthenticationError('ANPMessageService not found for serviceEndpoint');
    }
    return matched;
  }

  if (candidates.length === 1) {
    return candidates[0];
  }

  throw new AuthenticationError(
    'Multiple ANPMessageService entries found; serviceId or serviceEndpoint is required'
  );
}
