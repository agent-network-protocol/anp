import { AuthenticationError } from '../errors/index.js';
import { ANP_MESSAGE_SERVICE_TYPE, isAuthenticationAuthorized } from './did-wba.js';
import { resolveDidDocument } from './did-resolver.js';
import { extractSignatureMetadata, verifyHttpMessageSignature } from './http-signatures.js';
import type {
  DidDocument,
  FederatedVerificationOptions,
  FederatedVerificationResult,
  ServiceRecord,
} from './types.js';

export async function verifyFederatedHttpRequest(
  senderDid: string,
  requestMethod: string,
  requestUrl: string,
  headers: Record<string, string>,
  body?: Uint8Array | string,
  options: FederatedVerificationOptions = {}
): Promise<FederatedVerificationResult> {
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

  const service = selectAnpMessageService(senderDidDocument, options.serviceId, options.serviceEndpoint);
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
    body
  );
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
