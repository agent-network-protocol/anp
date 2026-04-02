import { resolveDidWbaDocument } from '../authentication/did-wba.js';
import type { DidDocument } from '../authentication/types.js';
import { HandleBindingError } from '../errors/index.js';
import type {
  BindingVerificationOptions,
  BindingVerificationResult,
  HandleServiceEntry,
} from './types.js';
import { HandleStatus } from './types.js';
import { resolveHandle } from './resolver.js';
import { buildResolutionUrl, validateHandle } from './validator.js';
import { ANP_HANDLE_SERVICE_TYPE as ANP_HANDLE_SERVICE_TYPE_VALUE } from './types.js';

export async function verifyHandleBinding(
  handle: string,
  options: BindingVerificationOptions = {}
): Promise<BindingVerificationResult> {
  const bareHandle = handle.startsWith('wba://') ? handle.slice('wba://'.length) : handle;
  let localPart: string;
  let domain: string;
  try {
    [localPart, domain] = validateHandle(bareHandle);
  } catch (error) {
    return {
      isValid: false,
      handle: bareHandle,
      did: '',
      forwardVerified: false,
      reverseVerified: false,
      errorMessage: (error as Error).message,
    };
  }

  const normalizedHandle = `${localPart}.${domain}`;

  try {
    const resolution = await resolveHandle(normalizedHandle, options.resolutionOptions);
    if (resolution.status !== HandleStatus.Active) {
      return {
        isValid: false,
        handle: normalizedHandle,
        did: resolution.did,
        forwardVerified: false,
        reverseVerified: false,
        errorMessage: `Handle status is '${resolution.status}', expected 'active'`,
      };
    }

    if (!resolution.did.startsWith('did:wba:')) {
      return {
        isValid: false,
        handle: normalizedHandle,
        did: resolution.did,
        forwardVerified: true,
        reverseVerified: false,
        errorMessage: 'DID does not use did:wba method',
      };
    }

    const didDomain = resolution.did.split(':')[2] ?? '';
    if (didDomain.toLowerCase() !== domain) {
      return {
        isValid: false,
        handle: normalizedHandle,
        did: resolution.did,
        forwardVerified: true,
        reverseVerified: false,
        errorMessage: `Domain mismatch: handle domain '${domain}' != DID domain '${didDomain}'`,
      };
    }

    const didDocument =
      options.didDocument ??
      (await resolveDidWbaDocument(resolution.did, false, options.didResolutionOptions));
    const handleServices = extractHandleServiceFromDidDocument(didDocument);
    const reverseVerified = handleServices.some(
      (service) => matchesHandleServiceDomain(service.serviceEndpoint, domain)
    );
    if (!reverseVerified) {
      return {
        isValid: false,
        handle: normalizedHandle,
        did: resolution.did,
        forwardVerified: true,
        reverseVerified: false,
        errorMessage:
          `DID Document does not contain an ${ANP_HANDLE_SERVICE_TYPE_VALUE} entry ` +
          `whose HTTPS domain matches '${domain}'`,
      };
    }

    return {
      isValid: true,
      handle: normalizedHandle,
      did: resolution.did,
      forwardVerified: true,
      reverseVerified: true,
    };
  } catch (error) {
    if (error instanceof HandleBindingError) {
      throw error;
    }
    return {
      isValid: false,
      handle: normalizedHandle,
      did: '',
      forwardVerified: false,
      reverseVerified: false,
      errorMessage: (error as Error).message,
    };
  }
}

export function buildHandleServiceEntry(
  did: string,
  localPart: string,
  domain: string
): HandleServiceEntry {
  return {
    id: `${did}#handle`,
    type: ANP_HANDLE_SERVICE_TYPE_VALUE,
    serviceEndpoint: buildResolutionUrl(localPart, domain),
  };
}

export function extractHandleServiceFromDidDocument(didDocument: DidDocument): HandleServiceEntry[] {
  return (didDocument.service ?? [])
    .filter((service) => service.type === ANP_HANDLE_SERVICE_TYPE_VALUE)
    .map((service) => ({
      id: String(service.id),
      type: String(service.type),
      serviceEndpoint: String(service.serviceEndpoint),
    }));
}

function matchesHandleServiceDomain(serviceEndpoint: string, expectedDomain: string): boolean {
  try {
    const parsed = new URL(serviceEndpoint);
    return (
      parsed.protocol === 'https:' && parsed.hostname.toLowerCase() === expectedDomain.toLowerCase()
    );
  } catch {
    return false;
  }
}
