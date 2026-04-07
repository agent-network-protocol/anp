import { isIP } from 'node:net';

import { AuthenticationError, NetworkError } from '../errors/index.js';
import {
  computeJwkThumbprint,
  ed25519PublicKeyToMultibase,
  generateKeyPairPem,
  normalizePrivateKeyMaterial,
  normalizePublicKeyMaterial,
  publicKeyToJwk,
  sha256,
  signMessage,
  x25519PublicKeyToMultibase,
  type PublicKeyInput,
  type PublicKeyMaterial,
} from '../internal/keys.js';
import { canonicalizeJson, cloneJson, type JsonObject } from '../internal/json.js';
import { encodeBase64Url } from '../internal/base64.js';
import {
  CRYPTOSUITE_DIDWBA_SECP256K1_2025,
  CRYPTOSUITE_EDDSA_JCS_2022,
  PROOF_TYPE_DATA_INTEGRITY,
  PROOF_TYPE_SECP256K1,
  generateW3cProof,
  verifyW3cProof,
  type ProofGenerationOptions,
} from '../proof/proof.js';
import { createVerificationMethod, extractPublicKey } from './verification-methods.js';
import type {
  AnpMessageServiceOptions,
  DidDocument,
  DidDocumentBundle,
  DidDocumentOptions,
  DidProfile,
  DidResolutionOptions,
  LegacyAuthOptions,
  ParsedAuthHeader,
  ServiceRecord,
  VerificationMethodRecord,
} from './types.js';
import { DidProfile as DidProfileEnum } from './types.js';

export const VM_KEY_AUTH = 'key-1';
export const VM_KEY_E2EE_SIGNING = 'key-2';
export const VM_KEY_E2EE_AGREEMENT = 'key-3';
export const ANP_MESSAGE_SERVICE_TYPE = 'ANPMessageService';

export async function resolveDidWbaDocument(
  did: string,
  verifyProof = true,
  options: DidResolutionOptions = {}
): Promise<DidDocument> {
  if (!did.startsWith('did:wba:')) {
    throw new AuthenticationError('Invalid DID format');
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
  if (!validateDidDocumentBinding(document, verifyProof)) {
    throw new AuthenticationError('DID binding verification failed');
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

export function buildAnpMessageService(
  didOrServiceRef: string,
  serviceEndpoint: string,
  options: AnpMessageServiceOptions = {}
): ServiceRecord {
  const fragment = options.fragment ?? 'message';
  const serviceId =
    didOrServiceRef.startsWith('#') || didOrServiceRef.startsWith('did:')
      ? didOrServiceRef.startsWith('#')
        ? didOrServiceRef
        : `${didOrServiceRef}#${fragment}`
      : `${didOrServiceRef}#${fragment}`;

  const service: ServiceRecord = {
    id: serviceId,
    type: ANP_MESSAGE_SERVICE_TYPE,
    serviceEndpoint,
  };
  if (options.serviceDid) {
    service.serviceDid = options.serviceDid;
  }
  if (options.profiles?.length) {
    service.profiles = [...options.profiles];
  }
  if (options.securityProfiles?.length) {
    service.securityProfiles = [...options.securityProfiles];
  }
  if (options.accepts?.length) {
    service.accepts = [...options.accepts];
  }
  if (options.priority !== undefined) {
    service.priority = options.priority;
  }
  if (options.authSchemes?.length) {
    service.authSchemes = [...options.authSchemes];
  }
  return service;
}

export function buildAgentMessageService(
  didOrServiceRef: string,
  serviceEndpoint: string,
  options: AnpMessageServiceOptions = {}
): ServiceRecord {
  return buildAnpMessageService(didOrServiceRef, serviceEndpoint, {
    profiles: options.profiles ?? ['anp.core.binding.v1', 'anp.direct.base.v1', 'anp.direct.e2ee.v1'],
    securityProfiles: options.securityProfiles ?? ['transport-protected', 'direct-e2ee'],
    ...options,
  });
}

export function buildGroupMessageService(
  didOrServiceRef: string,
  serviceEndpoint: string,
  options: AnpMessageServiceOptions = {}
): ServiceRecord {
  return buildAnpMessageService(didOrServiceRef, serviceEndpoint, {
    profiles: options.profiles ?? ['anp.core.binding.v1', 'anp.group.base.v1', 'anp.group.e2ee.v1'],
    securityProfiles: options.securityProfiles ?? ['transport-protected', 'group-e2ee'],
    ...options,
  });
}

export function createDidWbaDocument(
  hostname: string,
  options: DidDocumentOptions = {}
): DidDocumentBundle {
  if (!hostname.trim()) {
    throw new AuthenticationError('Hostname cannot be empty');
  }
  if (isIP(hostname) !== 0) {
    throw new AuthenticationError('Hostname cannot be an IP address');
  }

  const didProfile = options.didProfile ?? DidProfileEnum.E1;
  const didBase = buildDidBase(hostname, options.port);
  const pathSegments = [...(options.pathSegments ?? [])];
  const contexts = ['https://www.w3.org/ns/did/v1'];
  const verificationMethods: VerificationMethodRecord[] = [];
  const authentication: string[] = [];
  const assertionMethod: string[] = [];
  const keyAgreement: string[] = [];
  const keys: DidDocumentBundle['keys'] = {};

  const authKey = generateKeyPairPem(
    didProfile === DidProfileEnum.E1 ? 'ed25519' : 'secp256k1'
  );
  const authPublicKey = authKey.publicKey;

  let did = didBase;
  if (didProfile === DidProfileEnum.E1 && pathSegments.length > 0) {
    pathSegments.push(`e1_${computeMultikeyFingerprint(authPublicKey)}`);
  }
  if (didProfile === DidProfileEnum.K1 && pathSegments.length > 0) {
    pathSegments.push(`k1_${computeJwkFingerprint(authPublicKey)}`);
  }
  did = joinDid(didBase, pathSegments);

  const authVerificationMethodId = `${did}#${VM_KEY_AUTH}`;
  const authVerificationMethod = buildAuthVerificationMethod(did, didProfile, authPublicKey, contexts);
  verificationMethods.push(authVerificationMethod);
  authentication.push(authVerificationMethodId);
  if (didProfile === DidProfileEnum.E1 || didProfile === DidProfileEnum.K1) {
    assertionMethod.push(authVerificationMethodId);
  }
  keys[VM_KEY_AUTH] = authKey.pair;

  if (options.enableE2ee !== false) {
    contexts.push('https://w3id.org/security/suites/x25519-2019/v1');
    const signingKey = generateKeyPairPem('secp256r1');
    const agreementKey = generateKeyPairPem('x25519');
    verificationMethods.push({
      id: `${did}#${VM_KEY_E2EE_SIGNING}`,
      type: 'EcdsaSecp256r1VerificationKey2019',
      controller: did,
      publicKeyJwk: publicKeyToJwk(signingKey.publicKey),
    });
    verificationMethods.push({
      id: `${did}#${VM_KEY_E2EE_AGREEMENT}`,
      type: 'X25519KeyAgreementKey2019',
      controller: did,
      publicKeyMultibase: x25519PublicKeyToMultibase(agreementKey.publicKey.bytes),
    });
    keyAgreement.push(`${did}#${VM_KEY_E2EE_AGREEMENT}`);
    keys[VM_KEY_E2EE_SIGNING] = signingKey.pair;
    keys[VM_KEY_E2EE_AGREEMENT] = agreementKey.pair;
  }

  const document: DidDocument = {
    '@context': contexts,
    id: did,
    verificationMethod: verificationMethods,
    authentication,
  };
  if (assertionMethod.length > 0) {
    document.assertionMethod = assertionMethod;
  }
  if (keyAgreement.length > 0) {
    document.keyAgreement = keyAgreement;
  }

  const services = buildServiceEntries(did, options.agentDescriptionUrl, options.services);
  if (services.length > 0) {
    document.service = services;
  }

  const proofOptions: ProofGenerationOptions = {
    proofPurpose: options.proofPurpose ?? 'assertionMethod',
    proofType:
      didProfile === DidProfileEnum.PlainLegacy ? PROOF_TYPE_SECP256K1 : PROOF_TYPE_DATA_INTEGRITY,
    cryptosuite:
      didProfile === DidProfileEnum.E1
        ? CRYPTOSUITE_EDDSA_JCS_2022
        : didProfile === DidProfileEnum.K1
          ? CRYPTOSUITE_DIDWBA_SECP256K1_2025
          : undefined,
    created: options.created,
    domain: options.domain,
    challenge: options.challenge,
  };

  const signedDocument = generateW3cProof(
    document,
    authKey.privateKey,
    options.verificationMethod ?? authVerificationMethodId,
    proofOptions
  );

  return {
    didDocument: signedDocument as DidDocument,
    keys,
  };
}

export function createDidWbaDocumentWithKeyBinding(
  hostname: string,
  options: DidDocumentOptions = {}
): DidDocumentBundle {
  return createDidWbaDocument(hostname, {
    ...options,
    pathSegments: options.pathSegments?.length ? options.pathSegments : ['user'],
    didProfile: DidProfileEnum.K1,
  });
}

export function computeJwkFingerprint(publicKeyInput: PublicKeyInput): string {
  const publicKey = normalizePublicKeyMaterial(publicKeyInput);
  if (publicKey.type !== 'secp256k1') {
    throw new AuthenticationError('Invalid DID document');
  }
  return computeJwkThumbprint(publicKeyToJwk(publicKey));
}

export function computeMultikeyFingerprint(publicKeyInput: PublicKeyInput): string {
  const publicKey = normalizePublicKeyMaterial(publicKeyInput);
  if (publicKey.type !== 'ed25519') {
    throw new AuthenticationError('Invalid DID document');
  }
  return computeJwkThumbprint(publicKeyToJwk(publicKey));
}

export function verifyDidKeyBinding(
  did: string,
  bindingMaterial: VerificationMethodRecord | PublicKeyMaterial | string
): boolean {
  const lastSegment = did.split(':').at(-1) ?? '';
  const publicKey = toPublicKeyMaterial(bindingMaterial);
  if (lastSegment.startsWith('k1_')) {
    return publicKey.type === 'secp256k1' && computeJwkFingerprint(publicKey) === lastSegment.slice(3);
  }
  if (lastSegment.startsWith('e1_')) {
    return publicKey.type === 'ed25519' && computeMultikeyFingerprint(publicKey) === lastSegment.slice(3);
  }
  return true;
}

export function validateDidDocumentBinding(didDocument: DidDocument, verifyProof = true): boolean {
  const lastSegment = didDocument.id.split(':').at(-1) ?? '';
  if (lastSegment.startsWith('e1_')) {
    return validateE1Binding(didDocument, lastSegment.slice(3));
  }
  if (lastSegment.startsWith('k1_')) {
    if (verifyProof) {
      return validateK1Binding(didDocument, lastSegment.slice(3));
    }
    return didDocument.verificationMethod.some(
      (method) => isAuthenticationAuthorized(didDocument, method.id) && verifyDidKeyBinding(didDocument.id, method)
    );
  }
  return true;
}

export function generateAuthHeader(
  didDocument: DidDocument,
  serviceDomain: string,
  privateKeyInput: string,
  version = '1.1',
  options: LegacyAuthOptions = {}
): string {
  const payload = generateAuthPayload(
    didDocument,
    serviceDomain,
    privateKeyInput,
    version,
    options
  );
  return `DIDWba v="${payload.version}", did="${payload.did}", nonce="${payload.nonce}", timestamp="${payload.timestamp}", verification_method="${payload.verificationMethod}", signature="${payload.signature}"`;
}

export function generateAuthJson(
  didDocument: DidDocument,
  serviceDomain: string,
  privateKeyInput: string,
  version = '1.1',
  options: LegacyAuthOptions = {}
): string {
  const payload = generateAuthPayload(
    didDocument,
    serviceDomain,
    privateKeyInput,
    version,
    options
  );
  return JSON.stringify({
    v: payload.version,
    did: payload.did,
    nonce: payload.nonce,
    timestamp: payload.timestamp,
    verification_method: payload.verificationMethod,
    signature: payload.signature,
  });
}

export function extractAuthHeaderParts(authHeader: string): ParsedAuthHeader {
  if (!authHeader.trimStart().startsWith('DIDWba')) {
    throw new AuthenticationError('Authentication header must start with DIDWba');
  }

  const versionMatch = authHeader.match(/\bv="([^"]+)"/i);
  return {
    did: requiredHeaderField(authHeader, 'did'),
    nonce: requiredHeaderField(authHeader, 'nonce'),
    timestamp: requiredHeaderField(authHeader, 'timestamp'),
    verificationMethod: requiredHeaderField(authHeader, 'verification_method'),
    signature: requiredHeaderField(authHeader, 'signature'),
    version: versionMatch?.[1] ?? '1.1',
  };
}

export function verifyAuthHeaderSignature(
  authHeader: string,
  didDocument: DidDocument,
  serviceDomain: string
): boolean {
  verifyAuthPayload(extractAuthHeaderParts(authHeader), didDocument, serviceDomain);
  return true;
}

export function verifyAuthJsonSignature(
  authJson: string,
  didDocument: DidDocument,
  serviceDomain: string
): boolean {
  const value = JSON.parse(authJson) as Record<string, unknown>;
  verifyAuthPayload(
    {
      did: String(value.did ?? ''),
      nonce: String(value.nonce ?? ''),
      timestamp: String(value.timestamp ?? ''),
      verificationMethod: String(value.verification_method ?? ''),
      signature: String(value.signature ?? ''),
      version: String(value.v ?? '1.1'),
    },
    didDocument,
    serviceDomain
  );
  return true;
}

export function findVerificationMethod(
  didDocument: DidDocument,
  verificationMethodId: string
): VerificationMethodRecord | undefined {
  const directMethod = didDocument.verificationMethod.find(
    (method) => method.id === verificationMethodId
  );
  if (directMethod) {
    return directMethod;
  }
  for (const entry of didDocument.authentication) {
    if (typeof entry !== 'string' && entry.id === verificationMethodId) {
      return entry;
    }
  }
  for (const entry of didDocument.assertionMethod ?? []) {
    if (typeof entry !== 'string' && entry.id === verificationMethodId) {
      return entry;
    }
  }
  return undefined;
}

export function isAuthenticationAuthorized(
  didDocument: DidDocument,
  verificationMethodId: string
): boolean {
  return isVerificationMethodAuthorized(didDocument.authentication, verificationMethodId);
}

export function isAssertionMethodAuthorized(
  didDocument: DidDocument,
  verificationMethodId: string
): boolean {
  return isVerificationMethodAuthorized(didDocument.assertionMethod ?? [], verificationMethodId);
}

function validateE1Binding(didDocument: DidDocument, expectedFingerprint: string): boolean {
  const proof = didDocument.proof;
  if (!proof) {
    return false;
  }
  if (proof.type !== PROOF_TYPE_DATA_INTEGRITY || proof.cryptosuite !== CRYPTOSUITE_EDDSA_JCS_2022) {
    return false;
  }
  if (!isAssertionMethodAuthorized(didDocument, proof.verificationMethod)) {
    return false;
  }
  const method = findVerificationMethod(didDocument, proof.verificationMethod);
  if (!method) {
    return false;
  }
  const publicKey = extractPublicKey(method);
  return (
    publicKey.type === 'ed25519' &&
    verifyW3cProof(didDocument, publicKey, { expectedPurpose: 'assertionMethod' }) &&
    computeMultikeyFingerprint(publicKey) === expectedFingerprint
  );
}

function validateK1Binding(didDocument: DidDocument, expectedFingerprint: string): boolean {
  const proof = didDocument.proof;
  if (!proof) {
    return false;
  }
  if (!isAssertionMethodAuthorized(didDocument, proof.verificationMethod)) {
    return false;
  }
  const method = findVerificationMethod(didDocument, proof.verificationMethod);
  if (!method) {
    return false;
  }
  const publicKey = extractPublicKey(method);
  return (
    publicKey.type === 'secp256k1' &&
    verifyW3cProof(didDocument, publicKey, { expectedPurpose: 'assertionMethod' }) &&
    computeJwkFingerprint(publicKey) === expectedFingerprint
  );
}

function generateAuthPayload(
  didDocument: DidDocument,
  serviceDomain: string,
  privateKeyInput: string,
  version: string,
  options: LegacyAuthOptions = {}
): ParsedAuthHeader {
  const did = didDocument.id;
  const [method, fragment] = selectAuthenticationMethod(didDocument);
  const nonce = options.nonce ?? encodeBase64Url(crypto.getRandomValues(new Uint8Array(16)));
  const timestamp = options.timestamp ?? new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
  const payload = {
    nonce,
    timestamp,
    [domainFieldForVersion(version)]: serviceDomain,
    did,
  };
  const contentHash = sha256(canonicalizeJson(payload));
  const signatureBytes = signMessage(normalizePrivateKeyMaterial(privateKeyInput), contentHash);
  const verifier = createVerificationMethod(method);
  return {
    did,
    nonce,
    timestamp,
    verificationMethod: fragment,
    signature: verifier.encodeSignature(signatureBytes),
    version,
  };
}

function verifyAuthPayload(
  parsed: ParsedAuthHeader,
  didDocument: DidDocument,
  serviceDomain: string
): void {
  if (didDocument.id.toLowerCase() !== parsed.did.toLowerCase()) {
    throw new AuthenticationError('Verification failed');
  }

  const payload = {
    nonce: parsed.nonce,
    timestamp: parsed.timestamp,
    [domainFieldForVersion(parsed.version)]: serviceDomain,
    did: parsed.did,
  };
  const contentHash = sha256(canonicalizeJson(payload));
  const verificationMethodId = `${parsed.did}#${parsed.verificationMethod}`;
  const method = findVerificationMethod(didDocument, verificationMethodId);
  if (!method) {
    throw new AuthenticationError('Verification method not found');
  }
  const verifier = createVerificationMethod(method);
  if (!verifier.verifySignature(contentHash, parsed.signature)) {
    throw new AuthenticationError('Verification failed');
  }
}

function selectAuthenticationMethod(
  didDocument: DidDocument
): [VerificationMethodRecord, string] {
  const first = didDocument.authentication[0];
  if (!first) {
    throw new AuthenticationError('Invalid DID document');
  }
  if (typeof first === 'string') {
    const method = findVerificationMethod(didDocument, first);
    if (!method) {
      throw new AuthenticationError('Verification method not found');
    }
    return [method, first.split('#').at(-1) ?? ''];
  }
  return [first, first.id.split('#').at(-1) ?? ''];
}

function buildAuthVerificationMethod(
  did: string,
  didProfile: DidProfile,
  authPublicKey: PublicKeyMaterial,
  contexts: string[]
): VerificationMethodRecord {
  if (didProfile === DidProfileEnum.E1) {
    contexts.push('https://w3id.org/security/data-integrity/v2');
    contexts.push('https://w3id.org/security/multikey/v1');
    return {
      id: `${did}#${VM_KEY_AUTH}`,
      type: 'Multikey',
      controller: did,
      publicKeyMultibase: ed25519PublicKeyToMultibase(authPublicKey.bytes),
    };
  }

  contexts.push('https://w3id.org/security/suites/jws-2020/v1');
  contexts.push('https://w3id.org/security/suites/secp256k1-2019/v1');
  if (didProfile === DidProfileEnum.K1) {
    contexts.push('https://w3id.org/security/data-integrity/v2');
  }
  return {
    id: `${did}#${VM_KEY_AUTH}`,
    type: 'EcdsaSecp256k1VerificationKey2019',
    controller: did,
    publicKeyJwk: publicKeyToJwk(authPublicKey),
  };
}

function buildServiceEntries(
  did: string,
  agentDescriptionUrl?: string,
  services?: Array<ServiceRecord | JsonObject>
): ServiceRecord[] {
  const output: ServiceRecord[] = [];
  if (agentDescriptionUrl) {
    output.push({
      id: `${did}#ad`,
      type: 'AgentDescription',
      serviceEndpoint: agentDescriptionUrl,
    });
  }
  for (const service of services ?? []) {
    const copy = cloneJson(service) as unknown as ServiceRecord;
    if (typeof copy.id === 'string' && copy.id.startsWith('#')) {
      copy.id = `${did}${copy.id}`;
    }
    output.push(copy);
  }
  return output;
}

function buildDidBase(hostname: string, port?: number): string {
  return port === undefined ? `did:wba:${hostname}` : `did:wba:${hostname}%3A${port}`;
}

function joinDid(base: string, pathSegments: string[]): string {
  return pathSegments.length === 0 ? base : `${base}:${pathSegments.join(':')}`;
}

function buildDidResolutionUrl(did: string, baseUrlOverride?: string): string {
  const parts = did.split(':');
  if (parts.length < 3) {
    throw new AuthenticationError('Invalid DID format');
  }
  const domain = decodeURIComponent(parts[2]);
  const pathSegments = parts.slice(3);
  const baseUrl = (baseUrlOverride ?? `https://${domain}`).replace(/\/$/, '');
  if (pathSegments.length === 0) {
    return `${baseUrl}/.well-known/did.json`;
  }
  return `${baseUrl}/${pathSegments.join('/')}/did.json`;
}

function domainFieldForVersion(version: string): 'aud' | 'service' {
  return Number.parseFloat(version) >= 1.1 ? 'aud' : 'service';
}

function requiredHeaderField(authHeader: string, field: string): string {
  const match = authHeader.match(new RegExp(`${field}="([^"]+)"`, 'i'));
  if (!match?.[1]) {
    throw new AuthenticationError(`Missing field in authorization header: ${field}`);
  }
  return match[1];
}

function toPublicKeyMaterial(
  bindingMaterial: VerificationMethodRecord | PublicKeyMaterial | string
): PublicKeyMaterial {
  if (typeof bindingMaterial === 'string') {
    return normalizePublicKeyMaterial(bindingMaterial);
  }
  if ('bytes' in bindingMaterial) {
    return bindingMaterial;
  }
  return extractPublicKey(bindingMaterial);
}

function isVerificationMethodAuthorized(
  entries: Array<string | VerificationMethodRecord>,
  verificationMethodId: string
): boolean {
  return entries.some((entry) =>
    typeof entry === 'string' ? entry === verificationMethodId : entry.id === verificationMethodId
  );
}
