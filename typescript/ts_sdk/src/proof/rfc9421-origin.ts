import { ProofError } from '../errors/index.js';
import { canonicalizeJson, cloneJson, type JsonObject } from '../internal/json.js';
import type { PrivateKeyInput } from '../internal/keys.js';
import {
  IM_PROOF_DEFAULT_COMPONENTS,
  IM_PROOF_RELATION_AUTHENTICATION,
  buildImContentDigest,
  buildImSignatureInput,
  generateImProof,
  parseImSignatureInput,
  verifyImProof,
  type ImProof,
  type ImProofVerificationResult,
} from './im.js';
import type { DidDocument, VerificationMethodRecord } from '../authentication/types.js';

export const RFC9421_ORIGIN_PROOF_DEFAULT_LABEL = 'sig1';
export const RFC9421_ORIGIN_PROOF_DEFAULT_COMPONENTS = IM_PROOF_DEFAULT_COMPONENTS;
export const TARGET_KIND_AGENT = 'agent';
export const TARGET_KIND_GROUP = 'group';
export const TARGET_KIND_SERVICE = 'service';

const ALLOWED_TARGET_KINDS = new Set([TARGET_KIND_AGENT, TARGET_KIND_GROUP, TARGET_KIND_SERVICE]);

export class Rfc9421OriginProofError extends ProofError {
  constructor(message: string, cause?: Error) {
    super(message, cause);
    this.name = 'Rfc9421OriginProofError';
  }
}

export interface SignedRequestObject {
  method: string;
  meta: JsonObject;
  body: JsonObject;
}

export type Rfc9421OriginProof = ImProof;

export interface Rfc9421OriginProofGenerationOptions {
  created?: number;
  expires?: number;
  nonce?: string;
  label?: string;
}

export interface Rfc9421OriginProofVerificationOptions {
  expectedSignerDid?: string;
}

export function buildSignedRequestObject(
  method: string,
  meta: Record<string, unknown>,
  body: Record<string, unknown>
): SignedRequestObject {
  if (typeof method !== 'string' || !method.trim()) {
    throw new Rfc9421OriginProofError('method is required');
  }
  if (!isPlainObject(meta)) {
    throw new Rfc9421OriginProofError('meta must be an object');
  }
  if (!isPlainObject(body)) {
    throw new Rfc9421OriginProofError('body must be an object');
  }
  return {
    method,
    meta: cloneJson(meta) as JsonObject,
    body: cloneJson(body) as JsonObject,
  };
}

export function canonicalizeSignedRequestObject(
  signedRequestObject: SignedRequestObject | Record<string, unknown>
): Uint8Array {
  const keys = Object.keys(signedRequestObject);
  if (
    keys.length !== 3 ||
    !keys.includes('method') ||
    !keys.includes('meta') ||
    !keys.includes('body')
  ) {
    throw new Rfc9421OriginProofError(
      'signed request object must contain only method, meta, and body'
    );
  }
  return canonicalizeJson({
    method: signedRequestObject.method,
    meta: signedRequestObject.meta,
    body: signedRequestObject.body,
  });
}

export function buildLogicalTargetUri(targetKind: string, targetDid: string): string {
  const normalizedKind = String(targetKind).trim();
  if (!ALLOWED_TARGET_KINDS.has(normalizedKind)) {
    throw new Rfc9421OriginProofError(`unsupported target kind: ${targetKind}`);
  }
  const normalizedDid = String(targetDid).trim();
  if (!normalizedDid) {
    throw new Rfc9421OriginProofError('target did is required');
  }
  return `anp://${normalizedKind}/${quoteRfc3986Unreserved(normalizedDid)}`;
}

export function buildRfc9421OriginSignatureBase(
  method: string,
  logicalTargetUri: string,
  contentDigest: string,
  signatureInput: string
): Uint8Array {
  if (typeof method !== 'string' || !method.trim()) {
    throw new Rfc9421OriginProofError('method is required');
  }
  if (typeof logicalTargetUri !== 'string' || !logicalTargetUri.trim()) {
    throw new Rfc9421OriginProofError('logical_target_uri is required');
  }
  if (typeof contentDigest !== 'string' || !contentDigest.trim()) {
    throw new Rfc9421OriginProofError('content_digest is required');
  }
  const parsed = parseImSignatureInput(signatureInput);
  validateParsedSignatureInput(parsed.label, parsed.components);
  const componentValues: Record<string, string> = {
    '@method': method,
    '@target-uri': logicalTargetUri,
    'content-digest': contentDigest,
  };
  const lines = parsed.components.map(
    (component) => `"${component}": ${componentValues[component]}`
  );
  lines.push(`"@signature-params": ${parsed.signatureParams}`);
  return new TextEncoder().encode(lines.join('\n'));
}

export function generateRfc9421OriginProof(
  method: string,
  meta: Record<string, unknown>,
  body: Record<string, unknown>,
  privateKey: PrivateKeyInput,
  keyId: string,
  options: Rfc9421OriginProofGenerationOptions = {}
): Rfc9421OriginProof {
  const label = options.label ?? RFC9421_ORIGIN_PROOF_DEFAULT_LABEL;
  validateLabel(label);
  const signedRequestObject = buildSignedRequestObject(method, meta, body);
  const canonicalRequest = canonicalizeSignedRequestObject(signedRequestObject);
  const logicalTargetUri = buildLogicalTargetUriFromMeta(signedRequestObject.meta);
  const contentDigest = buildImContentDigest(canonicalRequest);
  const signatureInput = buildImSignatureInput(keyId, {
    components: [...RFC9421_ORIGIN_PROOF_DEFAULT_COMPONENTS],
    label,
    created: options.created,
    expires: options.expires,
    nonce: options.nonce,
  });
  const signatureBase = buildRfc9421OriginSignatureBase(
    method,
    logicalTargetUri,
    contentDigest,
    signatureInput
  );
  const proof = generateImProof(canonicalRequest, signatureBase, privateKey, keyId, {
    components: [...RFC9421_ORIGIN_PROOF_DEFAULT_COMPONENTS],
    label,
    created: options.created,
    expires: options.expires,
    nonce: options.nonce,
  });
  const parsed = parseImSignatureInput(proof.signatureInput);
  validateParsedSignatureInput(parsed.label, parsed.components);
  return proof;
}

export function verifyRfc9421OriginProof(
  originProof: Rfc9421OriginProof,
  method: string,
  meta: Record<string, unknown>,
  body: Record<string, unknown>,
  verification: {
    didDocument?: DidDocument;
    verificationMethod?: VerificationMethodRecord;
    options?: Rfc9421OriginProofVerificationOptions;
  } = {}
): ImProofVerificationResult {
  const signedRequestObject = buildSignedRequestObject(method, meta, body);
  const canonicalRequest = canonicalizeSignedRequestObject(signedRequestObject);
  const logicalTargetUri = buildLogicalTargetUriFromMeta(signedRequestObject.meta);
  const signatureInput = requireProofField(originProof, 'signatureInput');
  const parsed = parseImSignatureInput(signatureInput);
  validateParsedSignatureInput(parsed.label, parsed.components);
  const signatureBase = buildRfc9421OriginSignatureBase(
    method,
    logicalTargetUri,
    requireProofField(originProof, 'contentDigest'),
    signatureInput
  );
  return verifyImProof(
    originProof,
    canonicalRequest,
    signatureBase,
    {
      didDocument: verification.didDocument,
      verificationMethod: verification.verificationMethod,
      verificationRelationship: IM_PROOF_RELATION_AUTHENTICATION,
    },
    verification.options?.expectedSignerDid
  );
}

function buildLogicalTargetUriFromMeta(meta: JsonObject): string {
  const target = meta.target;
  if (!isPlainObject(target)) {
    throw new Rfc9421OriginProofError('meta.target is required');
  }
  return buildLogicalTargetUri(String(target.kind), String(target.did));
}

function validateLabel(label: string): void {
  if (label !== RFC9421_ORIGIN_PROOF_DEFAULT_LABEL) {
    throw new Rfc9421OriginProofError('RFC 9421 origin proof requires signature label sig1');
  }
}

function validateParsedSignatureInput(label: string, components: string[]): void {
  validateLabel(label);
  const expected = [...RFC9421_ORIGIN_PROOF_DEFAULT_COMPONENTS];
  if (
    components.length !== expected.length ||
    components.some((value, index) => value !== expected[index])
  ) {
    throw new Rfc9421OriginProofError(
      'RFC 9421 origin proof requires covered components ("@method" "@target-uri" "content-digest")'
    );
  }
}

function requireProofField(proof: Rfc9421OriginProof, field: keyof Rfc9421OriginProof): string {
  const value = proof[field];
  if (!value) {
    throw new Rfc9421OriginProofError(`missing proof field: ${field}`);
  }
  return value;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Percent-encode like Python urllib.parse.quote(..., safe="-._~"). */
export function quoteRfc3986Unreserved(value: string): string {
  let output = '';
  for (const char of value) {
    if (/[A-Za-z0-9\-._~]/.test(char)) {
      output += char;
      continue;
    }
    for (const byte of new TextEncoder().encode(char)) {
      output += `%${byte.toString(16).toUpperCase().padStart(2, '0')}`;
    }
  }
  return output;
}
