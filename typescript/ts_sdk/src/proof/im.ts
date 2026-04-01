import { randomBytes } from 'node:crypto';

import { findVerificationMethod } from '../authentication/did-wba.js';
import type { DidDocument, VerificationMethodRecord } from '../authentication/types.js';
import { extractPublicKey } from '../authentication/verification-methods.js';
import { ProofError } from '../errors/index.js';
import { decodeBase64, decodeBase64Url, encodeBase64, encodeBase64Url } from '../internal/base64.js';
import {
  normalizePrivateKeyMaterial,
  signMessage,
  verifyMessage,
  type PrivateKeyInput,
} from '../internal/keys.js';
import { buildContentDigest } from '../authentication/http-signatures.js';

export const IM_PROOF_DEFAULT_COMPONENTS = ['@method', '@target-uri', 'content-digest'] as const;

export interface ImProof {
  contentDigest: string;
  signatureInput: string;
  signature: string;
}

export interface ParsedImSignatureInput {
  label: string;
  components: string[];
  signatureParams: string;
  keyid: string;
  nonce?: string;
  created?: number;
  expires?: number;
}

export interface ImProofGenerationOptions {
  label?: string;
  components?: string[];
  created?: number;
  expires?: number;
  nonce?: string;
}

export interface ImProofVerificationResult {
  parsedSignatureInput: ParsedImSignatureInput;
  verificationMethod: VerificationMethodRecord;
}

export function buildImContentDigest(payload: Uint8Array | string): string {
  return buildContentDigest(payload);
}

export function verifyImContentDigest(payload: Uint8Array | string, contentDigest: string): boolean {
  return buildImContentDigest(payload) === contentDigest.trim();
}

export function buildImSignatureInput(
  keyid: string,
  options: ImProofGenerationOptions = {}
): string {
  const label = options.label ?? 'sig1';
  const components = options.components ?? [...IM_PROOF_DEFAULT_COMPONENTS];
  if (components.length === 0) {
    throw new ProofError('signatureInput must include covered components');
  }
  const created = options.created ?? Math.floor(Date.now() / 1000);
  const nonce = options.nonce ?? encodeBase64Url(randomBytes(16));
  const quotedComponents = components.map((component) => `"${component}"`).join(' ');
  const params = [`created=${created}`];
  if (options.expires !== undefined) {
    params.push(`expires=${options.expires}`);
  }
  params.push(`nonce="${nonce}"`);
  params.push(`keyid="${keyid}"`);
  return `${label}=(${quotedComponents});${params.join(';')}`;
}

export function parseImSignatureInput(value: string): ParsedImSignatureInput {
  const separator = value.indexOf('=');
  if (separator < 0) {
    throw new ProofError('invalid proof.signatureInput format');
  }
  const label = value.slice(0, separator).trim();
  const remainder = value.slice(separator + 1).trim();
  const openIndex = remainder.indexOf('(');
  const closeIndex = remainder.indexOf(')');
  if (openIndex < 0 || closeIndex < 0 || closeIndex <= openIndex) {
    throw new ProofError('invalid proof.signatureInput format');
  }

  const components = remainder
    .slice(openIndex + 1, closeIndex)
    .split(/\s+/)
    .map((component) => component.replaceAll('"', ''))
    .filter(Boolean);
  if (components.length === 0) {
    throw new ProofError('proof.signatureInput must include covered components');
  }

  const params: Record<string, string> = {};
  const paramsRaw = remainder.slice(closeIndex + 1).replace(/^;/, '');
  for (const part of paramsRaw.split(';')) {
    const trimmed = part.trim();
    if (!trimmed) {
      continue;
    }
    const [name, rawValue] = trimmed.split('=', 2);
    if (!name || rawValue === undefined) {
      throw new ProofError('invalid proof.signatureInput format');
    }
    params[name.trim()] = rawValue.trim().replace(/^"|"$/g, '');
  }

  if (!params.keyid) {
    throw new ProofError('proof.signatureInput must include keyid');
  }

  return {
    label,
    components,
    signatureParams: remainder,
    keyid: params.keyid,
    nonce: params.nonce,
    created: params.created ? Number(params.created) : undefined,
    expires: params.expires ? Number(params.expires) : undefined,
  };
}

export function encodeImSignature(signatureBytes: Uint8Array, label = 'sig1'): string {
  return `${label}=:${encodeBase64(signatureBytes)}:`;
}

export function decodeImSignature(signature: string): { label?: string; signatureBytes: Uint8Array } {
  const trimmed = signature.trim();
  const labeled = trimmed.match(/^\s*([a-zA-Z0-9_-]+)=:(.+):\s*$/);
  const unlabeled = trimmed.match(/^\s*:(.+):\s*$/);
  const label = labeled?.[1];
  const encoded = labeled?.[2] ?? unlabeled?.[1];
  if (!encoded) {
    throw new ProofError('invalid proof.signature encoding');
  }
  try {
    return { label, signatureBytes: decodeBase64(encoded) };
  } catch {
    try {
      return { label, signatureBytes: decodeBase64Url(encoded) };
    } catch {
      throw new ProofError('invalid proof.signature encoding');
    }
  }
}

export function generateImProof(
  payload: Uint8Array | string,
  signatureBase: Uint8Array | string,
  privateKeyInput: PrivateKeyInput,
  keyid: string,
  options: ImProofGenerationOptions = {}
): ImProof {
  const payloadBytes = toBytes(payload);
  const signatureInput = buildImSignatureInput(keyid, options);
  const privateKey = normalizePrivateKeyMaterial(privateKeyInput);
  const signatureBytes = signMessage(privateKey, toBytes(signatureBase));
  return {
    contentDigest: buildImContentDigest(payloadBytes),
    signatureInput,
    signature: encodeImSignature(signatureBytes, options.label ?? 'sig1'),
  };
}

export function verifyImProof(
  proof: ImProof,
  payload: Uint8Array | string,
  signatureBase: Uint8Array | string,
  verificationTarget: { didDocument?: DidDocument; verificationMethod?: VerificationMethodRecord },
  expectedSignerDid?: string
): ImProofVerificationResult {
  if (!verifyImContentDigest(payload, proof.contentDigest)) {
    throw new ProofError('proof contentDigest does not match request payload');
  }
  const parsed = parseImSignatureInput(proof.signatureInput);
  if (expectedSignerDid && !parsed.keyid.startsWith(expectedSignerDid)) {
    throw new ProofError('proof keyid must belong to expected signer DID');
  }

  const verificationMethod =
    verificationTarget.verificationMethod ??
    resolveVerificationMethod(verificationTarget.didDocument, parsed.keyid);
  const publicKey = extractPublicKey(verificationMethod);
  const { signatureBytes } = decodeImSignature(proof.signature);
  if (!verifyMessage(publicKey, toBytes(signatureBase), signatureBytes)) {
    throw new ProofError('signature verification failed');
  }

  return {
    parsedSignatureInput: parsed,
    verificationMethod,
  };
}

function resolveVerificationMethod(
  didDocument: DidDocument | undefined,
  verificationMethodId: string
): VerificationMethodRecord {
  if (!didDocument) {
    throw new ProofError('didDocument or verificationMethod is required');
  }
  const method = findVerificationMethod(didDocument, verificationMethodId);
  if (!method) {
    throw new ProofError('verification method not found in DID document');
  }
  return method;
}

function toBytes(value: Uint8Array | string): Uint8Array {
  return typeof value === 'string' ? new TextEncoder().encode(value) : value;
}
