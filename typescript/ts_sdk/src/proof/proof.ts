import { ProofError } from '../errors/index.js';
import {
  normalizePrivateKeyMaterial,
  normalizePublicKeyMaterial,
  sha256,
  signMessage,
  verifyMessage,
  type PrivateKeyInput,
  type PublicKeyInput,
} from '../internal/keys.js';
import { canonicalizeJson, cloneJson } from '../internal/json.js';
import { decodeBase64Url, encodeBase64Url } from '../internal/base64.js';

export const PROOF_TYPE_SECP256K1 = 'EcdsaSecp256k1Signature2019';
export const PROOF_TYPE_ED25519 = 'Ed25519Signature2020';
export const PROOF_TYPE_DATA_INTEGRITY = 'DataIntegrityProof';

export const CRYPTOSUITE_EDDSA_JCS_2022 = 'eddsa-jcs-2022';
export const CRYPTOSUITE_DIDWBA_SECP256K1_2025 = 'didwba-jcs-ecdsa-secp256k1-2025';

export interface ProofGenerationOptions {
  proofPurpose?: string;
  proofType?: string;
  cryptosuite?: string;
  created?: string;
  domain?: string;
  challenge?: string;
}

export interface ProofVerificationOptions {
  expectedPurpose?: string;
  expectedDomain?: string;
  expectedChallenge?: string;
}

export interface ProofObject {
  type: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue: string;
  cryptosuite?: string;
  domain?: string;
  challenge?: string;
}

export function generateW3cProof<T extends object>(
  document: T,
  privateKeyInput: PrivateKeyInput,
  verificationMethod: string,
  options: ProofGenerationOptions = {}
): T & { proof: ProofObject } {
  const privateKey = normalizePrivateKeyMaterial(privateKeyInput);
  const proofType = options.proofType ?? inferProofType(privateKey.type);
  validateProofCompatibility(privateKey.type, proofType, options.cryptosuite);

  const proof: ProofObject = {
    type: proofType,
    created: options.created ?? new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
    verificationMethod,
    proofPurpose: options.proofPurpose ?? 'assertionMethod',
    proofValue: '',
  };

  if (proofType === PROOF_TYPE_DATA_INTEGRITY) {
    proof.cryptosuite = options.cryptosuite ?? inferCryptosuite(privateKey.type);
  }
  if (options.domain) {
    proof.domain = options.domain;
  }
  if (options.challenge) {
    proof.challenge = options.challenge;
  }

  const signingDocument = cloneJson(document);
  delete (signingDocument as { proof?: unknown }).proof;
  const signingInput = computeSigningInput(signingDocument, omitProofValue(proof));
  proof.proofValue = encodeBase64Url(signMessage(privateKey, signingInput));

  return {
    ...cloneJson(document),
    proof,
  };
}

export function verifyW3cProof(
  document: object,
  publicKeyInput: PublicKeyInput,
  options: ProofVerificationOptions = {}
): boolean {
  try {
    verifyW3cProofDetailed(document, publicKeyInput, options);
    return true;
  } catch {
    return false;
  }
}

export function verifyW3cProofDetailed(
  document: object,
  publicKeyInput: PublicKeyInput,
  options: ProofVerificationOptions = {}
): void {
  const publicKey = normalizePublicKeyMaterial(publicKeyInput);
  const proof = (document as { proof?: unknown }).proof;
  if (!proof || typeof proof !== 'object') {
    throw new ProofError('Missing proof object');
  }

  const proofObject = proof as ProofObject;
  const proofType = requireStringField(proofObject, 'type');
  const proofValue = requireStringField(proofObject, 'proofValue');
  const proofPurpose = requireStringField(proofObject, 'proofPurpose');
  requireStringField(proofObject, 'verificationMethod');
  requireStringField(proofObject, 'created');

  validatePublicKeyCompatibility(publicKey.type, proofType, proofObject.cryptosuite);
  if (options.expectedPurpose && options.expectedPurpose !== proofPurpose) {
    throw new ProofError('Verification failed: proofPurpose mismatch');
  }
  if (options.expectedDomain && proofObject.domain !== options.expectedDomain) {
    throw new ProofError('Verification failed: domain mismatch');
  }
  if (options.expectedChallenge && proofObject.challenge !== options.expectedChallenge) {
    throw new ProofError('Verification failed: challenge mismatch');
  }

  const signingDocument = cloneJson(document);
  delete (signingDocument as { proof?: unknown }).proof;
  const signingInput = computeSigningInput(signingDocument, omitProofValue(proofObject));
  const signature = decodeBase64Url(proofValue);
  if (!verifyMessage(publicKey, signingInput, signature)) {
    throw new ProofError('Verification failed');
  }
}

function inferProofType(keyType: string): string {
  switch (keyType) {
    case 'secp256k1':
      return PROOF_TYPE_SECP256K1;
    case 'ed25519':
      return PROOF_TYPE_ED25519;
    default:
      return PROOF_TYPE_DATA_INTEGRITY;
  }
}

function inferCryptosuite(keyType: string): string {
  switch (keyType) {
    case 'ed25519':
      return CRYPTOSUITE_EDDSA_JCS_2022;
    case 'secp256k1':
      return CRYPTOSUITE_DIDWBA_SECP256K1_2025;
    default:
      throw new ProofError(`Unsupported cryptosuite for key type: ${keyType}`);
  }
}

function validateProofCompatibility(
  keyType: string,
  proofType: string,
  cryptosuite?: string
): void {
  if (proofType === PROOF_TYPE_SECP256K1 && keyType !== 'secp256k1') {
    throw new ProofError('Key type mismatch for secp256k1 proof generation');
  }
  if (proofType === PROOF_TYPE_ED25519 && keyType !== 'ed25519') {
    throw new ProofError('Key type mismatch for Ed25519 proof generation');
  }
  if (proofType === PROOF_TYPE_DATA_INTEGRITY && cryptosuite) {
    validateCryptosuite(keyType, cryptosuite);
  }
}

function validatePublicKeyCompatibility(
  keyType: string,
  proofType: string,
  cryptosuite?: string
): void {
  if (proofType === PROOF_TYPE_SECP256K1 && keyType !== 'secp256k1') {
    throw new ProofError('Invalid public key for proof verification');
  }
  if (proofType === PROOF_TYPE_ED25519 && keyType !== 'ed25519') {
    throw new ProofError('Invalid public key for proof verification');
  }
  if (proofType === PROOF_TYPE_DATA_INTEGRITY && cryptosuite) {
    validateCryptosuite(keyType, cryptosuite);
  }
}

function validateCryptosuite(keyType: string, cryptosuite: string): void {
  if (cryptosuite === CRYPTOSUITE_EDDSA_JCS_2022 && keyType !== 'ed25519') {
    throw new ProofError('Unsupported cryptosuite for non-Ed25519 key');
  }
  if (cryptosuite === CRYPTOSUITE_DIDWBA_SECP256K1_2025 && keyType !== 'secp256k1') {
    throw new ProofError('Unsupported cryptosuite for non-secp256k1 key');
  }
  if (
    cryptosuite !== CRYPTOSUITE_EDDSA_JCS_2022 &&
    cryptosuite !== CRYPTOSUITE_DIDWBA_SECP256K1_2025
  ) {
    throw new ProofError(`Unsupported cryptosuite: ${cryptosuite}`);
  }
}

function computeSigningInput(
  document: object,
  proofOptions: Omit<ProofObject, 'proofValue'>
): Uint8Array {
  const documentHash = sha256(canonicalizeJson(document));
  const proofHash = sha256(canonicalizeJson(proofOptions));
  const combined = new Uint8Array(documentHash.length + proofHash.length);
  combined.set(proofHash, 0);
  combined.set(documentHash, proofHash.length);
  return combined;
}

function omitProofValue(proof: ProofObject): Omit<ProofObject, 'proofValue'> {
  const clone = { ...proof };
  delete (clone as { proofValue?: string }).proofValue;
  return clone;
}

function requireStringField(proof: ProofObject, key: keyof ProofObject): string {
  const value = proof[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new ProofError(`Missing proof field: ${String(key)}`);
  }
  return value;
}
