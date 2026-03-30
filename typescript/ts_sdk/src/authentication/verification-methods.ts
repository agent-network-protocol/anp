import bs58 from 'bs58';

import { AuthenticationError } from '../errors/index.js';
import { decodeBase64Url, encodeBase64Url } from '../internal/base64.js';
import {
  parseEd25519Multibase,
  parseX25519Multibase,
  publicKeyFromJwk,
  verifyMessage,
  type PublicKeyMaterial,
} from '../internal/keys.js';
import type { VerificationMethodRecord } from './types.js';

export class VerificationMethod {
  constructor(
    public readonly id: string,
    public readonly methodType: string,
    public readonly publicKey: PublicKeyMaterial
  ) {}

  verifySignature(content: Uint8Array, signature: string): boolean {
    return verifyMessage(this.publicKey, content, decodeBase64Url(signature));
  }

  encodeSignature(signatureBytes: Uint8Array): string {
    if (this.publicKey.type === 'x25519') {
      throw new AuthenticationError('X25519 cannot encode signatures');
    }
    return encodeBase64Url(signatureBytes);
  }
}

export function createVerificationMethod(method: VerificationMethodRecord): VerificationMethod {
  if (!method.type) {
    throw new AuthenticationError('Missing verification method type');
  }
  return new VerificationMethod(method.id ?? '', method.type, extractPublicKey(method));
}

export function extractPublicKey(method: VerificationMethodRecord): PublicKeyMaterial {
  switch (method.type) {
    case 'EcdsaSecp256k1VerificationKey2019':
      return extractEcPublicKey(method, 'secp256k1');
    case 'EcdsaSecp256r1VerificationKey2019':
      return extractEcPublicKey(method, 'P-256');
    case 'Ed25519VerificationKey2018':
    case 'Ed25519VerificationKey2020':
    case 'Multikey':
      return extractEd25519PublicKey(method);
    case 'X25519KeyAgreementKey2019':
      return extractX25519PublicKey(method);
    case 'JsonWebKey2020':
      if (!method.publicKeyJwk) {
        throw new AuthenticationError('Missing key material');
      }
      return publicKeyFromJwk(method.publicKeyJwk);
    default:
      throw new AuthenticationError(`Unsupported verification method type: ${method.type}`);
  }
}

function extractEcPublicKey(
  method: VerificationMethodRecord,
  expectedCurve: 'secp256k1' | 'P-256'
): PublicKeyMaterial {
  if (method.publicKeyJwk) {
    const publicKey = publicKeyFromJwk(method.publicKeyJwk);
    const actualCurve = publicKey.type === 'secp256k1' ? 'secp256k1' : 'P-256';
    if (actualCurve !== expectedCurve) {
      throw new AuthenticationError('Invalid JWK parameters');
    }
    return publicKey;
  }

  if (method.publicKeyMultibase) {
    return {
      type: expectedCurve === 'secp256k1' ? 'secp256k1' : 'secp256r1',
      bytes: new Uint8Array(bs58.decode(stripMultibasePrefix(method.publicKeyMultibase))),
    };
  }

  throw new AuthenticationError('Missing key material');
}

function extractEd25519PublicKey(method: VerificationMethodRecord): PublicKeyMaterial {
  if (method.publicKeyJwk) {
    return publicKeyFromJwk(method.publicKeyJwk);
  }
  if (method.publicKeyMultibase) {
    return parseEd25519Multibase(method.publicKeyMultibase);
  }
  if (method.publicKeyBase58) {
    const bytes = bs58.decode(method.publicKeyBase58);
    if (bytes.length !== 32) {
      throw new AuthenticationError('Invalid Ed25519 publicKeyBase58');
    }
    return {
      type: 'ed25519',
      bytes: new Uint8Array(bytes),
    };
  }
  throw new AuthenticationError('Missing key material');
}

function extractX25519PublicKey(method: VerificationMethodRecord): PublicKeyMaterial {
  if (!method.publicKeyMultibase) {
    throw new AuthenticationError('Missing key material');
  }
  return parseX25519Multibase(method.publicKeyMultibase);
}

function stripMultibasePrefix(value: string): string {
  return value.startsWith('z') ? value.slice(1) : value;
}
