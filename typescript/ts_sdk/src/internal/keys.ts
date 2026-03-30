import { ECDH, createECDH, createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify, type KeyObject } from 'node:crypto';

import bs58 from 'bs58';
import { ed25519, x25519 } from '@noble/curves/ed25519';

import { AuthenticationError, CryptoError } from '../errors/index.js';
import { decodeBase64Url, encodeBase64Url } from './base64.js';
import { decodePem, encodePem } from './pem.js';

export type KeyType = 'secp256k1' | 'secp256r1' | 'ed25519' | 'x25519';
export type PrivateKeyInput = string | PrivateKeyMaterial;
export type PublicKeyInput = string | PublicKeyMaterial;

export interface PrivateKeyMaterial {
  type: KeyType;
  bytes: Uint8Array;
}

export interface PublicKeyMaterial {
  type: KeyType;
  bytes: Uint8Array;
}

export interface GeneratedKeyPairPem {
  privateKeyPem: string;
  publicKeyPem: string;
}

const PRIVATE_LABELS: Record<KeyType, string> = {
  secp256k1: 'ANP SECP256K1 PRIVATE KEY',
  secp256r1: 'ANP SECP256R1 PRIVATE KEY',
  ed25519: 'ANP ED25519 PRIVATE KEY',
  x25519: 'ANP X25519 PRIVATE KEY',
};

const PUBLIC_LABELS: Record<KeyType, string> = {
  secp256k1: 'ANP SECP256K1 PUBLIC KEY',
  secp256r1: 'ANP SECP256R1 PUBLIC KEY',
  ed25519: 'ANP ED25519 PUBLIC KEY',
  x25519: 'ANP X25519 PUBLIC KEY',
};

const EC_CURVES: Record<'secp256k1' | 'secp256r1', string> = {
  secp256k1: 'secp256k1',
  secp256r1: 'prime256v1',
};

export function sha256(value: Uint8Array): Uint8Array {
  return new Uint8Array(createHash('sha256').update(value).digest());
}

export function normalizePrivateKeyMaterial(input: PrivateKeyInput): PrivateKeyMaterial {
  return typeof input === 'string' ? privateKeyFromPem(input) : input;
}

export function normalizePublicKeyMaterial(input: PublicKeyInput): PublicKeyMaterial {
  return typeof input === 'string' ? publicKeyFromPem(input) : input;
}

export function generatePrivateKeyMaterial(type: KeyType): PrivateKeyMaterial {
  switch (type) {
    case 'secp256k1': {
      const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
      const jwk = privateKey.export({ format: 'jwk' }) as JsonWebKey;
      return { type, bytes: requireBase64UrlBytes(jwk.d, 'Missing secp256k1 private key') };
    }
    case 'secp256r1': {
      const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const jwk = privateKey.export({ format: 'jwk' }) as JsonWebKey;
      return { type, bytes: requireBase64UrlBytes(jwk.d, 'Missing secp256r1 private key') };
    }
    case 'ed25519': {
      const { privateKey } = generateKeyPairSync('ed25519');
      const jwk = privateKey.export({ format: 'jwk' }) as JsonWebKey;
      return { type, bytes: requireBase64UrlBytes(jwk.d, 'Missing ed25519 private key') };
    }
    case 'x25519': {
      const { privateKey } = generateKeyPairSync('x25519');
      const jwk = privateKey.export({ format: 'jwk' }) as JsonWebKey;
      return { type, bytes: requireBase64UrlBytes(jwk.d, 'Missing x25519 private key') };
    }
    default:
      throw new CryptoError(`Unsupported key type: ${String(type)}`);
  }
}

export function derivePublicKey(privateKey: PrivateKeyMaterial): PublicKeyMaterial {
  switch (privateKey.type) {
    case 'secp256k1':
    case 'secp256r1': {
      const ecdh = createECDH(EC_CURVES[privateKey.type]);
      ecdh.setPrivateKey(Buffer.from(privateKey.bytes));
      return {
        type: privateKey.type,
        bytes: new Uint8Array(ecdh.getPublicKey(undefined, 'compressed')),
      };
    }
    case 'ed25519':
      return { type: 'ed25519', bytes: ed25519.getPublicKey(privateKey.bytes) };
    case 'x25519':
      return { type: 'x25519', bytes: x25519.getPublicKey(privateKey.bytes) };
    default:
      throw new CryptoError(`Unsupported key type: ${String(privateKey.type)}`);
  }
}

export function generateKeyPairPem(type: KeyType): {
  privateKey: PrivateKeyMaterial;
  publicKey: PublicKeyMaterial;
  pair: GeneratedKeyPairPem;
} {
  const privateKey = generatePrivateKeyMaterial(type);
  const publicKey = derivePublicKey(privateKey);
  return {
    privateKey,
    publicKey,
    pair: {
      privateKeyPem: privateKeyToPem(privateKey),
      publicKeyPem: publicKeyToPem(publicKey),
    },
  };
}

export function privateKeyToPem(privateKey: PrivateKeyMaterial): string {
  return encodePem(PRIVATE_LABELS[privateKey.type], privateKey.bytes);
}

export function publicKeyToPem(publicKey: PublicKeyMaterial): string {
  return encodePem(PUBLIC_LABELS[publicKey.type], publicKey.bytes);
}

export function privateKeyFromPem(input: string): PrivateKeyMaterial {
  const decoded = decodePem(input);
  return { type: keyTypeFromLabel(decoded.label, true), bytes: decoded.bytes };
}

export function publicKeyFromPem(input: string): PublicKeyMaterial {
  const decoded = decodePem(input);
  return { type: keyTypeFromLabel(decoded.label, false), bytes: decoded.bytes };
}

export function signMessage(privateKey: PrivateKeyMaterial, message: Uint8Array): Uint8Array {
  const keyObject = toPrivateKeyObject(privateKey);
  switch (privateKey.type) {
    case 'secp256k1':
    case 'secp256r1':
      return new Uint8Array(
        cryptoSign('sha256', Buffer.from(message), {
          key: keyObject,
          dsaEncoding: 'ieee-p1363',
        })
      );
    case 'ed25519':
      return new Uint8Array(cryptoSign(null, Buffer.from(message), keyObject));
    case 'x25519':
      throw new CryptoError('X25519 keys cannot be used for signing');
    default:
      throw new CryptoError(`Unsupported key type: ${String(privateKey.type)}`);
  }
}

export function verifyMessage(publicKey: PublicKeyMaterial, message: Uint8Array, signature: Uint8Array): boolean {
  const keyObject = toPublicKeyObject(publicKey);
  switch (publicKey.type) {
    case 'secp256k1':
    case 'secp256r1':
      return cryptoVerify(
        'sha256',
        Buffer.from(message),
        { key: keyObject, dsaEncoding: 'ieee-p1363' },
        Buffer.from(signature)
      );
    case 'ed25519':
      return cryptoVerify(null, Buffer.from(message), keyObject, Buffer.from(signature));
    case 'x25519':
      throw new CryptoError('X25519 keys cannot be used for signature verification');
    default:
      throw new CryptoError(`Unsupported key type: ${String(publicKey.type)}`);
  }
}

export function publicKeyToJwk(publicKey: PublicKeyMaterial): JsonWebKey {
  switch (publicKey.type) {
    case 'secp256k1':
    case 'secp256r1': {
      const uncompressed = new Uint8Array(
        ECDH.convertKey(
          Buffer.from(publicKey.bytes),
          EC_CURVES[publicKey.type],
          undefined,
          undefined,
          'uncompressed'
        ) as Buffer
      );
      if (uncompressed.length !== 65 || uncompressed[0] !== 0x04) {
        throw new AuthenticationError('Invalid EC public key');
      }
      return {
        kty: 'EC',
        crv: publicKey.type === 'secp256k1' ? 'secp256k1' : 'P-256',
        x: encodeBase64Url(uncompressed.slice(1, 33)),
        y: encodeBase64Url(uncompressed.slice(33, 65)),
      };
    }
    case 'ed25519':
      return { kty: 'OKP', crv: 'Ed25519', x: encodeBase64Url(publicKey.bytes) };
    case 'x25519':
      return { kty: 'OKP', crv: 'X25519', x: encodeBase64Url(publicKey.bytes) };
    default:
      throw new AuthenticationError('Unsupported public key type');
  }
}

export function computeJwkThumbprint(jwk: JsonWebKey): string {
  const ordered = Object.keys(jwk)
    .sort()
    .reduce<Record<string, string>>((result, key) => {
      const value = jwk[key as keyof JsonWebKey];
      if (typeof value === 'string') {
        result[key] = value;
      }
      return result;
    }, {});
  return encodeBase64Url(sha256(new TextEncoder().encode(JSON.stringify(ordered))));
}

export function ed25519PublicKeyToMultibase(publicKey: Uint8Array): string {
  return `z${bs58.encode(Buffer.concat([Buffer.from([0xed, 0x01]), Buffer.from(publicKey)]))}`;
}

export function x25519PublicKeyToMultibase(publicKey: Uint8Array): string {
  return `z${bs58.encode(Buffer.concat([Buffer.from([0xec, 0x01]), Buffer.from(publicKey)]))}`;
}

export function parseEd25519Multibase(value: string): PublicKeyMaterial {
  const bytes = bs58.decode(stripMultibasePrefix(value));
  const normalized = bytes.length === 34 && bytes[0] === 0xed && bytes[1] === 0x01 ? bytes.slice(2) : bytes;
  if (normalized.length !== 32) {
    throw new AuthenticationError('Invalid Ed25519 multibase value');
  }
  return { type: 'ed25519', bytes: new Uint8Array(normalized) };
}

export function parseX25519Multibase(value: string): PublicKeyMaterial {
  const bytes = bs58.decode(stripMultibasePrefix(value));
  const normalized = bytes.length === 34 && bytes[0] === 0xec && bytes[1] === 0x01 ? bytes.slice(2) : bytes;
  if (normalized.length !== 32) {
    throw new AuthenticationError('Invalid X25519 multibase value');
  }
  return { type: 'x25519', bytes: new Uint8Array(normalized) };
}

export function publicKeyFromJwk(jwk: JsonWebKey): PublicKeyMaterial {
  if (jwk.kty === 'EC' && jwk.x && jwk.y) {
    const curve = jwk.crv;
    if (curve !== 'secp256k1' && curve !== 'P-256') {
      throw new AuthenticationError(`Unsupported EC curve: ${curve}`);
    }
    const uncompressed = Buffer.concat([
      Buffer.from([0x04]),
      Buffer.from(decodeBase64Url(jwk.x)),
      Buffer.from(decodeBase64Url(jwk.y)),
    ]);
    const bytes = new Uint8Array(
      ECDH.convertKey(
        uncompressed,
        curve === 'secp256k1' ? 'secp256k1' : 'prime256v1',
        undefined,
        undefined,
        'compressed'
      ) as Buffer
    );
    return { type: curve === 'secp256k1' ? 'secp256k1' : 'secp256r1', bytes };
  }
  if (jwk.kty === 'OKP' && jwk.x) {
    if (jwk.crv === 'Ed25519') {
      return { type: 'ed25519', bytes: decodeBase64Url(jwk.x) };
    }
    if (jwk.crv === 'X25519') {
      return { type: 'x25519', bytes: decodeBase64Url(jwk.x) };
    }
  }
  throw new AuthenticationError('Unsupported JWK key material');
}

export function toPrivateKeyObject(privateKey: PrivateKeyMaterial): KeyObject {
  switch (privateKey.type) {
    case 'secp256k1':
    case 'secp256r1': {
      const ecdh = createECDH(EC_CURVES[privateKey.type]);
      ecdh.setPrivateKey(Buffer.from(privateKey.bytes));
      const publicKey = new Uint8Array(ecdh.getPublicKey(undefined, 'uncompressed'));
      return createPrivateKey({
        key: {
          kty: 'EC',
          crv: privateKey.type === 'secp256k1' ? 'secp256k1' : 'P-256',
          d: encodeBase64Url(privateKey.bytes),
          x: encodeBase64Url(publicKey.slice(1, 33)),
          y: encodeBase64Url(publicKey.slice(33, 65)),
        },
        format: 'jwk',
      });
    }
    case 'ed25519': {
      const publicKey = ed25519.getPublicKey(privateKey.bytes);
      return createPrivateKey({
        key: {
          kty: 'OKP',
          crv: 'Ed25519',
          d: encodeBase64Url(privateKey.bytes),
          x: encodeBase64Url(publicKey),
        },
        format: 'jwk',
      });
    }
    case 'x25519': {
      const publicKey = x25519.getPublicKey(privateKey.bytes);
      return createPrivateKey({
        key: {
          kty: 'OKP',
          crv: 'X25519',
          d: encodeBase64Url(privateKey.bytes),
          x: encodeBase64Url(publicKey),
        },
        format: 'jwk',
      });
    }
    default:
      throw new CryptoError(`Unsupported key type: ${String(privateKey.type)}`);
  }
}

export function toPublicKeyObject(publicKey: PublicKeyMaterial): KeyObject {
  return createPublicKey({
    key: publicKeyToJwk(publicKey) as import('node:crypto').JsonWebKey,
    format: 'jwk',
  });
}

function keyTypeFromLabel(label: string, isPrivate: boolean): KeyType {
  const source = isPrivate ? PRIVATE_LABELS : PUBLIC_LABELS;
  for (const [type, candidate] of Object.entries(source)) {
    if (candidate === label) {
      return type as KeyType;
    }
  }
  throw new AuthenticationError(`Unsupported PEM label: ${label}`);
}

function requireBase64UrlBytes(value: string | undefined, message: string): Uint8Array {
  if (!value) {
    throw new AuthenticationError(message);
  }
  return decodeBase64Url(value);
}

function stripMultibasePrefix(value: string): string {
  return value.startsWith('z') ? value.slice(1) : value;
}
