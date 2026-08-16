import { p256 } from '@noble/curves/p256';
import { secp256k1 } from '@noble/curves/secp256k1';
import bs58 from 'bs58';

import { DeviceManifestError } from '../errors/index.js';
import { decodeBase64Url, encodeBase64Url } from '../internal/base64.js';

export const DEVICE_MANIFEST_TYPE = 'ANPDeviceManifest';

export const PROFILE_CORE_BINDING_V1 = 'anp.core.binding.v1';
export const PROFILE_IDENTITY_DISCOVERY_V1 = 'anp.identity.discovery.v1';
export const PROFILE_DIRECT_BASE_V1 = 'anp.direct.base.v1';
export const PROFILE_GROUP_BASE_V1 = 'anp.group.base.v1';
export const PROFILE_DIRECT_E2EE_V2 = 'anp.direct.e2ee.v2';
export const PROFILE_GROUP_E2EE_V2 = 'anp.group.e2ee.v2';

export const PROFILE_CORE_BINDING_V2 = 'anp.core.binding.v2';
export const PROFILE_IDENTITY_DISCOVERY_V2 = 'anp.identity.discovery.v2';
export const PROFILE_DIRECT_BASE_V2 = 'anp.direct.base.v2';
export const PROFILE_GROUP_BASE_V2 = 'anp.group.base.v2';

const MANIFEST_FIELDS = new Set(['type', 'devices']);
const ENTRY_FIELDS = new Set(['device_id', 'signing_key_id', 'e2ee_key_id', 'profiles']);
const P5_DEPENDENCIES = new Set([
  PROFILE_CORE_BINDING_V1,
  PROFILE_IDENTITY_DISCOVERY_V1,
  PROFILE_DIRECT_BASE_V1,
  PROFILE_DIRECT_E2EE_V2,
]);
const P6_DEPENDENCIES = new Set([
  PROFILE_CORE_BINDING_V1,
  PROFILE_IDENTITY_DISCOVERY_V1,
  PROFILE_GROUP_BASE_V1,
  PROFILE_GROUP_E2EE_V2,
]);
const P5_LEGACY_DRAFT_DEPENDENCIES = new Set([
  PROFILE_CORE_BINDING_V2,
  PROFILE_IDENTITY_DISCOVERY_V2,
  PROFILE_DIRECT_BASE_V2,
  PROFILE_DIRECT_E2EE_V2,
]);
const P6_LEGACY_DRAFT_DEPENDENCIES = new Set([
  PROFILE_CORE_BINDING_V2,
  PROFILE_IDENTITY_DISCOVERY_V2,
  PROFILE_GROUP_BASE_V2,
  PROFILE_GROUP_E2EE_V2,
]);
const LEGACY_DRAFT_FOUNDATION_PROFILES = new Set([
  PROFILE_CORE_BINDING_V2,
  PROFILE_IDENTITY_DISCOVERY_V2,
  PROFILE_DIRECT_BASE_V2,
  PROFILE_GROUP_BASE_V2,
]);
const BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
const SIGNING_ALGORITHMS = new Set(['Ed25519', 'P-256', 'secp256k1']);

export type ManifestDidDocument = Record<string, unknown>;

export interface DeviceManifestEntryWire {
  device_id: string;
  signing_key_id: string;
  e2ee_key_id: string;
  profiles: string[];
}

export interface DeviceManifestWire {
  type: string;
  devices: DeviceManifestEntryWire[];
}

export class DeviceManifestEntry {
  constructor(
    public readonly deviceId: string,
    public readonly signingKeyId: string,
    public readonly e2eeKeyId: string,
    public readonly profiles: readonly string[]
  ) {}

  static fromWire(value: DeviceManifestEntryWire): DeviceManifestEntry {
    return new DeviceManifestEntry(value.device_id, value.signing_key_id, value.e2ee_key_id, [
      ...value.profiles,
    ]);
  }

  toDict(): DeviceManifestEntryWire {
    return {
      device_id: this.deviceId,
      signing_key_id: this.signingKeyId,
      e2ee_key_id: this.e2eeKeyId,
      profiles: [...this.profiles],
    };
  }
}

export class DeviceManifest {
  constructor(
    public readonly type: string,
    public readonly devices: readonly DeviceManifestEntry[]
  ) {}

  toDict(): DeviceManifestWire {
    return {
      type: this.type,
      devices: this.devices.map((device) => device.toDict()),
    };
  }
}

interface PublicKeyIdentity {
  algorithm: string;
  rawPublicKey: string;
}

export function parseDeviceManifest(didDocument: ManifestDidDocument): DeviceManifest | null {
  if (!Object.prototype.hasOwnProperty.call(didDocument, 'deviceManifest')) {
    return null;
  }
  const rawManifest = didDocument.deviceManifest;
  if (!isPlainObject(rawManifest)) {
    throw new DeviceManifestError('deviceManifest must be an object');
  }
  requireExactFields(rawManifest, MANIFEST_FIELDS, 'deviceManifest');
  if (rawManifest.type !== DEVICE_MANIFEST_TYPE) {
    throw new DeviceManifestError('deviceManifest.type must equal ANPDeviceManifest');
  }
  const rawDevices = rawManifest.devices;
  if (!Array.isArray(rawDevices)) {
    throw new DeviceManifestError('deviceManifest.devices must be an array');
  }

  const devices: DeviceManifestEntry[] = [];
  rawDevices.forEach((rawEntry, index) => {
    const subject = `deviceManifest.devices[${index}]`;
    if (!isPlainObject(rawEntry)) {
      throw new DeviceManifestError(`${subject} must be an object`);
    }
    requireExactFields(rawEntry, ENTRY_FIELDS, subject);
    const deviceId = requireString(rawEntry.device_id, `${subject}.device_id`);
    const signingKeyId = requireString(rawEntry.signing_key_id, `${subject}.signing_key_id`);
    const e2eeKeyId = requireString(rawEntry.e2ee_key_id, `${subject}.e2ee_key_id`);
    const rawProfiles = rawEntry.profiles;
    if (!Array.isArray(rawProfiles)) {
      throw new DeviceManifestError(`${subject}.profiles must be a string array`);
    }
    const profiles = rawProfiles.map((profile) => requireString(profile, `${subject}.profiles[]`));
    devices.push(new DeviceManifestEntry(deviceId, signingKeyId, e2eeKeyId, profiles));
  });

  return new DeviceManifest(DEVICE_MANIFEST_TYPE, devices);
}

export function validateDeviceManifest(didDocument: ManifestDidDocument): DeviceManifest | null {
  const manifest = parseDeviceManifest(didDocument);
  if (manifest === null) {
    return null;
  }

  const did = requireNonEmptyString(didDocument.id, 'DID document id');
  const verificationMethods = didDocument.verificationMethod;
  if (!Array.isArray(verificationMethods)) {
    throw new DeviceManifestError('DID document verificationMethod must be an array');
  }

  const methodsById = new Map<string, Record<string, unknown>[]>();
  for (const method of verificationMethods) {
    if (!isPlainObject(method)) {
      continue;
    }
    const methodId = method.id;
    if (typeof methodId === 'string') {
      const existing = methodsById.get(methodId) ?? [];
      existing.push(method);
      methodsById.set(methodId, existing);
    }
  }

  const seenDeviceIds = new Set<string>();
  const seenKeyIds = new Set<string>();
  for (const entry of manifest.devices) {
    requireNonEmptyString(entry.deviceId, 'device_id');
    requireNonEmptyString(entry.signingKeyId, 'signing_key_id');
    requireNonEmptyString(entry.e2eeKeyId, 'e2ee_key_id');
    if (entry.profiles.length === 0) {
      throw new DeviceManifestError('profiles must be non-empty');
    }
    for (const profile of entry.profiles) {
      requireNonEmptyString(profile, 'profile');
    }
    if (seenDeviceIds.has(entry.deviceId)) {
      throw new DeviceManifestError('device_id must be unique');
    }
    seenDeviceIds.add(entry.deviceId);

    if (entry.signingKeyId === entry.e2eeKeyId) {
      throw new DeviceManifestError('signing_key_id and e2ee_key_id must be distinct');
    }
    for (const keyId of [entry.signingKeyId, entry.e2eeKeyId]) {
      if (seenKeyIds.has(keyId)) {
        throw new DeviceManifestError('a verification method can belong to only one device entry');
      }
      seenKeyIds.add(keyId);
      validateSameDocumentMethod(did, keyId, methodsById);
    }

    const profileSet = new Set(entry.profiles);
    if (profileSet.has(PROFILE_DIRECT_E2EE_V2)) {
      requireDependencies(profileSet, P5_DEPENDENCIES, P5_LEGACY_DRAFT_DEPENDENCIES, 'P5');
      requireRelationship(didDocument, 'assertionMethod', entry.signingKeyId, 'P5 signing key');
    }
    if (profileSet.has(PROFILE_GROUP_E2EE_V2)) {
      requireDependencies(profileSet, P6_DEPENDENCIES, P6_LEGACY_DRAFT_DEPENDENCIES, 'P6');
      requireRelationship(didDocument, 'assertionMethod', entry.signingKeyId, 'P6 binding key');
      requireRelationship(didDocument, 'authentication', entry.signingKeyId, 'P6 origin-proof key');
    }
    requireRelationship(didDocument, 'keyAgreement', entry.e2eeKeyId, 'device E2EE key');
  }

  return manifest;
}

export function findEligibleDevice(
  didDocument: ManifestDidDocument,
  deviceId: string,
  requiredProfile: string
): DeviceManifestEntry | null {
  const manifest = validateDeviceManifest(didDocument);
  if (manifest === null) {
    return null;
  }
  if (requiredProfile !== PROFILE_DIRECT_E2EE_V2 && requiredProfile !== PROFILE_GROUP_E2EE_V2) {
    return null;
  }
  return (
    manifest.devices.find(
      (entry) => entry.deviceId === deviceId && entry.profiles.includes(requiredProfile)
    ) ?? null
  );
}

export function buildVnextDidDocument(
  baseDocument: ManifestDidDocument,
  rootKeyId: string,
  rootVerificationMethod: Record<string, unknown>,
  device: DeviceManifestEntry,
  deviceSigningVerificationMethod: Record<string, unknown>,
  deviceE2eeVerificationMethod: Record<string, unknown>
): ManifestDidDocument {
  requireCanonicalWriteProfiles(device);
  const document = cloneDocument(baseDocument);
  for (const field of [
    'verificationMethod',
    'authentication',
    'assertionMethod',
    'keyAgreement',
    'deviceManifest',
    'proof',
  ]) {
    if (field in document) {
      throw new DeviceManifestError(`base DID document must not contain managed field ${field}`);
    }
  }

  const did = documentDid(document);
  validateRootMethod(did, rootKeyId, rootVerificationMethod);
  validateDeviceMethods(
    did,
    rootKeyId,
    device,
    deviceSigningVerificationMethod,
    deviceE2eeVerificationMethod
  );
  Object.assign(document, {
    verificationMethod: [
      structuredClone(rootVerificationMethod),
      structuredClone(deviceSigningVerificationMethod),
      structuredClone(deviceE2eeVerificationMethod),
    ],
    authentication: [device.signingKeyId],
    assertionMethod: [rootKeyId, device.signingKeyId],
    keyAgreement: [device.e2eeKeyId],
    deviceManifest: {
      type: DEVICE_MANIFEST_TYPE,
      devices: [device.toDict()],
    },
  });
  validateVnextDocument(document, rootKeyId);
  return document;
}

export function addDeviceToDidDocument(
  didDocument: ManifestDidDocument,
  rootKeyId: string,
  device: DeviceManifestEntry,
  deviceSigningVerificationMethod: Record<string, unknown>,
  deviceE2eeVerificationMethod: Record<string, unknown>,
  retiredDeviceIds: Iterable<string>
): ManifestDidDocument {
  requireCanonicalWriteProfiles(device);
  const document = prepareDocumentForMutation(didDocument, rootKeyId);
  const manifest = validateDeviceManifest(document);
  if (manifest === null) {
    throw new DeviceManifestError('deviceManifest is required for device update');
  }
  if (manifest.devices.some((entry) => entry.deviceId === device.deviceId)) {
    throw new DeviceManifestError('device_id already exists');
  }
  const retired = validateRetiredDeviceIds(retiredDeviceIds);
  if (retired.has(device.deviceId)) {
    throw new DeviceManifestError('retired device_id cannot be reused');
  }
  appendDeviceMaterial(
    document,
    rootKeyId,
    device,
    deviceSigningVerificationMethod,
    deviceE2eeVerificationMethod
  );
  validateVnextDocument(document, rootKeyId);
  return document;
}

export function updateDeviceInDidDocument(
  didDocument: ManifestDidDocument,
  rootKeyId: string,
  device: DeviceManifestEntry,
  deviceSigningVerificationMethod: Record<string, unknown>,
  deviceE2eeVerificationMethod: Record<string, unknown>
): ManifestDidDocument {
  requireCanonicalWriteProfiles(device);
  const document = prepareDocumentForMutation(didDocument, rootKeyId);
  const manifest = validateDeviceManifest(document);
  if (manifest === null) {
    throw new DeviceManifestError('deviceManifest is required for device update');
  }
  const oldEntry = manifest.devices.find((entry) => entry.deviceId === device.deviceId);
  if (oldEntry === undefined) {
    throw new DeviceManifestError('device_id does not exist');
  }
  removeDeviceMaterial(document, oldEntry);
  appendDeviceMaterial(
    document,
    rootKeyId,
    device,
    deviceSigningVerificationMethod,
    deviceE2eeVerificationMethod
  );
  validateVnextDocument(document, rootKeyId);
  return document;
}

export function removeDeviceFromDidDocument(
  didDocument: ManifestDidDocument,
  rootKeyId: string,
  deviceId: string
): ManifestDidDocument {
  const document = prepareDocumentForMutation(didDocument, rootKeyId);
  const manifest = validateDeviceManifest(document);
  if (manifest === null) {
    throw new DeviceManifestError('deviceManifest is required for device update');
  }
  const oldEntry = manifest.devices.find((entry) => entry.deviceId === deviceId);
  if (oldEntry === undefined) {
    throw new DeviceManifestError('device_id does not exist');
  }
  removeDeviceMaterial(document, oldEntry);
  validateVnextDocument(document, rootKeyId);
  return document;
}

function cloneDocument(didDocument: ManifestDidDocument): ManifestDidDocument {
  if (!isPlainObject(didDocument)) {
    throw new DeviceManifestError('DID document must be an object');
  }
  validateJsonValue(didDocument, 'DID document');
  return structuredClone(didDocument);
}

function documentDid(didDocument: ManifestDidDocument): string {
  return requireNonEmptyString(didDocument.id, 'DID document id');
}

function prepareDocumentForMutation(
  didDocument: ManifestDidDocument,
  rootKeyId: string
): ManifestDidDocument {
  const document = cloneDocument(didDocument);
  validateVnextDocument(document, rootKeyId);
  const manifest = validateDeviceManifest(document);
  if (manifest === null) {
    throw new DeviceManifestError('deviceManifest is required');
  }
  for (const entry of manifest.devices) {
    requireCanonicalWriteProfiles(entry);
  }
  delete document.proof;
  return document;
}

function requireCanonicalWriteProfiles(device: DeviceManifestEntry): void {
  if (device.profiles.some((profile) => LEGACY_DRAFT_FOUNDATION_PROFILES.has(profile))) {
    throw new DeviceManifestError(
      'legacy draft foundation profiles are read-only and cannot be published'
    );
  }
}

function validateVnextDocument(didDocument: ManifestDidDocument, rootKeyId: string): void {
  validateJsonValue(didDocument, 'DID document');
  rejectPrivateKeyMaterial(didDocument, 'DID document');
  const did = documentDid(didDocument);
  const methods = didDocument.verificationMethod;
  if (!Array.isArray(methods)) {
    throw new DeviceManifestError('DID document verificationMethod must be an array');
  }
  const rootMethods = methods.filter((method) => isPlainObject(method) && method.id === rootKeyId);
  if (rootMethods.length !== 1 || !isPlainObject(rootMethods[0])) {
    throw new DeviceManifestError('root key must resolve exactly once in verificationMethod');
  }
  const rootIdentity = validateRootMethod(did, rootKeyId, rootMethods[0]);
  requireRelationship(didDocument, 'assertionMethod', rootKeyId, 'DID root key');
  const manifest = validateDeviceManifest(didDocument);
  if (manifest === null) {
    throw new DeviceManifestError('deviceManifest is required');
  }
  const seenMaterial = new Set([rootIdentity.rawPublicKey]);
  for (const entry of manifest.devices) {
    if (rootKeyId === entry.signingKeyId || rootKeyId === entry.e2eeKeyId) {
      throw new DeviceManifestError('DID root key cannot be a device key');
    }
    const signingMethod = uniqueMethod(didDocument, entry.signingKeyId);
    const e2eeMethod = uniqueMethod(didDocument, entry.e2eeKeyId);
    const [signingIdentity, e2eeIdentity] = validateDeviceMethods(
      did,
      rootKeyId,
      entry,
      signingMethod,
      e2eeMethod
    );
    requireRelationship(didDocument, 'authentication', entry.signingKeyId, 'device signing key');
    requireRelationship(didDocument, 'assertionMethod', entry.signingKeyId, 'device signing key');
    requireRelationship(didDocument, 'keyAgreement', entry.e2eeKeyId, 'device E2EE key');
    if (relationshipContains(didDocument, 'keyAgreement', entry.signingKeyId)) {
      throw new DeviceManifestError('device signing key must not be in keyAgreement');
    }
    if (
      relationshipContains(didDocument, 'authentication', entry.e2eeKeyId) ||
      relationshipContains(didDocument, 'assertionMethod', entry.e2eeKeyId)
    ) {
      throw new DeviceManifestError('device E2EE key must not be a signing relationship');
    }
    for (const identity of [signingIdentity, e2eeIdentity]) {
      if (seenMaterial.has(identity.rawPublicKey)) {
        throw new DeviceManifestError('root and device public key material must be unique');
      }
      seenMaterial.add(identity.rawPublicKey);
    }
  }
}

function validateRootMethod(
  did: string,
  rootKeyId: string,
  verificationMethod: Record<string, unknown>
): PublicKeyIdentity {
  return validatePublicMethod(
    did,
    rootKeyId,
    verificationMethod,
    SIGNING_ALGORITHMS,
    'DID root verification method'
  );
}

function validateDeviceMethods(
  did: string,
  rootKeyId: string,
  device: DeviceManifestEntry,
  signingMethod: Record<string, unknown>,
  e2eeMethod: Record<string, unknown>
): [PublicKeyIdentity, PublicKeyIdentity] {
  if (rootKeyId === device.signingKeyId || rootKeyId === device.e2eeKeyId) {
    throw new DeviceManifestError('DID root key cannot be a device key');
  }
  const standardObjectProof = device.profiles.some(
    (profile) => profile === PROFILE_DIRECT_E2EE_V2 || profile === PROFILE_GROUP_E2EE_V2
  );
  const signingIdentity = validatePublicMethod(
    did,
    device.signingKeyId,
    signingMethod,
    standardObjectProof ? new Set(['Ed25519']) : SIGNING_ALGORITHMS,
    'device signing verification method'
  );
  const e2eeIdentity = validatePublicMethod(
    did,
    device.e2eeKeyId,
    e2eeMethod,
    new Set(['X25519']),
    'device E2EE verification method'
  );
  if (signingIdentity.rawPublicKey === e2eeIdentity.rawPublicKey) {
    throw new DeviceManifestError('device key material must be unique across roles');
  }
  return [signingIdentity, e2eeIdentity];
}

function validatePublicMethod(
  did: string,
  expectedKeyId: string,
  method: Record<string, unknown>,
  allowedAlgorithms: Set<string>,
  subject: string
): PublicKeyIdentity {
  if (!isPlainObject(method)) {
    throw new DeviceManifestError(`${subject} must be an object`);
  }
  validateJsonValue(method, subject);
  if (method.id !== expectedKeyId) {
    throw new DeviceManifestError(`${subject} id does not match its role`);
  }
  if (method.controller !== did) {
    throw new DeviceManifestError(`${subject} controller must match the DID`);
  }
  validateSameDocumentKeyId(did, expectedKeyId);
  rejectPrivateKeyMaterial(method, subject);
  const methodType = requireNonEmptyString(method.type, `${subject}.type`);
  const materialFields = ['publicKeyJwk', 'publicKeyMultibase', 'publicKeyBase58'].filter((field) =>
    Object.prototype.hasOwnProperty.call(method, field)
  );
  if (materialFields.length !== 1) {
    throw new DeviceManifestError(`${subject} must contain exactly one supported public key field`);
  }
  const materialField = materialFields[0];
  let identity: PublicKeyIdentity;
  if (materialField === 'publicKeyJwk') {
    identity = decodePublicJwk(methodType, method[materialField], subject);
  } else if (materialField === 'publicKeyMultibase') {
    identity = decodePublicMultikey(methodType, method[materialField], subject);
  } else {
    throw new DeviceManifestError(`${subject} publicKeyBase58 is not supported by vNext helpers`);
  }
  if (!allowedAlgorithms.has(identity.algorithm)) {
    throw new DeviceManifestError(`${subject} uses the wrong key algorithm`);
  }
  return identity;
}

function validateSameDocumentKeyId(did: string, keyId: string): void {
  if (!keyId.startsWith(`${did}#`) || keyId === `${did}#`) {
    throw new DeviceManifestError('key id must be a DID URL in the same document');
  }
}

function decodePublicJwk(methodType: string, value: unknown, subject: string): PublicKeyIdentity {
  if (
    methodType !== 'JsonWebKey2020' &&
    methodType !== 'EcdsaSecp256k1VerificationKey2019' &&
    methodType !== 'EcdsaSecp256r1VerificationKey2019'
  ) {
    throw new DeviceManifestError(`${subject} type is incompatible with publicKeyJwk`);
  }
  if (!isPlainObject(value)) {
    throw new DeviceManifestError(`${subject}.publicKeyJwk must be an object`);
  }
  const kty = value.kty;
  const curve = value.crv;
  if (kty === 'OKP' && (curve === 'Ed25519' || curve === 'X25519')) {
    if (methodType !== 'JsonWebKey2020') {
      throw new DeviceManifestError(`${subject} type contradicts its JWK`);
    }
    const raw = decodeCanonicalBase64url32(value.x, `${subject}.x`);
    return { algorithm: curve, rawPublicKey: encodeRaw(raw) };
  }
  if (kty === 'EC' && (curve === 'P-256' || curve === 'secp256k1')) {
    const expectedType =
      curve === 'P-256' ? 'EcdsaSecp256r1VerificationKey2019' : 'EcdsaSecp256k1VerificationKey2019';
    if (methodType !== 'JsonWebKey2020' && methodType !== expectedType) {
      throw new DeviceManifestError(`${subject} type contradicts its JWK`);
    }
    const x = decodeCanonicalBase64url32(value.x, `${subject}.x`);
    const y = decodeCanonicalBase64url32(value.y, `${subject}.y`);
    validateEcPoint(curve, x, y, subject);
    return { algorithm: curve, rawPublicKey: encodeRaw(concatBytes(x, y)) };
  }
  throw new DeviceManifestError(`${subject} contains an unsupported public JWK`);
}

function decodePublicMultikey(
  methodType: string,
  value: unknown,
  subject: string
): PublicKeyIdentity {
  if (methodType !== 'Multikey' && methodType !== 'X25519KeyAgreementKey2019') {
    throw new DeviceManifestError(`${subject} type is incompatible with publicKeyMultibase`);
  }
  if (typeof value !== 'string' || !value.startsWith('z') || value.length === 1) {
    throw new DeviceManifestError(`${subject}.publicKeyMultibase must be base58btc`);
  }
  let decoded: Uint8Array;
  try {
    decoded = bs58.decode(value.slice(1));
  } catch (error) {
    throw new DeviceManifestError(`${subject}.publicKeyMultibase is invalid`, error as Error);
  }
  if (`z${bs58.encode(decoded)}` !== value) {
    throw new DeviceManifestError(`${subject}.publicKeyMultibase must be canonical`);
  }
  if (decoded.length !== 34) {
    throw new DeviceManifestError(`${subject}.publicKeyMultibase must contain a 32-byte key`);
  }
  const prefix = decoded[0] * 256 + decoded[1];
  let algorithm: string;
  if (prefix === 0xed01) {
    algorithm = 'Ed25519';
  } else if (prefix === 0xec01) {
    algorithm = 'X25519';
  } else {
    throw new DeviceManifestError(`${subject}.publicKeyMultibase uses an unsupported codec`);
  }
  if (methodType === 'X25519KeyAgreementKey2019' && algorithm !== 'X25519') {
    throw new DeviceManifestError(`${subject} type contradicts its Multikey`);
  }
  return { algorithm, rawPublicKey: encodeRaw(decoded.slice(2)) };
}

function decodeCanonicalBase64url32(value: unknown, subject: string): Uint8Array {
  if (typeof value !== 'string' || !BASE64URL_RE.test(value)) {
    throw new DeviceManifestError(`${subject} must be unpadded base64url`);
  }
  let decoded: Uint8Array;
  try {
    decoded = decodeBase64Url(value);
  } catch (error) {
    throw new DeviceManifestError(`${subject} is invalid base64url`, error as Error);
  }
  const canonical = encodeBase64Url(decoded);
  if (decoded.length !== 32 || canonical !== value) {
    throw new DeviceManifestError(`${subject} must canonically encode 32 bytes`);
  }
  return decoded;
}

function validateEcPoint(
  curve: 'P-256' | 'secp256k1',
  x: Uint8Array,
  y: Uint8Array,
  subject: string
): void {
  const uncompressed = new Uint8Array(65);
  uncompressed[0] = 0x04;
  uncompressed.set(x, 1);
  uncompressed.set(y, 33);
  try {
    if (curve === 'P-256') {
      p256.ProjectivePoint.fromHex(uncompressed);
    } else {
      secp256k1.ProjectivePoint.fromHex(uncompressed);
    }
  } catch (error) {
    throw new DeviceManifestError(`${subject} contains an invalid EC point`, error as Error);
  }
}

function rejectPrivateKeyMaterial(value: unknown, subject: string): void {
  if (isPlainObject(value)) {
    for (const [key, nested] of Object.entries(value)) {
      const normalizedKey = key.toLowerCase().replaceAll('_', '').replaceAll('-', '');
      if (normalizedKey.includes('privatekey') || (key === 'd' && 'kty' in value)) {
        throw new DeviceManifestError(`${subject} must not contain private key material`);
      }
      rejectPrivateKeyMaterial(nested, subject);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const nested of value) {
      rejectPrivateKeyMaterial(nested, subject);
    }
  }
}

function validateJsonValue(value: unknown, subject: string): void {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new DeviceManifestError(`${subject} contains a non-finite number`);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const nested of value) {
      validateJsonValue(nested, subject);
    }
    return;
  }
  if (isPlainObject(value)) {
    for (const [key, nested] of Object.entries(value)) {
      if (typeof key !== 'string') {
        throw new DeviceManifestError(`${subject} contains a non-string object key`);
      }
      validateJsonValue(nested, subject);
    }
    return;
  }
  throw new DeviceManifestError(`${subject} contains a non-JSON value`);
}

function validateRetiredDeviceIds(retiredDeviceIds: Iterable<string>): Set<string> {
  if (typeof retiredDeviceIds === 'string') {
    throw new DeviceManifestError('retired_device_ids must be a string collection');
  }
  const values: string[] = [];
  try {
    for (const deviceId of retiredDeviceIds) {
      values.push(deviceId);
    }
  } catch (error) {
    throw new DeviceManifestError('retired_device_ids must be a string collection', error as Error);
  }
  for (const deviceId of values) {
    requireNonEmptyString(deviceId, 'retired device_id');
  }
  return new Set(values);
}

function uniqueMethod(didDocument: ManifestDidDocument, keyId: string): Record<string, unknown> {
  const methods = didDocument.verificationMethod;
  if (!Array.isArray(methods)) {
    throw new DeviceManifestError('DID document verificationMethod must be an array');
  }
  const matches = methods.filter((method) => isPlainObject(method) && method.id === keyId);
  if (matches.length !== 1 || !isPlainObject(matches[0])) {
    throw new DeviceManifestError('key id must resolve exactly once in verificationMethod');
  }
  return matches[0];
}

function appendDeviceMaterial(
  document: ManifestDidDocument,
  rootKeyId: string,
  device: DeviceManifestEntry,
  signingMethod: Record<string, unknown>,
  e2eeMethod: Record<string, unknown>
): void {
  const did = documentDid(document);
  validateDeviceMethods(did, rootKeyId, device, signingMethod, e2eeMethod);
  const methods = document.verificationMethod;
  const authentication = document.authentication;
  const assertionMethod = document.assertionMethod;
  const keyAgreement = document.keyAgreement;
  const manifest = document.deviceManifest;
  if (
    !Array.isArray(methods) ||
    !Array.isArray(authentication) ||
    !Array.isArray(assertionMethod) ||
    !Array.isArray(keyAgreement) ||
    !isPlainObject(manifest) ||
    !Array.isArray(manifest.devices)
  ) {
    throw new DeviceManifestError('DID document relationships are invalid');
  }
  methods.push(structuredClone(signingMethod), structuredClone(e2eeMethod));
  authentication.push(device.signingKeyId);
  assertionMethod.push(device.signingKeyId);
  keyAgreement.push(device.e2eeKeyId);
  manifest.devices.push(device.toDict());
}

function removeDeviceMaterial(document: ManifestDidDocument, device: DeviceManifestEntry): void {
  const keyIds = new Set([device.signingKeyId, device.e2eeKeyId]);
  const methods = document.verificationMethod;
  if (!Array.isArray(methods)) {
    throw new DeviceManifestError('DID document verificationMethod must be an array');
  }
  document.verificationMethod = methods.filter(
    (method) => !(isPlainObject(method) && typeof method.id === 'string' && keyIds.has(method.id))
  );
  for (const relationship of ['authentication', 'assertionMethod', 'keyAgreement']) {
    const entries = document[relationship];
    if (!Array.isArray(entries)) {
      throw new DeviceManifestError(`${relationship} must be an array`);
    }
    document[relationship] = entries.filter(
      (entry) => ![...keyIds].some((keyId) => relationshipEntryIs(entry, keyId))
    );
  }
  const manifest = document.deviceManifest;
  if (!isPlainObject(manifest) || !Array.isArray(manifest.devices)) {
    throw new DeviceManifestError('deviceManifest.devices must be an array');
  }
  manifest.devices = manifest.devices.filter(
    (entry) => !(isPlainObject(entry) && entry.device_id === device.deviceId)
  );
}

function relationshipEntryIs(entry: unknown, keyId: string): boolean {
  return entry === keyId || (isPlainObject(entry) && entry.id === keyId);
}

function relationshipContains(
  didDocument: ManifestDidDocument,
  relationship: string,
  keyId: string
): boolean {
  const entries = didDocument[relationship];
  return Array.isArray(entries) && entries.some((entry) => relationshipEntryIs(entry, keyId));
}

function requireExactFields(
  value: Record<string, unknown>,
  expected: Set<string>,
  subject: string
): void {
  const actual = new Set(Object.keys(value));
  if (actual.size !== expected.size || [...expected].some((field) => !actual.has(field))) {
    throw new DeviceManifestError(
      `${subject} must contain exactly ${[...expected].sort().join(', ')}`
    );
  }
}

function requireString(value: unknown, subject: string): string {
  if (typeof value !== 'string') {
    throw new DeviceManifestError(`${subject} must be a string`);
  }
  return value;
}

function requireNonEmptyString(value: unknown, subject: string): string {
  const result = requireString(value, subject);
  if (!result) {
    throw new DeviceManifestError(`${subject} must be a non-empty string`);
  }
  return result;
}

function validateSameDocumentMethod(
  did: string,
  keyId: string,
  methodsById: Map<string, Record<string, unknown>[]>
): void {
  if (!keyId.startsWith(`${did}#`) || keyId === `${did}#`) {
    throw new DeviceManifestError('device key IDs must be DID URLs in the same DID document');
  }
  const methods = methodsById.get(keyId) ?? [];
  if (methods.length !== 1) {
    throw new DeviceManifestError('device key ID must resolve exactly once in verificationMethod');
  }
}

function requireDependencies(
  profiles: Set<string>,
  required: Set<string>,
  legacyDraft: Set<string>,
  profileName: string
): void {
  const hasRequired = [...required].every((profile) => profiles.has(profile));
  const hasLegacy = [...legacyDraft].every((profile) => profiles.has(profile));
  if (!hasRequired && !hasLegacy) {
    throw new DeviceManifestError(`${profileName} device profile dependencies are incomplete`);
  }
}

function requireRelationship(
  didDocument: ManifestDidDocument,
  relationship: string,
  keyId: string,
  subject: string
): void {
  const entries = didDocument[relationship];
  if (!Array.isArray(entries)) {
    throw new DeviceManifestError(`${subject} requires ${relationship}`);
  }
  for (const entry of entries) {
    if (entry === keyId) {
      return;
    }
    if (isPlainObject(entry) && entry.id === keyId) {
      return;
    }
  }
  throw new DeviceManifestError(`${subject} is not authorized by ${relationship}`);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function encodeRaw(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

function concatBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
  const output = new Uint8Array(left.length + right.length);
  output.set(left);
  output.set(right, left.length);
  return output;
}
