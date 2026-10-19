import { AuthenticationError } from '../errors/index.js';
import {
  ed25519PublicKeyToMultibase,
  privateKeyToPem,
  type PrivateKeyMaterial,
  type PublicKeyMaterial,
} from '../internal/keys.js';
import type { DidDocument, ServiceRecord, VerificationMethodRecord } from './types.js';

/**
 * did:bid (Xinghuo BIF) integration for ANP authentication.
 *
 * Scope: resolve did:bid documents and use a pre-provisioned did:bid ED25519
 * identity to sign ANP authentication headers. This module never writes to the
 * chain; identity registration is an application/operations concern.
 *
 * The BID SDK is an ESM-only, optionally-installed dependency. It is loaded
 * lazily through a dynamic import so the main ANP entry stays free of it and the
 * CJS build keeps working on Node 20.
 *
 * Trust note: BID documents carry no self-certifying proof. ANP's binding check
 * is a no-op for did:bid, so trust rests on the chain/parser, not on the
 * document itself. Callers must treat the resolved document accordingly.
 */

/** Minimal structural view of a BID public key entry (avoids a hard type dependency). */
export interface BidPublicKeyRecord {
  id: string;
  type: string;
  controller: string;
  publicKeyHex: string;
}

/** Minimal structural view of a BID service entry. */
export interface BidServiceRecord {
  id: string;
  type: string;
  serviceEndpoint: string;
  protocol?: number;
  serverType?: number;
  version?: string;
}

/** Minimal structural view of a resolved BID document. */
export interface BuiltBidDocument {
  '@context': string[];
  version?: string;
  id: string;
  publicKey?: BidPublicKeyRecord[];
  authentication?: string[];
  service?: BidServiceRecord[];
  created?: string;
  updated?: string;
  extension?: Record<string, unknown>;
}

interface BidRawKey {
  readonly algorithm: string;
  readonly keyHex: string;
}

interface BidModuleLike {
  configureBidSdk(urls: { parserUrl?: string; directNodeUrl?: string }): unknown;
  createBidSdk(): BidSdkLike;
  bidKeypairOperations: {
    convert: { toRawPublicKey(enc: string): BidRawKey; toRawPrivateKey(enc: string): BidRawKey };
  };
}

interface BidSdkLike {
  connect(config: { mode: 'direct' }): unknown;
  bid: { resolve(id: string, options?: { signal?: AbortSignal }): Promise<BuiltBidDocument> };
}

export interface BidIntegrationConfig {
  /** Resolution service base URL, e.g. `https://xinghuoid.zetrix.com/bid/`. */
  parserUrl: string;
  /**
   * Direct chain node URL. Only used to satisfy the BID SDK's connect() check.
   * When `parserUrl` is configured, resolution never contacts this URL, so a
   * placeholder is safe. It MUST still be a valid absolute URL.
   */
  directNodeUrl?: string;
}

/** Placeholder node URL used when only parser-based resolution is wanted. */
export const DEFAULT_BID_DIRECT_NODE_URL = 'https://example.invalid';

const ED25519_PUBLIC_PREFIX = 'b06566';

let configured: BidIntegrationConfig | undefined;
let modulePromise: Promise<BidModuleLike> | undefined;
let sdk: BidSdkLike | undefined;
let connected = false;

/** True when the DID uses the did:bid method. */
export function isBidDid(did: string): boolean {
  return did.startsWith('did:bid:');
}

/**
 * Configure the did:bid integration. Call once at application startup.
 *
 * Uses the BID SDK's direct mode, which has no apiKey/apiSecret; with a
 * `parserUrl` configured, resolution goes through the parser and `directNodeUrl`
 * is never contacted.
 */
export function configureBid(config: BidIntegrationConfig): void {
  if (typeof config.parserUrl !== 'string' || config.parserUrl.length === 0) {
    throw new AuthenticationError('BID integration requires a parserUrl');
  }
  configured = {
    parserUrl: config.parserUrl,
    directNodeUrl: config.directNodeUrl ?? DEFAULT_BID_DIRECT_NODE_URL,
  };
  modulePromise = undefined;
  sdk = undefined;
  connected = false;
}

/** Reset cached SDK state. Intended for tests and reconfiguration. */
export function resetBidIntegration(): void {
  configured = undefined;
  modulePromise = undefined;
  sdk = undefined;
  connected = false;
}

async function loadBidModule(): Promise<BidModuleLike> {
  modulePromise ??= import('@caict-bif/bid-typescript-sdk')
    .then((loaded) => loaded as unknown as BidModuleLike)
    .catch((cause: unknown) => {
      modulePromise = undefined;
      throw new AuthenticationError(
        'BID SDK is unavailable; install @caict-bif/bid-typescript-sdk to use did:bid',
        cause as Error
      );
    });
  return modulePromise;
}

async function getBidSdk(): Promise<BidSdkLike> {
  if (!configured) {
    throw new AuthenticationError(
      'BID integration is not configured; call configureBid({ parserUrl }) first'
    );
  }
  const bidModule = await loadBidModule();
  if (!sdk) {
    bidModule.configureBidSdk({
      parserUrl: configured.parserUrl,
      directNodeUrl: configured.directNodeUrl,
    });
    sdk = bidModule.createBidSdk();
  }
  if (!connected) {
    sdk.connect({ mode: 'direct' });
    connected = true;
  }
  return sdk;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new AuthenticationError('BID key material is not valid hex');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function assertEd25519(raw: BidRawKey, kind: 'public' | 'private'): void {
  if (raw.algorithm !== 'ED25519') {
    throw new AuthenticationError(`Unsupported BID ${kind} key algorithm: ${raw.algorithm}`);
  }
}

/** Convert a starfire-encoded BID public key to ANP Ed25519 key material. */
export async function bidPublicKeyToMaterial(encPublicKey: string): Promise<PublicKeyMaterial> {
  const bidModule = await loadBidModule();
  const raw = bidModule.bidKeypairOperations.convert.toRawPublicKey(encPublicKey);
  assertEd25519(raw, 'public');
  return { type: 'ed25519', bytes: hexToBytes(raw.keyHex) };
}

/** Convert a starfire-encoded BID private key to ANP Ed25519 key material. */
export async function bidPrivateKeyToMaterial(encPrivateKey: string): Promise<PrivateKeyMaterial> {
  const bidModule = await loadBidModule();
  const raw = bidModule.bidKeypairOperations.convert.toRawPrivateKey(encPrivateKey);
  assertEd25519(raw, 'private');
  return { type: 'ed25519', bytes: hexToBytes(raw.keyHex) };
}

/**
 * Convert a starfire-encoded BID private key to the ANP PEM form accepted by
 * `generateAuthHeader` and `generateHttpSignatureHeaders`.
 */
export async function bidPrivateKeyToPem(encPrivateKey: string): Promise<string> {
  return privateKeyToPem(await bidPrivateKeyToMaterial(encPrivateKey));
}

/**
 * True when a starfire-encoded public key uses the ED25519 encoding
 * (`b0 65 66` + 32 bytes). Lets callers reject SM2 keys without loading the SDK.
 */
export function isEd25519StarfirePublicKey(encPublicKey: string): boolean {
  return (
    encPublicKey.length === ED25519_PUBLIC_PREFIX.length + 64 &&
    encPublicKey.toLowerCase().startsWith(ED25519_PUBLIC_PREFIX)
  );
}

/** Map a resolved BID document to the ANP DID document shape. */
export async function mapBidDocumentToDidDocument(
  document: BuiltBidDocument
): Promise<DidDocument> {
  if (typeof document.id !== 'string' || !isBidDid(document.id)) {
    throw new AuthenticationError('Invalid did:bid document id');
  }

  const verificationMethod: VerificationMethodRecord[] = [];
  for (const publicKey of document.publicKey ?? []) {
    const material = await bidPublicKeyToMaterial(publicKey.publicKeyHex);
    verificationMethod.push({
      id: publicKey.id,
      type: 'Ed25519VerificationKey2020',
      controller: publicKey.controller,
      publicKeyMultibase: ed25519PublicKeyToMultibase(material.bytes),
    });
  }

  const contexts =
    Array.isArray(document['@context']) && document['@context'].length > 0
      ? [...document['@context']]
      : ['https://www.w3.org/ns/did/v1'];

  const didDocument: DidDocument = {
    '@context': contexts,
    id: document.id,
    verificationMethod,
    authentication: [...(document.authentication ?? [])],
  };

  if (document.service && document.service.length > 0) {
    didDocument.service = document.service.map((entry) => ({
      id: entry.id,
      type: entry.type,
      serviceEndpoint: entry.serviceEndpoint,
    })) satisfies ServiceRecord[];
  }

  return didDocument;
}

/**
 * Resolve a did:bid document and map it to the ANP DID document shape. Requires
 * `configureBid({ parserUrl })` and network access to the parser service.
 */
export async function resolveBidDocument(did: string): Promise<DidDocument> {
  if (!isBidDid(did)) {
    throw new AuthenticationError('Invalid did:bid format');
  }
  const bidSdk = await getBidSdk();
  let resolved: BuiltBidDocument;
  try {
    resolved = await bidSdk.bid.resolve(did);
  } catch (cause) {
    throw new AuthenticationError(
      `Failed to resolve did:bid document: ${(cause as Error).message}`,
      cause as Error
    );
  }
  if (resolved.id !== did) {
    throw new AuthenticationError('did:bid document ID mismatch');
  }
  return mapBidDocumentToDidDocument(resolved);
}
