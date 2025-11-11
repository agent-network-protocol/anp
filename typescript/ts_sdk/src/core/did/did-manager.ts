/**
 * DID Manager for creating and managing DID:WBA identities
 */

import {
  generateKeyPair,
  KeyType,
  exportPublicKeyJWK,
} from '../../crypto/key-generation.js';
import { sign as cryptoSign, verify as cryptoVerify } from '../../crypto/signing.js';
import { DIDResolutionError } from '../../errors/index.js';
import type {
  DIDDocument,
  DIDIdentity,
  CreateDIDOptions,
  ResolveDIDOptions,
  VerificationMethod,
} from '../../types/index.js';

/**
 * Key metadata for tracking key types
 */
interface KeyMetadata {
  key: CryptoKey;
  type: KeyType;
}

/**
 * Signature structure
 */
export interface Signature {
  value: Uint8Array;
  verificationMethod: string;
}

/**
 * Cache entry for resolved DID documents
 */
interface CacheEntry {
  document: DIDDocument;
  timestamp: number;
}

/**
 * Configuration for DID Manager
 */
export interface DIDManagerConfig {
  cacheTTL?: number; // Cache TTL in milliseconds (default: 5 minutes)
  timeout?: number; // HTTP timeout in milliseconds (default: 10 seconds)
}

/**
 * DID Manager class for managing DID:WBA identities
 */
export class DIDManager {
  private cache: Map<string, CacheEntry> = new Map();
  private readonly cacheTTL: number;
  private readonly timeout: number;

  constructor(config: DIDManagerConfig = {}) {
    this.cacheTTL = config.cacheTTL ?? 5 * 60 * 1000; // 5 minutes default
    this.timeout = config.timeout ?? 10000; // 10 seconds default
  }

  /**
   * Create a new DID:WBA identity
   */
  async createDID(options: CreateDIDOptions): Promise<DIDIdentity> {
    // Validate domain
    this.validateDomain(options.domain);

    // Validate port if provided
    if (options.port !== undefined) {
      this.validatePort(options.port);
    }

    // Construct DID identifier
    const did = this.constructDID(options);

    // Generate keys
    const authKeyPair = await generateKeyPair(KeyType.ED25519);
    const keyAgreementPair = await generateKeyPair(KeyType.X25519);

    // Export public keys
    const authPublicKeyJwk = await exportPublicKeyJWK(authKeyPair.publicKey);
    const keyAgreementPublicKeyJwk = await exportPublicKeyJWK(
      keyAgreementPair.publicKey
    );

    // Create verification methods
    const authVerificationMethod: VerificationMethod = {
      id: `${did}#auth-key`,
      type: 'Ed25519VerificationKey2020',
      controller: did,
      publicKeyJwk: authPublicKeyJwk,
    };

    const keyAgreementVerificationMethod: VerificationMethod = {
      id: `${did}#key-agreement`,
      type: 'X25519KeyAgreementKey2019',
      controller: did,
      publicKeyJwk: keyAgreementPublicKeyJwk,
    };

    // Create DID document
    const document: DIDDocument = {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/jws-2020/v1',
      ],
      id: did,
      verificationMethod: [
        authVerificationMethod,
        keyAgreementVerificationMethod,
      ],
      authentication: [authVerificationMethod.id],
      keyAgreement: [keyAgreementVerificationMethod.id],
    };

    // Store private keys with metadata
    const privateKeys = new Map<string, KeyMetadata>();
    privateKeys.set(authVerificationMethod.id, {
      key: authKeyPair.privateKey,
      type: KeyType.ED25519,
    });
    privateKeys.set(keyAgreementVerificationMethod.id, {
      key: keyAgreementPair.privateKey,
      type: KeyType.X25519,
    });

    return {
      did,
      document,
      privateKeys,
    };
  }

  /**
   * Resolve a DID to its document
   */
  async resolveDID(
    did: string,
    options: ResolveDIDOptions = {}
  ): Promise<DIDDocument> {
    // Check cache if enabled
    if (options.cache !== false) {
      const cached = this.cache.get(did);
      if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
        return cached.document;
      }
    }

    // Construct URL from DID
    const url = this.constructURLFromDID(did);

    try {
      // Fetch DID document
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeout);

      const response = await fetch(url, {
        signal: controller.signal,
        headers: {
          Accept: 'application/did+json',
        },
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new DIDResolutionError(
          did,
          new Error(`HTTP ${response.status}: ${response.statusText}`)
        );
      }

      const document = await response.json();

      // Validate document
      this.validateDIDDocument(document, did);

      // Cache the document
      this.cache.set(did, {
        document,
        timestamp: Date.now(),
      });

      return document;
    } catch (error) {
      if (error instanceof DIDResolutionError) {
        throw error;
      }
      throw new DIDResolutionError(did, error as Error);
    }
  }

  /**
   * Sign data with a DID identity
   */
  async sign(identity: DIDIdentity, data: Uint8Array): Promise<Signature> {
    // Get the authentication key
    const authMethodId = `${identity.did}#auth-key`;
    const keyMetadata = identity.privateKeys.get(authMethodId);

    if (!keyMetadata) {
      throw new Error('Private key not found for authentication');
    }

    // Sign the data
    const signatureValue = await cryptoSign(
      keyMetadata.key,
      data,
      keyMetadata.type as KeyType
    );

    return {
      value: signatureValue,
      verificationMethod: authMethodId,
    };
  }

  /**
   * Verify a signature
   */
  async verify(
    did: string,
    data: Uint8Array,
    signature: Signature,
    document?: DIDDocument
  ): Promise<boolean> {
    // Resolve DID document if not provided
    const didDocument = document ?? (await this.resolveDID(did));

    // Find the verification method
    const verificationMethod = didDocument.verificationMethod.find(
      (vm) => vm.id === signature.verificationMethod
    );

    if (!verificationMethod) {
      throw new Error(
        `Verification method not found: ${signature.verificationMethod}`
      );
    }

    if (!verificationMethod.publicKeyJwk) {
      throw new Error('Public key not found in verification method');
    }

    // Determine key type from verification method type
    const keyType = this.getKeyTypeFromVerificationMethod(verificationMethod);

    // Import the public key
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      verificationMethod.publicKeyJwk,
      {
        name: keyType === KeyType.ED25519 ? 'Ed25519' : 'ECDSA',
        namedCurve: keyType === KeyType.ED25519 ? 'Ed25519' : 'P-256',
      } as any,
      true,
      ['verify']
    );

    // Verify the signature
    return cryptoVerify(publicKey, data, signature.value, keyType);
  }

  /**
   * Export DID document (without private keys)
   */
  exportDocument(identity: DIDIdentity): DIDDocument {
    return identity.document;
  }

  /**
   * Validate domain format
   */
  private validateDomain(domain: string): void {
    if (!domain || domain.trim() === '') {
      throw new Error('Invalid domain: domain cannot be empty');
    }

    // Check for protocol
    if (domain.includes('://')) {
      throw new Error('Invalid domain: domain should not include protocol');
    }

    // Check for spaces
    if (domain.includes(' ')) {
      throw new Error('Invalid domain: domain cannot contain spaces');
    }

    // Basic domain validation (alphanumeric, dots, hyphens, optional port)
    // Supports formats like: example.com, localhost, example.com:8080, localhost:9000
    const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*(:[0-9]{1,5})?$/;
    if (!domainRegex.test(domain)) {
      throw new Error('Invalid domain: invalid domain format');
    }

    // If port is included in domain, validate it
    if (domain.includes(':')) {
      const parts = domain.split(':');
      if (parts.length !== 2) {
        throw new Error('Invalid domain: invalid port format');
      }
      const port = parseInt(parts[1], 10);
      if (isNaN(port) || port < 1 || port > 65535) {
        throw new Error('Invalid domain: port must be between 1 and 65535');
      }
    }
  }

  /**
   * Validate port number
   */
  private validatePort(port: number): void {
    if (port < 1 || port > 65535) {
      throw new Error('Invalid port: port must be between 1 and 65535');
    }
  }

  /**
   * Construct DID identifier from options
   */
  private constructDID(options: CreateDIDOptions): string {
    const domain = options.domain.toLowerCase();
    let didIdentifier = 'did:wba:';

    // Handle port encoding
    if (options.port !== undefined && options.port !== 443) {
      didIdentifier += encodeURIComponent(`${domain}:${options.port}`);
    } else {
      didIdentifier += domain;
    }

    // Handle path encoding
    if (options.path) {
      didIdentifier += ':' + encodeURIComponent(options.path);
    }

    return didIdentifier;
  }

  /**
   * Construct URL from DID identifier
   */
  private constructURLFromDID(did: string): string {
    // Parse DID
    if (!did.startsWith('did:wba:')) {
      throw new Error('Invalid DID: must start with did:wba:');
    }

    const parts = did.substring(8).split(':');
    const domainPart = decodeURIComponent(parts[0]);
    const pathPart = parts.length > 1 ? decodeURIComponent(parts[1]) : null;

    // Extract domain and port
    let domain: string;
    let port: string | null = null;

    if (domainPart.includes(':')) {
      const domainPortParts = domainPart.split(':');
      domain = domainPortParts[0];
      port = domainPortParts[1];
    } else {
      domain = domainPart;
    }

    // Construct URL
    // Use http:// for localhost, https:// for everything else
    const protocol = domain === 'localhost' || domain === '127.0.0.1' ? 'http://' : 'https://';
    let url = protocol;
    url += domain;

    if (port) {
      url += ':' + port;
    }

    if (pathPart) {
      url += '/' + pathPart + '/did.json';
    } else {
      url += '/.well-known/did.json';
    }

    return url;
  }

  /**
   * Validate DID document
   */
  private validateDIDDocument(document: any, expectedDID: string): void {
    if (!document.id) {
      throw new DIDResolutionError(
        expectedDID,
        new Error('Invalid DID document: missing id field')
      );
    }

    if (document.id !== expectedDID) {
      throw new DIDResolutionError(
        expectedDID,
        new Error(`DID mismatch: expected ${expectedDID}, got ${document.id}`)
      );
    }

    if (!Array.isArray(document.verificationMethod)) {
      throw new DIDResolutionError(
        expectedDID,
        new Error('Invalid DID document: verificationMethod must be an array')
      );
    }

    if (!Array.isArray(document.authentication)) {
      throw new DIDResolutionError(
        expectedDID,
        new Error('Invalid DID document: authentication must be an array')
      );
    }
  }

  /**
   * Get key type from verification method type
   */
  private getKeyTypeFromVerificationMethod(
    verificationMethod: VerificationMethod
  ): KeyType {
    switch (verificationMethod.type) {
      case 'Ed25519VerificationKey2020':
        return KeyType.ED25519;
      case 'EcdsaSecp256k1VerificationKey2019':
        return KeyType.ECDSA_SECP256K1;
      case 'X25519KeyAgreementKey2019':
        return KeyType.X25519;
      default:
        throw new Error(
          `Unsupported verification method type: ${verificationMethod.type}`
        );
    }
  }
}
