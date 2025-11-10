/**
 * Authentication Manager for handling HTTP authentication using DID:WBA
 */

import { DIDManager } from '../did/did-manager.js';
import { AuthenticationError } from '../../errors/index.js';
import { encodeSignature } from '../../crypto/signing.js';
import type { DIDIdentity } from '../../types/index.js';

/**
 * Configuration for Authentication Manager
 */
export interface AuthConfig {
  maxTokenAge: number; // milliseconds
  nonceLength: number;
  clockSkewTolerance: number; // seconds
}

/**
 * Verification result structure
 */
export interface VerificationResult {
  success: boolean;
  did?: string;
  error?: string;
}

/**
 * Token verification result structure
 */
export interface TokenVerificationResult {
  valid: boolean;
  did?: string;
  expiresAt?: number;
  error?: string;
}

/**
 * Authentication Manager class
 */
export class AuthenticationManager {
  private readonly config: AuthConfig;
  private readonly didManager: DIDManager;
  private readonly usedNonces: Set<string> = new Set();

  constructor(didManager: DIDManager, config: AuthConfig) {
    this.didManager = didManager;
    this.config = config;
  }

  /**
   * Generate authentication header for outgoing request
   *
   * @param identity - The DID identity to authenticate with
   * @param targetDomain - The domain of the service being accessed
   * @param verificationMethodId - The verification method ID to use for signing
   * @returns The Authorization header value
   */
  async generateAuthHeader(
    identity: DIDIdentity,
    targetDomain: string,
    verificationMethodId: string
  ): Promise<string> {
    // Verify the verification method exists
    const keyMetadata = identity.privateKeys.get(verificationMethodId);
    if (!keyMetadata) {
      throw new AuthenticationError(
        `Verification method not found: ${verificationMethodId}`
      );
    }

    // Generate nonce
    const nonce = this.generateNonce();

    // Generate timestamp in ISO 8601 format
    const timestamp = new Date().toISOString();

    // Extract verification method fragment (remove DID# prefix)
    const verificationMethodFragment = verificationMethodId.split('#')[1];
    if (!verificationMethodFragment) {
      throw new AuthenticationError(
        'Invalid verification method ID: must contain # fragment'
      );
    }

    // Construct signature data according to ANP spec
    const signatureData = {
      nonce,
      timestamp,
      service: targetDomain,
      did: identity.did,
    };

    // Canonicalize using JCS (JSON Canonicalization Scheme)
    const canonicalJson = this.canonicalizeJSON(signatureData);

    // Hash the canonical JSON
    const encoder = new TextEncoder();
    const data = encoder.encode(canonicalJson);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hash = new Uint8Array(hashBuffer);

    // Sign the hash
    const signatureResult = await this.didManager.sign(identity, hash);

    // Encode signature to base64url
    const signatureBase64 = encodeSignature(signatureResult.value);

    // Construct Authorization header
    const authHeader = `DIDWba did="${identity.did}", nonce="${nonce}", timestamp="${timestamp}", verification_method="${verificationMethodFragment}", signature="${signatureBase64}"`;

    return authHeader;
  }

  /**
   * Generate a cryptographically secure nonce
   */
  private generateNonce(): string {
    const bytes = new Uint8Array(this.config.nonceLength);
    crypto.getRandomValues(bytes);

    // Convert to base64url
    return this.base64UrlEncode(bytes);
  }

  /**
   * Canonicalize JSON according to JCS (RFC 8785)
   *
   * This is a simplified implementation that handles the basic cases.
   * For production use, consider using a full JCS library.
   */
  private canonicalizeJSON(obj: any): string {
    if (obj === null) {
      return 'null';
    }

    if (typeof obj === 'boolean') {
      return obj ? 'true' : 'false';
    }

    if (typeof obj === 'number') {
      // Handle numbers according to JCS spec
      if (!isFinite(obj)) {
        throw new Error('Cannot canonicalize non-finite numbers');
      }
      return JSON.stringify(obj);
    }

    if (typeof obj === 'string') {
      return JSON.stringify(obj);
    }

    if (Array.isArray(obj)) {
      const items = obj.map((item) => this.canonicalizeJSON(item));
      return '[' + items.join(',') + ']';
    }

    if (typeof obj === 'object') {
      // Sort keys lexicographically
      const keys = Object.keys(obj).sort();
      const pairs = keys.map((key) => {
        const value = this.canonicalizeJSON(obj[key]);
        return `${JSON.stringify(key)}:${value}`;
      });
      return '{' + pairs.join(',') + '}';
    }

    throw new Error(`Cannot canonicalize type: ${typeof obj}`);
  }

  /**
   * Encode bytes to base64url
   */
  private base64UrlEncode(bytes: Uint8Array): string {
    const base64 = btoa(String.fromCharCode(...bytes));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  /**
   * Verify incoming request authentication
   *
   * @param authHeader - The Authorization header value
   * @param expectedDomain - The expected service domain
   * @returns Verification result
   */
  async verifyAuthHeader(
    authHeader: string,
    expectedDomain: string
  ): Promise<VerificationResult> {
    try {
      // Parse the auth header
      const parsed = this.parseAuthHeader(authHeader);
      if (!parsed) {
        return {
          success: false,
          error: 'Invalid authorization header format',
        };
      }

      const { did, nonce, timestamp, verificationMethod, signature } = parsed;

      // Validate timestamp
      const timestampValid = this.validateTimestamp(timestamp);
      if (!timestampValid) {
        return {
          success: false,
          error: 'Invalid or expired timestamp',
        };
      }

      // Check for nonce replay
      if (this.usedNonces.has(nonce)) {
        return {
          success: false,
          error: 'Nonce has already been used (replay attack detected)',
        };
      }

      // Resolve DID document
      let didDocument;
      try {
        didDocument = await this.didManager.resolveDID(did);
      } catch (error) {
        return {
          success: false,
          error: `DID resolution failed: ${(error as Error).message}`,
        };
      }

      // Reconstruct signature data
      const signatureData = {
        nonce,
        timestamp,
        service: expectedDomain,
        did,
      };

      // Canonicalize and hash
      const canonicalJson = this.canonicalizeJSON(signatureData);
      const encoder = new TextEncoder();
      const data = encoder.encode(canonicalJson);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hash = new Uint8Array(hashBuffer);

      // Decode signature
      const signatureBytes = this.base64UrlDecode(signature);

      // Verify signature
      const verificationMethodId = `${did}#${verificationMethod}`;
      const signatureObj = {
        value: signatureBytes,
        verificationMethod: verificationMethodId,
      };

      const isValid = await this.didManager.verify(
        did,
        hash,
        signatureObj,
        didDocument
      );

      if (!isValid) {
        return {
          success: false,
          error: 'Invalid signature',
        };
      }

      // Mark nonce as used
      this.usedNonces.add(nonce);

      // Clean up old nonces periodically (simple implementation)
      if (this.usedNonces.size > 10000) {
        this.usedNonces.clear();
      }

      return {
        success: true,
        did,
      };
    } catch (error) {
      return {
        success: false,
        error: `Verification failed: ${(error as Error).message}`,
      };
    }
  }

  /**
   * Parse authorization header
   */
  private parseAuthHeader(authHeader: string): {
    did: string;
    nonce: string;
    timestamp: string;
    verificationMethod: string;
    signature: string;
  } | null {
    // Check if header starts with DIDWba
    if (!authHeader.startsWith('DIDWba ')) {
      return null;
    }

    // Remove prefix
    const headerContent = authHeader.substring(7);

    // Parse key-value pairs
    const regex = /(\w+)="([^"]+)"/g;
    const matches: Record<string, string> = {};
    let match;

    while ((match = regex.exec(headerContent)) !== null) {
      matches[match[1]] = match[2];
    }

    // Validate required fields
    if (
      !matches.did ||
      !matches.nonce ||
      !matches.timestamp ||
      !matches.verification_method ||
      !matches.signature
    ) {
      return null;
    }

    return {
      did: matches.did,
      nonce: matches.nonce,
      timestamp: matches.timestamp,
      verificationMethod: matches.verification_method,
      signature: matches.signature,
    };
  }

  /**
   * Validate timestamp
   */
  private validateTimestamp(timestamp: string): boolean {
    try {
      const timestampDate = new Date(timestamp);
      const now = new Date();

      // Check if timestamp is valid
      if (isNaN(timestampDate.getTime())) {
        return false;
      }

      // Calculate difference in seconds
      const diffSeconds = Math.abs(now.getTime() - timestampDate.getTime()) / 1000;

      // Check if within clock skew tolerance
      return diffSeconds <= this.config.clockSkewTolerance;
    } catch {
      return false;
    }
  }

  /**
   * Decode base64url to bytes
   */
  private base64UrlDecode(str: string): Uint8Array {
    // Add padding if needed
    const padding = '='.repeat((4 - (str.length % 4)) % 4);
    const base64 = str.replace(/-/g, '+').replace(/_/g, '/') + padding;

    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Generate access token after successful authentication
   *
   * @param did - The DID to generate token for
   * @param expiresIn - Token expiration time in milliseconds
   * @returns The access token
   */
  generateAccessToken(did: string, expiresIn: number): string {
    const now = Math.floor(Date.now() / 1000);
    const exp = Math.floor((Date.now() + expiresIn) / 1000);

    // Create JWT header
    const header = {
      alg: 'HS256',
      typ: 'JWT',
    };

    // Create JWT payload
    const payload = {
      did,
      iat: now,
      exp,
    };

    // Encode header and payload
    const headerBase64 = this.base64UrlEncode(
      new TextEncoder().encode(JSON.stringify(header))
    );
    const payloadBase64 = this.base64UrlEncode(
      new TextEncoder().encode(JSON.stringify(payload))
    );

    // Create signature data
    const signatureData = `${headerBase64}.${payloadBase64}`;

    // Generate signature (using a simple HMAC-like approach with the DID as secret)
    // Note: In production, use a proper secret key management system
    const signature = this.generateTokenSignature(signatureData, did);

    return `${signatureData}.${signature}`;
  }

  /**
   * Verify access token
   *
   * @param token - The access token to verify
   * @returns Token verification result
   */
  verifyAccessToken(token: string): TokenVerificationResult {
    try {
      // Split token into parts
      const parts = token.split('.');
      if (parts.length !== 3) {
        return {
          valid: false,
          error: 'Invalid token format',
        };
      }

      const [headerBase64, payloadBase64, signature] = parts;

      // Decode payload
      let payload: any;
      try {
        const payloadJson = new TextDecoder().decode(
          this.base64UrlDecode(payloadBase64)
        );
        payload = JSON.parse(payloadJson);
      } catch {
        return {
          valid: false,
          error: 'Invalid token payload',
        };
      }

      // Validate required fields
      if (!payload.did || !payload.exp || !payload.iat) {
        return {
          valid: false,
          error: 'Missing required token fields',
        };
      }

      // Check expiration
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp < now) {
        return {
          valid: false,
          error: 'Token has expired',
        };
      }

      // Verify signature
      const signatureData = `${headerBase64}.${payloadBase64}`;
      const expectedSignature = this.generateTokenSignature(
        signatureData,
        payload.did
      );

      if (signature !== expectedSignature) {
        return {
          valid: false,
          error: 'Invalid token signature',
        };
      }

      return {
        valid: true,
        did: payload.did,
        expiresAt: payload.exp * 1000, // Convert to milliseconds
      };
    } catch (error) {
      return {
        valid: false,
        error: `Token verification failed: ${(error as Error).message}`,
      };
    }
  }

  /**
   * Generate token signature
   * 
   * Note: This is a simplified implementation for demonstration.
   * In production, use proper HMAC with a secure secret key.
   */
  private generateTokenSignature(data: string, secret: string): string {
    // For synchronous operation, use a simple hash-based approach
    // This is not cryptographically secure for production use
    const encoder = new TextEncoder();
    const combined = encoder.encode(data + secret);
    
    // Simple hash using Array.from for synchronous operation
    let hash = 0;
    for (let i = 0; i < combined.length; i++) {
      hash = ((hash << 5) - hash) + combined[i];
      hash = hash & hash; // Convert to 32-bit integer
    }
    
    // Convert to base64url
    const hashBytes = new Uint8Array(new Int32Array([hash]).buffer);
    return this.base64UrlEncode(hashBytes);
  }
}
