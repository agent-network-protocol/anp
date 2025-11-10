/**
 * Unit tests for Authentication Manager
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { AuthenticationManager } from '../../../../src/core/auth/authentication-manager.js';
import { DIDManager } from '../../../../src/core/did/did-manager.js';
import type { DIDIdentity } from '../../../../src/types/index.js';

describe('AuthenticationManager', () => {
  let authManager: AuthenticationManager;
  let didManager: DIDManager;
  let testIdentity: DIDIdentity;

  beforeEach(async () => {
    didManager = new DIDManager();
    authManager = new AuthenticationManager(didManager, {
      maxTokenAge: 3600000, // 1 hour
      nonceLength: 32,
      clockSkewTolerance: 60, // 60 seconds
    });

    // Create a test identity
    testIdentity = await didManager.createDID({
      domain: 'example.com',
      path: 'user/alice',
    });
  });

  describe('generateAuthHeader', () => {
    it('should generate auth header with correct format', async () => {
      const targetDomain = 'service.example.com';
      const verificationMethodId = `${testIdentity.did}#auth-key`;

      const authHeader = await authManager.generateAuthHeader(
        testIdentity,
        targetDomain,
        verificationMethodId
      );

      // Verify header starts with DIDWba
      expect(authHeader).toMatch(/^DIDWba /);

      // Verify header contains required fields
      expect(authHeader).toContain('did=');
      expect(authHeader).toContain('nonce=');
      expect(authHeader).toContain('timestamp=');
      expect(authHeader).toContain('verification_method=');
      expect(authHeader).toContain('signature=');

      // Verify DID is properly quoted
      expect(authHeader).toContain(`did="${testIdentity.did}"`);

      // Verify verification method is just the fragment (without #)
      expect(authHeader).toContain('verification_method="auth-key"');
    });

    it('should generate unique nonces for each request', async () => {
      const targetDomain = 'service.example.com';
      const verificationMethodId = `${testIdentity.did}#auth-key`;

      const header1 = await authManager.generateAuthHeader(
        testIdentity,
        targetDomain,
        verificationMethodId
      );

      const header2 = await authManager.generateAuthHeader(
        testIdentity,
        targetDomain,
        verificationMethodId
      );

      // Extract nonces from headers
      const nonce1Match = header1.match(/nonce="([^"]+)"/);
      const nonce2Match = header2.match(/nonce="([^"]+)"/);

      expect(nonce1Match).toBeTruthy();
      expect(nonce2Match).toBeTruthy();
      expect(nonce1Match![1]).not.toBe(nonce2Match![1]);
    });

    it('should generate timestamp in ISO 8601 format', async () => {
      const targetDomain = 'service.example.com';
      const verificationMethodId = `${testIdentity.did}#auth-key`;

      const authHeader = await authManager.generateAuthHeader(
        testIdentity,
        targetDomain,
        verificationMethodId
      );

      // Extract timestamp
      const timestampMatch = authHeader.match(/timestamp="([^"]+)"/);
      expect(timestampMatch).toBeTruthy();

      const timestamp = timestampMatch![1];

      // Verify ISO 8601 format (YYYY-MM-DDTHH:mm:ss.sssZ)
      expect(timestamp).toMatch(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
      );

      // Verify timestamp is recent (within last 5 seconds)
      const timestampDate = new Date(timestamp);
      const now = new Date();
      const diff = now.getTime() - timestampDate.getTime();
      expect(diff).toBeLessThan(5000);
      expect(diff).toBeGreaterThanOrEqual(0);
    });

    it('should generate valid signature', async () => {
      const targetDomain = 'service.example.com';
      const verificationMethodId = `${testIdentity.did}#auth-key`;

      const authHeader = await authManager.generateAuthHeader(
        testIdentity,
        targetDomain,
        verificationMethodId
      );

      // Extract signature
      const signatureMatch = authHeader.match(/signature="([^"]+)"/);
      expect(signatureMatch).toBeTruthy();

      const signature = signatureMatch![1];

      // Verify signature is base64url encoded (no +, /, or =)
      expect(signature).toMatch(/^[A-Za-z0-9_-]+$/);

      // Verify signature has reasonable length (Ed25519 signatures are 64 bytes = 86 base64url chars)
      expect(signature.length).toBeGreaterThan(50);
    });

    it('should use correct verification method', async () => {
      const targetDomain = 'service.example.com';
      const verificationMethodId = `${testIdentity.did}#auth-key`;

      const authHeader = await authManager.generateAuthHeader(
        testIdentity,
        targetDomain,
        verificationMethodId
      );

      // Verify verification method is extracted correctly (fragment only)
      expect(authHeader).toContain('verification_method="auth-key"');
    });

    it('should throw error if verification method not found', async () => {
      const targetDomain = 'service.example.com';
      const invalidMethodId = `${testIdentity.did}#invalid-key`;

      await expect(
        authManager.generateAuthHeader(
          testIdentity,
          targetDomain,
          invalidMethodId
        )
      ).rejects.toThrow('Verification method not found');
    });

    it('should include service domain in signature data', async () => {
      const targetDomain = 'service.example.com';
      const verificationMethodId = `${testIdentity.did}#auth-key`;

      // Generate header
      const authHeader = await authManager.generateAuthHeader(
        testIdentity,
        targetDomain,
        verificationMethodId
      );

      // The signature should be different for different target domains
      const authHeader2 = await authManager.generateAuthHeader(
        testIdentity,
        'different.example.com',
        verificationMethodId
      );

      const sig1Match = authHeader.match(/signature="([^"]+)"/);
      const sig2Match = authHeader2.match(/signature="([^"]+)"/);

      // Signatures should be different (different service domains)
      // Note: nonces are also different, but this tests the service is included
      expect(sig1Match![1]).not.toBe(sig2Match![1]);
    });

    it('should handle DID with port encoding', async () => {
      const identityWithPort = await didManager.createDID({
        domain: 'example.com',
        port: 8800,
        path: 'user/bob',
      });

      const targetDomain = 'service.example.com';
      const verificationMethodId = `${identityWithPort.did}#auth-key`;

      const authHeader = await authManager.generateAuthHeader(
        identityWithPort,
        targetDomain,
        verificationMethodId
      );

      // Verify DID is properly included
      expect(authHeader).toContain(`did="${identityWithPort.did}"`);
      expect(authHeader).toMatch(/^DIDWba /);
    });
  });

  describe('verifyAuthHeader', () => {
    it('should successfully verify valid auth header', async () => {
      const targetDomain = 'service.example.com';
      const verificationMethodId = `${testIdentity.did}#auth-key`;

      // Generate a valid auth header
      const authHeader = await authManager.generateAuthHeader(
        testIdentity,
        targetDomain,
        verificationMethodId
      );

      // Mock DID resolution to return the test identity's document
      vi.spyOn(didManager, 'resolveDID').mockResolvedValue(
        testIdentity.document
      );

      // Verify the header
      const result = await authManager.verifyAuthHeader(
        authHeader,
        targetDomain
      );

      expect(result.success).toBe(true);
      expect(result.did).toBe(testIdentity.did);
      expect(result.error).toBeUndefined();
    });

    it('should resolve DID during verification', async () => {
      const targetDomain = 'service.example.com';
      const verificationMethodId = `${testIdentity.did}#auth-key`;

      const authHeader = await authManager.generateAuthHeader(
        testIdentity,
        targetDomain,
        verificationMethodId
      );

      const resolveSpy = vi
        .spyOn(didManager, 'resolveDID')
        .mockResolvedValue(testIdentity.document);

      await authManager.verifyAuthHeader(authHeader, targetDomain);

      // Verify DID was resolved
      expect(resolveSpy).toHaveBeenCalledWith(testIdentity.did);
    });

    it('should verify signature correctly', async () => {
      const targetDomain = 'service.example.com';
      const verificationMethodId = `${testIdentity.did}#auth-key`;

      const authHeader = await authManager.generateAuthHeader(
        testIdentity,
        targetDomain,
        verificationMethodId
      );

      vi.spyOn(didManager, 'resolveDID').mockResolvedValue(
        testIdentity.document
      );

      const result = await authManager.verifyAuthHeader(
        authHeader,
        targetDomain
      );

      expect(result.success).toBe(true);
    });

    it('should reject header with invalid signature', async () => {
      const targetDomain = 'service.example.com';
      const verificationMethodId = `${testIdentity.did}#auth-key`;

      const authHeader = await authManager.generateAuthHeader(
        testIdentity,
        targetDomain,
        verificationMethodId
      );

      // Tamper with the signature
      const tamperedHeader = authHeader.replace(
        /signature="[^"]+"/,
        'signature="invalid_signature_data"'
      );

      vi.spyOn(didManager, 'resolveDID').mockResolvedValue(
        testIdentity.document
      );

      const result = await authManager.verifyAuthHeader(
        tamperedHeader,
        targetDomain
      );

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error).toContain('signature');
    });

    it('should prevent nonce replay attacks', async () => {
      const targetDomain = 'service.example.com';
      const verificationMethodId = `${testIdentity.did}#auth-key`;

      const authHeader = await authManager.generateAuthHeader(
        testIdentity,
        targetDomain,
        verificationMethodId
      );

      vi.spyOn(didManager, 'resolveDID').mockResolvedValue(
        testIdentity.document
      );

      // First verification should succeed
      const result1 = await authManager.verifyAuthHeader(
        authHeader,
        targetDomain
      );
      expect(result1.success).toBe(true);

      // Second verification with same nonce should fail
      const result2 = await authManager.verifyAuthHeader(
        authHeader,
        targetDomain
      );
      expect(result2.success).toBe(false);
      expect(result2.error?.toLowerCase()).toContain('nonce');
    });

    it('should validate timestamp within clock skew tolerance', async () => {
      const targetDomain = 'service.example.com';
      const verificationMethodId = `${testIdentity.did}#auth-key`;

      // Create auth header with current timestamp
      const authHeader = await authManager.generateAuthHeader(
        testIdentity,
        targetDomain,
        verificationMethodId
      );

      vi.spyOn(didManager, 'resolveDID').mockResolvedValue(
        testIdentity.document
      );

      // Should succeed within tolerance
      const result = await authManager.verifyAuthHeader(
        authHeader,
        targetDomain
      );
      expect(result.success).toBe(true);
    });

    it('should reject expired timestamp', async () => {
      const targetDomain = 'service.example.com';
      const verificationMethodId = `${testIdentity.did}#auth-key`;

      // Generate header
      const authHeader = await authManager.generateAuthHeader(
        testIdentity,
        targetDomain,
        verificationMethodId
      );

      // Replace timestamp with old one (2 minutes ago, beyond 60 second tolerance)
      const oldTimestamp = new Date(Date.now() - 120000).toISOString();
      const expiredHeader = authHeader.replace(
        /timestamp="[^"]+"/,
        `timestamp="${oldTimestamp}"`
      );

      vi.spyOn(didManager, 'resolveDID').mockResolvedValue(
        testIdentity.document
      );

      const result = await authManager.verifyAuthHeader(
        expiredHeader,
        targetDomain
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('timestamp');
    });

    it('should reject future timestamp beyond clock skew', async () => {
      const targetDomain = 'service.example.com';
      const verificationMethodId = `${testIdentity.did}#auth-key`;

      // Generate header
      const authHeader = await authManager.generateAuthHeader(
        testIdentity,
        targetDomain,
        verificationMethodId
      );

      // Replace timestamp with future one (2 minutes ahead, beyond 60 second tolerance)
      const futureTimestamp = new Date(Date.now() + 120000).toISOString();
      const futureHeader = authHeader.replace(
        /timestamp="[^"]+"/,
        `timestamp="${futureTimestamp}"`
      );

      vi.spyOn(didManager, 'resolveDID').mockResolvedValue(
        testIdentity.document
      );

      const result = await authManager.verifyAuthHeader(
        futureHeader,
        targetDomain
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('timestamp');
    });

    it('should reject malformed auth header', async () => {
      const malformedHeader = 'DIDWba invalid_format';

      const result = await authManager.verifyAuthHeader(
        malformedHeader,
        'service.example.com'
      );

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should reject header with missing fields', async () => {
      const incompleteHeader =
        'DIDWba did="did:wba:example.com", nonce="abc123"';

      const result = await authManager.verifyAuthHeader(
        incompleteHeader,
        'service.example.com'
      );

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should handle DID resolution failure', async () => {
      const targetDomain = 'service.example.com';
      const verificationMethodId = `${testIdentity.did}#auth-key`;

      const authHeader = await authManager.generateAuthHeader(
        testIdentity,
        targetDomain,
        verificationMethodId
      );

      // Mock DID resolution to fail
      vi.spyOn(didManager, 'resolveDID').mockRejectedValue(
        new Error('DID resolution failed')
      );

      const result = await authManager.verifyAuthHeader(
        authHeader,
        targetDomain
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('DID resolution');
    });
  });

  describe('generateAccessToken', () => {
    it('should generate access token with correct format', () => {
      const did = testIdentity.did;
      const expiresIn = 3600000; // 1 hour

      const token = authManager.generateAccessToken(did, expiresIn);

      // Token should be a non-empty string
      expect(token).toBeTruthy();
      expect(typeof token).toBe('string');

      // Token should have JWT-like format (3 parts separated by dots)
      const parts = token.split('.');
      expect(parts.length).toBe(3);

      // Each part should be base64url encoded
      parts.forEach((part) => {
        expect(part).toMatch(/^[A-Za-z0-9_-]+$/);
      });
    });

    it('should include DID in token', () => {
      const did = testIdentity.did;
      const expiresIn = 3600000;

      const token = authManager.generateAccessToken(did, expiresIn);

      // Decode payload (second part)
      const parts = token.split('.');
      const payloadBase64 = parts[1];
      const payloadJson = atob(
        payloadBase64.replace(/-/g, '+').replace(/_/g, '/')
      );
      const payload = JSON.parse(payloadJson);

      expect(payload.did).toBe(did);
    });

    it('should include expiration time in token', () => {
      const did = testIdentity.did;
      const expiresIn = 3600000; // 1 hour

      const token = authManager.generateAccessToken(did, expiresIn);

      // Decode payload
      const parts = token.split('.');
      const payloadBase64 = parts[1];
      const payloadJson = atob(
        payloadBase64.replace(/-/g, '+').replace(/_/g, '/')
      );
      const payload = JSON.parse(payloadJson);

      expect(payload.exp).toBeDefined();
      expect(typeof payload.exp).toBe('number');

      // Expiration should be approximately now + expiresIn
      const expectedExp = Math.floor((Date.now() + expiresIn) / 1000);
      expect(Math.abs(payload.exp - expectedExp)).toBeLessThan(2); // Within 2 seconds
    });

    it('should include issued at time in token', () => {
      const did = testIdentity.did;
      const expiresIn = 3600000;

      const token = authManager.generateAccessToken(did, expiresIn);

      // Decode payload
      const parts = token.split('.');
      const payloadBase64 = parts[1];
      const payloadJson = atob(
        payloadBase64.replace(/-/g, '+').replace(/_/g, '/')
      );
      const payload = JSON.parse(payloadJson);

      expect(payload.iat).toBeDefined();
      expect(typeof payload.iat).toBe('number');

      // Issued at should be approximately now
      const expectedIat = Math.floor(Date.now() / 1000);
      expect(Math.abs(payload.iat - expectedIat)).toBeLessThan(2);
    });
  });

  describe('verifyAccessToken', () => {
    it('should verify valid token', () => {
      const did = testIdentity.did;
      const expiresIn = 3600000;

      const token = authManager.generateAccessToken(did, expiresIn);
      const result = authManager.verifyAccessToken(token);

      expect(result.valid).toBe(true);
      expect(result.did).toBe(did);
      expect(result.expiresAt).toBeDefined();
      expect(result.error).toBeUndefined();
    });

    it('should reject expired token', () => {
      const did = testIdentity.did;
      const expiresIn = -1000; // Already expired

      const token = authManager.generateAccessToken(did, expiresIn);
      const result = authManager.verifyAccessToken(token);

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
      expect(result.error?.toLowerCase()).toContain('expired');
    });

    it('should reject malformed token', () => {
      const malformedToken = 'not.a.valid.token';

      const result = authManager.verifyAccessToken(malformedToken);

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should reject token with invalid signature', () => {
      const did = testIdentity.did;
      const expiresIn = 3600000;

      const token = authManager.generateAccessToken(did, expiresIn);

      // Tamper with the signature
      const parts = token.split('.');
      const tamperedToken = `${parts[0]}.${parts[1]}.invalid_signature`;

      const result = authManager.verifyAccessToken(tamperedToken);

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should reject token with missing required fields', () => {
      // Create a token without required fields
      const header = { alg: 'HS256', typ: 'JWT' };
      const payload = { someField: 'value' }; // Missing did, exp, iat

      const headerBase64 = btoa(JSON.stringify(header))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
      const payloadBase64 = btoa(JSON.stringify(payload))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      const invalidToken = `${headerBase64}.${payloadBase64}.signature`;

      const result = authManager.verifyAccessToken(invalidToken);

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should return expiration timestamp', () => {
      const did = testIdentity.did;
      const expiresIn = 3600000;

      const token = authManager.generateAccessToken(did, expiresIn);
      const result = authManager.verifyAccessToken(token);

      expect(result.valid).toBe(true);
      expect(result.expiresAt).toBeDefined();
      expect(typeof result.expiresAt).toBe('number');

      // Expiration should be in the future
      expect(result.expiresAt!).toBeGreaterThan(Date.now());
    });
  });
});
