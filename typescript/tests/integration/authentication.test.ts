/**
 * Integration test for end-to-end authentication flow
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { DIDManager } from '../../src/core/did/did-manager.js';
import { AuthenticationManager } from '../../src/core/auth/authentication-manager.js';
import type { DIDIdentity, DIDDocument } from '../../src/types/index.js';

describe('End-to-End Authentication Integration', () => {
  let didManager: DIDManager;
  let authManager: AuthenticationManager;
  let aliceIdentity: DIDIdentity;
  let bobIdentity: DIDIdentity;

  beforeEach(async () => {
    // Initialize managers
    didManager = new DIDManager();
    authManager = new AuthenticationManager(didManager, {
      maxTokenAge: 3600000, // 1 hour
      nonceLength: 32,
      clockSkewTolerance: 60, // 60 seconds
    });

    // Create two DID identities
    aliceIdentity = await didManager.createDID({
      domain: 'alice.example.com',
      path: 'agent',
    });

    bobIdentity = await didManager.createDID({
      domain: 'bob.example.com',
      path: 'service',
    });
  });

  it('should complete full authentication flow between two agents', async () => {
    // Step 1: Alice generates auth header to access Bob's service
    const bobDomain = 'bob.example.com';
    const aliceVerificationMethod = `${aliceIdentity.did}#auth-key`;

    const authHeader = await authManager.generateAuthHeader(
      aliceIdentity,
      bobDomain,
      aliceVerificationMethod
    );

    expect(authHeader).toBeTruthy();
    expect(authHeader).toMatch(/^DIDWba /);

    // Step 2: Bob receives the request and verifies Alice's authentication
    // Mock DID resolution to return Alice's document
    vi.spyOn(didManager, 'resolveDID').mockResolvedValue(
      aliceIdentity.document
    );

    const verificationResult = await authManager.verifyAuthHeader(
      authHeader,
      bobDomain
    );

    expect(verificationResult.success).toBe(true);
    expect(verificationResult.did).toBe(aliceIdentity.did);
    expect(verificationResult.error).toBeUndefined();

    // Step 3: Bob generates access token for Alice
    const accessToken = authManager.generateAccessToken(
      aliceIdentity.did,
      3600000
    );

    expect(accessToken).toBeTruthy();
    expect(typeof accessToken).toBe('string');

    // Step 4: Alice makes subsequent request with access token
    const tokenVerification = authManager.verifyAccessToken(accessToken);

    expect(tokenVerification.valid).toBe(true);
    expect(tokenVerification.did).toBe(aliceIdentity.did);
    expect(tokenVerification.expiresAt).toBeGreaterThan(Date.now());
  });

  it('should enforce access control with token validation', async () => {
    // Alice authenticates with Bob
    const bobDomain = 'bob.example.com';
    const aliceVerificationMethod = `${aliceIdentity.did}#auth-key`;

    const authHeader = await authManager.generateAuthHeader(
      aliceIdentity,
      bobDomain,
      aliceVerificationMethod
    );

    vi.spyOn(didManager, 'resolveDID').mockResolvedValue(
      aliceIdentity.document
    );

    const verificationResult = await authManager.verifyAuthHeader(
      authHeader,
      bobDomain
    );

    expect(verificationResult.success).toBe(true);

    // Bob generates token for Alice
    const aliceToken = authManager.generateAccessToken(
      aliceIdentity.did,
      3600000
    );

    // Verify Alice's token is valid
    const aliceTokenVerification = authManager.verifyAccessToken(aliceToken);
    expect(aliceTokenVerification.valid).toBe(true);
    expect(aliceTokenVerification.did).toBe(aliceIdentity.did);

    // Try to use a token for a different DID (should fail)
    const bobToken = authManager.generateAccessToken(bobIdentity.did, 3600000);
    const bobTokenVerification = authManager.verifyAccessToken(bobToken);

    expect(bobTokenVerification.valid).toBe(true);
    expect(bobTokenVerification.did).toBe(bobIdentity.did);
    expect(bobTokenVerification.did).not.toBe(aliceIdentity.did);
  });

  it('should reject expired tokens', async () => {
    // Generate token with very short expiration
    const shortLivedToken = authManager.generateAccessToken(
      aliceIdentity.did,
      -1000 // Already expired
    );

    const verification = authManager.verifyAccessToken(shortLivedToken);

    expect(verification.valid).toBe(false);
    expect(verification.error).toBeDefined();
    expect(verification.error?.toLowerCase()).toContain('expired');
  });

  it('should prevent replay attacks with nonce validation', async () => {
    const bobDomain = 'bob.example.com';
    const aliceVerificationMethod = `${aliceIdentity.did}#auth-key`;

    // Generate auth header
    const authHeader = await authManager.generateAuthHeader(
      aliceIdentity,
      bobDomain,
      aliceVerificationMethod
    );

    vi.spyOn(didManager, 'resolveDID').mockResolvedValue(
      aliceIdentity.document
    );

    // First verification should succeed
    const firstVerification = await authManager.verifyAuthHeader(
      authHeader,
      bobDomain
    );

    expect(firstVerification.success).toBe(true);

    // Second verification with same header should fail (replay attack)
    const secondVerification = await authManager.verifyAuthHeader(
      authHeader,
      bobDomain
    );

    expect(secondVerification.success).toBe(false);
    expect(secondVerification.error?.toLowerCase()).toContain('nonce');
  });

  it('should handle cross-domain authentication', async () => {
    // Alice authenticates with Bob's service
    const bobDomain = 'bob.example.com';
    const aliceVerificationMethod = `${aliceIdentity.did}#auth-key`;

    const authHeaderForBob = await authManager.generateAuthHeader(
      aliceIdentity,
      bobDomain,
      aliceVerificationMethod
    );

    vi.spyOn(didManager, 'resolveDID').mockResolvedValue(
      aliceIdentity.document
    );

    const bobVerification = await authManager.verifyAuthHeader(
      authHeaderForBob,
      bobDomain
    );

    expect(bobVerification.success).toBe(true);
    expect(bobVerification.did).toBe(aliceIdentity.did);

    // Alice authenticates with a different service
    const charlieManager = new AuthenticationManager(didManager, {
      maxTokenAge: 3600000,
      nonceLength: 32,
      clockSkewTolerance: 60,
    });

    const charlieDomain = 'charlie.example.com';
    const authHeaderForCharlie = await charlieManager.generateAuthHeader(
      aliceIdentity,
      charlieDomain,
      aliceVerificationMethod
    );

    const charlieVerification = await charlieManager.verifyAuthHeader(
      authHeaderForCharlie,
      charlieDomain
    );

    expect(charlieVerification.success).toBe(true);
    expect(charlieVerification.did).toBe(aliceIdentity.did);
  });

  it('should validate signature integrity', async () => {
    const bobDomain = 'bob.example.com';
    const aliceVerificationMethod = `${aliceIdentity.did}#auth-key`;

    const authHeader = await authManager.generateAuthHeader(
      aliceIdentity,
      bobDomain,
      aliceVerificationMethod
    );

    // Tamper with the signature
    const tamperedHeader = authHeader.replace(
      /signature="[^"]+"/,
      'signature="tampered_signature_value"'
    );

    vi.spyOn(didManager, 'resolveDID').mockResolvedValue(
      aliceIdentity.document
    );

    const verification = await authManager.verifyAuthHeader(
      tamperedHeader,
      bobDomain
    );

    expect(verification.success).toBe(false);
    expect(verification.error).toBeDefined();
  });

  it('should handle DID resolution failures gracefully', async () => {
    const bobDomain = 'bob.example.com';
    const aliceVerificationMethod = `${aliceIdentity.did}#auth-key`;

    const authHeader = await authManager.generateAuthHeader(
      aliceIdentity,
      bobDomain,
      aliceVerificationMethod
    );

    // Mock DID resolution to fail
    vi.spyOn(didManager, 'resolveDID').mockRejectedValue(
      new Error('Network error')
    );

    const verification = await authManager.verifyAuthHeader(
      authHeader,
      bobDomain
    );

    expect(verification.success).toBe(false);
    expect(verification.error).toBeDefined();
    expect(verification.error).toContain('DID resolution');
  });

  it('should support multiple concurrent authentication sessions', async () => {
    const bobDomain = 'bob.example.com';
    const aliceVerificationMethod = `${aliceIdentity.did}#auth-key`;

    // Create multiple auth headers
    const authHeader1 = await authManager.generateAuthHeader(
      aliceIdentity,
      bobDomain,
      aliceVerificationMethod
    );

    const authHeader2 = await authManager.generateAuthHeader(
      aliceIdentity,
      bobDomain,
      aliceVerificationMethod
    );

    vi.spyOn(didManager, 'resolveDID').mockResolvedValue(
      aliceIdentity.document
    );

    // Both should verify successfully (different nonces)
    const verification1 = await authManager.verifyAuthHeader(
      authHeader1,
      bobDomain
    );

    const verification2 = await authManager.verifyAuthHeader(
      authHeader2,
      bobDomain
    );

    expect(verification1.success).toBe(true);
    expect(verification2.success).toBe(true);

    // Generate tokens for both sessions
    const token1 = authManager.generateAccessToken(aliceIdentity.did, 3600000);
    const token2 = authManager.generateAccessToken(aliceIdentity.did, 3600000);

    // Both tokens should be valid
    const tokenVerification1 = authManager.verifyAccessToken(token1);
    const tokenVerification2 = authManager.verifyAccessToken(token2);

    expect(tokenVerification1.valid).toBe(true);
    expect(tokenVerification2.valid).toBe(true);
  });
});
