/**
 * Unit tests for DID Manager functionality
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { DIDManager } from '../../../../src/core/did/did-manager.js';
import { DIDResolutionError } from '../../../../src/errors/index.js';
import type { DIDDocument, DIDIdentity } from '../../../../src/types/index.js';

describe('DID Manager', () => {
  let didManager: DIDManager;

  beforeEach(() => {
    didManager = new DIDManager();
  });

  describe('DID Creation', () => {
    describe('DID identifier construction from domain', () => {
      it('should construct a valid DID identifier from domain', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });

        expect(identity.did).toBe('did:wba:example.com');
        expect(identity.document.id).toBe('did:wba:example.com');
      });

      it('should handle domains with subdomains', async () => {
        const identity = await didManager.createDID({
          domain: 'api.example.com',
        });

        expect(identity.did).toBe('did:wba:api.example.com');
        expect(identity.document.id).toBe('did:wba:api.example.com');
      });

      it('should normalize domain to lowercase', async () => {
        const identity = await didManager.createDID({
          domain: 'Example.COM',
        });

        expect(identity.did).toBe('did:wba:example.com');
      });
    });

    describe('DID identifier construction with path', () => {
      it('should construct DID identifier with path', async () => {
        const identity = await didManager.createDID({
          domain: 'example.com',
          path: 'agent1',
        });

        expect(identity.did).toBe('did:wba:example.com:agent1');
        expect(identity.document.id).toBe('did:wba:example.com:agent1');
      });

      it('should handle path with multiple segments', async () => {
        const identity = await didManager.createDID({
          domain: 'example.com',
          path: 'agents/agent1',
        });

        expect(identity.did).toBe('did:wba:example.com:agents%2Fagent1');
      });

      it('should encode special characters in path', async () => {
        const identity = await didManager.createDID({
          domain: 'example.com',
          path: 'agent name',
        });

        expect(identity.did).toBe('did:wba:example.com:agent%20name');
      });
    });

    describe('DID identifier with port encoding', () => {
      it('should encode port in DID identifier', async () => {
        const identity = await didManager.createDID({
          domain: 'example.com',
          port: 8080,
        });

        expect(identity.did).toBe('did:wba:example.com%3A8080');
      });

      it('should encode port with path', async () => {
        const identity = await didManager.createDID({
          domain: 'example.com',
          port: 8080,
          path: 'agent1',
        });

        expect(identity.did).toBe('did:wba:example.com%3A8080:agent1');
      });

      it('should not encode standard HTTPS port 443', async () => {
        const identity = await didManager.createDID({
          domain: 'example.com',
          port: 443,
        });

        expect(identity.did).toBe('did:wba:example.com');
      });
    });

    describe('DID document generation', () => {
      it('should generate a valid DID document', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });
        const doc = identity.document;

        expect(doc['@context']).toEqual([
          'https://www.w3.org/ns/did/v1',
          'https://w3id.org/security/suites/jws-2020/v1',
        ]);
        expect(doc.id).toBe('did:wba:example.com');
        expect(Array.isArray(doc.verificationMethod)).toBe(true);
        expect(Array.isArray(doc.authentication)).toBe(true);
      });

      it('should include verificationMethod array', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });

        expect(identity.document.verificationMethod).toBeDefined();
        expect(identity.document.verificationMethod.length).toBeGreaterThan(0);
      });

      it('should include authentication array', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });

        expect(identity.document.authentication).toBeDefined();
        expect(identity.document.authentication.length).toBeGreaterThan(0);
      });

      it('should include keyAgreement array', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });

        expect(identity.document.keyAgreement).toBeDefined();
        expect(identity.document.keyAgreement!.length).toBeGreaterThan(0);
      });
    });

    describe('Verification method creation', () => {
      it('should create verification method for authentication', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });
        const authMethod = identity.document.verificationMethod.find((vm) =>
          vm.id.includes('#auth-key')
        );

        expect(authMethod).toBeDefined();
        expect(authMethod!.type).toBe('Ed25519VerificationKey2020');
        expect(authMethod!.controller).toBe('did:wba:example.com');
        expect(authMethod!.publicKeyJwk).toBeDefined();
      });

      it('should create verification method for key agreement', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });
        const keyAgreementMethod = identity.document.verificationMethod.find(
          (vm) => vm.id.includes('#key-agreement')
        );

        expect(keyAgreementMethod).toBeDefined();
        expect(keyAgreementMethod!.type).toBe('X25519KeyAgreementKey2019');
        expect(keyAgreementMethod!.controller).toBe('did:wba:example.com');
        expect(keyAgreementMethod!.publicKeyJwk).toBeDefined();
      });

      it('should store private keys in identity', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });

        expect(identity.privateKeys).toBeDefined();
        expect(identity.privateKeys.size).toBeGreaterThan(0);
      });

      it('should reference verification methods in authentication', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });
        const authMethodId = identity.document.verificationMethod.find((vm) =>
          vm.id.includes('#auth-key')
        )?.id;

        expect(identity.document.authentication).toContain(authMethodId);
      });

      it('should reference verification methods in keyAgreement', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });
        const keyAgreementMethodId =
          identity.document.verificationMethod.find((vm) =>
            vm.id.includes('#key-agreement')
          )?.id;

        expect(identity.document.keyAgreement).toContain(keyAgreementMethodId);
      });
    });

    describe('Error handling for invalid domains', () => {
      it('should throw error for empty domain', async () => {
        await expect(didManager.createDID({ domain: '' })).rejects.toThrow(
          'Invalid domain'
        );
      });

      it('should throw error for domain with protocol', async () => {
        await expect(
          didManager.createDID({ domain: 'https://example.com' })
        ).rejects.toThrow('Invalid domain');
      });

      it('should throw error for domain with invalid characters', async () => {
        await expect(
          didManager.createDID({ domain: 'example com' })
        ).rejects.toThrow('Invalid domain');
      });

      it('should throw error for invalid port number', async () => {
        await expect(
          didManager.createDID({ domain: 'example.com', port: -1 })
        ).rejects.toThrow('Invalid port');
      });

      it('should throw error for port exceeding maximum', async () => {
        await expect(
          didManager.createDID({ domain: 'example.com', port: 70000 })
        ).rejects.toThrow('Invalid port');
      });
    });
  });

  describe('DID Resolution', () => {
    describe('Resolution from .well-known path', () => {
      it('should resolve DID from .well-known path', async () => {
        const mockDoc: DIDDocument = {
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: 'did:wba:example.com',
          verificationMethod: [],
          authentication: [],
        };

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          json: async () => mockDoc,
        });

        const doc = await didManager.resolveDID('did:wba:example.com');

        expect(doc).toEqual(mockDoc);
        expect(global.fetch).toHaveBeenCalledWith(
          'https://example.com/.well-known/did.json',
          expect.any(Object)
        );
      });

      it('should construct correct URL for domain-only DID', async () => {
        const mockDoc: DIDDocument = {
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: 'did:wba:example.com',
          verificationMethod: [],
          authentication: [],
        };

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          json: async () => mockDoc,
        });

        await didManager.resolveDID('did:wba:example.com');

        expect(global.fetch).toHaveBeenCalledWith(
          'https://example.com/.well-known/did.json',
          expect.any(Object)
        );
      });
    });

    describe('Resolution from custom path', () => {
      it('should resolve DID with custom path', async () => {
        const mockDoc: DIDDocument = {
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: 'did:wba:example.com:agent1',
          verificationMethod: [],
          authentication: [],
        };

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          json: async () => mockDoc,
        });

        const doc = await didManager.resolveDID('did:wba:example.com:agent1');

        expect(doc).toEqual(mockDoc);
        expect(global.fetch).toHaveBeenCalledWith(
          'https://example.com/agent1/did.json',
          expect.any(Object)
        );
      });

      it('should decode URL-encoded path segments', async () => {
        const mockDoc: DIDDocument = {
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: 'did:wba:example.com:agents%2Fagent1',
          verificationMethod: [],
          authentication: [],
        };

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          json: async () => mockDoc,
        });

        await didManager.resolveDID('did:wba:example.com:agents%2Fagent1');

        expect(global.fetch).toHaveBeenCalledWith(
          'https://example.com/agents/agent1/did.json',
          expect.any(Object)
        );
      });
    });

    describe('Resolution with port', () => {
      it('should resolve DID with encoded port', async () => {
        const mockDoc: DIDDocument = {
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: 'did:wba:example.com%3A8080',
          verificationMethod: [],
          authentication: [],
        };

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          json: async () => mockDoc,
        });

        const doc = await didManager.resolveDID('did:wba:example.com%3A8080');

        expect(doc).toEqual(mockDoc);
        expect(global.fetch).toHaveBeenCalledWith(
          'https://example.com:8080/.well-known/did.json',
          expect.any(Object)
        );
      });

      it('should resolve DID with port and path', async () => {
        const mockDoc: DIDDocument = {
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: 'did:wba:example.com%3A8080:agent1',
          verificationMethod: [],
          authentication: [],
        };

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          json: async () => mockDoc,
        });

        await didManager.resolveDID('did:wba:example.com%3A8080:agent1');

        expect(global.fetch).toHaveBeenCalledWith(
          'https://example.com:8080/agent1/did.json',
          expect.any(Object)
        );
      });
    });

    describe('Caching mechanism', () => {
      it('should cache resolved DID documents', async () => {
        const mockDoc: DIDDocument = {
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: 'did:wba:example.com',
          verificationMethod: [],
          authentication: [],
        };

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          json: async () => mockDoc,
        });

        await didManager.resolveDID('did:wba:example.com');
        await didManager.resolveDID('did:wba:example.com');

        expect(global.fetch).toHaveBeenCalledTimes(1);
      });

      it('should respect cache TTL', async () => {
        const mockDoc: DIDDocument = {
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: 'did:wba:example.com',
          verificationMethod: [],
          authentication: [],
        };

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          json: async () => mockDoc,
        });

        const shortTTLManager = new DIDManager({ cacheTTL: 100 });
        await shortTTLManager.resolveDID('did:wba:example.com');

        await new Promise((resolve) => setTimeout(resolve, 150));

        await shortTTLManager.resolveDID('did:wba:example.com');

        expect(global.fetch).toHaveBeenCalledTimes(2);
      });

      it('should allow bypassing cache', async () => {
        const mockDoc: DIDDocument = {
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: 'did:wba:example.com',
          verificationMethod: [],
          authentication: [],
        };

        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          json: async () => mockDoc,
        });

        await didManager.resolveDID('did:wba:example.com');
        await didManager.resolveDID('did:wba:example.com', { cache: false });

        expect(global.fetch).toHaveBeenCalledTimes(2);
      });
    });

    describe('Error handling for 404 responses', () => {
      it('should throw DIDResolutionError for 404 response', async () => {
        global.fetch = vi.fn().mockResolvedValue({
          ok: false,
          status: 404,
          statusText: 'Not Found',
        });

        await expect(
          didManager.resolveDID('did:wba:example.com')
        ).rejects.toThrow(DIDResolutionError);
      });

      it('should include DID in error message', async () => {
        global.fetch = vi.fn().mockResolvedValue({
          ok: false,
          status: 404,
        });

        await expect(
          didManager.resolveDID('did:wba:example.com')
        ).rejects.toThrow('did:wba:example.com');
      });
    });

    describe('Error handling for invalid documents', () => {
      it('should throw error for document without id', async () => {
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          json: async () => ({
            '@context': ['https://www.w3.org/ns/did/v1'],
          }),
        });

        await expect(
          didManager.resolveDID('did:wba:example.com')
        ).rejects.toThrow(DIDResolutionError);
      });

      it('should throw error for document with mismatched id', async () => {
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          json: async () => ({
            '@context': ['https://www.w3.org/ns/did/v1'],
            id: 'did:wba:different.com',
            verificationMethod: [],
            authentication: [],
          }),
        });

        await expect(
          didManager.resolveDID('did:wba:example.com')
        ).rejects.toThrow(DIDResolutionError);
      });

      it('should throw error for malformed JSON', async () => {
        global.fetch = vi.fn().mockResolvedValue({
          ok: true,
          json: async () => {
            throw new Error('Invalid JSON');
          },
        });

        await expect(
          didManager.resolveDID('did:wba:example.com')
        ).rejects.toThrow(DIDResolutionError);
      });
    });
  });

  describe('DID Operations', () => {
    describe('Signing with DID identity', () => {
      it('should sign data with DID identity', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });
        const data = new TextEncoder().encode('test message');

        const signature = await didManager.sign(identity, data);

        expect(signature).toBeDefined();
        expect(signature.value).toBeInstanceOf(Uint8Array);
        expect(signature.verificationMethod).toBeDefined();
      });

      it('should include verification method in signature', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });
        const data = new TextEncoder().encode('test message');

        const signature = await didManager.sign(identity, data);

        expect(signature.verificationMethod).toContain('#auth-key');
      });

      it('should produce different signatures for different data', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });
        const data1 = new TextEncoder().encode('message 1');
        const data2 = new TextEncoder().encode('message 2');

        const sig1 = await didManager.sign(identity, data1);
        const sig2 = await didManager.sign(identity, data2);

        expect(sig1.value).not.toEqual(sig2.value);
      });
    });

    describe('Verification with resolved DID', () => {
      it('should verify valid signature', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });
        const data = new TextEncoder().encode('test message');
        const signature = await didManager.sign(identity, data);

        const isValid = await didManager.verify(
          identity.did,
          data,
          signature,
          identity.document
        );

        expect(isValid).toBe(true);
      });

      it('should reject invalid signature', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });
        const data = new TextEncoder().encode('test message');
        const signature = await didManager.sign(identity, data);

        const tamperedData = new TextEncoder().encode('tampered message');

        const isValid = await didManager.verify(
          identity.did,
          tamperedData,
          signature,
          identity.document
        );

        expect(isValid).toBe(false);
      });

      it('should reject signature with wrong verification method', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });
        const data = new TextEncoder().encode('test message');
        const signature = await didManager.sign(identity, data);

        signature.verificationMethod = 'did:wba:example.com#wrong-key';

        await expect(
          didManager.verify(identity.did, data, signature, identity.document)
        ).rejects.toThrow('Verification method not found');
      });
    });

    describe('Export of DID document', () => {
      it('should export DID document', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });

        const exported = didManager.exportDocument(identity);

        expect(exported).toEqual(identity.document);
      });

      it('should export document without private keys', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });

        const exported = didManager.exportDocument(identity);
        const exportedStr = JSON.stringify(exported);

        expect(exportedStr).not.toContain('privateKey');
        // Check that JWK doesn't contain the 'd' (private key) component
        // by verifying no JWK object has a 'd' property
        const jwks = exported.verificationMethod
          .map((vm) => vm.publicKeyJwk)
          .filter((jwk) => jwk !== undefined);
        jwks.forEach((jwk) => {
          expect(jwk).not.toHaveProperty('d');
        });
      });

      it('should export valid JSON-LD document', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });

        const exported = didManager.exportDocument(identity);

        expect(exported['@context']).toBeDefined();
        expect(Array.isArray(exported['@context'])).toBe(true);
      });
    });

    describe('Error handling for missing keys', () => {
      it('should throw error when signing with missing private key', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });
        identity.privateKeys.clear();

        const data = new TextEncoder().encode('test message');

        await expect(didManager.sign(identity, data)).rejects.toThrow(
          'Private key not found'
        );
      });

      it('should throw error when verifying with missing verification method', async () => {
        const identity = await didManager.createDID({ domain: 'example.com' });
        const data = new TextEncoder().encode('test message');

        const signature = {
          value: new Uint8Array(),
          verificationMethod: 'did:wba:example.com#nonexistent',
        };

        await expect(
          didManager.verify(identity.did, data, signature, identity.document)
        ).rejects.toThrow('Verification method not found');
      });
    });
  });
});
