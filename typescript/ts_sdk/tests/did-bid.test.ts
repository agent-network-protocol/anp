import { beforeEach, describe, expect, test } from 'vitest';

import { createHash } from 'node:crypto';

import canonicalize from 'canonicalize';
import { bidKeypairOperations } from '@caict-bif/bid-typescript-sdk';

import {
  DEFAULT_BID_DIRECT_NODE_URL,
  bidPrivateKeyToMaterial,
  bidPrivateKeyToPem,
  bidPublicKeyToMaterial,
  configureBid,
  generateAuthHeader,
  generateHttpSignatureHeaders,
  isEd25519StarfirePublicKey,
  mapBidDocumentToDidDocument,
  resetBidIntegration,
  resolveDidDocument,
  verifyAuthHeaderSignature,
  verifyHttpMessageSignature,
  type BuiltBidDocument,
} from '../src/index.js';
import { signMessage, verifyMessage } from '../src/internal/keys.js';

const identity = bidKeypairOperations.generate();

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

function bidDocument(): BuiltBidDocument {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: identity.address,
    publicKey: [
      {
        id: `${identity.address}#key-1`,
        type: 'Ed25519',
        controller: identity.address,
        publicKeyHex: identity.publicKey,
      },
    ],
    authentication: [`${identity.address}#key-1`],
    service: [
      {
        id: `${identity.address}#ad`,
        type: 'AgentDescription',
        serviceEndpoint: 'https://example.com/ad.json',
      },
    ],
  };
}

beforeEach(() => {
  resetBidIntegration();
});

describe('did:bid integration', () => {
  test('maps a BID document to an ANP DID document with an Ed25519 multibase key', async () => {
    const mapped = await mapBidDocumentToDidDocument(bidDocument());

    expect(mapped.id).toBe(identity.address);
    expect(mapped.authentication).toEqual([`${identity.address}#key-1`]);

    const method = mapped.verificationMethod[0];
    expect(method.id).toBe(`${identity.address}#key-1`);
    expect(method.type).toBe('Ed25519VerificationKey2020');
    expect(method.publicKeyMultibase?.startsWith('z')).toBe(true);

    expect(mapped.service?.[0].type).toBe('AgentDescription');
    expect(mapped.service?.[0].serviceEndpoint).toBe('https://example.com/ad.json');
  });

  test('rejects a BID document whose id is not did:bid', async () => {
    await expect(
      mapBidDocumentToDidDocument({ ...bidDocument(), id: 'did:web:example.com' })
    ).rejects.toThrow(/did:bid/);
  });

  test('converts starfire keys and cross-verifies ANP and BID Ed25519 signatures', async () => {
    const anpPrivate = await bidPrivateKeyToMaterial(identity.privateKey);
    const anpPublic = await bidPublicKeyToMaterial(identity.publicKey);
    const message = new TextEncoder().encode('did:bid interop');

    const anpSignature = signMessage(anpPrivate, message);
    const bidSignatureHex = bidKeypairOperations
      .signer(identity.privateKey)
      .sign(bytesToHex(message));

    // Ed25519 is deterministic: both sides must produce identical bytes.
    expect(bytesToHex(anpSignature)).toBe(bidSignatureHex);
    expect(verifyMessage(anpPublic, message, hexToBytes(bidSignatureHex))).toBe(true);
  });

  test('signs and verifies a legacy DIDWba header with a pre-provisioned did:bid identity', async () => {
    const mapped = await mapBidDocumentToDidDocument(bidDocument());
    const pem = await bidPrivateKeyToPem(identity.privateKey);

    const header = generateAuthHeader(mapped, 'api.example.com', pem);

    expect(header.startsWith('DIDWba')).toBe(true);
    expect(header).toContain(`did="${identity.address}"`);
    expect(header).toContain('verification_method="key-1"');
    expect(verifyAuthHeaderSignature(header, mapped, 'api.example.com')).toBe(true);
  });

  test('signs and verifies HTTP message signatures with a pre-provisioned did:bid identity', async () => {
    const mapped = await mapBidDocumentToDidDocument(bidDocument());
    const pem = await bidPrivateKeyToPem(identity.privateKey);
    const url = 'https://api.example.com/orders';
    const body = '{"item":"book"}';

    const headers = generateHttpSignatureHeaders(mapped, url, 'POST', pem, {}, body);
    const metadata = verifyHttpMessageSignature(mapped, 'POST', url, headers, body);

    expect(metadata.keyid).toBe(`${identity.address}#key-1`);

    expect(() =>
      verifyHttpMessageSignature(mapped, 'POST', url, headers, '{"item":"music"}')
    ).toThrow();
  });

  test('throws when resolving did:bid without configuration', async () => {
    await expect(resolveDidDocument(`did:bid:ef${'a'.repeat(20)}`)).rejects.toThrow(
      /not configured/i
    );
  });

  test('configureBid validates parserUrl and defaults the placeholder node URL', () => {
    expect(() => configureBid({ parserUrl: '' })).toThrow(/parserUrl/);
    expect(() => new URL(DEFAULT_BID_DIRECT_NODE_URL)).not.toThrow();
  });

  test('detects the ED25519 starfire public key encoding', () => {
    expect(isEd25519StarfirePublicKey(identity.publicKey)).toBe(true);
    expect(isEd25519StarfirePublicKey(`b07a66${'00'.repeat(65)}`)).toBe(false);
    expect(isEd25519StarfirePublicKey('')).toBe(false);
  });

  // Opt-in live check. Set ANP_BID_PARSER_URL (and optionally ANP_BID_DID) to run
  // against a real parser service; skipped by default to keep the suite offline.
  const liveParserUrl = process.env.ANP_BID_PARSER_URL ?? '';
  const liveDid = process.env.ANP_BID_DID ?? 'did:bid:efg8YPjq6jMbou6jdZdc9YEwHuyz1QMW';

  test.skipIf(liveParserUrl === '')(
    'resolves a live did:bid document through the parser',
    async () => {
      configureBid({ parserUrl: liveParserUrl });
      const didDocument = await resolveDidDocument(liveDid);

      expect(didDocument.id).toBe(liveDid);
      expect(didDocument.authentication).toEqual([`${liveDid}#key-1`]);

      const method = didDocument.verificationMethod[0];
      expect(method.type).toBe('Ed25519VerificationKey2020');
      expect(method.publicKeyMultibase?.startsWith('z')).toBe(true);
    }
  );

  // Opt-in live signing check. Requires a real did:bid private key supplied via
  // ANP_BID_TEST_PRIVATE_KEY (never committed); set ANP_BID_TEST_DID to override
  // the identity. Skipped by default.
  const livePrivateKey = process.env.ANP_BID_TEST_PRIVATE_KEY ?? '';
  const liveSignDid = process.env.ANP_BID_TEST_DID ?? 'did:bid:efjDRB4SvsBhBXQeyqog4WQdRmn3ojQ9';

  test.skipIf(liveParserUrl === '' || livePrivateKey === '')(
    'signs a legacy DIDWba header with a live did:bid identity and cross-verifies with the BID signer',
    async () => {
      configureBid({ parserUrl: liveParserUrl });
      const didDocument = await resolveDidDocument(liveSignDid);
      const pem = await bidPrivateKeyToPem(livePrivateKey);

      const header = generateAuthHeader(didDocument, 'api.example.com', pem);
      expect(verifyAuthHeaderSignature(header, didDocument, 'api.example.com')).toBe(true);

      const field = (name: string): string => {
        const match = header.match(new RegExp(`${name}="([^"]+)"`));
        if (!match) throw new Error(`missing ${name} in authorization header`);
        return match[1];
      };
      const contentHash = createHash('sha256')
        .update(
          canonicalize({
            nonce: field('nonce'),
            timestamp: field('timestamp'),
            aud: 'api.example.com',
            did: liveSignDid,
          }) ?? ''
        )
        .digest();

      const anpSignatureHex = Buffer.from(field('signature'), 'base64url').toString('hex');
      const bidSigner = bidKeypairOperations.signer(livePrivateKey);

      // Ed25519 is deterministic: ANP and the BID signer must agree byte-for-byte,
      // and the BID-native verifier must accept the ANP-produced signature.
      expect(anpSignatureHex).toBe(bidSigner.sign(contentHash.toString('hex')));
      expect(bidSigner.verify(contentHash.toString('hex'), anpSignatureHex)).toBe(true);
    }
  );
});
