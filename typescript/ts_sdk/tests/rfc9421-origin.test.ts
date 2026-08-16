import { describe, expect, test } from 'vitest';

import {
  DidProfile,
  RFC9421_ORIGIN_PROOF_DEFAULT_LABEL,
  Rfc9421OriginProofError,
  buildLogicalTargetUri,
  buildSignedRequestObject,
  canonicalizeSignedRequestObject,
  createDidDocument,
  generateRfc9421OriginProof,
  verifyRfc9421OriginProof,
} from '../src/index.js';
import { canonicalizeJson } from '../src/internal/json.js';

const DIRECT_META = {
  anp_version: '1.0',
  profile: 'anp.direct.base.v1',
  security_profile: 'transport-protected',
  sender_did: 'did:wba:example.com:user:alice:e1_alice',
  target: {
    kind: 'agent',
    did: 'did:wba:example.com:user:bob:e1_bob',
  },
  operation_id: 'op-1',
  message_id: 'msg-1',
  content_type: 'text/plain',
};

describe('RFC 9421 origin proof', () => {
  test('canonicalizes only method, meta, and body', () => {
    const signed = buildSignedRequestObject('direct.send', DIRECT_META, { text: 'hello' });
    const canonical = canonicalizeSignedRequestObject(signed);
    expect(Buffer.from(canonical).toString('utf8')).toBe(
      Buffer.from(
        canonicalizeJson({
          method: 'direct.send',
          meta: signed.meta,
          body: { text: 'hello' },
        })
      ).toString('utf8')
    );
    const text = Buffer.from(canonical).toString('utf8');
    expect(text).not.toContain('"auth"');
    expect(text).not.toContain('"client"');
    expect(text).not.toContain('"jsonrpc"');
  });

  test('builds a percent-encoded logical target URI', () => {
    expect(
      buildLogicalTargetUri('service', 'did:wba:example.com:services:message:e1_service')
    ).toBe('anp://service/did%3Awba%3Aexample.com%3Aservices%3Amessage%3Ae1_service');
  });

  test('generates and verifies a direct origin proof with caller created/nonce', () => {
    const bundle = createDidDocument('example.com', {
      pathSegments: ['user', 'alice'],
      didProfile: DidProfile.E1,
      enableE2ee: false,
    });
    const meta = {
      ...DIRECT_META,
      sender_did: bundle.didDocument.id,
    };
    const body = { text: 'hello' };
    const proof = generateRfc9421OriginProof(
      'direct.send',
      meta,
      body,
      bundle.keys['key-1'].privateKeyPem,
      `${bundle.didDocument.id}#key-1`,
      { created: 1712000000, nonce: 'nonce-1' }
    );

    expect(proof.signatureInput).toContain('created=1712000000');
    expect(proof.signatureInput).toContain('nonce="nonce-1"');

    const result = verifyRfc9421OriginProof(proof, 'direct.send', meta, body, {
      didDocument: bundle.didDocument,
      options: { expectedSignerDid: bundle.didDocument.id },
    });
    expect(result.parsedSignatureInput.label).toBe(RFC9421_ORIGIN_PROOF_DEFAULT_LABEL);
    expect(result.parsedSignatureInput.components).toEqual([
      '@method',
      '@target-uri',
      'content-digest',
    ]);
    expect(result.parsedSignatureInput.nonce).toBe('nonce-1');
    expect(result.parsedSignatureInput.created).toBe(1712000000);
  });

  test('generates and verifies a group.create origin proof', () => {
    const bundle = createDidDocument('example.com', {
      pathSegments: ['user', 'alice'],
      didProfile: DidProfile.E1,
      enableE2ee: false,
    });
    const serviceDid = 'did:wba:example.com:services:message:e1_service';
    const meta = {
      anp_version: '1.0',
      profile: 'anp.group.base.v1',
      security_profile: 'transport-protected',
      sender_did: bundle.didDocument.id,
      target: { kind: 'service', did: serviceDid },
      operation_id: 'op-group-create-1',
      content_type: 'application/json',
    };
    const body = {
      group_profile: { display_name: 'Demo' },
      group_policy: {
        admission_mode: 'open-join',
        permissions: {
          send: 'member',
          add: 'admin',
          remove: 'admin',
          update_profile: 'admin',
          update_policy: 'owner',
        },
      },
    };
    const proof = generateRfc9421OriginProof(
      'group.create',
      meta,
      body,
      bundle.keys['key-1'].privateKeyPem,
      `${bundle.didDocument.id}#key-1`,
      { created: 1712000100, nonce: 'nonce-group-create' }
    );
    const result = verifyRfc9421OriginProof(proof, 'group.create', meta, body, {
      didDocument: bundle.didDocument,
      options: { expectedSignerDid: bundle.didDocument.id },
    });
    expect(result.parsedSignatureInput.nonce).toBe('nonce-group-create');
  });

  test('rejects a non-sig1 label', () => {
    const bundle = createDidDocument('example.com', {
      pathSegments: ['user', 'alice'],
      didProfile: DidProfile.E1,
      enableE2ee: false,
    });
    expect(() =>
      generateRfc9421OriginProof(
        'direct.send',
        { ...DIRECT_META, sender_did: bundle.didDocument.id },
        { text: 'hello' },
        bundle.keys['key-1'].privateKeyPem,
        `${bundle.didDocument.id}#key-1`,
        { label: 'sig2' }
      )
    ).toThrow(Rfc9421OriginProofError);
    expect(() =>
      generateRfc9421OriginProof(
        'direct.send',
        { ...DIRECT_META, sender_did: bundle.didDocument.id },
        { text: 'hello' },
        bundle.keys['key-1'].privateKeyPem,
        `${bundle.didDocument.id}#key-1`,
        { label: 'sig2' }
      )
    ).toThrow(/signature label sig1/);
  });

  test('rejects signature input with an extra covered component', () => {
    const bundle = createDidDocument('example.com', {
      pathSegments: ['user', 'alice'],
      didProfile: DidProfile.E1,
      enableE2ee: false,
    });
    const meta = { ...DIRECT_META, sender_did: bundle.didDocument.id };
    const body = { text: 'hello' };
    const proof = generateRfc9421OriginProof(
      'direct.send',
      meta,
      body,
      bundle.keys['key-1'].privateKeyPem,
      `${bundle.didDocument.id}#key-1`,
      { created: 1712000200, nonce: 'nonce-extra-component' }
    );
    const tampered = {
      ...proof,
      signatureInput: proof.signatureInput.replace(
        '("@method" "@target-uri" "content-digest")',
        '("@method" "@target-uri" "content-digest" "@authority")'
      ),
    };
    expect(() =>
      verifyRfc9421OriginProof(tampered, 'direct.send', meta, body, {
        didDocument: bundle.didDocument,
        options: { expectedSignerDid: bundle.didDocument.id },
      })
    ).toThrow(/covered components/);
  });
});
