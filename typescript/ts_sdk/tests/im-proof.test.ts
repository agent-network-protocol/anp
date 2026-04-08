import { describe, expect, test } from 'vitest';

import {
  DidProfile,
  IM_PROOF_RELATION_ASSERTION_METHOD,
  buildImContentDigest,
  buildImSignatureInput,
  createDidWbaDocument,
  decodeImSignature,
  encodeImSignature,
  generateImProof,
  parseImSignatureInput,
  verifyImProof,
} from '../src/index.js';

function buildBusinessSignatureBase(
  method: string,
  targetUri: string,
  contentDigest: string,
  signatureInput: string
): string {
  const parsed = parseImSignatureInput(signatureInput);
  const componentValues: Record<string, string> = {
    '@method': method,
    '@target-uri': targetUri,
    'content-digest': contentDigest,
  };
  const lines = parsed.components.map(
    (component) => `"${component}": ${componentValues[component]}`
  );
  lines.push(`"@signature-params": ${parsed.signatureParams}`);
  return lines.join('\n');
}

describe('im proof', () => {
  test('generates and verifies e1 proof', () => {
    const bundle = createDidWbaDocument('example.com', {
      pathSegments: ['user', 'alice'],
      didProfile: DidProfile.E1,
    });
    const payload = '{"text":"hello"}';
    const signatureInput = buildImSignatureInput(`${bundle.didDocument.id}#key-1`, {
      nonce: 'nonce-1',
      created: 1712000000,
    });
    const signatureBase = buildBusinessSignatureBase(
      'direct.send',
      `anp://agent/${encodeURIComponent(bundle.didDocument.id)}`,
      buildImContentDigest(payload),
      signatureInput
    );
    const proof = generateImProof(
      payload,
      signatureBase,
      bundle.keys['key-1'].privateKeyPem,
      `${bundle.didDocument.id}#key-1`,
      {
        nonce: 'nonce-1',
        created: 1712000000,
      }
    );

    const result = verifyImProof(
      proof,
      payload,
      buildBusinessSignatureBase(
        'direct.send',
        `anp://agent/${encodeURIComponent(bundle.didDocument.id)}`,
        proof.contentDigest,
        proof.signatureInput
      ),
      { didDocument: bundle.didDocument },
      bundle.didDocument.id
    );
    expect(result.parsedSignatureInput.keyid).toBe(`${bundle.didDocument.id}#key-1`);
    expect(result.parsedSignatureInput.nonce).toBe('nonce-1');
  });

  test('generates and verifies k1 proof', () => {
    const bundle = createDidWbaDocument('example.com', {
      pathSegments: ['user', 'bob'],
      didProfile: DidProfile.K1,
    });
    const payload = '{"text":"hello-k1"}';
    const proof = generateImProof(
      payload,
      buildBusinessSignatureBase(
        'group.send',
        `anp://group/${encodeURIComponent(bundle.didDocument.id)}`,
        buildImContentDigest(payload),
        buildImSignatureInput(`${bundle.didDocument.id}#key-1`, {
          nonce: 'nonce-k1',
          created: 1712000100,
        })
      ),
      bundle.keys['key-1'].privateKeyPem,
      `${bundle.didDocument.id}#key-1`,
      {
        nonce: 'nonce-k1',
        created: 1712000100,
      }
    );
    const result = verifyImProof(
      proof,
      payload,
      buildBusinessSignatureBase(
        'group.send',
        `anp://group/${encodeURIComponent(bundle.didDocument.id)}`,
        proof.contentDigest,
        proof.signatureInput
      ),
      { didDocument: bundle.didDocument },
      bundle.didDocument.id
    );
    expect(result.parsedSignatureInput.nonce).toBe('nonce-k1');
  });

  test('rejects tampered payload', () => {
    const bundle = createDidWbaDocument('example.com', {
      pathSegments: ['user', 'eve'],
      didProfile: DidProfile.E1,
    });
    const payload = '{"text":"hello"}';
    const proof = generateImProof(
      payload,
      buildBusinessSignatureBase(
        'direct.send',
        `anp://agent/${encodeURIComponent(bundle.didDocument.id)}`,
        buildImContentDigest(payload),
        buildImSignatureInput(`${bundle.didDocument.id}#key-1`)
      ),
      bundle.keys['key-1'].privateKeyPem,
      `${bundle.didDocument.id}#key-1`
    );

    expect(() =>
      verifyImProof(
        proof,
        '{"text":"tampered"}',
        buildBusinessSignatureBase(
          'direct.send',
          `anp://agent/${encodeURIComponent(bundle.didDocument.id)}`,
          proof.contentDigest,
          proof.signatureInput
        ),
        { didDocument: bundle.didDocument },
        bundle.didDocument.id
      )
    ).toThrow(/contentDigest/);
  });

  test('signature helpers round trip', () => {
    const encoded = encodeImSignature(new TextEncoder().encode('hello'), 'sig2');
    const decoded = decodeImSignature(encoded);
    expect(decoded.label).toBe('sig2');
    expect(new TextDecoder().decode(decoded.signatureBytes)).toBe('hello');
  });

  test('defaults to authentication relationship', () => {
    const bundle = createDidWbaDocument('example.com', {
      pathSegments: ['user', 'assertion-only'],
      didProfile: DidProfile.E1,
    });
    const payload = '{"text":"hello"}';
    const proof = generateImProof(
      payload,
      buildBusinessSignatureBase(
        'direct.send',
        `anp://agent/${bundle.didDocument.id}`,
        buildImContentDigest(payload),
        buildImSignatureInput(`${bundle.didDocument.id}#key-1`, {
          nonce: 'nonce-auth',
          created: 1712000200,
        })
      ),
      bundle.keys['key-1'].privateKeyPem,
      `${bundle.didDocument.id}#key-1`,
      {
        nonce: 'nonce-auth',
        created: 1712000200,
      }
    );
    const didDocument = {
      ...bundle.didDocument,
      authentication: [],
    };

    expect(() =>
      verifyImProof(
        proof,
        payload,
        buildBusinessSignatureBase(
          'direct.send',
          `anp://agent/${bundle.didDocument.id}`,
          proof.contentDigest,
          proof.signatureInput
        ),
        { didDocument },
        bundle.didDocument.id
      )
    ).toThrow(/authorized for authentication/);

    const result = verifyImProof(
      proof,
      payload,
      buildBusinessSignatureBase(
        'direct.send',
        `anp://agent/${bundle.didDocument.id}`,
        proof.contentDigest,
        proof.signatureInput
      ),
      {
        didDocument,
        verificationRelationship: IM_PROOF_RELATION_ASSERTION_METHOD,
      },
      bundle.didDocument.id
    );
    expect(result.parsedSignatureInput.keyid).toBe(`${bundle.didDocument.id}#key-1`);
  });

  test('requires exact signer DID match', () => {
    const bundle = createDidWbaDocument('example.com', {
      pathSegments: ['user', 'prefix-check'],
      didProfile: DidProfile.E1,
    });
    const payload = '{"text":"hello"}';
    const proof = generateImProof(
      payload,
      buildBusinessSignatureBase(
        'direct.send',
        `anp://agent/${bundle.didDocument.id}`,
        buildImContentDigest(payload),
        buildImSignatureInput(`${bundle.didDocument.id}#key-1`, {
          nonce: 'nonce-prefix',
          created: 1712000300,
        })
      ),
      bundle.keys['key-1'].privateKeyPem,
      `${bundle.didDocument.id}#key-1`,
      {
        nonce: 'nonce-prefix',
        created: 1712000300,
      }
    );

    expect(() =>
      verifyImProof(
        proof,
        payload,
        buildBusinessSignatureBase(
          'direct.send',
          `anp://agent/${bundle.didDocument.id}`,
          proof.contentDigest,
          proof.signatureInput
        ),
        { didDocument: bundle.didDocument },
        'did:wba:example.com:user:prefix-check'
      )
    ).toThrow(/expected signer DID/);
  });
});
