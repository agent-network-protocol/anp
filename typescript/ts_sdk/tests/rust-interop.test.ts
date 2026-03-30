import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, test } from 'vitest';

import {
  generateAuthHeader,
  validateDidDocumentBinding,
  verifyAuthHeaderSignature,
  verifyW3cProof,
} from '../src/index.js';

describe('rust interop fixtures', () => {
  test('verifies Rust e1 DID proof', () => {
    const fixtureDir = join(process.cwd(), 'tests/fixtures/rust/e1');
    const didDocument = JSON.parse(readFileSync(join(fixtureDir, 'did.json'), 'utf8'));
    const publicKeyPem = readFileSync(join(fixtureDir, 'key-1_public.pem'), 'utf8');

    expect(validateDidDocumentBinding(didDocument, true)).toBe(true);
    expect(verifyW3cProof(didDocument, publicKeyPem)).toBe(true);
  });

  test('verifies Rust k1 DID proof and legacy auth header', () => {
    const fixtureDir = join(process.cwd(), 'tests/fixtures/rust/k1');
    const didDocument = JSON.parse(readFileSync(join(fixtureDir, 'did.json'), 'utf8'));
    const publicKeyPem = readFileSync(join(fixtureDir, 'key-1_public.pem'), 'utf8');
    const privateKeyPem = readFileSync(join(fixtureDir, 'key-1_private.pem'), 'utf8');

    expect(validateDidDocumentBinding(didDocument, true)).toBe(true);
    expect(verifyW3cProof(didDocument, publicKeyPem)).toBe(true);

    const header = generateAuthHeader(didDocument, 'api.example.com', privateKeyPem);
    expect(verifyAuthHeaderSignature(header, didDocument, 'api.example.com')).toBe(true);
  });
});
