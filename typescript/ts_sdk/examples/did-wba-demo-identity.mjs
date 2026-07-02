import { existsSync } from 'node:fs';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';

import { DidProfile, createDidDocument } from '../dist/index.js';

const EXAMPLES_DIR = dirname(fileURLToPath(import.meta.url));
const SDK_DIR = resolve(EXAMPLES_DIR, '..');
const REPO_ROOT = resolve(SDK_DIR, '..', '..');
const GENERATED_DIR = join(EXAMPLES_DIR, '.generated', 'did-wba-http');

export const DEFAULT_PORT = Number.parseInt(process.env.ANP_TS_DEMO_PORT ?? '8090', 10);
export const DEFAULT_HOST = process.env.ANP_TS_DEMO_HOST ?? '127.0.0.1';

export function serverOrigin() {
  return `http://${DEFAULT_HOST}:${DEFAULT_PORT}`;
}

export function demoPaths() {
  return {
    generatedDir: GENERATED_DIR,
    tsClientDidDocument: join(GENERATED_DIR, 'ts-client.did.json'),
    tsClientPrivateKey: join(GENERATED_DIR, 'ts-client.key.pem'),
    tsServerDidDocument: join(GENERATED_DIR, 'ts-server.did.json'),
    tsServerPrivateKey: join(GENERATED_DIR, 'ts-server.key.pem'),
    tokenSecret: join(GENERATED_DIR, 'token-secret.txt'),
    pythonDidDocument: join(REPO_ROOT, 'docs', 'did_public', 'public-did-doc.json'),
    pythonPrivateKey: join(REPO_ROOT, 'docs', 'did_public', 'public-private-key.pem'),
  };
}

export async function ensureDemoIdentities() {
  const paths = demoPaths();
  await mkdir(paths.generatedDir, { recursive: true });

  if (!existsSync(paths.tsClientDidDocument) || !existsSync(paths.tsClientPrivateKey)) {
    const bundle = createDidDocument('example.com', {
      pathSegments: ['agents', 'ts-client'],
      didProfile: DidProfile.K1,
      enableE2ee: false,
    });
    await writeJson(paths.tsClientDidDocument, bundle.didDocument);
    await writeFile(paths.tsClientPrivateKey, bundle.keys['key-1'].privateKeyPem, 'utf8');
  }

  if (!existsSync(paths.tsServerDidDocument) || !existsSync(paths.tsServerPrivateKey)) {
    const bundle = createDidDocument('example.com', {
      pathSegments: ['services', 'ts-auth-server'],
      didProfile: DidProfile.K1,
      enableE2ee: false,
    });
    await writeJson(paths.tsServerDidDocument, bundle.didDocument);
    await writeFile(paths.tsServerPrivateKey, bundle.keys['key-1'].privateKeyPem, 'utf8');
  }

  if (!existsSync(paths.tokenSecret)) {
    await writeFile(paths.tokenSecret, randomBytes(32).toString('base64url'), 'utf8');
  }

  return loadDemoIdentities();
}

export async function loadDemoIdentities() {
  const paths = demoPaths();
  const [tsClientDidDocument, tsServerDidDocument, pythonDidDocument, tokenSecret] =
    await Promise.all([
      readJson(paths.tsClientDidDocument),
      readJson(paths.tsServerDidDocument),
      readJson(paths.pythonDidDocument),
      readFile(paths.tokenSecret, 'utf8'),
    ]);

  const trustedDidDocuments = new Map(
    [tsClientDidDocument, pythonDidDocument, tsServerDidDocument].map((document) => [
      document.id,
      document,
    ])
  );

  return {
    paths,
    tsClientDidDocument,
    tsServerDidDocument,
    pythonDidDocument,
    tokenSecret: tokenSecret.trim(),
    trustedDidDocuments,
  };
}

async function readJson(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

async function writeJson(path, value) {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}
