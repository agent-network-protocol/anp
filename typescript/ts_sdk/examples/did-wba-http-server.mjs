import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';

import { DidWbaVerifier, DidWbaVerifierError, createSignatureHeaders } from '../dist/index.js';
import {
  DEFAULT_HOST,
  DEFAULT_PORT,
  ensureDemoIdentities,
  serverOrigin,
} from './did-wba-demo-identity.mjs';

const EXEMPT_PATHS = new Set(['/health', '/.well-known/did.json']);

const identities = await ensureDemoIdentities();
const verifier = new DidWbaVerifier({
  jwtPrivateKey: identities.tokenSecret,
  jwtPublicKey: identities.tokenSecret,
  jwtAlgorithm: 'HS256',
  accessTokenExpireMinutes: 60,
  didResolver: async (did) => identities.trustedDidDocuments.get(did),
});
const serverPrivateKeyPem = await readFile(identities.paths.tsServerPrivateKey, 'utf8');

const server = createServer(async (request, response) => {
  try {
    const requestUrl = new URL(request.url ?? '/', serverOrigin());

    if (request.method === 'GET' && requestUrl.pathname === '/health') {
      return sendJson(response, 200, {
        status: 'healthy',
        service: 'did-wba-ts-http-server',
        serverDid: identities.tsServerDidDocument.id,
      });
    }

    if (request.method === 'GET' && requestUrl.pathname === '/.well-known/did.json') {
      return sendJson(response, 200, identities.tsServerDidDocument);
    }

    if (request.method === 'GET' && requestUrl.pathname.startsWith('/known-dids/')) {
      const did = decodeURIComponent(requestUrl.pathname.slice('/known-dids/'.length));
      const didDocument = identities.trustedDidDocuments.get(did);
      if (!didDocument) {
        return sendJson(response, 404, { detail: 'DID document not found' });
      }
      return sendJson(response, 200, didDocument);
    }

    if (!EXEMPT_PATHS.has(requestUrl.pathname)) {
      const body = await readBody(request);
      const authResult = await verifier.verifyRequest(
        request.method ?? 'GET',
        requestUrl.href,
        normalizeHeaders(request.headers),
        body,
        request.headers.host?.split(':')[0] ?? DEFAULT_HOST
      );

      if (requestUrl.pathname === '/api/protected') {
        return sendSignedJson(
          request,
          response,
          200,
          {
            message: 'Authentication successful',
            did: authResult.did,
            authScheme: authResult.authScheme,
            serverDid: identities.tsServerDidDocument.id,
          },
          authResult.responseHeaders
        );
      }

      if (requestUrl.pathname === '/api/user-info') {
        return sendSignedJson(
          request,
          response,
          200,
          {
            did: authResult.did,
            authenticated: true,
            authScheme: authResult.authScheme,
            serverDid: identities.tsServerDidDocument.id,
          },
          authResult.responseHeaders
        );
      }
    }

    return sendJson(response, 404, { detail: 'Not found' });
  } catch (error) {
    if (error instanceof DidWbaVerifierError) {
      return sendJson(response, error.statusCode, { detail: error.message }, error.headers);
    }
    return sendJson(response, 500, { detail: error instanceof Error ? error.message : 'Server error' });
  }
});

server.listen(DEFAULT_PORT, DEFAULT_HOST, () => {
  console.log(`DID-WBA TS server listening at ${serverOrigin()}`);
  console.log(`Server DID: ${identities.tsServerDidDocument.id}`);
  console.log(`Trusted TS client DID: ${identities.tsClientDidDocument.id}`);
  console.log(`Trusted Python client DID: ${identities.pythonDidDocument.id}`);
});

function sendJson(response, statusCode, payload, headers = {}) {
  response.writeHead(statusCode, {
    'Content-Type': 'application/json',
    ...headers,
  });
  response.end(`${JSON.stringify(payload, null, 2)}\n`);
}

function sendSignedJson(request, response, statusCode, payload, headers = {}) {
  const body = `${JSON.stringify(payload, null, 2)}\n`;
  const responseUrl = new URL(request.url ?? '/', serverOrigin()).href;
  const signedHeaders = createSignatureHeaders(
    identities.tsServerDidDocument,
    responseUrl,
    'RESPONSE',
    serverPrivateKeyPem,
    { 'Content-Type': 'application/json' },
    body,
    {
      coveredComponents: ['@method', '@target-uri', '@authority', 'content-type'],
    }
  );
  response.writeHead(statusCode, {
    'Content-Type': 'application/json',
    ...headers,
    'ANP-Server-DID': identities.tsServerDidDocument.id,
    ...signedHeaders,
  });
  response.end(body);
}

function normalizeHeaders(headers) {
  const normalized = {};
  for (const [key, value] of Object.entries(headers)) {
    if (Array.isArray(value)) {
      normalized[key] = value.join(', ');
    } else if (value !== undefined) {
      normalized[key] = value;
    }
  }
  return normalized;
}

async function readBody(request) {
  const chunks = [];
  for await (const chunk of request) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}
