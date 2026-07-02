import { jwtVerify } from 'jose';

import { DIDWbaAuthHeader, verifySignatureHeaders } from '../dist/index.js';
import { ensureDemoIdentities, serverOrigin } from './did-wba-demo-identity.mjs';

const identities = await ensureDemoIdentities();
const authenticator = new DIDWbaAuthHeader(
  identities.paths.tsClientDidDocument,
  identities.paths.tsClientPrivateKey
);

const protectedUrl = `${serverOrigin()}/api/protected`;
const userInfoUrl = `${serverOrigin()}/api/user-info`;

console.log('Step 1: health check');
const health = await fetchJson(`${serverOrigin()}/health`);
console.log(health.body);

console.log('\nStep 2: TS client authenticates to TS server with DID-WBA');
let headers = await authenticator.getAuthHeaders(protectedUrl, true, 'GET');
let protectedResponse = await fetch(protectedUrl, { headers });
if (protectedResponse.status === 401 && authenticator.shouldRetryAfter401(toHeaderRecord(protectedResponse.headers))) {
  headers = await authenticator.getChallengeAuthHeaders(
    protectedUrl,
    toHeaderRecord(protectedResponse.headers),
    'GET'
  );
  protectedResponse = await fetch(protectedUrl, { headers });
}
const protectedBody = await readSignedJsonResponse(protectedResponse, protectedUrl);
console.log({ status: protectedResponse.status, body: protectedBody });
assertOk(protectedResponse, protectedBody);

const token = authenticator.updateToken(protectedUrl, toHeaderRecord(protectedResponse.headers));
if (!token) {
  throw new Error('TS server did not return a Bearer token');
}

const serverTokenPayload = await verifyServerToken(token, identities.tokenSecret);
if (serverTokenPayload.sub !== identities.tsClientDidDocument.id) {
  throw new Error('Server token subject does not match the TS client DID');
}
console.log('Verified server-issued Bearer token for:', serverTokenPayload.sub);

console.log('\nStep 3: TS client reuses cached Bearer token');
headers = await authenticator.getAuthHeaders(userInfoUrl);
const userInfoResponse = await fetch(userInfoUrl, { headers });
const userInfoBody = await readSignedJsonResponse(userInfoResponse, userInfoUrl);
console.log({ status: userInfoResponse.status, body: userInfoBody });
assertOk(userInfoResponse, userInfoBody);

console.log('\nTS client/server mutual DID-WBA authentication completed.');

async function fetchJson(url) {
  const response = await fetch(url);
  return {
    status: response.status,
    headers: toHeaderRecord(response.headers),
    body: await readJsonResponse(response),
  };
}

async function readJsonResponse(response) {
  return JSON.parse(await response.text());
}

async function readSignedJsonResponse(response, url) {
  const bodyText = await response.text();
  if (response.ok) {
    const headers = toHeaderRecord(response.headers);
    const serverDid = headers['anp-server-did'];
    if (serverDid !== identities.tsServerDidDocument.id) {
      throw new Error(`Unexpected server DID: ${serverDid}`);
    }
    verifySignatureHeaders(
      identities.tsServerDidDocument,
      'RESPONSE',
      url,
      headers,
      bodyText
    );
    console.log('Verified server DID response signature for:', serverDid);
  }
  return JSON.parse(bodyText);
}

function toHeaderRecord(headers) {
  return Object.fromEntries(headers.entries());
}

async function verifyServerToken(token, secret) {
  const result = await jwtVerify(token, new TextEncoder().encode(secret), {
    algorithms: ['HS256'],
  });
  return result.payload;
}

function assertOk(response, body) {
  if (!response.ok) {
    throw new Error(`Request failed with ${response.status}: ${JSON.stringify(body)}`);
  }
}
