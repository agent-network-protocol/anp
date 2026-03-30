import {
  AuthMode,
  DidProfile,
  DidWbaVerifier,
  createDidDocument,
  createLegacyAuthHeader,
  createSignatureHeaders,
} from '../dist/index.js';

const bundle = createDidDocument('example.com', {
  pathSegments: ['agents', 'demo'],
  didProfile: DidProfile.K1,
});

console.log('DID:', bundle.didDocument.id);

const legacyHeader = createLegacyAuthHeader(
  bundle.didDocument,
  'api.example.com',
  bundle.keys['key-1'].privateKeyPem
);
console.log('Legacy header:', legacyHeader);

const httpSignatureHeaders = createSignatureHeaders(
  bundle.didDocument,
  'https://api.example.com/orders',
  'POST',
  bundle.keys['key-1'].privateKeyPem,
  {},
  JSON.stringify({ item: 'book' })
);
console.log('HTTP signature headers:', httpSignatureHeaders);

const verifier = new DidWbaVerifier({
  jwtPrivateKey: 'demo-secret',
  jwtPublicKey: 'demo-secret',
  jwtAlgorithm: 'HS256',
});

const verification = await verifier.verifyRequestWithDidDocument(
  'GET',
  'https://api.example.com/orders',
  { Authorization: legacyHeader },
  bundle.didDocument
);
console.log('Verification result:', verification);
console.log('Suggested auth mode:', AuthMode.HttpSignatures);
