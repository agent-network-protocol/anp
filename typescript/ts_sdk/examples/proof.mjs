import {
  DidProfile,
  createDidDocument,
  createProof,
  verifyProof,
} from '../dist/index.js';

const bundle = createDidDocument('example.com', {
  pathSegments: ['agents', 'demo'],
  didProfile: DidProfile.E1,
});

const unsignedDocument = {
  id: 'did:wba:example.com:credential:alice',
  type: 'VerifiableCredential',
  credentialSubject: {
    id: 'did:wba:example.com:agents:alice',
    capability: 'hotel-booking',
  },
};

const signedDocument = createProof(
  unsignedDocument,
  bundle.keys['key-1'].privateKeyPem,
  `${bundle.didDocument.id}#key-1`,
  {
    proofType: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    domain: 'example.com',
  }
);

console.log('Signed proof:', signedDocument.proof);
console.log('Proof verified:', verifyProof(signedDocument, bundle.keys['key-1'].publicKeyPem));
