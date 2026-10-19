// did:bid (Xinghuo BIF) integration example.
//
// The SDK never reads `.env`; the Node `--env-file` flag loads it for this process.
//
// Required:
//   ANP_BID_PARSER_URL      resolution service base URL (trailing slash)
// Optional:
//   ANP_BID_TEST_DID        did:bid to resolve (defaults to a public demo identity)
//   ANP_BID_TEST_PRIVATE_KEY  starfire private key (priSPK...) enables the signing part
//
// Run:
//   npm run build
//   node --env-file=.env examples/did-bid.mjs
//   # or pass variables inline:
//   ANP_BID_PARSER_URL=https://xinghuoid.zetrix.com/bid/ node examples/did-bid.mjs

import {
  bidPrivateKeyToPem,
  configureBid,
  generateAuthHeader,
  resolveDidDocument,
  verifyAuthHeaderSignature,
} from '../dist/index.js';

const parserUrl = process.env.ANP_BID_PARSER_URL;
const did = process.env.ANP_BID_TEST_DID ?? 'did:bid:efg8YPjq6jMbou6jdZdc9YEwHuyz1QMW';
const privateKey = process.env.ANP_BID_TEST_PRIVATE_KEY;

if (!parserUrl) {
  console.error(
    'Set ANP_BID_PARSER_URL first, e.g.\n' +
      '  ANP_BID_PARSER_URL=https://xinghuoid.zetrix.com/bid/ node examples/did-bid.mjs'
  );
  process.exit(1);
}

configureBid({ parserUrl });

const document = await resolveDidDocument(did);
console.log('Resolved did:bid document:');
console.log('  id            :', document.id);
console.log('  authentication:', document.authentication.join(', '));
console.log(
  '  verification  :',
  document.verificationMethod.map((method) => `${method.type} (${method.id})`).join(', ')
);

if (!privateKey) {
  console.log(
    '\nSet ANP_BID_TEST_PRIVATE_KEY to also demonstrate signing with a pre-provisioned did:bid identity.'
  );
  process.exit(0);
}

const pem = await bidPrivateKeyToPem(privateKey);
const header = generateAuthHeader(document, 'api.example.com', pem);

console.log('\nLegacy DIDWba header issued by the did:bid identity:');
console.log(' ', header);
console.log('  verifies:', verifyAuthHeaderSignature(header, document, 'api.example.com'));