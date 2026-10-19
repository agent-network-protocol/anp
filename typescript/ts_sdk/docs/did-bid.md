# did:bid (Xinghuo BIF) Integration

The SDK resolves `did:bid` documents and authenticates with a pre-provisioned
`did:bid` identity. It uses
[`@caict-bif/bid-typescript-sdk`](https://www.npmjs.com/package/@caict-bif/bid-typescript-sdk)
as a lazily-loaded, ESM-only dependency, so the main entry point stays free of it.

Scope and guarantees:

- **ED25519 only.** SM2 (国密) identities are not supported.
- **Read-only.** The SDK resolves documents and signs with a key you provide. It
  never writes to the chain; `did:bid` registration and updates remain an
  application/operations responsibility (the same boundary used for `did:web`).
- **Pre-provisioned identity.** You supply the starfire-encoded private key; the
  SDK never generates or stores it.

## Requirements

- Node 20+
- `@caict-bif/bid-typescript-sdk` installed (declared as a dependency)
- A reachable BID parser service base URL

## Configuration

Call `configureBid()` once at startup:

```ts
import { configureBid } from '@awiki/anp-typescript-sdk';

configureBid({
  parserUrl: 'https://xinghuoid.zetrix.com/bid/',
});
```

- `parserUrl` is the resolution service base URL. With it set, resolution goes
  through the parser.
- `directNodeUrl` is optional and defaults to the placeholder
  `https://example.invalid`. It only exists to satisfy the BID SDK's `connect()`
  check; because `parserUrl` is set, the direct node is never contacted.

> The placeholder `directNodeUrl` must still be a valid absolute URL
> (`configureBid` validates it). If you later remove `parserUrl`, resolution falls
> back to the chain node and fails against the placeholder.

## Resolve a did:bid document

```ts
import { resolveDidDocument } from '@awiki/anp-typescript-sdk';

const document = await resolveDidDocument('did:bid:efg8YPjq6jMbou6jdZdc9YEwHuyz1QMW');
console.log(document.id);                          // did:bid:efg8...
console.log(document.verificationMethod[0].type);  // Ed25519VerificationKey2020
```

Or through the namespace:

```ts
import { authentication } from '@awiki/anp-typescript-sdk';

const document = await authentication.bid.resolveBidDocument('did:bid:ef...');
```

`resolveDidDocument()` dispatches by DID method; `did:bid:` needs no extra
options. The resolved document is mapped to the SDK's DID document shape: BID
`publicKey[]` (starfire-encoded `publicKeyHex`) becomes `verificationMethod[]`
with an Ed25519 `publicKeyMultibase`, and `authentication[]` / `service[]` are
preserved. BID's `extension`, `created`, and `updated` are not carried over.

## Sign with a pre-provisioned did:bid identity

```ts
import {
  bidPrivateKeyToPem,
  createLegacyAuthHeader,
  createSignatureHeaders,
  resolveDidDocument,
} from '@awiki/anp-typescript-sdk';

const document = await resolveDidDocument('did:bid:ef...');
const pem = await bidPrivateKeyToPem('priSPK...');

// Legacy DIDWba header
const header = createLegacyAuthHeader(document, 'api.example.com', pem);

// HTTP Message Signatures
const headers = createSignatureHeaders(
  document,
  'https://api.example.com/orders',
  'POST',
  pem,
  {},
  JSON.stringify({ item: 'book' })
);
```

The starfire private key is converted to the SDK's Ed25519 PEM form, and signing
uses the SDK's native Ed25519 path. The signatures are byte-identical to the ones
the BID SDK produces, so a BID-native verifier accepts them (and vice versa).

## Verify inbound did:bid requests

Once `configureBid()` has been called, `DidWbaVerifier` resolves `did:bid` peers
automatically through `resolveDidDocument()` for both HTTP Message Signatures and
legacy `DIDWba` headers. Bearer tokens whose subject is `did:bid:` are accepted
too.

```ts
import { DidWbaVerifier, configureBid } from '@awiki/anp-typescript-sdk';

configureBid({ parserUrl: 'https://xinghuoid.zetrix.com/bid/' });
const verifier = new DidWbaVerifier({
  jwtPrivateKey: 'secret',
  jwtPublicKey: 'secret',
  jwtAlgorithm: 'HS256',
});
const result = await verifier.verifyRequest('POST', url, headers, body);
```

## Key helpers

| Helper | Purpose |
|---|---|
| `bidPrivateKeyToPem(key)` | Starfire `priSPK...` → SDK Ed25519 PEM |
| `bidPrivateKeyToMaterial(key)` | Starfire private key → `{ type: 'ed25519', bytes }` |
| `bidPublicKeyToMaterial(key)` | Starfire `b06566...` public key → `{ type: 'ed25519', bytes }` |
| `isEd25519StarfirePublicKey(key)` | Detect the ED25519 starfire encoding without loading the SDK |
| `mapBidDocumentToDidDocument(doc)` | Map a raw BID document to the SDK shape |

## Security and trust model

- **No self-certifying proof.** A `did:bid` document carries no proof, so the
  SDK's binding check is intentionally a no-op for `did:bid`; trust rests on the
  chain/parser. Treat the resolved document accordingly.
- **Secrets.** The SDK never reads `.env` and never stores keys. Pass the private
  key yourself; keep it in a secret manager, or a gitignored local file for tests.
- **TLS.** The reference parser (`https://xinghuoid.zetrix.com/bid/`) is trusted
  by Node's built-in CA on Node 20. Other Xinghuo hosts may require
  `NODE_EXTRA_CA_CERTS`.

## Live tests (opt-in)

The did:bid tests are offline by default; two live tests are skipped unless these
environment variables are set:

- `ANP_BID_PARSER_URL` — enables the live resolution test.
- `ANP_BID_TEST_PRIVATE_KEY` — additionally enables the live signing test.
- `ANP_BID_TEST_DID` — optional identity override.

Copy `.env.example` to `.env` (gitignored) and run with Node's built-in
`--env-file` (Node 20.6+). The SDK does not read `.env` itself:

```bash
cd typescript/ts_sdk
cp .env.example .env   # fill in your values
node --env-file=.env ./node_modules/vitest/vitest.mjs --run tests/did-bid.test.ts
```

In CI, set the same variables as secret environment variables instead of a `.env`
file. See also [`examples/did-bid.mjs`](../examples/did-bid.mjs).

## Limitations

- ED25519 only (no SM2).
- No chain writes: creating or updating a `did:bid` identity is out of scope.
- BID `extension` / `created` / `updated` are not propagated into the SDK document
  model.