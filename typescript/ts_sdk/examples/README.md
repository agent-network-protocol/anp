# Examples

These examples focus on the stable three-module public API:

- `authentication`
- `proof`
- `wns`

Build the SDK first:

```bash
npm run build
```

Then run an example:

```bash
node examples/authentication.mjs
node examples/proof.mjs
node examples/wns.mjs
```

## DID-WBA HTTP authentication

The HTTP examples mirror the Python DID-WBA flow:

- The first protected request is signed with HTTP Message Signatures.
- If the server returns `401` with `WWW-Authenticate` / `Accept-Signature`, the client retries with the server nonce.
- On success, the server returns a Bearer token in `Authentication-Info`.
- Later requests reuse the cached Bearer token.

Start the TypeScript server:

```bash
npm run build
node examples/did-wba-http-server.mjs
```

In another terminal, run the TypeScript client:

```bash
node examples/did-wba-http-client.mjs
```

From the repository root, a Python SDK client can authenticate against the same TypeScript server:

```bash
uv run python typescript/ts_sdk/examples/python_to_ts_did_wba_client.py
```

The examples generate local demo TS DID files under `examples/.generated/`.
