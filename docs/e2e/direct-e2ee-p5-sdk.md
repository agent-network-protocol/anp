# ANP SDK Direct E2EE P5

## Status

- ANP-P5 v1 session support remains unchanged. The vNext wire contract is exposed side by side as explicit `v2` Rust, Python, Go, and Dart models/builders/validators; no v1 Session or Ratchet state is implicitly upgraded or reused.
- Frozen protocol authority: `AgentNetworkProtocol@25bfbc59a5a925141b565c4bc6c24195736382b5b`, [P5 Direct End-to-End Encryption](../../../AgentNetworkProtocol/message/vnext/05-direct-end-to-end-encryption.md).
- Harness map: [Direct E2EE cross-repo feature map](../../../../awiki-harness/features/direct-e2ee.md).
- Public discovery is controlled by product services and remains off until a separate discovery/security decision enables it.

## Owned surface

ANP SDK owns the cryptographic and wire semantics for private-chat E2EE:

- Go package: `golang/direct_e2ee/`.
- Rust module: `rust/src/direct_e2ee/`.
- Python package: `anp/direct_e2ee/`.
- Dart module: `dart/lib/src/direct_e2ee/` (wire models and Appendix-B verifier adapter; no Dart Ratchet implementation).
- Shared P5 vectors: `testdata/direct_e2ee/`.
- Go guide: `golang/docs/direct_e2ee-guide.md`.
- Go example: `golang/examples/direct_e2ee/`.

Product repositories should consume SDK models/helpers instead of reimplementing P5 algorithms or canonicalization.

## P5 primitives and models

The SDK-owned boundary includes:

- `PrekeyBundle` and `OneTimePrekey`.
- `DirectInitBody` for `application/anp-direct-init+json`.
- `DirectCipherBody` for `application/anp-direct-cipher+json`.
- `DirectEnvelopeMetadata` and canonical AAD builders.
- `ApplicationPlaintext`.
- X3DH-like initial material with optional OPK DH4.
- HKDF-SHA256 `kdf_rk` and `kdf_ck` labels defined by P5.
- pending-confirmation session state.
- Double Ratchet-like send/receive chains, replay protection, skipped-key handling, and max-skip behavior.
- file-backed reference stores for sessions, signed prekeys, OPKs, and pending outbox records.

P5 rules that product integrations rely on:

- `prekey_bundle` must not embed `one_time_prekey`; OPK is a top-level sidecar from `direct.e2ee.get_prekey_bundle`.
- A prekey-bundle publish `operation_id` identifies the complete publish payload, not only the stable `bundle_id`. Callers must reuse it when retrying the same payload and create a new one when the OPK sidecar changes.
- Direct E2EE `direct.send` requires `operation_id == message_id`.
- Current phase-1 direct-e2ee wire omits `params.auth` unless a future extension/capability explicitly changes that.
- Direct init/cipher AAD uses JCS/RFC8785 and P5 `content_type` bindings.
- Old HPKE-style `e2ee_init` / `e2ee_msg` service target objects are not P5.

The v2 surface additionally fixes these interoperability rules:

- SDK `*_request_v2` helpers return the repository's existing transport-neutral `{method, params}` object. They intentionally do not add JSON-RPC `jsonrpc` or `id`; the caller's binding layer owns the full envelope. The corresponding parsers accept only this helper shape, not a full JSON-RPC envelope.
- `PrekeyBundle` includes `owner_device_id`; its Appendix-B Object Proof protects the complete bundle after removing only top-level `proof` and its signing/static keys must equal the selected Manifest device keys.
- publish/get requests are service-scoped and select an exact sender/target device; `one_time_prekey` remains a get-response sidecar.
- `preferred_suite` is a non-empty negotiation preference and is not restricted to the MTI identifier at the wire-model layer; returned Bundles and MTI cipher objects remain suite-validated.
- `direct.send` contains exactly one recipient-device ciphertext, both device selectors, and `operation_id == message_id`; there is no `deliveries[]` aggregate.
- `AD_init` and `AD_msg` bind both DIDs, both device IDs, both outer IDs, and the exact P5 wire fields. Optional outer `anp_version` and `created_at` never enter either AAD.
- `logical_message_id` exists only inside AEAD-protected `ApplicationPlaintext`.
- Optional wire members must be omitted when absent; explicit `null` is rejected, including `recipient_one_time_prekey_id` and key-service preferences.
- `text/plain` uses `text`, while `application/json` and the standard attachment Manifest content type use an object `payload`; `annotations` is also an object. Empty JSON objects are preserved by every SDK.
- Dart uses the same RFC 8785 numeric serialization and Appendix-B `z...` base58-btc Ed25519 Object Proof as Rust, Python, and Go; the generic legacy Dart W3C-proof encoding is not reused for Bundle proofs.
- error allocations are the normative `4000` through `4012` table.
- AWiki root-transfer metadata, Registry/version fields, role/readiness state, and other same-domain control fields are not ANP P5 wire members.

For ordinary structured JSON, products should use `application/json` as the inner
`application_content_type` and put the JSON object directly in `payload`:

```json
{
  "application_content_type": "application/json",
  "payload": {
    "type": "example",
    "data": {
      "hello": "world"
    }
  }
}
```

In Rust this is represented with the existing helper:

```rust
ApplicationPlaintext::new_json(
    "application/json",
    serde_json::json!({"type": "example", "data": {"hello": "world"}}),
)
```

The SDK does not define command/status/task/result schemas; those are product
semantics above the ANP SDK layer.

## Product boundaries

| Product repo | Consumes SDK for | Must not do |
| --- | --- | --- |
| `awiki-cli` | Go direct session, prekey/OPK stores, secure send/decrypt, outbox/retry/drop/status. | Reimplement P5 crypto or put private ratchet material in argv/logs. |
| `message-service` | Rust/public P5 model validation and proof-boundary helpers. | Decrypt plaintext or store private session/key material. |
| `user-service` | DID document key roles and service metadata expectations. | Store private E2EE sessions, RK/CK/MK, OPK private material, or decrypt messages. |

## Shared vectors and parity

`testdata/direct_e2ee/p5_shared_vectors.json` anchors deterministic behavior for:

- direct init AAD with and without OPK;
- direct cipher AAD;
- X3DH-like no-OPK and OPK material;
- `kdf_ck` / `kdf_rk` output labels.

Keep Go/Rust/Python parity tests aligned before claiming SDK compatibility or public discovery readiness.

`testdata/direct_e2ee/p5_v2_wire_vectors.json` is the separate vNext contract fixture consumed by Rust, Python, Go, and Dart. It anchors Bundle protected bytes, a real cross-language Appendix-B signed Bundle, publish/get requests (including a non-MTI suite preference), device-qualified `direct.send`, `AD_init`, `AD_msg`, RFC 8785 numeric/empty-object plaintext, forbidden/null negatives, and the exact error table. It intentionally does not replace the v1 cryptographic vectors.

## Validation

Focused SDK checks:

```bash
cd anp/anp
go test ./golang/direct_e2ee ./golang/integration
cargo test --manifest-path rust/Cargo.toml direct_e2ee --all-targets
uv run pytest anp/unittest/direct_e2ee -q
(cd dart && dart analyze && dart test test/codec/codec_test.dart test/proof/proof_test.dart test/direct_e2ee/v2_wire_vectors_test.dart)
```

If only shared vectors changed, run the language-specific shared-vector tests first and then product focused tests in `awiki-cli`, `message-service`, and `awiki-system-test`.

## Non-goals

- Public service discovery enablement.
- Group E2EE / MLS.
- Product-local device roles, join/SAS, Registry, root-key transfer, and recovery semantics.
- Direct Init Accountability Extension.
- PQ/PQXDH.
- Service-side plaintext decrypt.
