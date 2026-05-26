# ANP SDK Direct E2EE P5

## Status

- ANP-P5 Direct E2EE SDK support is implemented across the product-consumed Go and Rust surfaces, with Python helpers and shared vectors retained for parity and regression coverage.
- Protocol authority: [ANP P5 私聊端到端加密](../../../AgentNetworkProtocol/chinese/message/05-私聊端到端加密.md).
- Harness map: [Direct E2EE cross-repo feature map](../../../../awiki-harness/features/direct-e2ee.md).
- Public discovery is controlled by product services and remains off until a separate discovery/security decision enables it.

## Owned surface

ANP SDK owns the cryptographic and wire semantics for private-chat E2EE:

- Go package: `golang/direct_e2ee/`.
- Rust module: `rust/src/direct_e2ee/`.
- Python package: `anp/direct_e2ee/`.
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
- Direct E2EE `direct.send` requires `operation_id == message_id`.
- Current phase-1 direct-e2ee wire omits `params.auth` unless a future extension/capability explicitly changes that.
- Direct init/cipher AAD uses JCS/RFC8785 and P5 `content_type` bindings.
- Old HPKE-style `e2ee_init` / `e2ee_msg` service target objects are not P5.

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

## Validation

Focused SDK checks:

```bash
cd anp/anp
go test ./golang/direct_e2ee ./golang/integration
cargo test --manifest-path rust/Cargo.toml direct_e2ee --all-targets
uv run pytest anp/unittest/direct_e2ee -q
```

If only shared vectors changed, run the language-specific shared-vector tests first and then product focused tests in `awiki-cli`, `message-service`, and `awiki-system-test`.

## Non-goals

- Public service discovery enablement.
- Group E2EE / MLS.
- Multi-device protocol semantics.
- Direct Init Accountability Extension.
- PQ/PQXDH.
- Service-side plaintext decrypt.
