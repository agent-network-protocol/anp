# ANP SDK Direct E2EE P5

## Status

- ANP-P5 v1 session support remains unchanged. The vNext wire contract is exposed side by side as explicit `v2` Rust, Python, Go, and Dart models/builders/validators. Rust additionally exposes the P5 v2 exact-device session runtime; no v1 Session or Ratchet state is implicitly upgraded or reused.
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

The Rust v2 runtime is the explicit `V2DirectE2eeSession` surface. Its
persisted `V2DirectSessionState` and `V2PendingOutboundRecord` use separate v2
format identifiers and bind the complete
`(local_did, local_device_id, peer_did, peer_device_id, session_id, suite,
local_e2ee_key_id, peer_e2ee_key_id)` index. Every send/decrypt call also takes
the expected `V2SessionBinding`, so a current device/key mismatch fails closed.
Session state contains private ratchet material and must be stored encrypted;
its `Debug` implementation redacts secrets.

### Rust runtime integration preconditions

The Rust runtime deliberately does not resolve DID documents or own a product
database. Before `V2DirectE2eeSession::initiate_session`, the caller must use
one current DID-document view whose authenticity was already validated by the
normal DID-resolution path to:

1. confirm the exact target device is Manifest-eligible for P5 v2;
2. validate the complete `V2GetPrekeyBundleResult`;
3. verify its Bundle proof and Manifest key binding with
   `verify_prekey_bundle_v2`;
4. extract the recipient static X25519 public key from that same verified DID
   document; and
5. use only an OPK sidecar from that same get response and exact target.

The caller must likewise check that its local static private key derives the
current local Manifest E2EE public key. Before accepting init, the receiver
must bind its Bundle, signed-prekey private key, and optional OPK record/private
key to the current local Manifest device, and extract the sender static public
key from the current sender DID document for the exact peer binding.
The runtime tests include a real Object Proof plus Device Manifest flow through
Bundle verification, key extraction, init creation, and init acceptance; test
fixtures with placeholder proofs are not evidence that these preconditions
were performed.

Product persistence provides the transaction boundary that an in-memory SDK
cannot provide:

- persist the returned pending init before its first send, and retry the exact
  stored body, `operation_id`, and `message_id` bytes rather than generating a
  new ephemeral init;
- on receive, atomically record init replay/idempotency state, persist the new
  session, and consume/delete the returned OPK ID; and
- atomically persist each accepted Ratchet transition. A matching skipped key
  is the sole failure path that intentionally commits key deletion after AEAD
  failure, as required by P5. A product wrapper must therefore persist the
  possibly mutated state even when that call returns `DecryptFailed`; ordinary
  failure paths leave the state byte-for-byte unchanged.

Skipped message keys use one per-session bound across all DH chains. The
persisted vector is insertion-ordered; once `MAX_SKIP` is full, insertion
deterministically evicts the oldest entry first. Successful runtime commits
validate the complete resulting state before replacement, while ordinary
authentication, max-skip, and Ratchet failures leave the prior state intact.

Runtime failures expose `DirectE2eeV2RuntimeErrorKind` and
`DirectE2eeV2Error::protocol_error()` for stable product mapping:

| Runtime category | P5 code | `anp_code` |
| --- | ---: | --- |
| `BadInitMessage` | 4007 | `anp.direct.e2ee.bad_init_message` |
| `ReplayDetected` | 4008 | `anp.direct.e2ee.replay_detected` |
| `DecryptFailed` | 4009 | `anp.direct.e2ee.decrypt_failed` |
| `MaxSkipExceeded` | 4010 | `anp.direct.e2ee.max_skip_exceeded` |
| `InvalidSecurityBinding` | 4012 | `anp.direct.e2ee.invalid_security_binding` |

Replay detection is product-store state: when the atomic init replay check
rejects a non-idempotent replay, the integration maps it with
`DirectE2eeV2Error::runtime(DirectE2eeV2RuntimeErrorKind::ReplayDetected)`.
The SDK does not maintain a second hidden replay database.

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
- Same-DID own-device sessions are supported when the two opaque device IDs and E2EE key references differ. The identical DID/device endpoint is rejected.
- `select_default_outbound_session_v2` selects only an established, enabled session within one exact binding from a caller-provided newest-first slice. `disable_peer_device_sessions_v2` disables only the selected peer device; it is a local primitive and does not implement a product Registry.
- A matching skipped message key follows P5 section 10.2.3.2 and is consumed even when AEAD authentication fails. Ordinary unmatched-message failures remain tentative and do not advance session state.
- The `MAX_SKIP` cap is global to one session, not reset per DH chain; eviction is deterministic oldest-insertion-first and never uses wall-clock time.

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

In the Rust v2 runtime this is represented by the typed plaintext model:

```rust
let plaintext = V2ApplicationPlaintext {
    application_content_type: "application/json".to_owned(),
    logical_message_id: Some("logical-123".to_owned()),
    conversation_id: None,
    reply_to_message_id: None,
    annotations: None,
    text: None,
    payload: Some(serde_json::json!({
        "type": "example",
        "data": {"hello": "world"}
    })),
    payload_b64u: None,
};
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
cargo test --manifest-path rust/Cargo.toml --lib direct_e2ee::v2_session
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
