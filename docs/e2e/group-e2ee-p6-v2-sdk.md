# P6 vNext SDK wire and binding helpers

## Scope and protocol snapshot

This SDK slice implements the frozen cross-domain surface of
[`anp.group.e2ee.v2`](../../../AgentNetworkProtocol/message/vnext/06-group-end-to-end-encryption.md)
from `AgentNetworkProtocol@25bfbc59a5a925141b565c4bc6c24195736382b5b`.
It is side-by-side with the existing `anp.group.e2ee.v1` models and typed
OpenMLS library operations; no v1 wire object is silently reinterpreted as v2.

Rust exposes the v2 helpers under `anp::group_e2ee`; Go exposes them from
`golang/group_e2ee`. Both SDKs include:

- closed publish/get/create/add/remove/send/notice/incoming DTOs;
- method-specific metadata, target-kind, security-profile and Origin Proof
  shape checks;
- `owner_did + owner_device_id` KeyPackage binding;
- canonical MLS `authenticated_data`, Add/Remove submission binding, and
  Group Application Plaintext helpers;
- the P6 `did_wba_binding` Object Proof and current P2 Manifest eligibility
  verifier;
- same-DID sibling-leaf validation without sharing a device ID or leaf key;
- the recommended P6 error table.

The shared Rust/Go vectors are in
`testdata/group_e2ee/p6_v2_wire_vectors.json`.

## MLS trust boundary

The JSON `group_key_package.did_wba_binding` member is a convenience copy. It
does not prove what is inside `mls_key_package_b64u`. A caller must first use a
conforming MLS implementation to decode and cryptographically validate the
TLS-serialized KeyPackage, then pass this authenticated projection to the SDK:

- credential identity bytes;
- the verified TLS-serialized KeyPackage bytes, which must equal the outer
  `mls_key_package_b64u` bytes;
- actual LeafNode signature public key;
- LeafNode extensions and extension bytes;
- LeafNode capability extension types;
- GroupContext required-capability extension types.

The verifier requires `credential.identity` to equal the UTF-8 Agent DID,
requires exactly one device-binding extension, compares its bytes with RFC
8785 JCS of the full signed binding, and checks both capability declarations.
It then follows the current Manifest entry to the device `signing_key_id` and
verifies the P1 Ed25519 Object Proof. Device-ID, leaf-key, credential, extension
or capability substitution fails closed.

The existing v1 typed OpenMLS operation path does not emit this complete v2
extension/capability profile and must not be advertised as P6 v2. Rust now has
a separate persistent v2 operation facade at
`anp::group_e2ee::operations::v2`; it does not reinterpret or migrate v1 group
state.

## Persistent Rust operation facade

The v2 facade uses `GroupMlsStore` and `ImCoreSqliteGroupMlsStore` so every
local DID/device pair has independent OpenMLS signer, KeyPackage private
material, Leaf state and epoch secrets. It provides typed operations for:

- device-bound KeyPackage generation;
- create/Add/Remove preparation followed by explicit finalize or abort after
  the Group Host accepts or rejects the request;
- device-targeted Welcome and ordered Commit processing;
- one-shot MLS application encryption and device-local decryption.

Every KeyPackage and current Leaf is checked against the exact DID/device
binding extension and current DID document. Add rejects an existing sibling
pair or leaf key, Remove selects exactly one DID/device Leaf, application
decryption verifies both the frozen JCS `authenticated_data` and the sender
Leaf binding, and no private MLS state appears in a returned wire object.

The facade performs the local cryptographic obligations only. P4 membership,
owner authorization, current group-state CAS, KeyPackage lease/consumption and
delivery authorization remain Group Host/product responsibilities.

## Real OpenMLS multi-device gate

`rust/tests/group_e2ee_v2_multi_device_mls.rs` is a development integration
gate over real OpenMLS 0.8 cryptography. It creates independent providers,
signers, KeyPackages and group state for two devices of the same business DID,
then verifies the frozen v2 binding before exercising Add/Commit/Welcome,
post-join application decryption, exact-device Remove, epoch advancement and
future-message exclusion. It also proves that a new device cannot decrypt
pre-join history, another device's storage cannot consume its Welcome, a
consumed KeyPackage cannot be added again, and an authenticated binding cannot
be substituted around another device's actual TLS KeyPackage.

The test deliberately projects the business member count by de-duplicating MLS
credential DIDs; it does not change MLS credentials or add an internal counter
to the cross-domain P6 model. This gate proves that the frozen semantics are
expressible with the pinned OpenMLS version. The persistent public-facade gate
in `rust/tests/group_e2ee_v2_operations.rs` exercises the same lifecycle using
separate on-disk device stores, service-acceptance finalization, canonical
application plaintext, and a single MLS-encrypted attachment Manifest. Neither
test upgrades the legacy typed path or bypasses the draft extension release
gate.

## Draft extension release gate

The frozen draft uses provisional extension type `0xF0A1`. Runtime development
and contract tests may use it only after explicit `anp.group.e2ee.v2`
negotiation. `ensure_p6_v2_public_release_ready` /
`EnsureP6V2PublicReleaseReady` intentionally returns an error while that value
is not a stable registered codepoint. Public v2 discovery or release must stay
disabled until the protocol publishes the stable assignment and the SDK is
updated together with its vectors.

## Validation

```bash
cargo test --manifest-path rust/Cargo.toml --locked --test group_e2ee_v2_wire_vectors
cargo test --manifest-path rust/Cargo.toml --locked --test group_e2ee_v2_multi_device_mls
cargo test --manifest-path rust/Cargo.toml --locked --test group_e2ee_v2_operations
cargo test --manifest-path rust/Cargo.toml --locked --test group_e2ee_typed_operations_tests
(cd golang && go test ./group_e2ee)
```
