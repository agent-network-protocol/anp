# ANP SDK Group E2EE / OpenMLS

## Status

- Hidden/test-only implementation for AWiki Group E2EE.
- Protocol authority: [ANP P6 群组端到端加密](../../../AgentNetworkProtocol/chinese/message/06-群组端到端加密.md).
- The side-by-side vNext wire/binding SDK is documented in
  [P6 vNext SDK wire and binding helpers](group-e2ee-p6-v2-sdk.md).
- Harness map: [Group E2EE cross-repo feature map](../../../../awiki-harness/features/group-e2ee.md).
- Public discovery remains disabled until a separate security-reviewed enablement change.

The historical `anp-mls` subprocess and JSON command surface has been removed.
Rust callers use the typed library API; this file name is retained so existing
documentation links remain stable. Do not reconstruct or depend on the removed
binary.

## Owned surface

ANP SDK owns reusable P6 contracts and local MLS execution primitives:

- Rust P6 models/helpers: `rust/src/group_e2ee/`.
- Rust typed OpenMLS operations: `rust/src/group_e2ee/operations/typed.rs`.
- Rust P6 v2 persistent operations: `rust/src/group_e2ee/operations/v2.rs`.
- Rust local-state adapters: `rust/src/group_e2ee/storage.rs`.
- Legacy typed-operation regression: `rust/tests/group_e2ee_typed_operations_tests.rs`.
- Real vNext multi-device OpenMLS gate: `rust/tests/group_e2ee_v2_multi_device_mls.rs`.
- Persistent vNext operation gate: `rust/tests/group_e2ee_v2_operations.rs`.
- Rust/Go wire and proof vectors: `rust/tests/group_e2ee_v2_wire_vectors.rs`,
  `rust/tests/proof_tests.rs`, `golang/group_e2ee/`, `golang/proof/`, and
  `testdata/group_e2ee/`.

The SDK does not own message-service storage, public discovery, or CLI UX. It
supplies wire models, canonicalization helpers, DID WBA binding/proof utilities,
and local cryptographic primitives used by clients.

## Typed Rust library contract

`anp::group_e2ee::operations` exposes one-call typed functions for:

- KeyPackage generation;
- group create/add/remove preparation;
- local leave terminal-state handling;
- member update/recovery preparation;
- pending commit finalize/abort;
- Welcome and commit-notice processing;
- application encrypt/decrypt;
- local group status.

Callers select a `GroupMlsStore`. `CompatDataDirStore` preserves the legacy
`state.db` layout; `ImCoreSqliteGroupMlsStore` scopes state from an im-core local
state root. OpenMLS private state, KeyPackage private material, group bindings,
epoch summaries, idempotency records and pending commits remain local. They are
not emitted in service-facing P6 objects.

These typed operations implement the legacy P6 v1 execution surface. They do
not emit the vNext `0xF0A1` LeafNode binding extension or its Leaf/GroupContext
capability declarations, and callers must not relabel their output as
`anp.group.e2ee.v2`.

The separate `anp::group_e2ee::operations::v2` facade is the Rust vNext path.
It uses the same `GroupMlsStore` boundary but creates new v2-only state with the
required device-binding extension and capabilities. It supports device-bound
KeyPackage generation, create/Add/Remove prepare plus finalize/abort,
device-targeted Welcome/Commit processing, standard notice-native processing,
and canonical application encrypt/decrypt. Notice-native Commit processing
derives the originating sender, operation and exact affected Leaf from MLS AAD
and verifies them against current DID documents; callers do not synthesize a
second control metadata object. It never copies state between sibling devices.
An actor's post-finalize Commit echo is receipt-only: it is accepted after
restart only when the finalized local journal exactly matches actor device,
operation, group/state/epoch, subject and Commit digest, so the Commit is never
merged twice.
P4 membership, owner policy, service CAS and KeyPackage lease/consumption remain
product and Group Host checks rather than local MLS checks.

Because OpenMLS storage and SDK metadata use separate SQLite connections, the
v2 facade uses a recoverable write-ahead journal rather than claiming one SQL
transaction across both providers. `reconcile_pending_v2` rolls back an
interrupted `preparing` operation, leaves `prepared` awaiting the service
decision, and completes `accepted` to `finalized` idempotently after restart.
Finalize and abort can be retried; the journal never contains exported MLS
private state or epoch secrets.

## P6 v2 real-cryptography gate

The vNext integration test uses the pinned OpenMLS 0.8 implementation together
with the public P6 v2 binding verifier. It establishes that:

- two devices of one business DID use distinct MLS Leaf signature keys,
  KeyPackages, providers and private state;
- an eligible owner verifies the actual TLS KeyPackage/Leaf/binding chain before
  adding the second device;
- adding a sibling Leaf does not add another business-level DID member;
- both sibling devices decrypt post-join applications, while the new device
  cannot decrypt pre-join history;
- removal targets the verified device Leaf and advances the epoch without
  removing its sibling;
- the removed device cannot decrypt future applications;
- wrong-device/key substitution, Welcome/private-state interchange and
  KeyPackage reuse fail in the verifier or OpenMLS rather than through test-only
  flags.

The second gate, `group_e2ee_v2_operations`, runs that lifecycle through the
persistent v2 facade and independent SQLite stores, including one encrypted
attachment Manifest shared by current Leaves, standard notice replay/binding,
and crash-state reconciliation. This adds no wire field. Public release remains
blocked while the Profile uses the provisional extension codepoint.

## Legacy runtime safety rules

- Group application AAD is bound to the group/message operation fields expected
  by the legacy P6 surface, including `group_state_ref.group_state_version`.
- Decrypt rejects group ID, epoch or state claims that disagree with the local
  group binding before returning plaintext.
- Product flows must obtain add/update/recovery KeyPackages through the
  authoritative message-service lease/consume path. The legacy local runtime
  validates the decoded MLS package and local binding shape but does not resolve
  arbitrary remote DID documents.
- A Handle-backed DID rebind does not add a P6 method. After P4 authorization,
  the Group Host serializes the existing add-new-DID and remove-old-DID
  operations and pauses applications between them.
- `recover_member` is a same-DID/device MLS recovery primitive, not a DID-rebind
  shortcut.

## Non-goals

- Public discovery enablement.
- A replacement `anp-mls` binary or daemon.
- Cloud snapshot or backup.
- Service-side decryption or service-side MLS private state.
- Claiming the legacy typed runtime is P6 v2.
- Enabling public P6 v2 discovery while the draft extension is provisional.

## Validation

```bash
cargo fmt --manifest-path rust/Cargo.toml --check
cargo test --manifest-path rust/Cargo.toml --locked --test group_e2ee_typed_operations_tests
cargo test --manifest-path rust/Cargo.toml --locked --test group_e2ee_v2_wire_vectors
cargo test --manifest-path rust/Cargo.toml --locked --test group_e2ee_v2_multi_device_mls
cargo test --manifest-path rust/Cargo.toml --locked --test group_e2ee_v2_operations
cargo test --manifest-path rust/Cargo.toml --locked --test proof_tests
```

Keep Rust/Go proof and wire-vector tests aligned before any discovery-readiness
claim.
