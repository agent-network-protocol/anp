# ANP SDK / anp-mls Group E2EE

## Status

- Hidden/test-only implementation for AWiki Group E2EE.
- Protocol authority: [ANP P6 群组端到端加密](../../../AgentNetworkProtocol/chinese/message/06-群组端到端加密.md).
- Harness map: [Group E2EE cross-repo feature map](../../../../awiki-harness/features/group-e2ee.md).
- Public discovery must remain disabled until a separate security-reviewed enablement PR.

## Owned surface

ANP SDK owns reusable P6 contracts and local MLS execution primitives:

- Rust P6 helpers: `rust/src/group_e2ee/`.
- Rust one-shot binary: `rust/src/bin/anp-mls.rs`.
- Rust real OpenMLS tests: `rust/tests/group_e2ee_real_mls_tests.rs`.
- Rust/Go contract tests and proof vectors: `rust/tests/group_e2ee_contract_tests.rs`, `rust/tests/proof_tests.rs`, `golang/group_e2ee/`, `golang/proof/`, `testdata/group_e2ee/`.
- Go SDK provider contract: `golang/group_e2ee/exec_provider.go` and P6 models.

The SDK does not own message-service storage, public discovery, or CLI UX. It supplies wire models, canonicalization helpers, DID WBA binding/proof utilities, and the local cryptographic engine used by clients.

## One-shot `anp-mls` contract

`anp-mls` is designed for command-driven clients without a resident process:

- JSON request is read from stdin (`--json-in -`).
- JSON response is written to stdout.
- logs/errors go to stderr.
- The Go CLI remains pure Go / no CGO.
- Default real mode requires `--data-dir`.
- Local state is persisted under agent/device-scoped directories, typically `<workspace>/mls/agents/<agent-hash>/<device>/state.db`.
- A sibling `state.lock` guards mutations.
- Operation records must redact decrypted plaintext and avoid persisting application plaintext or MLS private data in command logs.

State held by `anp-mls` includes OpenMLS private state, KeyPackage private material, group bindings, epoch summaries, idempotency/operation records, and pending membership/update/remove commits.

## Implemented command families

Real OpenMLS mode covers:

- `system version` for packaging/doctor compatibility checks.
- `key-package generate` with `purpose=normal|recovery|update`.
- `group create`.
- `group add-member`.
- `welcome process`.
- `message encrypt` / `message decrypt` with P6 AAD binding.
- `group commit process/finalize/abort` for missed commit repair.
- `group remove-member prepare/finalize/abort`.
- `group recover-member prepare/finalize/abort` for same-DID/device active-member recovery.
- `group update-member prepare/finalize/abort` for hidden update-key leaf replacement.
- `group status` / local binding summaries.

Contract-test artifacts remain explicit test fixtures only. They must stay marked non-cryptographic and must not be used to claim real security.

## P6 binding and safety rules

- `group.e2ee.send` AAD is bound to canonical P6 metadata: content type, sender DID, group DID, crypto group ID, epoch/state ref, security profile, message ID, and operation ID.
- Decrypt reconstructs expected AAD and rejects tampering before returning plaintext.
- Welcome processing validates the outer `group_state_ref`, `group_did`, crypto group ID / OpenMLS group ID, and epoch before persisting state.
- KeyPackage DID WBA binding must validate owner/agent DID, device ID, assertion method / verification method, MLS BasicCredential identity, leaf signature key, validity window, and proof vectors before public discovery claims.
- Hidden update-member uses OpenMLS `swap_members` with a `purpose=update` KeyPackage and finalizes only after service acceptance.
- Recover-member is only for active P4 members; removed/left rejoin uses add/welcome with a fresh normal KeyPackage.

## Non-goals

- Public discovery enablement.
- Multi-device sync.
- k1 DID compatibility.
- External Commit.
- Cloud snapshot / backup.
- Required `anp-mls serve` daemon.
- Service-side decryption or service-side MLS private state.

## Validation

Focused commands used during Group E2EE development:

```bash
cd anp/anp
cargo fmt --manifest-path rust/Cargo.toml --check
cargo test --manifest-path rust/Cargo.toml group_e2ee --all-targets
cargo test --manifest-path rust/Cargo.toml proof --all-targets
```

Keep Rust and Go proof/vector tests aligned before any discovery-readiness claim.
