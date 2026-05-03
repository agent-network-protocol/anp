# Group E2EE Step B P6 Conformance Notes — ANP SDK / anp-mls

## Scope

- Align `anp-mls` real OpenMLS path with P6 before any public discovery claim.
- Add required `ratchet_tree_b64u` export/import for add/welcome processing.
- Bind MLS encrypt/decrypt authenticated data to canonical P6 send AAD and keep a stable golden vector in the Rust SDK helper.
- Deepen local DID WBA binding checks against member DID, MLS BasicCredential identity, leaf signature key, verification method, validity window, and optional proof shape.
- Treat `group_state_ref.group_state_version` as service state for AAD only; MLS epoch validation remains bound to explicit `epoch` so P4 state versions and MLS epochs are not conflated.

## Public discovery stance

- This is still hidden/test-only integration work.
- Do not advertise `anp.group.e2ee.v1` / `group-e2ee` from ANP SDK release notes until message-service discovery gate and security review pass in a separate enablement PR.

## Config / migration impact

- No ANP database migration.
- No Go/CLI CGO dependency is introduced; product clients still invoke `anp-mls` via JSON stdin/stdout.
- Contract-test artifacts remain available only when explicitly enabled and remain marked non-cryptographic.

## Fresh validation evidence

- `cargo fmt --manifest-path rust/Cargo.toml --check`
- `cargo test --manifest-path rust/Cargo.toml group_e2ee --all-targets` → passed: Rust P6 helper tests 3 passed; real `anp-mls` group E2EE tests 12 passed.

## Rollback

- Revert the Step B `anp-mls` changes if the service/CLI side must return to the previous hidden minimal loop. This would remove ratchet-tree-required welcome processing and MLS AAD tamper rejection, so public discovery must remain disabled.

## Caveats

- Still no MLS remove/leave, External Commit, multi-device membership sync, group attachment E2EE, cloud snapshot, or HTTP `anp-mls serve` requirement.
- No k1 DID compatibility is included.
