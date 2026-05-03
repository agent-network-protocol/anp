# Group E2EE v1 PR Closeout Notes — ANP SDK / anp-mls

## Scope

- Close stale wording in the Rust P6 group E2EE helper so it reflects the current split: P6 wire/canonicalization helpers in `rust/src/group_e2ee/`, real OpenMLS operations in the `anp-mls` binary.
- Keep contract-test artifacts explicitly non-cryptographic; do not claim public discovery readiness.

## Commits / branch context

- Current branch is ahead of origin with recent Group E2EE work through `25cdb83 Harden anp-mls release probes and local bindings`.
- This closeout only adjusts wording/docs for the existing hidden/test-only v1 minimal loop.

## Config / migration impact

- No ANP SDK database migration or config default changes.
- No k1 DID compatibility work.

## Validation

- Fresh evidence collected in this Ralph pass:
  - `cargo test --manifest-path Cargo.toml group_e2ee -- --nocapture` from `anp/anp/rust` → passed: P6 helper tests 2 passed and real `anp-mls` Group E2EE tests 9 passed.
  - Stale wording grep no longer finds the old “no MLS implementation here yet” disclaimer in current Rust P6 helper comments.

## Rollback

- Revert the wording-only commit if needed. No schema or wire behavior rollback is required.

## Caveats

- Group E2EE v1 remains a minimal same-domain/single-device loop.
- Step B P6 conformance is tracked in `docs/pr-notes/group-e2ee-p6-conformance-before-discovery.md`; public discovery still requires a separate security-reviewed enablement PR.
- Public discovery remains hidden; do not advertise `anp.group.e2ee.v1` / `group-e2ee` from this PR.
