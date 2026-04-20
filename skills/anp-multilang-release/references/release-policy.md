# ANP Multi-SDK Release Policy

## Scope

This release skill manages one shared version for:

- Python package in `pyproject.toml`
- Python runtime version in `anp/__init__.py`
- Rust crate in `rust/Cargo.toml`
- Go runtime version in `golang/version.go`
- Go module tag for `golang/`

It also keeps these lock files aligned:

- `uv.lock`
- `rust/Cargo.lock`

## Version rule

Use single-digit semantic versions only: `X.Y.Z`, where each segment is `0-9`.

Auto-increment uses this order:

- `0.7.2 -> 0.7.3`
- `0.7.9 -> 0.8.0`
- `0.9.9 -> 1.0.0`

The script refuses versions such as `0.7.10`.

## Tag rule

- Root release tag: `<version>` such as `0.7.2`
- Go module tag: `golang/v<version>` such as `golang/v0.7.2`

The Go tag format follows the Go subdirectory module rule.

## Release order

1. Verify the working tree is clean.
2. Verify current Python/Rust versions and lock files are aligned.
3. Update version files.
4. Run:
   - `uv build`
   - `cargo publish --dry-run --manifest-path rust/Cargo.toml`
   - `go test ./...`
5. Commit and push the version bump if files changed.
6. Publish Python with explicit target-version artifacts only.
7. Publish Rust with `cargo publish`.
8. Push the root tag and Go tag.

## Required access

- Git push access to the configured remote.
- Valid Python package publish credentials for `uv publish`.
- Valid crates.io credentials for `cargo publish`.
