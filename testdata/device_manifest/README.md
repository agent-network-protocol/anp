# Device Manifest vNext shared fixtures

`vnext_device_manifest_fixtures.json` is the shared Rust, Python, Go, and Dart
contract fixture for the P2 `deviceManifest` shape frozen at protocol commit
`25bfbc59a5a925141b565c4bc6c24195736382b5b`.

`vnext_did_builder_fixtures.json` is the matching shared fixture for the
public-key-only DID builder and add/update/remove helpers. It fixes the exact
relationship and Manifest synchronization output, stale-proof removal, and
unknown top-level extension preservation across all four SDKs. Version 2 also
fixes canonical 32-byte Ed25519/X25519 JWK and Multikey vectors plus shared
negative cases for malformed/contradictory key methods, P5/P6 non-Ed25519
device signing, cross-format raw-key reuse, role-confused relationships, and
retired `device_id` reuse.

The retired-ID list is an explicit input to `Add`, not SDK-owned fixture state.
The caller must persist device-ID history in its authoritative lifecycle store
and pass that history to the stateless helper. Update may retain an existing
active ID; remove/update clears both old key IDs from all managed DID
relationships.

The fixture covers the closed Manifest/entry schema, P5/P6 dependency sets,
key relationships, same-document references, and current-device/key
uniqueness. It intentionally contains no AWiki-local role, state, version,
hash, recovery, or management-readiness fields.
