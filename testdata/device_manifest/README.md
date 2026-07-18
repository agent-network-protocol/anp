# Device Manifest vNext shared fixtures

`vnext_device_manifest_fixtures.json` is the shared Rust, Python, Go, and Dart
contract fixture for the P2 `deviceManifest` shape frozen at protocol commit
`25bfbc59a5a925141b565c4bc6c24195736382b5b`.

The fixture covers the closed Manifest/entry schema, P5/P6 dependency sets,
key relationships, same-document references, and current-device/key
uniqueness. It intentionally contains no AWiki-local role, state, version,
hash, recovery, or management-readiness fields.
