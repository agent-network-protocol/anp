# Dependency Matrix

| Package | Role | Status |
|---|---|---|
| crypto | SHA-256 digest support | used in baseline |
| http | injectable HTTP client for DID/WNS resolution | used in baseline |
| pinenacl | Ed25519 and X25519 public-key derivation/signature primitives | used for key persistence and signatures |
| pointycastle | secp256k1/secp256r1 scalar multiplication and ECDSA primitives | used for key persistence and signatures |
| test | unit test runner | used in baseline |
| lints | recommended lint set | used in baseline |

Representative Dart↔Go fixture coverage now exists for key persistence, legacy/HTTP auth, W3C proofs, and WNS handle/service artifacts. Future release-gate work should deepen edge-case coverage for canonical JSON, JWK, nonce/replay verifier policy, WNS network error modes, and all non-representative proof wrappers.


## Go v0.8.5 key persistence update

Go commit `bdf13a7` standardized SDK persisted keys on PKCS#8 private-key PEM (`-----BEGIN PRIVATE KEY-----`) and SubjectPublicKeyInfo public-key PEM (`-----BEGIN PUBLIC KEY-----`), and rejects legacy `ANP ... PRIVATE KEY` / `ANP ... PUBLIC KEY` runtime labels.

The Dart SDK now emits and parses Go-compatible PKCS#8/SPKI DER for secp256k1, secp256r1, Ed25519, and X25519, rejects legacy ANP PEM labels, and is verified by Go's `verify-key-fixture` command for Dart-generated DID fixtures.
