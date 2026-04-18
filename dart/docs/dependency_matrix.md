# Dependency Matrix

| Package | Role | Status |
|---|---|---|
| crypto | SHA-256 digest support | used in baseline |
| http | injectable HTTP client for DID/WNS resolution | used in baseline |
| test | unit test runner | used in baseline |
| lints | recommended lint set | used in baseline |

Future release-gate work must evaluate asymmetric crypto packages for Go-compatible secp256k1, P-256, Ed25519, X25519 key material, canonical JSON bytes, PEM/JWK behavior, and HTTP Message Signatures.
