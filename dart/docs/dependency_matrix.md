# Dependency Matrix

| Package | Role | Status |
|---|---|---|
| crypto | SHA-256 digest support | used in baseline |
| http | injectable HTTP client for DID/WNS resolution | used in baseline |
| test | unit test runner | used in baseline |
| lints | recommended lint set | used in baseline |

Future release-gate work must evaluate asymmetric crypto packages for Go-compatible secp256k1, P-256, Ed25519, X25519 key material, canonical JSON bytes, PEM/JWK behavior, and HTTP Message Signatures.


## Go v0.8.5 key persistence update

Go commit `bdf13a7` standardized SDK persisted keys on PKCS#8 private-key PEM (`-----BEGIN PRIVATE KEY-----`) and SubjectPublicKeyInfo public-key PEM (`-----BEGIN PUBLIC KEY-----`), and rejects legacy `ANP ... PRIVATE KEY` / `ANP ... PUBLIC KEY` runtime labels.

The Dart baseline has been updated to stop emitting or accepting legacy ANP PEM labels. It now uses standard PEM labels, but the payload remains a Dart baseline envelope until the asymmetric crypto dependency spike implements true Go-parseable PKCS#8/SPKI DER for secp256k1, secp256r1, Ed25519, and X25519. Treat true Dart↔Go key fixture verification as not complete.
