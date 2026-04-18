# ANP Dart SDK

Dart SDK scaffold for Agent Network Protocol (ANP) helpers. The first release target is a pure Dart package usable from Flutter mobile and other Dart runtimes where dependencies support the platform.

## Status

Implemented baseline modules:

- codec helpers: base64/base64url, base58, canonical JSON
- key material models: secp256k1, secp256r1, ed25519, x25519 with standard PKCS#8/SPKI PEM persistence
- authentication helpers: DID WBA document creation, DID resolver shape, HTTP signature header shape, verifier/authenticator facades
- proof helpers: W3C proof shape, object/group/DID-WBA/IM/RFC9421 scaffolds
- WNS helpers: handle validation, URI parsing/building, resolver shape, binding helpers

`direct_e2ee` / X3DH is intentionally not exported in v1.

## Validation

```bash
dart pub get
dart analyze
dart test
dart run example/create_did_document.dart
dart run example/authentication_http_signature.dart
dart run example/proof.dart
dart run example/wns.dart
```

## Notes

This package is a recovery baseline after consensus planning. Dart↔Go key fixture interop is implemented; broader auth/proof/WNS cryptographic fixture parity remains a release-gate follow-up. See `docs/dependency_matrix.md` and `docs/go_to_dart_api_mapping.md`.


## Interop helpers

```bash
dart run tool/interop.dart did-fixture --profile e1 --hostname example.com > /tmp/dart-e1-fixture.json
(cd ../golang && go run ./cmd/anp-interop verify-key-fixture --fixture /tmp/dart-e1-fixture.json)
dart run tool/interop.dart verify-key-fixture --fixture /tmp/dart-e1-fixture.json
```
