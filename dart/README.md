# ANP Dart SDK

Dart SDK baseline for Agent Network Protocol (ANP) helpers. The first release target is a pure Dart package usable from Flutter mobile and other Dart runtimes where dependencies support the platform.

## Status

Implemented baseline modules:

- codec helpers: base64/base64url, base58, canonical JSON
- key material models: secp256k1, secp256r1, ed25519, x25519 with standard PKCS#8/SPKI PEM persistence
- authentication helpers: DID WBA document creation, legacy auth header/JSON verification, HTTP Message Signatures, DID resolver shape, verifier/authenticator facades
- proof helpers: Go-compatible W3C proof signing input, object/group/DID-WBA wrappers, IM helpers, RFC9421 origin proof helpers
- WNS helpers: Go-compatible dot-handle validation, URI parsing/building, resolver status handling, binding helpers

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

This package is a recovery baseline after consensus planning. Dart↔Go key, auth, proof, and WNS fixture interop helpers are implemented for representative release-gate cases. Direct E2EE/X3DH remains deferred. See `docs/dependency_matrix.md` and `docs/go_to_dart_api_mapping.md`.


## Interop helpers

```bash
dart run tool/interop.dart did-fixture --profile e1 --hostname example.com > /tmp/dart-e1-fixture.json
(cd ../golang && go run ./cmd/anp-interop verify-key-fixture --fixture /tmp/dart-e1-fixture.json)
dart run tool/interop.dart verify-key-fixture --fixture /tmp/dart-e1-fixture.json

dart run tool/interop.dart auth-fixture --scheme http > /tmp/dart-auth-http.json
(cd ../golang && go run ./cmd/anp-interop verify-auth-fixture --fixture /tmp/dart-auth-http.json)

dart run tool/interop.dart proof-fixture --case w3c-ed25519 > /tmp/dart-proof.json
(cd ../golang && go run ./cmd/anp-interop verify-proof-fixture --fixture /tmp/dart-proof.json)

dart run tool/interop.dart wns-fixture --handle alice.example.com > /tmp/dart-wns.json
(cd ../golang && go run ./cmd/anp-interop verify-wns-fixture --fixture /tmp/dart-wns.json)
```


## Flutter smoke

```bash
cd example/flutter_smoke
flutter pub get
flutter test
flutter test --platform chrome
```

Android/iOS build smoke is not claimed unless the local Android command-line tools/licenses and full Xcode/CocoaPods setup are available.
