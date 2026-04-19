# Platform Support

| Platform | Status | Evidence |
|---|---|---|
| Dart VM | verified | `cd dart && dart analyze && dart test` |
| Flutter test environment | verified | `cd dart/example/flutter_smoke && flutter test` |
| Flutter Web / Chrome test | verified | `cd dart/example/flutter_smoke && flutter test --platform chrome` |
| Flutter Android build/device | not verified | Flutter doctor reports missing Android cmdline-tools and unknown Android licenses |
| Flutter iOS/macOS build | not verified | Flutter doctor reports incomplete full Xcode installation and CocoaPods missing |
| Desktop | best effort | pure Dart baseline plus Flutter test import smoke; no platform channel code |

Flutter SDK used for smoke validation:

```text
Flutter 3.41.7 stable at ~/development/flutter
Dart 3.11.5 from Flutter toolchain
```
