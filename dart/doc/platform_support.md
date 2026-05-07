# Platform Support

| Platform | Status | Evidence |
|---|---|---|
| Dart VM | verified | `cd dart && dart analyze && dart test` |
| Flutter test environment | verified | `cd dart/example/flutter_smoke && flutter test` |
| Flutter Web / Chrome test | verified | `cd dart/example/flutter_smoke && flutter test --platform chrome` |
| Flutter Android debug build | verified | temporary Flutter app path-depending on `dart/`; `flutter build apk --debug` produced `/tmp/anp_android_smoke/build/app/outputs/flutter-apk/app-debug.apk` |
| Flutter iOS/macOS build | not verified | Flutter doctor reports incomplete full Xcode installation and CocoaPods missing |
| Desktop | best effort | pure Dart baseline plus Flutter test import smoke; no platform channel code |

Flutter SDK used for smoke validation:

```text
Flutter 3.41.7 stable at ~/development/flutter
Dart 3.11.5 from Flutter toolchain
```


## Android toolchain remediation performed locally

- Installed Flutter stable at `~/development/flutter`.
- Installed OpenJDK 17 through Homebrew for SDK manager compatibility.
- Installed Android SDK command-line tools `latest` manually from Google's repository because the legacy SDK manager was Java-incompatible.
- Accepted Android SDK licenses with `sdkmanager --licenses`.
- Installed Android SDK Platform 36 and Build Tools 36.0.0 / 28.0.3.
- `flutter doctor -v` now reports Android toolchain as passing.

Android debug build smoke was run in a temporary Flutter app outside the repository to avoid committing generated Android platform boilerplate:

```bash
flutter create --platforms=android --project-name anp_android_smoke /tmp/anp_android_smoke
# add path dependency: anp: { path: /Users/cs/work/agents/awiki-space/anp/anp/dart }
cd /tmp/anp_android_smoke
flutter pub get
flutter build apk --debug
```
