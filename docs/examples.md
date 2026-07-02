# Examples Guide

This guide is the central index for runnable examples in this repository. Run commands from the repository root unless the command starts with `cd`.

## Quick Index

| Language | Example path | Main topics | Setup | First command |
|---|---|---|---|---|
| Python | [examples/python/](../examples/python/) | OpenANP agents, DID WBA, proof, WNS, AP2, crawler, E2EE | `uv sync` or `uv sync --extra api` | `uv run python examples/python/proof_examples/proof_example.py` |
| Go | [golang/examples/](../golang/examples/) | DID WBA, proof, WNS, Direct E2EE | `cd golang` | `go run ./examples/create_did_document` |
| Rust | [rust/examples/](../rust/examples/) | DID WBA, proof, WNS, interop helpers | `cd rust` | `cargo run --example create_did_document` |
| Dart | [dart/example/](../dart/example/) | DID WBA, HTTP signatures, proof, WNS | `cd dart && dart pub get` | `dart run example/create_did_document.dart` |
| TypeScript | [typescript/ts_sdk/examples/](../typescript/ts_sdk/examples/) | Node.js SDK examples, DID WBA HTTP auth, proof, WNS | `cd typescript/ts_sdk && npm install && npm run build` | `node examples/authentication.mjs` |
| Java | [java/anp-examples/](../java/anp-examples/) | local Java agents, DID WBA, crawler, Spring Boot examples | `cd java && mvn clean install -DskipTests` | `mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.didwba.CreateDIDDocument"` |

## Python

Python examples are grouped by feature under [examples/python/](../examples/python/). For local development, install dependencies first:

```bash
uv sync
uv sync --extra api
```

Common entry points:

| Goal | Path | Run |
|---|---|---|
| Build and call an ANP agent | [examples/python/openanp_examples/](../examples/python/openanp_examples/) | Terminal 1: `uvicorn examples.python.openanp_examples.minimal_server:app --port 8000` |
| Call the OpenANP agent | [examples/python/openanp_examples/minimal_client.py](../examples/python/openanp_examples/minimal_client.py) | Terminal 2: `uv run python examples/python/openanp_examples/minimal_client.py` |
| Create and validate DID WBA material | [examples/python/did_wba_examples/](../examples/python/did_wba_examples/) | `uv run python examples/python/did_wba_examples/create_did_document.py` |
| Run DID WBA HTTP auth server | [examples/python/did_wba_examples/http_server.py](../examples/python/did_wba_examples/http_server.py) | Terminal 1: `uv run python examples/python/did_wba_examples/http_server.py` |
| Run DID WBA HTTP auth client | [examples/python/did_wba_examples/http_client.py](../examples/python/did_wba_examples/http_client.py) | Terminal 2: `uv run python examples/python/did_wba_examples/http_client.py` |
| Generate and verify proof data | [examples/python/proof_examples/proof_example.py](../examples/python/proof_examples/proof_example.py) | `uv run python examples/python/proof_examples/proof_example.py` |
| Validate and resolve WNS handles | [examples/python/wns_examples/](../examples/python/wns_examples/) | `uv run python examples/python/wns_examples/verify_binding.py` |
| Crawl a remote ANP service | [examples/python/anp_crawler_examples/](../examples/python/anp_crawler_examples/) | `uv run python examples/python/anp_crawler_examples/simple_amap_example.py` |
| Run AP2 flow in one process | [examples/python/ap2_examples/ap2_complete_flow.py](../examples/python/ap2_examples/ap2_complete_flow.py) | `uv run python examples/python/ap2_examples/ap2_complete_flow.py` |
| Check Python to Rust fixture interop | [examples/python/rust_interop_examples/](../examples/python/rust_interop_examples/) | `uv run python examples/python/rust_interop_examples/verify_rust_fixture.py` |

Some Python examples require network access or `.env` settings, especially remote crawler and LLM-assisted negotiation examples.

## Go

Go examples live under [golang/examples/](../golang/examples/). Run them from the Go module directory:

```bash
cd golang
go run ./examples/create_did_document
go run ./examples/proof
go run ./examples/wns
go run ./examples/direct_e2ee
```

The Direct E2EE example has its own walkthrough at [golang/examples/direct_e2ee/README.md](../golang/examples/direct_e2ee/README.md). Use `go test ./...` from `golang/` for the full Go validation suite.

## Rust

Rust examples live under [rust/examples/](../rust/examples/). Run them from the Rust crate directory:

```bash
cd rust
cargo run --example create_did_document
cargo run --example proof_example
cargo run --example wns_example
```

Interop and network helpers are also available:

```bash
cd rust
cargo run --example interop_cli
cargo run --example interop_server
cargo run --example direct_e2ee_interop_cli
cargo run --example direct_e2ee_verify_fixture
```

Use `cargo test` from `rust/` for the full Rust validation suite.

## Dart

Dart examples live under [dart/example/](../dart/example/). Run them from the Dart package directory:

```bash
cd dart
dart pub get
dart run example/create_did_document.dart
dart run example/authentication_http_signature.dart
dart run example/proof.dart
dart run example/wns.dart
```

Flutter smoke coverage is in [dart/example/flutter_smoke/](../dart/example/flutter_smoke/):

```bash
cd dart/example/flutter_smoke
flutter pub get
flutter test
flutter test --platform chrome
```

## TypeScript

TypeScript examples live under [typescript/ts_sdk/examples/](../typescript/ts_sdk/examples/). This workspace targets Node.js 20+ and is usable from source after building the SDK:

```bash
cd typescript/ts_sdk
npm install
npm run build
node examples/authentication.mjs
node examples/proof.mjs
node examples/wns.mjs
```

The DID WBA HTTP examples demonstrate the Node.js server/client flow:

```bash
# Terminal 1
cd typescript/ts_sdk
npm run build
node examples/did-wba-http-server.mjs

# Terminal 2
cd typescript/ts_sdk
node examples/did-wba-http-client.mjs
```

The same TypeScript server can be called by the Python SDK client:

```bash
# From the repository root, while the TS server is running
uv run python typescript/ts_sdk/examples/python_to_ts_did_wba_client.py
```

The TypeScript examples generate local demo DID material under `typescript/ts_sdk/examples/.generated/`.

## Java

Java examples live under [java/anp-examples/](../java/anp-examples/). Build the local Maven workspace first:

```bash
cd java
mvn clean install -DskipTests
```

Run standalone examples with `exec:java`:

```bash
cd java
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.didwba.CreateDIDDocument"
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.didwba.AuthenticateAndVerify"
```

Run the calculator agent pair in two terminals:

```bash
# Terminal 1
cd java
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.calculator.CalculatorServer"

# Terminal 2
cd java
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.calculator.CalculatorClient"
```

Additional Java entry points are under [java/anp-examples/src/main/java/com/agentconnect/example/](../java/anp-examples/src/main/java/com/agentconnect/example/), including crawler, local HTTP server, Spring Boot, AP2 concept, and negotiation concept examples.

## Cross-language Checks

| Flow | Start here | Run |
|---|---|---|
| Python verifies Rust-generated fixtures | [examples/python/rust_interop_examples/](../examples/python/rust_interop_examples/) | `uv run python examples/python/rust_interop_examples/verify_rust_fixture.py` |
| Python client authenticates to TypeScript server | [typescript/ts_sdk/examples/python_to_ts_did_wba_client.py](../typescript/ts_sdk/examples/python_to_ts_did_wba_client.py) | Start `node examples/did-wba-http-server.mjs`, then run `uv run python typescript/ts_sdk/examples/python_to_ts_did_wba_client.py` |
| Dart and Go fixture checks | [dart/README.md](../dart/README.md) | Use the `dart run tool/interop.dart ...` commands listed in the Dart README. |

## Notes

- Generated demo identities, keys, fixtures, and temporary files are local development artifacts. Do not commit real private keys.
- Prefer the language-specific README when it gives more detailed prerequisites or troubleshooting steps.
- Preview/local workspaces such as TypeScript and Java are usable from source even when they are not published to public package registries.
