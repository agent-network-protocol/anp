# 示例总览

这个文档是仓库内可运行示例的集中入口。除非命令以 `cd` 开头，否则默认从仓库根目录运行。

## 快速索引

| 语言 | 示例路径 | 主要内容 | 准备命令 | 第一个命令 |
|---|---|---|---|---|
| Python | [examples/python/](../examples/python/) | OpenANP 智能体、DID WBA、proof、WNS、AP2、crawler、E2EE | `uv sync` 或 `uv sync --extra api` | `uv run python examples/python/proof_examples/proof_example.py` |
| Go | [golang/examples/](../golang/examples/) | DID WBA、proof、WNS、Direct E2EE | `cd golang` | `go run ./examples/create_did_document` |
| Rust | [rust/examples/](../rust/examples/) | DID WBA、proof、WNS、互通辅助示例 | `cd rust` | `cargo run --example create_did_document` |
| Dart | [dart/example/](../dart/example/) | DID WBA、HTTP signatures、proof、WNS | `cd dart && dart pub get` | `dart run example/create_did_document.dart` |
| TypeScript | [typescript/ts_sdk/examples/](../typescript/ts_sdk/examples/) | Node.js SDK 示例、DID WBA HTTP auth、proof、WNS | `cd typescript/ts_sdk && npm install && npm run build` | `node examples/authentication.mjs` |
| Java | [java/anp-examples/](../java/anp-examples/) | 本地 Java agent、DID WBA、crawler、Spring Boot 示例 | `cd java && mvn clean install -DskipTests` | `mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.didwba.CreateDIDDocument"` |

## Python

Python 示例按功能放在 [examples/python/](../examples/python/) 下。本地开发先安装依赖：

```bash
uv sync
uv sync --extra api
```

常用入口：

| 目标 | 路径 | 运行方式 |
|---|---|---|
| 构建并调用 ANP 智能体 | [examples/python/openanp_examples/](../examples/python/openanp_examples/) | 终端 1：`uvicorn examples.python.openanp_examples.minimal_server:app --port 8000` |
| 调用 OpenANP 智能体 | [examples/python/openanp_examples/minimal_client.py](../examples/python/openanp_examples/minimal_client.py) | 终端 2：`uv run python examples/python/openanp_examples/minimal_client.py` |
| 创建和校验 DID WBA 材料 | [examples/python/did_wba_examples/](../examples/python/did_wba_examples/) | `uv run python examples/python/did_wba_examples/create_did_document.py` |
| 启动 DID WBA HTTP auth 服务端 | [examples/python/did_wba_examples/http_server.py](../examples/python/did_wba_examples/http_server.py) | 终端 1：`uv run python examples/python/did_wba_examples/http_server.py` |
| 运行 DID WBA HTTP auth 客户端 | [examples/python/did_wba_examples/http_client.py](../examples/python/did_wba_examples/http_client.py) | 终端 2：`uv run python examples/python/did_wba_examples/http_client.py` |
| 生成和验证 proof 数据 | [examples/python/proof_examples/proof_example.py](../examples/python/proof_examples/proof_example.py) | `uv run python examples/python/proof_examples/proof_example.py` |
| 校验和解析 WNS Handle | [examples/python/wns_examples/](../examples/python/wns_examples/) | `uv run python examples/python/wns_examples/verify_binding.py` |
| 爬取远程 ANP 服务 | [examples/python/anp_crawler_examples/](../examples/python/anp_crawler_examples/) | `uv run python examples/python/anp_crawler_examples/simple_amap_example.py` |
| 单进程运行 AP2 流程 | [examples/python/ap2_examples/ap2_complete_flow.py](../examples/python/ap2_examples/ap2_complete_flow.py) | `uv run python examples/python/ap2_examples/ap2_complete_flow.py` |
| 检查 Python 与 Rust fixture 互通 | [examples/python/rust_interop_examples/](../examples/python/rust_interop_examples/) | `uv run python examples/python/rust_interop_examples/verify_rust_fixture.py` |

部分 Python 示例需要网络或 `.env` 配置，尤其是远程 crawler 和 LLM 辅助协商示例。

## Go

Go 示例位于 [golang/examples/](../golang/examples/)。从 Go module 目录运行：

```bash
cd golang
go run ./examples/create_did_document
go run ./examples/proof
go run ./examples/wns
go run ./examples/direct_e2ee
```

Direct E2EE 示例有单独说明：[golang/examples/direct_e2ee/README.md](../golang/examples/direct_e2ee/README.md)。完整 Go 校验使用 `golang/` 目录下的 `go test ./...`。

## Rust

Rust 示例位于 [rust/examples/](../rust/examples/)。从 Rust crate 目录运行：

```bash
cd rust
cargo run --example create_did_document
cargo run --example proof_example
cargo run --example wns_example
```

还有互通和网络辅助入口：

```bash
cd rust
cargo run --example interop_cli
cargo run --example interop_server
cargo run --example direct_e2ee_interop_cli
cargo run --example direct_e2ee_verify_fixture
```

完整 Rust 校验使用 `rust/` 目录下的 `cargo test`。

## Dart

Dart 示例位于 [dart/example/](../dart/example/)。从 Dart package 目录运行：

```bash
cd dart
dart pub get
dart run example/create_did_document.dart
dart run example/authentication_http_signature.dart
dart run example/proof.dart
dart run example/wns.dart
```

Flutter smoke 示例位于 [dart/example/flutter_smoke/](../dart/example/flutter_smoke/)：

```bash
cd dart/example/flutter_smoke
flutter pub get
flutter test
flutter test --platform chrome
```

## TypeScript

TypeScript 示例位于 [typescript/ts_sdk/examples/](../typescript/ts_sdk/examples/)。该 workspace 面向 Node.js 20+，构建后可直接从源码使用：

```bash
cd typescript/ts_sdk
npm install
npm run build
node examples/authentication.mjs
node examples/proof.mjs
node examples/wns.mjs
```

DID WBA HTTP 示例演示 Node.js 服务端和客户端流程：

```bash
# 终端 1
cd typescript/ts_sdk
npm run build
node examples/did-wba-http-server.mjs

# 终端 2
cd typescript/ts_sdk
node examples/did-wba-http-client.mjs
```

同一个 TypeScript 服务端也可以用 Python SDK 客户端调用：

```bash
# 从仓库根目录运行，且保持 TS server 正在运行
uv run python typescript/ts_sdk/examples/python_to_ts_did_wba_client.py
```

TypeScript 示例会在 `typescript/ts_sdk/examples/.generated/` 下生成本地 demo DID 材料。

## Java

Java 示例位于 [java/anp-examples/](../java/anp-examples/)。先构建本地 Maven workspace：

```bash
cd java
mvn clean install -DskipTests
```

用 `exec:java` 运行独立示例：

```bash
cd java
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.didwba.CreateDIDDocument"
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.didwba.AuthenticateAndVerify"
```

Calculator agent 需要两个终端：

```bash
# 终端 1
cd java
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.calculator.CalculatorServer"

# 终端 2
cd java
mvn exec:java -pl anp-examples -Dexec.mainClass="com.agentconnect.example.calculator.CalculatorClient"
```

更多 Java 入口在 [java/anp-examples/src/main/java/com/agentconnect/example/](../java/anp-examples/src/main/java/com/agentconnect/example/)，包括 crawler、本地 HTTP server、Spring Boot、AP2 concept 和 negotiation concept 示例。

## 跨语言检查

| 流程 | 入口 | 运行方式 |
|---|---|---|
| Python 验证 Rust 生成的 fixtures | [examples/python/rust_interop_examples/](../examples/python/rust_interop_examples/) | `uv run python examples/python/rust_interop_examples/verify_rust_fixture.py` |
| Python client 认证调用 TypeScript server | [typescript/ts_sdk/examples/python_to_ts_did_wba_client.py](../typescript/ts_sdk/examples/python_to_ts_did_wba_client.py) | 先启动 `node examples/did-wba-http-server.mjs`，再运行 `uv run python typescript/ts_sdk/examples/python_to_ts_did_wba_client.py` |
| Dart 和 Go fixture 检查 | [dart/README.md](../dart/README.md) | 使用 Dart README 中列出的 `dart run tool/interop.dart ...` 命令。 |

## 注意事项

- 示例生成的 demo identity、key、fixture 和临时文件都只是本地开发产物，不要提交真实私钥。
- 当语言子目录 README 给出更详细的依赖或排错说明时，以子目录 README 为准。
- TypeScript 和 Java 这类 preview/local workspace 即使还没有公开发布到包注册表，也可以从源码构建使用。
