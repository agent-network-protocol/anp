<div align="center">

[English](README.md) | [中文](README.cn.md)

</div>

# AgentConnect：ANP 多语言 SDK

AgentConnect 是 [Agent Network Protocol（ANP）](https://github.com/agent-network-protocol/AgentNetworkProtocol) 的多语言 SDK 和参考实现。它帮助智能体完成身份识别、接口发现、标准 RPC 调用、可验证证明、可读 Handle 解析，以及端到端加密通信能力的构建。

Python 包名是 `anp`；本仓库同时包含 Go、Rust、Dart、TypeScript 和 Java 的 SDK 实现或 SDK 工作区。

<p align="center">
  <img src="/images/agentic-web.png" width="50%" alt="Agentic Web"/>
</p>

## ANP 是什么？

ANP 是面向开放智能体网络的协议栈。它主要回答这些问题：

- **我正在和谁通信？** DID WBA 身份、DID 文档、HTTP Message Signatures 和验证器工具。
- **这个智能体能做什么？** Agent Description 文档、OpenRPC 接口文档和 JSON-RPC 端点。
- **这个对象或请求可信吗？** W3C Data Integrity proofs、Appendix-B object proofs、IM/origin proofs 和 DID-WBA binding proofs。
- **人和智能体如何发现彼此？** WNS Handle 校验、解析和绑定验证。
- **智能体如何私密通信？** ANP 兼容客户端和服务使用的 Direct / Group E2EE 构建模块。

## 这个仓库提供什么？

- **Python Agent SDK**：OpenANP 用于快速构建和调用 ANP 智能体，并提供 authentication、proof、WNS、AP2、crawler 和 E2EE 模块。
- **共享协议 SDK**：Go 和 Rust 覆盖核心 ANP 身份、证明、WNS 功能和部分 E2EE 能力；Dart 聚焦核心身份、proof 和 WNS helpers。
- **预览 / 本地 SDK 工作区**：TypeScript 和 Java 实现可以从源码使用，公开包发布状态仍需在 README 中明确区分。
- **示例和 fixtures**：可运行示例、跨语言互通检查和共享测试向量。
- **发布工具**：Python / Go / Rust 的统一发版流程和版本规则。

## 选择你的路径

| 我想要... | 从这里开始 |
|---|---|
| 快速构建一个可运行的 ANP 智能体 | [Python OpenANP 快速开始](#快速开始构建-python-智能体) |
| 给 HTTP 服务添加 DID WBA 身份认证 | [DID WBA 示例](examples/python/did_wba_examples/) |
| 使用最新稳定 SDK 版本 | [SDK 与发布](#sdk-与发布) |
| 调用或爬取另一个 ANP 智能体 | [ANP Crawler 示例](examples/python/anp_crawler_examples/) |
| 查找多语言可运行示例 | [示例总览](docs/examples.cn.md) |
| 使用 Proof、WNS 或 E2EE | [核心概念](#核心概念) 和 [示例学习路径](#示例学习路径) |
| 参与仓库开发 | [开发](#开发) |

## 目录

- [SDK 与发布](#sdk-与发布)
- [快速开始：构建 Python 智能体](#快速开始构建-python-智能体)
- [示例学习路径](#示例学习路径)
- [示例总览](docs/examples.cn.md)
- [核心概念](#核心概念)
- [仓库地图](#仓库地图)
- [开发](#开发)
- [发布和版本规则](#发布和版本规则)
- [安全和兼容性说明](#安全和兼容性说明)
- [联系我们](#联系我们)
- [许可证](#许可证)

## SDK 与发布

Registry 状态核对时间：**2026-06-27**。Python、Go 和 Rust 是本仓库当前统一发版的稳定 release line。Dart 单独发布。TypeScript 和 Java 可以从源码或本地构建使用，但本 README **不声称** 它们已经公开发布到 npm 或 Maven Central。

| 语言 | 包 / 模块 | 获取位置 | 已核对版本 | 安装 / 使用 | 示例 | 状态 |
|---|---|---|---|---|---|---|
| Python | `anp` | [PyPI](https://pypi.org/project/anp/) | `0.8.8` | `pip install anp`；OpenANP/FastAPI extras 用 `pip install "anp[api]"` | [examples/python/](examples/python/) | 稳定公开发布 SDK |
| Go | `github.com/agent-network-protocol/anp/golang` | Go module proxy / [pkg.go.dev](https://pkg.go.dev/github.com/agent-network-protocol/anp/golang) | `v0.8.8` | `go get github.com/agent-network-protocol/anp/golang@latest` | [golang/examples/](golang/examples/) | 稳定公开发布 SDK；tag 格式是 `golang/vX.Y.Z` |
| Rust | `anp` | [crates.io](https://crates.io/crates/anp) / [docs.rs](https://docs.rs/anp) | `0.8.8` | `cargo add anp` | [rust/examples/](rust/examples/) | 稳定公开发布 SDK |
| Dart | `anp` | [pub.dev](https://pub.dev/packages/anp) | `0.8.7` | `dart pub add anp` | [dart/example/](dart/example/) | 已发布 SDK；不在当前 Python/Go/Rust 统一 release helper 中 |
| TypeScript | `@anp/typescript-sdk` | 源码工作区 | 本地 `0.1.0` | `cd typescript/ts_sdk && npm install && npm run build` | [typescript/ts_sdk/examples/](typescript/ts_sdk/examples/) | Preview/local source；npm registry 核对结果为 not found |
| Java | `com.agentconnect:anp4j`, `com.agentconnect:anp-spring-boot-starter` | 本地 Maven build | 本地 `1.0.0` | `cd java && mvn clean install -DskipTests` | [java/anp-examples/](java/anp-examples/) | Local SDK；Maven Central metadata 核对结果为 not found |

### 最小安装命令

```bash
# Python core SDK
pip install anp

# Python agent-building extras：FastAPI + OpenAI dependencies
pip install "anp[api]"

# Go
go get github.com/agent-network-protocol/anp/golang@latest

# Rust
cargo add anp

# Dart
dart pub add anp
```

如果你在本仓库内开发，请优先使用 [开发](#开发) 中的本地命令，而不是安装公开发布包。

## 快速开始：构建 Python 智能体

OpenANP 是最快看到 ANP 工作方式的入口。它可以把普通 Python 方法变成可发现的 ANP 接口，并自动暴露标准 Agent 文档和 JSON-RPC 端点。

如果使用已发布的 Python 包，请安装 API extras：

```bash
pip install "anp[api]"
```

如果从本仓库开发，请使用：

```bash
uv sync --extra api
```

创建 `app.py`：

```python
from fastapi import FastAPI
from anp.openanp import AgentConfig, anp_agent, interface

@anp_agent(AgentConfig(
    name="Calculator",
    did="did:wba:example.com:calculator",
    prefix="/agent",
    description="A simple calculator agent",
))
class CalculatorAgent:
    @interface
    async def add(self, a: int, b: int) -> int:
        return a + b

app = FastAPI(title="Calculator Agent")
app.include_router(CalculatorAgent.router())
```

启动服务：

```bash
uvicorn app:app --port 8000
```

OpenANP 会自动生成这些 ANP 端点：

| 端点 | 用途 |
|---|---|
| `GET /agent/ad.json` | 用于发现的 Agent Description 文档 |
| `GET /agent/interface.json` | 基于 Python type hints 生成的 OpenRPC 接口文档 |
| `POST /agent/rpc` | 用于方法调用的 JSON-RPC 2.0 端点 |

使用仓库里的示例客户端调用：

```bash
uv run python examples/python/openanp_examples/minimal_client.py
```

完整可运行示例：

```bash
# 终端 1
uvicorn examples.python.openanp_examples.minimal_server:app --port 8000

# 终端 2
uv run python examples/python/openanp_examples/minimal_client.py
```

## 示例学习路径

如果需要 Python、Go、Rust、Dart、TypeScript 和 Java 的示例文件路径及可直接复制的运行命令，请看 [示例总览](docs/examples.cn.md)。

| 难度 | 目标 | 从这里开始 | 说明 |
|---|---|---|---|
| 入门 | 构建并调用 ANP 智能体 | [examples/python/openanp_examples/](examples/python/openanp_examples/) | 需要 `api` optional dependencies。 |
| 入门 | 创建和验证 DID WBA 身份 | [examples/python/did_wba_examples/](examples/python/did_wba_examples/) | 离线示例适合作为第一个 auth smoke test。 |
| 入门 | 生成和验证 proof | [examples/python/proof_examples/](examples/python/proof_examples/) | 覆盖 W3C/Data Integrity 和 ANP proof helpers。 |
| 入门 | 校验和解析 WNS Handle | [examples/python/wns_examples/](examples/python/wns_examples/) | 部分解析流程需要网络或本地 resolver。 |
| 中级 | 发现 ANP 文档并执行 tools | [examples/python/anp_crawler_examples/](examples/python/anp_crawler_examples/) | 爬虫风格的接口发现和 JSON-RPC 执行。 |
| 中级 | 运行 AP2 支付协议流程 | [examples/python/ap2_examples/](examples/python/ap2_examples/) | merchant / shopper mandate 示例。 |
| 中级 | 检查 Python ↔ Rust 互通 | [examples/python/rust_interop_examples/](examples/python/rust_interop_examples/) | 修改 auth 或 wire fixtures 时很有用。 |
| 高级 | 了解 Direct E2EE 示例 | [examples/python/e2e_encryption_hpke_examples/](examples/python/e2e_encryption_hpke_examples/) 和 [docs/e2e/direct-e2ee-p5-sdk.md](docs/e2e/direct-e2ee-p5-sdk.md) | 产品侧 Direct E2EE 行为以当前 P5 文档为准。 |
| 高级 | 了解 Group E2EE / MLS | [docs/e2e/group-e2ee-p6-anp-mls.md](docs/e2e/group-e2ee-p6-anp-mls.md) | Group E2EE 属于安全敏感能力，请遵守文档边界。 |
| 高级 | 尝试 LLM 辅助协议协商 | [examples/python/negotiation_mode/](examples/python/negotiation_mode/) | 需要 `.env` 中的 LLM provider 配置。 |

各语言 SDK 也提供了自己的示例：[golang/examples/](golang/examples/)、[rust/examples/](rust/examples/)、[dart/example/](dart/example/)、[typescript/ts_sdk/examples/](typescript/ts_sdk/examples/) 和 [java/anp-examples/](java/anp-examples/)。集中入口 [示例总览](docs/examples.cn.md) 列出了每种语言的常用运行命令。

## 核心概念

| 概念 | 在本仓库中的含义 | 继续阅读 |
|---|---|---|
| DID WBA | 基于 Web 的去中心化身份、DID 文档、verification methods、HTTP Message Signatures 和认证验证器。 | [examples/python/did_wba_examples/](examples/python/did_wba_examples/) |
| Agent Description | `ad.json` 文档，用于让另一个智能体发现你的身份和接口位置。 | [examples/python/openanp_examples/](examples/python/openanp_examples/) |
| OpenRPC / JSON-RPC | OpenANP 基于 Python type hints 生成的接口 schema 和方法调用传输。 | [anp/openanp/](anp/openanp/) |
| Proof | W3C Data Integrity、Appendix-B object proof、group receipt、DID-WBA binding、IM 和 RFC 9421 origin proof helpers。 | [examples/python/proof_examples/](examples/python/proof_examples/) |
| WNS | WBA Name Space helpers，用于可读 Handle、`wba://` URI、解析和 DID 绑定验证。 | [examples/python/wns_examples/](examples/python/wns_examples/) |
| Direct E2EE | ANP-P5 私聊 E2EE 模型、会话状态、prekey 处理和跨 SDK 共享向量。 | [docs/e2e/direct-e2ee-p5-sdk.md](docs/e2e/direct-e2ee-p5-sdk.md) |
| Group E2EE | ANP-P6 group E2EE / MLS 操作接口和本地状态边界。 | [docs/e2e/group-e2ee-p6-anp-mls.md](docs/e2e/group-e2ee-p6-anp-mls.md) |
| AP2 | Agent Payment Protocol v2 mandate 模型和验证 helpers。 | [examples/python/ap2_examples/](examples/python/ap2_examples/) |
| Legacy / specialized modules | FastANP、旧 E2EE 示例和 meta-protocol negotiation 仍可用于兼容或高级实验。 | [examples/python/fastanp_examples/](examples/python/fastanp_examples/)、[examples/python/e2e_encryption_v2_examples/](examples/python/e2e_encryption_v2_examples/)、[examples/python/negotiation_mode/](examples/python/negotiation_mode/) |

## 仓库地图

| 路径 | 用途 |
|---|---|
| [anp/](anp/) | Python package：OpenANP、authentication、proof、WNS、AP2、crawler、E2EE 和 meta-protocol 模块。 |
| [examples/python/](examples/python/) | 按功能和学习路径组织的 Python 示例。 |
| [golang/](golang/) | Pure Go ANP SDK module 和示例。 |
| [rust/](rust/) | Rust `anp` crate、示例、测试和 MLS/E2EE operation surfaces。 |
| [dart/](dart/) | Dart SDK package、示例、测试和 Flutter smoke workspace。 |
| [typescript/ts_sdk/](typescript/ts_sdk/) | 面向 Node 20+ 的 TypeScript SDK preview workspace。 |
| [java/](java/) | Java SDK modules：core `anp4j`、Spring Boot starter 和 examples。 |
| [docs/](docs/) | DID、AP2、E2EE、public fixtures 和 PR notes 等协议相关文档。 |
| [testdata/](testdata/) | 跨语言共享 fixtures 和 vectors。 |
| [skills/anp-multilang-release/](skills/anp-multilang-release/) | Python / Go / Rust 统一发版 helper 和 policy。 |

## 开发

请根据你修改的语言 SDK 使用对应工具链。常用本地命令：

```bash
# Python
uv sync
uv sync --extra api      # OpenANP / FastAPI examples
uv sync --extra dev      # pytest and development tools
uv run pytest
uv build --wheel

# Go
cd golang
go test ./...

# Rust
cd rust
cargo test

# Dart
cd dart
dart pub get
dart analyze
dart test

# TypeScript preview workspace
cd typescript/ts_sdk
npm install
npm run typecheck
npm test
npm run build

# Java local workspace
cd java
mvn test
```

部分示例需要网络或 `.env` 配置，尤其是 [examples/python/negotiation_mode/](examples/python/negotiation_mode/) 下的 LLM 辅助协议协商示例。

## 发布和版本规则

Python、Go 和 Rust 使用 [skills/anp-multilang-release/](skills/anp-multilang-release/) 中的 release helper 维护同一个 `X.Y.Z` 版本。发版规则见 [skills/anp-multilang-release/references/release-policy.md](skills/anp-multilang-release/references/release-policy.md)。

当前统一版本文件包括：

- Python package version：[pyproject.toml](pyproject.toml)，runtime version：[anp/__init__.py](anp/__init__.py)。
- Rust crate version：[rust/Cargo.toml](rust/Cargo.toml)。
- Go runtime version：[golang/version.go](golang/version.go)。

Tag 规则：

- 根 release tag：`X.Y.Z`，例如 `0.8.8`。
- Go 子模块 tag：`golang/vX.Y.Z`，例如 `golang/v0.8.8`。

发版前先查看计划：

```bash
uv run python skills/anp-multilang-release/scripts/release.py plan --version 0.8.8
```

正式 release 会在发布前检查干净工作区、版本文件一致性、Python build、Rust dry-run publish 和 Go tests，然后发布并推送 tags。

## 安全和兼容性说明

- 从 `.env` 或运行时配置加载 secrets；不要硬编码真实私钥或 token。
- DID 私钥、E2EE 密钥材料和解密后的明文都应视为敏感本地数据。
- 新集成优先使用当前 DID WBA 和 HTTP Message Signatures 流程；legacy 模块仅用于兼容。
- 除非 README 明确说明，不要假设 preview/local SDK 工作区已经是公开发布包。

## 联系我们

- **作者**：GaoWei Chang
- **邮箱**：chgaowei@gmail.com
- **网站**：[https://agent-network-protocol.com/](https://agent-network-protocol.com/)
- **Discord**：[https://discord.gg/sFjBKTY7sB](https://discord.gg/sFjBKTY7sB)
- **GitHub**：[https://github.com/agent-network-protocol/AgentNetworkProtocol](https://github.com/agent-network-protocol/AgentNetworkProtocol)
- **微信**：flow10240

## 许可证

本项目基于 MIT License 开源。详见 [LICENSE](LICENSE)。

---

**Copyright (c) 2024 GaoWei Chang**
