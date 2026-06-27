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
- **共享协议 SDK**：Go、Rust 和 Dart SDK 覆盖核心 ANP 身份、证明、WNS 功能和部分 E2EE 能力。
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
| 使用 Proof、WNS 或 E2EE | [核心概念](#核心概念) 和 [示例学习路径](#示例学习路径) |
| 参与仓库开发 | [开发](#开发) |

## 目录

- [SDK 与发布](#sdk-与发布)
- [快速开始：构建 Python 智能体](#快速开始构建-python-智能体)
- [示例学习路径](#示例学习路径)
- [核心概念](#核心概念)
- [仓库地图](#仓库地图)
- [开发](#开发)
- [发布和版本规则](#发布和版本规则)
- [安全和兼容性说明](#安全和兼容性说明)
- [联系我们](#联系我们)
- [许可证](#许可证)

## SDK 与发布

这一节是用户获取 SDK 的主入口。详细的多语言版本、registry 和安装矩阵会在 README 改版的 release-matrix 步骤中补充。

## 快速开始：构建 Python 智能体

OpenANP 仍然是 Python 中构建 ANP 智能体的推荐第一入口。完整快速开始流程会在下一步 README 改版中展开。当前可以先查看 [examples/python/openanp_examples/](examples/python/openanp_examples/)。

## 示例学习路径

示例列表会在下一步按从入门到高级的路径重新组织。当前示例目录包括 [examples/python/](examples/python/)、[golang/examples/](golang/examples/)、[rust/examples/](rust/examples/)、[dart/example/](dart/example/)、[typescript/ts_sdk/examples/](typescript/ts_sdk/examples/) 和 [java/anp-examples/](java/anp-examples/)。

## 核心概念

这一节会保留简短、可导航的概念解释，包括 DID WBA、Agent Description、OpenRPC / JSON-RPC、HTTP Message Signatures、Proof、WNS、Direct E2EE、Group E2EE 和 AP2，并链接到权威文档和示例。

## 仓库地图

这一节会提供 Python 包、各语言 SDK 目录、文档、示例、测试数据和发布工具的紧凑地图。

## 开发

本地 Python 开发请在仓库根目录使用 `uv`：

```bash
uv sync
uv run pytest
```

各语言 SDK 的开发命令由对应目录维护，后续也会在本 README 中汇总。

## 发布和版本规则

Python、Go 和 Rust 使用 [skills/anp-multilang-release/](skills/anp-multilang-release/) 中的 release helper 统一发版。面向用户的版本规则摘要会在 release-matrix 步骤中补充。

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
