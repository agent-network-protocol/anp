# Step 02：审计并同步 Group E2EE status

主 Plan：[../plan.md](../plan.md)；Step index：02；Status：done（不适用）；Branch：`master`；Commit：无代码变更；Next action：无。

## 目标

确认 Rust `StatusOutput.member_dids` 是否存在其他语言的等价公开 API；存在则同步，不存在则记录不适用依据，避免制造不兼容的新抽象。

## 设计方法

以 API 能力等价而不是目录名称判断。Rust 字段来自本地 OpenMLS state；无 MLS runtime/typed status 的语言没有可靠数据源。

## 实现方法

搜索 status operation、typed output、exec provider 和 MLS runtime；只修改已有对等结构与测试。

## 路径

`anp/anp/golang/group_e2ee/`、`anp/anp/dart/`、`anp/anp/typescript/ts_sdk/`、`anp/anp/java/`。

## 验证方式

若修改则运行所属语言全套测试；若不适用则在主 Plan 回填搜索证据与理由。

## Review 环节

检查是否遗漏公开 status 类型、是否错误地把 contract-only payload 当成本地 MLS 状态、是否需要文档同步。

审计结果：在 Go、Dart、TypeScript、Java 中搜索 `StatusOutput`、`status` operation、`member_dids`、`pending_commits` 和 Group MLS runtime 未找到 Rust typed status 的对等 API。Go 的 `group_e2ee` 是 contract/provider surface，不拥有本地 OpenMLS member state，因此不增加该字段。
