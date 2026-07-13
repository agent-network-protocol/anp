# Step 03：最终全局 Review 与验证

主 Plan：[../plan.md](../plan.md)；Step index：03；Status：done；Branch：`master`；Commit：随任务聚焦提交记录；Next action：无。

## 目标

证明各适用 SDK 契约一致且无回归，并完成文档和工作区审计。

## 设计方法

组合 diff Review 加各语言原生全套测试；Python/Rust 作为来源基线复测。

## 实现方法

运行主 Plan 验证矩阵，统计结果；检查 `git diff --check`、公开导出、共享向量消费和文档描述；修复发现后重跑受影响测试。

## 路径

所有本任务变更路径、`anp/anp/README.md`、`anp/anp/README.cn.md`、`anp/anp/docs/e2e/group-e2ee-p6-anp-mls.md`、`awiki-harness/context/03-cross-repo-architecture.md`。

## 验证方式

`uv run pytest anp/unittest/wns`、Rust WNS tests、`go test ./...`、`npm test`、`dart test`、`git diff --check`。不能运行的命令必须记录准确原因。

## Review 环节

全局检查正确性、回归、兼容性、安全、文档漂移、未提交文件和步骤证据。回填最终状态、剩余风险与 commit。

结果：组合 diff 无 whitespace error；中英文能力矩阵已同步。Go/Python interop 与 Python pytest 受 PyPI TLS/缺少本地 pytest 阻塞，其他适用验证通过，详见主 Plan 第 9 节。
