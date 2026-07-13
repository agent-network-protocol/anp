# Plan：同步近期 Python/Rust SDK 变更到其他语言

状态：done
DOC：`anp/anp/plan/20260713-sync-recent-sdk-changes/`
Harness：`awiki-harness/`
创建时间：2026-07-13
恢复指针：全部步骤已完成

## 1. 目标

- 将最近一周 Python/Rust 已落地的 WNS `binding_generation` 契约同步到 Go、TypeScript、Dart SDK。
- 审计 Rust Group E2EE `status.member_dids` 在其他语言 SDK 的对应面，仅在已有等价 typed status API 时同步。
- 复用 `anp/anp/testdata/wns/binding_generation_vectors.json` 做跨语言一致性验证。
- 非目标：为 Java 或其他尚无 WNS/MLS 引擎的 SDK 新建完整子系统；发布新版本。
- 完成标准：适用语言实现相同的无符号十进制规范化、拒绝缺失/负数/小数/非规范字符串，并能做任意精度严格递增比较；各语言测试通过。

## 2. 上下文与影响

已读取 `awiki-harness/AGENTS.md`、`awiki-harness/context/00-context-map.md`、`02-repo-map.md`、`03-cross-repo-architecture.md`、`20-rules-index.md`、`30-tools-env.md`、`40-verification.md`、`50-task-workflow.md`，以及 `anp/anp/AGENTS.md`。实现权威为提交 `ff97a15`、`0dc561d`、`4987bd0` 和当前 Python/Rust 测试。

| 模块 | 影响 | 权威代码 |
|---|---|---|
| Go WNS | 模型、解析、比较、resolver 严格校验、共享向量测试 | `anp/anp/golang/wns/` |
| TypeScript WNS | 类型、解析、比较、resolver 严格校验、共享向量测试 | `anp/anp/typescript/ts_sdk/` |
| Dart WNS | 类型、解析、比较、resolver 严格校验、共享向量测试 | `anp/anp/dart/` |
| Java | 当前无 WNS/Group E2EE API，记录为不适用 | `anp/anp/java/` |
| Go Group E2EE | 审计是否存在 Rust typed `status` 对应 API | `anp/anp/golang/group_e2ee/` |

## 3. 总体设计

- JSON number 仅接受非负整数；JSON string 仅接受 `0` 或不带前导零的 ASCII 十进制数字。
- 统一规范化为十进制字符串，避免 JavaScript/Dart/Go 固定宽度整数造成大数回滚误判。
- 比较先看规范字符串长度，再做字典序比较。
- resolver 必须拒绝缺失或非法 `binding_generation`，不以默认值掩盖旧服务响应。
- 安全重点：防止 Handle 到 DID rebind 的 generation rollback；不改变 DID 密钥或网络信任边界。

## 4. 任务拆分与执行台账

| Step | 标题 | 依赖 | Parallel-safe | 写入范围 | 文档 | 状态 |
|---|---|---|---|---|---|---|
| 01 | 同步 WNS generation 契约 | 无 | 是（语言目录互斥） | `golang/wns/`、`typescript/ts_sdk/`、`dart/` | [steps/01-wns-generation.md](steps/01-wns-generation.md) | done |
| 02 | 审计并同步 Group status | Step 01 | 否 | `golang/group_e2ee/`（仅有对应面时） | [steps/02-group-status.md](steps/02-group-status.md) | done（不适用） |
| 03 | 全局 Review 与验证 | Step 01、02 | 否 | 测试/文档/台账 | [steps/03-final-verification.md](steps/03-final-verification.md) | done |

本次虽存在目录级并行点，但当前协作约束不允许启动子智能体，因此由 Coordinator 串行执行。每步完成后记录 Review 和验证；不覆盖用户已有变更。执行期间不自动发布。

## 5. 验证策略

| 层级 | 命令 |
|---|---|
| Python/Rust 基线 | `cd anp/anp && uv run pytest anp/unittest/wns`; `cd anp/anp && cargo test --manifest-path rust/Cargo.toml wns` |
| Go | `cd anp/anp/golang && go test ./...` |
| TypeScript | `cd anp/anp/typescript/ts_sdk && npm test` |
| Dart | `cd anp/anp/dart && dart test` |
| Final | `cd anp/anp && git diff --check`，组合 diff Review |

## 6. Review、Commit 与变更控制

- Review 重点：大整数精度、JSON 类型边界、缺失字段、前导零、严格递增、公开导出、错误传播、兼容性。
- 每个可独立步骤在验证后创建聚焦 commit，并回填 hash；若用户工作区出现外部修改则暂停提交并保留变更。
- 改变公开契约、步骤范围或验证策略前先更新本 Plan。
- Blocker 需记录命令、证据、影响与替代路径；共享契约 blocker 会暂停后续步骤。

## 7. Codex Goal 执行协议

启动或恢复前读取本 Plan、当前 Step、执行台账和 `git status --short --branch`。从首个非 done 步骤继续；每步依次实现、验证、Review、修复、提交和回填证据。全部完成后执行全局 Review 与整体验证。

## 8. Plan 变更记录

| 日期 | 变更 | 原因 | 影响步骤 |
|---|---|---|---|
| 2026-07-13 | 初始计划 | 同步最近一周 Python/Rust 契约 | 全部 |
| 2026-07-13 | 补齐 verification result generation | Review 发现首次实现只同步 resolution model，遗漏 DID recovery 调用方需要的已验证 generation | Step 01、03 |

## 9. 最终全局 Review 与整体验证

- Go：`go vet ./...` 通过；WNS 和其余原生包测试通过。`go test ./...` 仅 `golang/integration` 的 2 个 Python interop 用例失败，原因是 `uv` 无法通过 PyPI TLS 下载 `hatchling`。
- TypeScript：`npm run typecheck`、`npm run build`、focused WNS 9 tests 通过；全套 6 个 test files 均通过。
- Dart：format 稳定，`dart analyze lib test` 无问题，`dart test` 20 tests 通过。全目录 analyze 的 Flutter smoke 子项目缺少 `flutter_test`，与本次 SDK 代码无关。
- Rust 来源基线：`cargo test --manifest-path rust/Cargo.toml --test wns_tests` 13 tests 通过。
- Python 来源基线：未能运行；`uv run pytest anp/unittest/wns` 因 PyPI TLS 获取 `hatchling` 失败，本地 `.venv` 未安装 pytest。
- Group status 审计：Go、Dart、TypeScript、Java 均无 Rust typed `StatusOutput`/本地 OpenMLS status 对应 API；Go 仅有 contract/provider surface，因此未新增无数据源的 `member_dids`。
- Review：已检查任意精度、严格正整数字符串、缺失字段、JSON number、零、前导零、回滚、公开导出和文档声明，未发现未解决代码问题。
- 补充 Review：逐行对照 Python `BindingVerificationResult` 与 Rust `BindingVerificationResult` 后，已让 Go、Dart、TypeScript 仅在正反向验证均成功时返回 generation；失败结果不暴露 generation。补丁后 Go 非 Python-integration 全套通过，TypeScript 43 tests 通过，Dart 21 tests 通过。
- 文档：已更新中英文 README 能力矩阵；Group E2EE 和 Harness 架构边界未改变，无需修改 Harness。

## 10. Codex Goal 提示词

```text
请以 `anp/anp/plan/20260713-sync-recent-sdk-changes/plan.md` 为唯一规划入口执行完整实现。
开始前读取主 Plan、首个未 done 的 Step、执行台账和 `git status --short --branch`。
逐步同步 WNS binding_generation 契约，复用共享测试向量，避免任何语言的大整数精度损失。
仅在已有等价 API 时同步 Rust Group E2EE status.member_dids；无对应面要记录审计证据。
每步实现后运行指定测试、Review、修复发现、创建聚焦 commit，并回填状态和证据。
所有步骤完成后执行组合 diff Review、跨语言整体验证和文档一致性检查。
```
