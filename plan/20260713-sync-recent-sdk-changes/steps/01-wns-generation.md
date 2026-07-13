# Step 01：同步 WNS binding generation

主 Plan：[../plan.md](../plan.md)；Step index：01；Status：done；Branch：`master`；Baseline：`0967358`；Commit：随任务聚焦提交记录；Review evidence：任意精度、解析边界、公开导出和 resolver 已检查；Verification evidence：Go WNS、TypeScript WNS/typecheck/build、Dart format/analyze/test 均通过；Next action：无。

## 目标

Go、TypeScript、Dart 与 Python/Rust 对 `binding_generation` 的模型、解析、规范化、比较和 resolver 强制校验一致。

## 设计方法

使用十进制规范字符串承载任意精度值；共享 `testdata/wns/binding_generation_vectors.json` 是跨语言验收输入。该步骤目录写集可拆分并行，但本次受协作约束由主执行者串行完成。

## 实现方法

- 各语言增加公开 generation 类型或规范化/比较 API。
- `HandleResolutionDocument` 增加必填 generation 字段。
- resolver 从原始 JSON 严格解析，缺失或非法值直接失败。
- 测试覆盖共享 validation/transitions 向量及 HTTP resolver 缺失字段。

## 路径

`anp/anp/golang/wns/`、`anp/anp/typescript/ts_sdk/src/wns/`、`anp/anp/typescript/ts_sdk/tests/`、`anp/anp/dart/lib/src/wns/`、`anp/anp/dart/test/wns/`、`anp/anp/testdata/wns/binding_generation_vectors.json`。

## 验证方式

运行 Go、TypeScript、Dart WNS focused tests，再运行各 SDK 全套测试。验收包括超大整数、数字零、字符串零、缺失、负数、小数、布尔值、前导零、相等和回滚。

## Review 环节

检查公开导出、序列化形态、精度、错误消息、resolver 兼容性和测试是否真实读取共享向量。完成后聚焦提交并回填证据。
