---
name: anp-multilang-release
description: 在 ANP SDK 仓库里统一发布 Go、Python、Rust 三个 SDK。用于同时更新 pyproject.toml、anp/__init__.py、uv.lock、rust/Cargo.toml、rust/Cargo.lock、golang/version.go，执行 uv/cargo/go 校验，发布 PyPI 与 crates.io，并按 Go 子目录 module 规则推送 golang/vX.Y.Z tag。用户提到 Go/Python/Rust 一起发版、统一版本号、固定发布 0.7.2、下一版自动 +1、保持版本段为一位数时使用此 skill。
---

# ANP Multi SDK Release

在 `anp/` 仓库根目录执行统一发版。

优先使用脚本：

```bash
uv run python skills/anp-multilang-release/scripts/release.py ...
```

## 快速使用

### 本次固定发布 0.7.2

先看计划：

```bash
cd anp
uv run python skills/anp-multilang-release/scripts/release.py plan --version 0.7.2
```

确认后正式发布：

```bash
cd anp
uv run python skills/anp-multilang-release/scripts/release.py release --version 0.7.2
```

### 下次自动递增版本

查看下一个版本号：

```bash
cd anp
uv run python skills/anp-multilang-release/scripts/release.py next-version
```

直接按自动版本发布：

```bash
cd anp
uv run python skills/anp-multilang-release/scripts/release.py release
```

## 版本规则

- 统一版本格式是 `X.Y.Z`
- 每一段都必须是单个数字 `0-9`
- 自动递增顺序：
  - `0.7.2 -> 0.7.3`
  - `0.7.9 -> 0.8.0`
  - `0.9.9 -> 1.0.0`
- 不允许生成 `0.7.10` 这种两位数段

如果要改规则，先读 `references/release-policy.md`。

## 发布动作

脚本会按下面顺序执行：

1. 检查 Git 工作区是否干净
2. 检查 Python、Rust、锁文件版本是否一致
3. 更新：
   - `pyproject.toml`
   - `anp/__init__.py`
   - `uv.lock`
   - `rust/Cargo.toml`
   - `rust/Cargo.lock`
   - `golang/version.go`
4. 执行校验：
   - `uv build`
   - `cargo publish --dry-run --manifest-path rust/Cargo.toml`
   - `go test ./...`
5. 如果版本文件有变化，提交并推送分支
6. 发布 Python 包
7. 发布 Rust crate
8. 推送两个 tag：
   - 根 tag：`<version>`，例如 `0.7.2`
   - Go tag：`golang/v<version>`，例如 `golang/v0.7.2`

Python 发布阶段会显式上传当前目标版本对应的 `dist/` 构件，避免把历史产物一并上传。

## 使用前提

发布前确保：

- 当前仓库是 `anp/` 根目录
- Git remote 具备 push 权限
- `uv publish` 已经具备可用凭证
- `cargo publish` 已经具备可用凭证

如果不是用 `origin`，可以加：

```bash
uv run python skills/anp-multilang-release/scripts/release.py release --remote <remote-name>
```

## 处理异常

- 如果 tag 已存在，脚本会直接停止
- 如果版本文件不同步，脚本会直接停止
- 如果构建或发布失败，先修复问题，再重新执行
- 如果只是想查看动作，不要直接发版，先运行 `plan`
