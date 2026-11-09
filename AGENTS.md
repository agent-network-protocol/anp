Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- Prefer reliable existing libraries or patterns over reinventing the wheel.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.

# Repository Guidelines

## Shared rules

Engineering work follows [AI Coding Rules](../../awiki-harness/rules/ai-coding-rules.md).
Behavior changes and verification follow the relevant [Verification Policy](../../awiki-harness/rules/verification-policy.md)
sections; production behavior needs owning unit coverage and applicable System/product E2E review.
If Harness is absent, use local docs/tests/CI and disclose missing acceptance evidence.

## Project Structure & Module Organization
Core protocol logic lives under `anp/meta_protocol/`, with identity in `anp/authentication/`, encryption in `anp/e2e_encryption/`, shared helpers within `anp/utils/`, and interoperability tooling in `anp/anp_crawler/`. Tests shadow the package layout inside `anp/unittest/<module>/test_<topic>.py`, while docs stay in `docs/`, runnable walkthroughs in `examples/`, JVM clients in `java/`, and release bundles in `dist/`. Keep new assets alongside their feature modules to simplify discovery.

## Build, Test, and Development Commands
Run `uv sync` to install pinned dependencies, then `uv run pytest` (or `uv run pytest -k "handshake"`) for targeted suites. Package releases with `uv build --wheel`. Validate negotiation flows using `uv run python examples/ping_pong.py`, and inspect the CLI via `uv run python -m anp.meta_protocol.cli --help`. Keep a clean virtual environment by preferring `uv run <script>` over activating shells manually.

## Multi-language Release Workflow
Run `./scripts/release_sdks.py --version X.Y.Z` to publish the coordinated Python, Rust, and Go SDKs; omit `--version` to publish the next version. Add `--plan` to preview without changing or publishing anything. The launcher delegates to the guarded release helper documented in `skills/anp-multilang-release/references/release-policy.md`.
Publication does not run test suites by default. Use `--run-tests` for the Go suite only when the user explicitly requests tests; Python and Rust suites require separate explicit commands. Keep build and package verification enabled, and report tests not run.

## Coding Style & Naming Conventions
Follow Google Python Style: four-space indentation, type hints, and Google-style docstrings on public APIs. Use `snake_case` for modules/functions, `UpperCamelCase` for classes, and `UPPER_SNAKE_CASE` for constants. Comments and logs must be in English. Group utilities in the closest existing package and avoid hidden globals; prefer dependency injection or explicit configuration objects.

## Testing Guidelines
Test the language and module that owns the changed behavior. Python tests live
under `anp/unittest/`, use `test_<area>.py` / `test_<behavior>` and mark async tests
with `@pytest.mark.asyncio`. Rust, Go and Dart changes use their owning language
suites; include shared vectors when wire or cryptographic parity changes. Use
focused checks during implementation. Run full language coverage or the coordinated
release matrix only when the requested scope, release policy or a concrete unresolved
regression risk requires it. Update scenario examples when their protocol contract
changes.

## Commit & Pull Request Guidelines
Author imperative commit subjects (e.g., `Add credential signer`) and reference issues like `#42` when relevant. Pull requests should summarize behavior changes, risks, validation commands, and any compatibility impacts. Attach logs or screenshots for user-visible updates. Ordinary CI runs only when explicitly requested; GitHub-managed CodeQL default scanning remains automatic. Report unrun checks as not run rather than claiming success, and call out follow-up work.

## Security & Configuration Tips
Load secrets from `.env` via `python-dotenv`, never hardcode credentials, and validate partner certificates with helpers in `anp/authentication`. Honor the recommended cipher suites from `anp/e2e_encryption`, and review `docs/` for interoperability constraints before modifying negotiation flows. Keep configuration explicit and committed sample files redacted.
