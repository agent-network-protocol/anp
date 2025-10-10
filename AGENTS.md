# Repository Guidelines

These instructions help contributors navigate the AgentConnect codebase, follow consistent workflows, and ship production-grade changes with confidence.

## Project Structure & Module Organization
Core Python packages live under `anp/` and are grouped by capability: `authentication/` for identity flows, `e2e_encryption/` for secure messaging, `meta_protocol/` for negotiation logic, `anp_crawler/` for interoperability tools, and `utils/` for shared helpers. Generated artifacts belong in `dist/`, documentation in `docs/`, runnable scenarios in `examples/`, and JVM-specific assets in `java/`. Mirror source paths when adding tests by placing them in `anp/unittest/<package>/test_<topic>.py`.

## Build, Test, and Development Commands
Run `uv sync` to install or update dependencies defined in `pyproject.toml`. Use `uv run pytest` (or `uv run pytest -k "<pattern>"`) to execute the test suite. Build distributable wheels with `uv build --wheel` and inspect outputs under `dist/`. Launch sample flows using `uv run python examples/<script>.py` to validate end-to-end behavior before submitting changes.

## Coding Style & Naming Conventions
Follow Google Python Style: four-space indentation, type hints, and module-level docstrings. Use `snake_case` for functions and modules, `UpperCamelCase` for classes, and `UPPER_SNAKE_CASE` for constants. Keep public APIs documented with Google-style docstrings, and reserve inline comments for non-obvious logic. Prefer dependency injection over global state and keep network side effects isolated.

## Testing Guidelines
Write `pytest` tests under `anp/unittest`, naming files `test_<area>.py` and functions `test_<behavior>`. Target coverage of new control paths and edge cases; when helpful, share fixture data via `examples/`. Before creating a pull request, run `uv run pytest --cov=anp` and address any regressions or coverage gaps.

## Commit & Pull Request Guidelines
Author commits as concise imperative statements (for example, `Add DID verifier` or `Fix meta protocol retry`). Reference issues like `#19` when relevant and keep each commit scoped to a coherent change set. Pull requests must describe scope, testing evidence, and any protocol implications; include screenshots or logs for user-facing adjustments and ensure CI passes before requesting review.

## Security & Configuration Tips
Store secrets in `.env` files and load them via `python-dotenv`. Validate certificates with helpers in `anp/authentication` and default to the recommended E2E encryption settings. Review `docs/` for protocol updates prior to modifying negotiation flows to preserve interoperability with partner agents.
