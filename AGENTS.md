# Repository Guidelines

AgentConnect enables protocol-compliant communication between agents. Use this guide to stay aligned with our architecture, tooling, and review expectations.

## Project Structure & Module Organization
- `anp/authentication/` manages identity flows and credential validation.
- `anp/e2e_encryption/` secures payloads; `anp/meta_protocol/` orchestrates negotiation logic.
- Shared helpers reside in `anp/utils/`; interoperability tooling lives in `anp/anp_crawler/`.
- Tests mirror source paths under `anp/unittest/<package>/test_<topic>.py`.
- Documentation belongs in `docs/`, runnable scenarios in `examples/`, release artifacts in `dist/`, and JVM clients under `java/`.

## Build, Test, and Development Commands
- `uv sync` installs dependencies pinned in `pyproject.toml`.
- `uv run pytest` executes the full suite; add `-k "pattern"` to target specific paths.
- `uv build --wheel` produces distributable wheels in `dist/`.
- `uv run python examples/ping_pong.py` validates a round-trip negotiation flow.
- `uv run python -m anp.meta_protocol.cli --help` lists CLI options for manual probes.

## Coding Style & Naming Conventions
- Adhere to Google Python Style: four-space indentation, type hints, and module docstrings.
- Use `snake_case` for modules and functions, `UpperCamelCase` for classes, and `UPPER_SNAKE_CASE` for constants.
- Keep public APIs documented with Google-style docstrings; log and comment text must remain in English.
- Prefer dependency injection and explicit configuration over globals or hidden state.
- Group new utilities under the closest existing package to preserve discoverability.

## Testing Guidelines
- Place tests under `anp/unittest`, naming files `test_<area>.py` and functions `test_<behavior>`.
- Leverage `pytest` fixtures for shared setup; mark async coroutines with `pytest.mark.asyncio`.
- Run `uv run pytest --cov=anp` before review and cover new control paths and edge cases.
- Add scenario checks in `examples/` when introducing protocol changes that affect interoperability.

## Commit & Pull Request Guidelines
- Author commits as concise imperatives (e.g., `Add credential signer`), referencing issues like `#19` when relevant.
- Scope each PR to a coherent change set and describe behavior, risks, and validation steps.
- Attach logs or screenshots for user-facing adjustments and note any protocol compatibility impacts.
- Confirm CI success prior to requesting review; include reproduction steps for bug fixes.

## Security & Configuration Tips
- Store secrets in `.env` files and load them with `python-dotenv`.
- Validate partner certificates using helpers in `anp/authentication` and honor the recommended cipher suites in `anp/e2e_encryption`.
- Review updates in `docs/` before modifying negotiation flows to preserve interoperability with external agents.
