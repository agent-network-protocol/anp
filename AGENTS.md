# Repository Guidelines

## Project Structure & Module Organization
Core protocol logic lives under `anp/meta_protocol/`, with identity in `anp/authentication/`, encryption in `anp/e2e_encryption/`, shared helpers within `anp/utils/`, and interoperability tooling in `anp/anp_crawler/`. Tests shadow the package layout inside `anp/unittest/<module>/test_<topic>.py`, while docs stay in `docs/`, runnable walkthroughs in `examples/`, JVM clients in `java/`, and release bundles in `dist/`. Keep new assets alongside their feature modules to simplify discovery.

## Build, Test, and Development Commands
Run `uv sync` to install pinned dependencies, then `uv run pytest` (or `uv run pytest -k "handshake"`) for targeted suites. Package releases with `uv build --wheel`. Validate negotiation flows using `uv run python examples/ping_pong.py`, and inspect the CLI via `uv run python -m anp.meta_protocol.cli --help`. Keep a clean virtual environment by preferring `uv run <script>` over activating shells manually.

## Coding Style & Naming Conventions
Follow Google Python Style: four-space indentation, type hints, and Google-style docstrings on public APIs. Use `snake_case` for modules/functions, `UpperCamelCase` for classes, and `UPPER_SNAKE_CASE` for constants. Comments and logs must be in English. Group utilities in the closest existing package and avoid hidden globals; prefer dependency injection or explicit configuration objects.

## Testing Guidelines
All new logic must arrive with pytest coverage under the mirrored `anp/unittest` path, naming files `test_<area>.py` and functions `test_<behavior>`. Mark async tests with `@pytest.mark.asyncio`. Before review, run `uv run pytest --cov=anp` and ensure new branches are exercised. Add scenario checks in `examples/` whenever protocol behavior changes or interoperability could regress.

## Commit & Pull Request Guidelines
Author imperative commit subjects (e.g., `Add credential signer`) and reference issues like `#42` when relevant. Pull requests should summarize behavior changes, risks, validation commands, and any compatibility impacts. Attach logs or screenshots for user-visible updates, confirm CI success, and call out follow-up work explicitly to keep reviewers aligned.

## Security & Configuration Tips
Load secrets from `.env` via `python-dotenv`, never hardcode credentials, and validate partner certificates with helpers in `anp/authentication`. Honor the recommended cipher suites from `anp/e2e_encryption`, and review `docs/` for interoperability constraints before modifying negotiation flows. Keep configuration explicit and committed sample files redacted.
