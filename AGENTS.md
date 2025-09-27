# Repository Guidelines

## Project Structure & Module Organization
Core Python packages live in `agent_connect/`, grouped by capability: `authentication` for identity flows, `e2e_encryption` for secure messaging, `meta_protocol` for negotiation logic, `anp_crawler` for interoperability tools, and `utils` for shared helpers. SDK artifacts generated for distribution are stored in `dist/`. Reference documentation sits in `docs/`, runnable scenarios in `examples/`, and integration assets for other runtimes in `java/`. Place new tests alongside source by mirroring the package path under `agent_connect/unittest`.

## Build, Test, and Development Commands
Run `uv sync` to create or update the environment defined in `pyproject.toml`. Use `uv run pytest` to execute the full test suite locally; pass `-k <pattern>` for focused runs. Generate a wheel for release with `uv build --wheel` and inspect the output under `dist/`. Launch sample flows with `uv run python examples/<script>.py` to validate end-to-end behaviors.

## Coding Style & Naming Conventions
Follow Google Python Style: four-space indentation, module-level docstrings, and clear type hints. Functions and modules use `snake_case`, classes use `UpperCamelCase`, and constants remain `UPPER_SNAKE_CASE`. Keep public APIs documented with Google-style docstrings and inline comments only where logic is non-obvious. Prefer dependency injection over globals and isolate network side effects.

## Testing Guidelines
Write `pytest`-compatible tests under `agent_connect/unittest`, naming files `test_<area>.py` and test functions `test_<behavior>`. Cover authentication handshakes, encryption boundaries, and error paths with descriptive parametrized cases. Target qualitative coverage of new code paths and include fixture data in `examples/` when reusability helps. Run `uv run pytest --cov=agent_connect` before opening a pull request.

## Commit & Pull Request Guidelines
Commit messages should be concise imperative statements ("Add DID verifier"), optionally referencing issues like `#19`. Group related changes per commit to simplify review. Each pull request must describe scope, testing evidence, and any protocol impacts; attach screenshots or logs for user-facing adjustments. Ensure CI passes and request reviews from maintainers owning the touched modules.

## Security & Configuration Tips
Store credentials in `.env` files loaded via `python-dotenv`; never commit secrets. When configuring cross-agent communication, validate certificate material with the helpers in `authentication` and prefer the E2E encryption defaults. Review `docs/` for protocol updates before modifying negotiation flows to maintain interoperability.
