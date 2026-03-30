"""Shared constants for Rust interoperability tests."""

from __future__ import annotations

import json
from pathlib import Path

_CONFIG_PATH = Path(__file__).resolve().parents[3] / "tests" / "rust_interop_config.json"
_RELEASED_CONFIG = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))

RELEASED_PYTHON_ANP_VERSION = _RELEASED_CONFIG["released_python_anp_version"]
