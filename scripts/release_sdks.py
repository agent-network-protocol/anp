#!/usr/bin/env python3
"""One-command launcher for coordinated Python, Rust, and Go SDK releases."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Sequence


def build_parser() -> argparse.ArgumentParser:
    """Build the release launcher argument parser."""
    parser = argparse.ArgumentParser(
        description="Release the ANP Python, Rust, and Go SDKs together.",
    )
    parser.add_argument(
        "--version",
        help="Target X.Y.Z version. Omit to publish the next coordinated version.",
    )
    parser.add_argument(
        "--remote",
        default="origin",
        help="Git remote used for branch and tag pushes. Defaults to origin.",
    )
    parser.add_argument(
        "--plan",
        action="store_true",
        help="Print the release plan without changing or publishing anything.",
    )
    return parser


def build_release_command(
    repo_root: Path,
    *,
    plan: bool,
    version: str | None,
    remote: str,
) -> list[str]:
    """Build the command for the existing coordinated release helper."""
    command = [
        sys.executable,
        str(
            repo_root
            / "skills"
            / "anp-multilang-release"
            / "scripts"
            / "release.py"
        ),
        "plan" if plan else "release",
        "--remote",
        remote,
    ]
    if version:
        command.extend(["--version", version])
    return command


def main(argv: Sequence[str] | None = None) -> int:
    """Run the coordinated release helper and return its exit code."""
    args = build_parser().parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    command = build_release_command(
        repo_root,
        plan=args.plan,
        version=args.version,
        remote=args.remote,
    )
    result = subprocess.run(command, cwd=repo_root, check=False)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
