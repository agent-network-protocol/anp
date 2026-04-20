"""Tests for the ANP multi-SDK release helper script."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


def _load_release_module():
    """Load the release script as a Python module for unit tests."""
    repo_root = Path(__file__).resolve().parents[3]
    script_path = (
        repo_root / "skills" / "anp-multilang-release" / "scripts" / "release.py"
    )
    module_name = "anp_multilang_release_test_module"
    spec = importlib.util.spec_from_file_location(module_name, script_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load release module from {script_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _build_release_paths(release_module, repo_root: Path):
    """Create ReleasePaths values backed by a temporary repository layout."""
    dist_dir = repo_root / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)
    return release_module.ReleasePaths(
        repo_root=repo_root,
        pyproject_toml=repo_root / "pyproject.toml",
        python_init=repo_root / "anp" / "__init__.py",
        uv_lock=repo_root / "uv.lock",
        cargo_toml=repo_root / "rust" / "Cargo.toml",
        cargo_lock=repo_root / "rust" / "Cargo.lock",
        go_version=repo_root / "golang" / "version.go",
        go_mod=repo_root / "golang" / "go.mod",
        dist_dir=dist_dir,
    )


def test_update_version_files_keeps_runtime_versions_aligned(tmp_path):
    """The release helper must update Python and Go runtime version constants."""
    release = _load_release_module()
    (tmp_path / "anp").mkdir()
    (tmp_path / "rust").mkdir()
    (tmp_path / "golang").mkdir()
    paths = _build_release_paths(release, tmp_path)
    paths.pyproject_toml.write_text(
        '[project]\nname = "anp"\nversion = "0.8.5"\n',
        encoding="utf-8",
    )
    paths.python_init.write_text('__version__ = "0.8.5"\n', encoding="utf-8")
    paths.uv_lock.write_text(
        'name = "anp"\nversion = "0.8.5"\nsource = { editable = "." }\n',
        encoding="utf-8",
    )
    paths.cargo_toml.write_text(
        '[package]\nname = "anp"\nversion = "0.8.5"\n',
        encoding="utf-8",
    )
    paths.cargo_lock.write_text(
        'name = "anp"\nversion = "0.8.5"\n',
        encoding="utf-8",
    )
    paths.go_version.write_text(
        'package anp\n\nconst Version = "0.8.5"\n',
        encoding="utf-8",
    )

    changed_paths = release.update_version_files(
        paths,
        release.SemVer.parse("0.8.6"),
    )

    assert paths.python_init in changed_paths
    assert paths.go_version in changed_paths
    assert '__version__ = "0.8.6"' in paths.python_init.read_text(
        encoding="utf-8",
    )
    assert 'const Version = "0.8.6"' in paths.go_version.read_text(
        encoding="utf-8",
    )


def test_collect_python_publish_files_returns_only_target_version_artifacts(tmp_path):
    """The publish helper must ignore older dist artifacts."""
    release = _load_release_module()
    paths = _build_release_paths(release, tmp_path)

    old_sdist = paths.dist_dir / "anp-0.8.3.tar.gz"
    old_wheel = paths.dist_dir / "anp-0.8.3-py3-none-any.whl"
    target_sdist = paths.dist_dir / "anp-0.8.4.tar.gz"
    target_wheel = paths.dist_dir / "anp-0.8.4-py3-none-any.whl"

    for artifact in (old_sdist, old_wheel, target_sdist, target_wheel):
        artifact.write_text("artifact", encoding="utf-8")

    publish_files = release.collect_python_publish_files(
        paths,
        release.SemVer.parse("0.8.4"),
    )

    assert publish_files == [target_sdist, target_wheel]


def test_collect_python_publish_files_requires_target_artifacts(tmp_path):
    """The publish helper must fail fast when the target artifacts are missing."""
    release = _load_release_module()
    paths = _build_release_paths(release, tmp_path)
    (paths.dist_dir / "anp-0.8.4.tar.gz").write_text("artifact", encoding="utf-8")

    with pytest.raises(
        FileNotFoundError,
        match="Missing Python distribution files for publish",
    ):
        release.collect_python_publish_files(
            paths,
            release.SemVer.parse("0.8.4"),
        )


def test_publish_python_passes_explicit_target_files(tmp_path, monkeypatch):
    """The uv publish command must receive only the target artifact paths."""
    release = _load_release_module()
    paths = _build_release_paths(release, tmp_path)
    (paths.dist_dir / "anp-0.8.4.tar.gz").write_text("artifact", encoding="utf-8")
    (paths.dist_dir / "anp-0.8.4-py3-none-any.whl").write_text(
        "artifact",
        encoding="utf-8",
    )
    (paths.dist_dir / "anp-0.8.3.tar.gz").write_text("artifact", encoding="utf-8")

    recorded_calls = []

    def fake_run_command(command, *, cwd, capture_output=False):
        recorded_calls.append((command, cwd, capture_output))
        return None

    monkeypatch.setattr(release, "run_command", fake_run_command)

    release.publish_python(paths, release.SemVer.parse("0.8.4"))

    assert recorded_calls == [
        (
            [
                "uv",
                "publish",
                "dist/anp-0.8.4.tar.gz",
                "dist/anp-0.8.4-py3-none-any.whl",
            ],
            tmp_path,
            False,
        )
    ]
