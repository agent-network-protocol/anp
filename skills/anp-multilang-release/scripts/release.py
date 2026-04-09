#!/usr/bin/env python3
"""Release Go, Python, and Rust SDKs with one shared version."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


VERSION_PATTERN = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


@dataclass(frozen=True)
class SemVer:
    """A semantic version with single-digit segments."""

    major: int
    minor: int
    patch: int

    @classmethod
    def parse(cls, raw_value: str) -> "SemVer":
        """Parse and validate a single-digit semantic version."""
        match = VERSION_PATTERN.fullmatch(raw_value.strip())
        if not match:
            raise ValueError(
                f"Invalid version '{raw_value}'. Expected format X.Y.Z."
            )

        major, minor, patch = (int(part) for part in match.groups())
        version = cls(major=major, minor=minor, patch=patch)
        version.validate_single_digit()
        return version

    def validate_single_digit(self) -> None:
        """Ensure all version segments fit in one digit."""
        for field_name, value in (
            ("major", self.major),
            ("minor", self.minor),
            ("patch", self.patch),
        ):
            if value < 0 or value > 9:
                raise ValueError(
                    f"Version {self} is invalid: {field_name} must be 0-9."
                )

    def next_single_digit(self) -> "SemVer":
        """Return the next version while keeping all segments one digit."""
        if self.patch < 9:
            return SemVer(self.major, self.minor, self.patch + 1)
        if self.minor < 9:
            return SemVer(self.major, self.minor + 1, 0)
        if self.major < 9:
            return SemVer(self.major + 1, 0, 0)
        raise ValueError(
            "Cannot auto-increment version beyond 9.9.9 with single-digit rules."
        )

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True)
class ReleasePaths:
    """Repository paths used by the release workflow."""

    repo_root: Path
    pyproject_toml: Path
    uv_lock: Path
    cargo_toml: Path
    cargo_lock: Path
    go_mod: Path
    dist_dir: Path


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Release the ANP Python, Rust, and Go SDKs with one shared version."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan_parser = subparsers.add_parser(
        "plan",
        help="Show the current version, target version, and release actions.",
    )
    add_version_arguments(plan_parser)
    plan_parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Optional repository root. Defaults to the detected ANP repo root.",
    )
    plan_parser.add_argument(
        "--remote",
        default="origin",
        help="Git remote used to check or push tags. Defaults to origin.",
    )

    next_parser = subparsers.add_parser(
        "next-version",
        help="Print the next single-digit semantic version only.",
    )
    next_parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Optional repository root. Defaults to the detected ANP repo root.",
    )

    release_parser = subparsers.add_parser(
        "release",
        help="Update versions, validate builds, publish artifacts, and push tags.",
    )
    add_version_arguments(release_parser)
    release_parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Optional repository root. Defaults to the detected ANP repo root.",
    )
    release_parser.add_argument(
        "--remote",
        default="origin",
        help="Git remote used to check or push tags. Defaults to origin.",
    )
    release_parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Skip the clean working tree check before modifying files.",
    )
    return parser


def add_version_arguments(parser: argparse.ArgumentParser) -> None:
    """Add shared version-selection arguments."""
    parser.add_argument(
        "--version",
        default=None,
        help="Explicit target version such as 0.7.2.",
    )


def detect_repo_root(start_path: Path) -> Path:
    """Detect the ANP repository root by scanning parent directories."""
    current = start_path.resolve()
    for candidate in [current, *current.parents]:
        if (
            (candidate / "pyproject.toml").exists()
            and (candidate / "rust" / "Cargo.toml").exists()
            and (candidate / "golang" / "go.mod").exists()
        ):
            return candidate
    raise FileNotFoundError(
        "Could not detect the ANP repository root from the current location."
    )


def get_release_paths(repo_root: Path) -> ReleasePaths:
    """Return validated repository paths."""
    paths = ReleasePaths(
        repo_root=repo_root,
        pyproject_toml=repo_root / "pyproject.toml",
        uv_lock=repo_root / "uv.lock",
        cargo_toml=repo_root / "rust" / "Cargo.toml",
        cargo_lock=repo_root / "rust" / "Cargo.lock",
        go_mod=repo_root / "golang" / "go.mod",
        dist_dir=repo_root / "dist",
    )
    required_paths = [
        paths.pyproject_toml,
        paths.uv_lock,
        paths.cargo_toml,
        paths.cargo_lock,
        paths.go_mod,
    ]
    missing = [str(path) for path in required_paths if not path.exists()]
    if missing:
        raise FileNotFoundError(
            "Missing required release files:\n- " + "\n- ".join(missing)
        )
    return paths


def read_text(path: Path) -> str:
    """Read UTF-8 text from a file."""
    return path.read_text(encoding="utf-8")


def write_text(path: Path, content: str) -> None:
    """Write UTF-8 text to a file."""
    path.write_text(content, encoding="utf-8")


def extract_current_version(paths: ReleasePaths) -> SemVer:
    """Read and validate the current shared release version."""
    python_version = extract_project_version(paths.pyproject_toml)
    rust_version = extract_cargo_package_version(paths.cargo_toml)
    uv_lock_version = extract_uv_lock_version(paths.uv_lock)
    cargo_lock_version = extract_cargo_lock_version(paths.cargo_lock)

    versions = {
        "pyproject.toml": python_version,
        "rust/Cargo.toml": rust_version,
        "uv.lock": uv_lock_version,
        "rust/Cargo.lock": cargo_lock_version,
    }

    unique_versions = {str(version) for version in versions.values()}
    if len(unique_versions) != 1:
        mismatch_lines = [
            f"{name}: {version}" for name, version in versions.items()
        ]
        raise ValueError(
            "Version files are out of sync:\n- " + "\n- ".join(mismatch_lines)
        )
    return python_version


def extract_project_version(path: Path) -> SemVer:
    """Extract the package version from pyproject.toml."""
    text = read_text(path)
    match = re.search(
        r'(?ms)^\[project\]\s+.*?^version = "(\d+\.\d+\.\d+)"\s*$',
        text,
    )
    if not match:
        raise ValueError(f"Could not find [project] version in {path}.")
    return SemVer.parse(match.group(1))


def extract_cargo_package_version(path: Path) -> SemVer:
    """Extract the package version from rust/Cargo.toml."""
    text = read_text(path)
    match = re.search(
        r'(?ms)^\[package\]\s+.*?^version = "(\d+\.\d+\.\d+)"\s*$',
        text,
    )
    if not match:
        raise ValueError(f"Could not find [package] version in {path}.")
    return SemVer.parse(match.group(1))


def extract_uv_lock_version(path: Path) -> SemVer:
    """Extract the editable root package version from uv.lock."""
    text = read_text(path)
    match = re.search(
        r'(?ms)^name = "anp"\nversion = "(\d+\.\d+\.\d+)"\nsource = \{ editable = "\." \}$',
        text,
    )
    if not match:
        raise ValueError(
            "Could not find the editable root package version in uv.lock."
        )
    return SemVer.parse(match.group(1))


def extract_cargo_lock_version(path: Path) -> SemVer:
    """Extract the root package version from rust/Cargo.lock."""
    text = read_text(path)
    match = re.search(
        r'(?ms)^name = "anp"\nversion = "(\d+\.\d+\.\d+)"\n',
        text,
    )
    if not match:
        raise ValueError("Could not find the root package version in Cargo.lock.")
    return SemVer.parse(match.group(1))


def resolve_target_version(
    current_version: SemVer,
    explicit_version: str | None,
) -> SemVer:
    """Resolve the target version from arguments."""
    if explicit_version:
        return SemVer.parse(explicit_version)
    return current_version.next_single_digit()


def update_version_files(paths: ReleasePaths, target_version: SemVer) -> list[Path]:
    """Update all tracked version files and return the changed file list."""
    changed_paths: list[Path] = []

    replacements = [
        (
            paths.pyproject_toml,
            r'(?ms)(^\[project\]\s+.*?^version = ")(\d+\.\d+\.\d+)(".*$)',
        ),
        (
            paths.cargo_toml,
            r'(?ms)(^\[package\]\s+.*?^version = ")(\d+\.\d+\.\d+)(".*$)',
        ),
        (
            paths.uv_lock,
            r'(?ms)(^name = "anp"\nversion = ")(\d+\.\d+\.\d+)("\nsource = \{ editable = "\." \}$)',
        ),
        (
            paths.cargo_lock,
            r'(?ms)(^name = "anp"\nversion = ")(\d+\.\d+\.\d+)("\n)',
        ),
    ]

    for path, pattern in replacements:
        original_text = read_text(path)
        updated_text, count = re.subn(
            pattern,
            rf"\g<1>{target_version}\g<3>",
            original_text,
            count=1,
        )
        if count != 1:
            raise ValueError(f"Failed to update version in {path}.")
        if updated_text != original_text:
            write_text(path, updated_text)
            changed_paths.append(path)

    return changed_paths


def build_release_tags(target_version: SemVer) -> tuple[str, str]:
    """Return the root tag and Go module tag for the target version."""
    version_text = str(target_version)
    return version_text, f"golang/v{version_text}"


def check_tag_absent(repo_root: Path, remote: str, tag_name: str) -> None:
    """Ensure a tag does not already exist locally or remotely."""
    local_result = run_command(
        ["git", "tag", "--list", tag_name],
        cwd=repo_root,
        capture_output=True,
    )
    if local_result.stdout.strip():
        raise RuntimeError(f"Tag already exists locally: {tag_name}")

    remote_result = run_command(
        ["git", "ls-remote", "--tags", remote, f"refs/tags/{tag_name}"],
        cwd=repo_root,
        capture_output=True,
    )
    if remote_result.stdout.strip():
        raise RuntimeError(f"Tag already exists on {remote}: {tag_name}")


def ensure_clean_worktree(repo_root: Path) -> None:
    """Ensure the repository has no uncommitted changes."""
    status = run_command(
        ["git", "status", "--short"],
        cwd=repo_root,
        capture_output=True,
    )
    if status.stdout.strip():
        raise RuntimeError(
            "Working tree is not clean. Commit or stash changes before release."
        )


def clean_dist_directory(dist_dir: Path) -> None:
    """Remove previous release artifacts from dist/."""
    if not dist_dir.exists():
        return
    for child in dist_dir.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()


def run_release_validations(paths: ReleasePaths) -> None:
    """Run build and validation commands before publishing."""
    clean_dist_directory(paths.dist_dir)

    run_command(["uv", "build"], cwd=paths.repo_root)
    run_command(
        [
            "cargo",
            "publish",
            "--dry-run",
            "--allow-dirty",
            "--manifest-path",
            "rust/Cargo.toml",
        ],
        cwd=paths.repo_root,
    )
    run_command(["go", "test", "./..."], cwd=paths.repo_root / "golang")


def maybe_commit_version_bump(
    repo_root: Path,
    changed_paths: Sequence[Path],
    target_version: SemVer,
    remote: str,
) -> None:
    """Commit and push changed version files when needed."""
    if not changed_paths:
        print("No version files changed. Skip commit and branch push.")
        return

    relative_paths = [str(path.relative_to(repo_root)) for path in changed_paths]
    run_command(["git", "add", *relative_paths], cwd=repo_root)
    run_command(
        [
            "git",
            "commit",
            "-m",
            f"release: bump python, rust, and go to {target_version}",
        ],
        cwd=repo_root,
    )
    run_command(["git", "push", remote, "HEAD"], cwd=repo_root)


def publish_python(repo_root: Path) -> None:
    """Publish the Python package with uv."""
    run_command(["uv", "publish"], cwd=repo_root)


def publish_rust(repo_root: Path) -> None:
    """Publish the Rust crate to crates.io."""
    run_command(
        ["cargo", "publish", "--manifest-path", "rust/Cargo.toml"],
        cwd=repo_root,
    )


def create_and_push_tags(
    repo_root: Path,
    remote: str,
    root_tag: str,
    go_tag: str,
) -> None:
    """Create and push the root release tag and Go module tag."""
    run_command(["git", "tag", root_tag], cwd=repo_root)
    run_command(["git", "tag", go_tag], cwd=repo_root)
    run_command(["git", "push", remote, root_tag, go_tag], cwd=repo_root)


def print_release_plan(
    paths: ReleasePaths,
    current_version: SemVer,
    target_version: SemVer,
    remote: str,
) -> None:
    """Print the release plan without modifying files."""
    root_tag, go_tag = build_release_tags(target_version)
    print(f"Repository root: {paths.repo_root}")
    print(f"Current version: {current_version}")
    print(f"Target version: {target_version}")
    print(f"Git remote: {remote}")
    print(f"Root release tag: {root_tag}")
    print(f"Go module tag: {go_tag}")
    print("Files to update:")
    print(f"- {paths.pyproject_toml.relative_to(paths.repo_root)}")
    print(f"- {paths.uv_lock.relative_to(paths.repo_root)}")
    print(f"- {paths.cargo_toml.relative_to(paths.repo_root)}")
    print(f"- {paths.cargo_lock.relative_to(paths.repo_root)}")
    print("Validation steps:")
    print("- uv build")
    print("- cargo publish --dry-run --manifest-path rust/Cargo.toml")
    print("- go test ./... (from golang/)")
    print("Publish steps:")
    print("- git push origin HEAD (after version commit)")
    print("- uv publish")
    print("- cargo publish --manifest-path rust/Cargo.toml")
    print(f"- git push {remote} {root_tag} {go_tag}")


def run_command(
    command: Sequence[str],
    *,
    cwd: Path,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run a command and stream or capture its output."""
    print(f"Running: {' '.join(command)}")
    return subprocess.run(
        command,
        cwd=str(cwd),
        check=True,
        text=True,
        capture_output=capture_output,
    )


def main() -> int:
    """Run the CLI."""
    parser = build_parser()
    args = parser.parse_args()

    repo_root = detect_repo_root(
        args.repo_root.resolve() if args.repo_root else Path(__file__).resolve()
    )
    paths = get_release_paths(repo_root)
    current_version = extract_current_version(paths)

    if args.command == "next-version":
        print(current_version.next_single_digit())
        return 0

    target_version = resolve_target_version(current_version, args.version)
    root_tag, go_tag = build_release_tags(target_version)

    if args.command == "plan":
        print_release_plan(paths, current_version, target_version, args.remote)
        return 0

    if not args.allow_dirty:
        ensure_clean_worktree(paths.repo_root)

    check_tag_absent(paths.repo_root, args.remote, root_tag)
    check_tag_absent(paths.repo_root, args.remote, go_tag)

    changed_paths = update_version_files(paths, target_version)
    run_release_validations(paths)
    maybe_commit_version_bump(paths.repo_root, changed_paths, target_version, args.remote)
    publish_python(paths.repo_root)
    publish_rust(paths.repo_root)
    create_and_push_tags(paths.repo_root, args.remote, root_tag, go_tag)

    print(f"Release completed successfully for version {target_version}.")
    print("Note: pkg.go.dev and proxy.golang.org may take time to index the Go tag.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except subprocess.CalledProcessError as error:
        print(
            f"Command failed with exit code {error.returncode}: "
            f"{' '.join(error.cmd)}",
            file=sys.stderr,
        )
        if error.stdout:
            print(error.stdout, file=sys.stderr)
        if error.stderr:
            print(error.stderr, file=sys.stderr)
        sys.exit(error.returncode)
    except Exception as error:  # pylint: disable=broad-except
        print(f"Release failed: {error}", file=sys.stderr)
        sys.exit(1)
