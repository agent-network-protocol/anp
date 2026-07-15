"""End-to-end test for the runnable e1 authentication example."""

from pathlib import Path
import subprocess


def run_example(root: Path, script_name: str) -> subprocess.CompletedProcess[str]:
    """Run one documented DID-WBA example through uv."""
    script = root / "examples" / "python" / "did_wba_examples" / script_name
    return subprocess.run(
        ["uv", "run", "python", str(script)],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_e1_creation_and_validation_examples_run_from_the_command_line():
    """The two focused DID-material commands should run in documented order."""
    root = Path(__file__).resolve().parents[2]

    creation = run_example(root, "create_did_document.py")
    assert creation.returncode == 0, creation.stderr
    assert "Generated DID identifier: did:wba:" in creation.stdout
    assert ":e1_" in creation.stdout

    validation = run_example(root, "validate_did_document.py")
    assert validation.returncode == 0, validation.stderr
    assert "DID document validation succeeded." in validation.stdout


def test_e1_authentication_example_runs_from_the_command_line():
    """Users should be able to run the documented example command directly."""
    root = Path(__file__).resolve().parents[2]
    completed = run_example(root, "e1_authenticate_and_verify.py")

    assert completed.returncode == 0, completed.stderr
    assert "Created e1 DID: did:wba:example.com:agents:alice:e1_" in completed.stdout
    assert "Request authentication: http_signatures" in completed.stdout
    assert "Bearer token authentication: bearer" in completed.stdout
