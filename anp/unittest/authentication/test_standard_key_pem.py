import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519

from anp.authentication import create_did_wba_document
from tools.migrate_anp_key_pem import convert_legacy_anp_pem


def test_python_did_keys_use_standard_pkcs8_and_spki_pem():
    did_document, keys = create_did_wba_document(
        "example.com",
        path_segments=["user", "python-standard-pem"],
    )

    assert did_document["id"].startswith("did:wba:example.com")
    assert keys["key-1"][0].splitlines()[0] == b"-----BEGIN PRIVATE KEY-----"
    assert keys["key-1"][1].splitlines()[0] == b"-----BEGIN PUBLIC KEY-----"
    for private_pem, public_pem in keys.values():
        assert b"ANP " not in private_pem
        assert b"ANP " not in public_pem
        serialization.load_pem_private_key(private_pem, password=None)
        serialization.load_pem_public_key(public_pem)

    _, k1_keys = create_did_wba_document(
        "example.com",
        path_segments=["user", "python-standard-k1-pem"],
        did_profile="k1",
        enable_e2ee=False,
    )
    k1_private_pem, k1_public_pem = k1_keys["key-1"]
    assert k1_private_pem.splitlines()[0] == b"-----BEGIN PRIVATE KEY-----"
    assert k1_public_pem.splitlines()[0] == b"-----BEGIN PUBLIC KEY-----"
    serialization.load_pem_private_key(k1_private_pem, password=None)
    serialization.load_pem_public_key(k1_public_pem)


def test_migration_tool_converts_legacy_private_key_labels_to_pkcs8():
    for label, raw_key in _legacy_private_key_materials():
        converted = convert_legacy_anp_pem(_legacy_pem(label, raw_key))
        assert converted.splitlines()[0] == b"-----BEGIN PRIVATE KEY-----"
        assert b"ANP " not in converted
        serialization.load_pem_private_key(converted, password=None)


def test_migration_tool_converts_legacy_public_key_labels_to_spki():
    for label, raw_key in _legacy_public_key_materials():
        converted = convert_legacy_anp_pem(_legacy_pem(label, raw_key))
        assert converted.splitlines()[0] == b"-----BEGIN PUBLIC KEY-----"
        assert b"ANP " not in converted
        serialization.load_pem_public_key(converted)


def test_python_generated_standard_pem_keys_load_in_go(tmp_path):
    if shutil.which("go") is None:
        pytest.skip("go is required for Go key interoperability test")

    fixture_path = _write_key_fixture(tmp_path, _collect_python_standard_keys())
    result = _run_json(
        [
            "go",
            "run",
            "./cmd/anp-interop",
            "verify-key-fixture",
            "--fixture",
            str(fixture_path),
        ],
        _repo_root() / "golang",
    )
    assert result["verified"] is True


def test_python_generated_standard_pem_keys_load_in_rust(tmp_path):
    if shutil.which("cargo") is None:
        pytest.skip("cargo is required for Rust key interoperability test")

    fixture_path = _write_key_fixture(tmp_path, _collect_python_standard_keys())
    result = _run_json(
        [
            "cargo",
            "run",
            "--quiet",
            "--example",
            "interop_cli",
            "--",
            "verify-key-fixture",
            "--fixture",
            str(fixture_path),
        ],
        _repo_root() / "rust",
    )
    assert result["verified"] is True


def test_go_generated_standard_pem_keys_load_in_python():
    if shutil.which("go") is None:
        pytest.skip("go is required for Go key interoperability test")

    keys = {}
    for profile in ("e1", "k1"):
        fixture = _run_json(
            [
                "go",
                "run",
                "./cmd/anp-interop",
                "did-fixture",
                "--profile",
                profile,
                "--hostname",
                "example.com",
            ],
            _repo_root() / "golang",
        )
        keys.update(_prefix_fixture_keys(profile, fixture["keys"]))
    _assert_python_loads_standard_keys(keys)


def test_rust_generated_standard_pem_keys_load_in_python():
    if shutil.which("cargo") is None:
        pytest.skip("cargo is required for Rust key interoperability test")

    keys = {}
    for profile in ("e1", "k1"):
        fixture = _run_json(
            [
                "cargo",
                "run",
                "--quiet",
                "--example",
                "interop_cli",
                "--",
                "did-fixture",
                "--profile",
                profile,
                "--hostname",
                "example.com",
            ],
            _repo_root() / "rust",
        )
        keys.update(_prefix_fixture_keys(profile, fixture["keys"]))
    _assert_python_loads_standard_keys(keys)


def _collect_python_standard_keys() -> dict:
    _, e1_keys = create_did_wba_document(
        "example.com",
        path_segments=["user", "python-to-other-sdk"],
    )
    _, k1_keys = create_did_wba_document(
        "example.com",
        path_segments=["user", "python-to-other-sdk-k1"],
        did_profile="k1",
        enable_e2ee=False,
    )
    keys = {}
    keys.update(
        {
            f"e1-{name}": {
                "private_key_pem": pair[0].decode("ascii"),
                "public_key_pem": pair[1].decode("ascii"),
            }
            for name, pair in e1_keys.items()
        }
    )
    keys.update(
        {
            f"k1-{name}": {
                "private_key_pem": pair[0].decode("ascii"),
                "public_key_pem": pair[1].decode("ascii"),
            }
            for name, pair in k1_keys.items()
        }
    )
    return keys


def _write_key_fixture(tmp_path: Path, keys: dict) -> Path:
    fixture_path = tmp_path / "keys.json"
    fixture_path.write_text(json.dumps({"keys": keys}), encoding="utf-8")
    return fixture_path


def _prefix_fixture_keys(prefix: str, keys: dict) -> dict:
    return {f"{prefix}-{name}": value for name, value in keys.items()}


def _assert_python_loads_standard_keys(keys: dict) -> None:
    assert keys
    for fragment, value in keys.items():
        private_pem = value["private_key_pem"].encode("ascii")
        public_pem = value["public_key_pem"].encode("ascii")
        assert private_pem.splitlines()[0] == b"-----BEGIN PRIVATE KEY-----", fragment
        assert public_pem.splitlines()[0] == b"-----BEGIN PUBLIC KEY-----", fragment
        assert b"ANP " not in private_pem
        assert b"ANP " not in public_pem
        serialization.load_pem_private_key(private_pem, password=None)
        serialization.load_pem_public_key(public_pem)


def _run_json(command: list[str], cwd: Path) -> dict:
    result = subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"command failed: {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    output = result.stdout.strip().splitlines()[-1]
    return json.loads(output)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _legacy_pem(label: str, raw_key: bytes) -> bytes:
    body = base64.encodebytes(raw_key).replace(b"\n", b"")
    return (
        f"-----BEGIN {label}-----\n".encode("ascii")
        + body
        + f"\n-----END {label}-----\n".encode("ascii")
    )


def _legacy_private_key_materials():
    ed_key = ed25519.Ed25519PrivateKey.generate()
    x_key = x25519.X25519PrivateKey.generate()
    p256_key = ec.generate_private_key(ec.SECP256R1())
    k1_key = ec.generate_private_key(ec.SECP256K1())
    return [
        (
            "ANP ED25519 PRIVATE KEY",
            ed_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ),
        ),
        (
            "ANP X25519 PRIVATE KEY",
            x_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ),
        ),
        (
            "ANP SECP256R1 PRIVATE KEY",
            p256_key.private_numbers().private_value.to_bytes(32, "big"),
        ),
        (
            "ANP SECP256K1 PRIVATE KEY",
            k1_key.private_numbers().private_value.to_bytes(32, "big"),
        ),
    ]


def _legacy_public_key_materials():
    ed_key = ed25519.Ed25519PrivateKey.generate().public_key()
    x_key = x25519.X25519PrivateKey.generate().public_key()
    p256_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    k1_key = ec.generate_private_key(ec.SECP256K1()).public_key()
    return [
        (
            "ANP ED25519 PUBLIC KEY",
            ed_key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            ),
        ),
        (
            "ANP X25519 PUBLIC KEY",
            x_key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            ),
        ),
        (
            "ANP SECP256R1 PUBLIC KEY",
            p256_key.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.CompressedPoint,
            ),
        ),
        (
            "ANP SECP256K1 PUBLIC KEY",
            k1_key.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.CompressedPoint,
            ),
        ),
    ]
