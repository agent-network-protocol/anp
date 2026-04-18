"""Convert legacy ANP raw-key PEM files to standard PKCS#8/SPKI PEM.

The normal SDK runtime intentionally rejects legacy labels such as
``ANP ED25519 PRIVATE KEY``. This one-shot tool is the compatibility boundary
for existing files that need to be rewritten to standard PEM.
"""

from __future__ import annotations

import argparse
import base64
import re
import shutil
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519


LEGACY_PEM_RE = re.compile(
    rb"\A-----BEGIN (?P<label>ANP [A-Z0-9]+ (?:PRIVATE|PUBLIC) KEY)-----\s+"
    rb"(?P<body>[A-Za-z0-9+/=\s]+?)\s+"
    rb"-----END (?P=label)-----\s*\Z"
)


def convert_legacy_anp_pem(pem_data: bytes) -> bytes:
    """Return standard PKCS#8/SPKI PEM for a legacy ANP PEM blob."""

    match = LEGACY_PEM_RE.match(pem_data.strip())
    if not match:
        raise ValueError("input is not a legacy ANP PEM file")

    label = match.group("label").decode("ascii")
    raw_key = base64.b64decode(re.sub(rb"\s+", b"", match.group("body")), validate=True)

    if label.endswith(" PRIVATE KEY"):
        key = _load_legacy_private_key(label, raw_key)
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    key = _load_legacy_public_key(label, raw_key)
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _load_legacy_private_key(label: str, raw_key: bytes):
    if label == "ANP ED25519 PRIVATE KEY":
        if len(raw_key) != 32:
            raise ValueError("invalid Ed25519 private key length")
        return ed25519.Ed25519PrivateKey.from_private_bytes(raw_key)
    if label == "ANP X25519 PRIVATE KEY":
        if len(raw_key) != 32:
            raise ValueError("invalid X25519 private key length")
        return x25519.X25519PrivateKey.from_private_bytes(raw_key)
    if label == "ANP SECP256R1 PRIVATE KEY":
        return _derive_ec_private_key(raw_key, ec.SECP256R1())
    if label == "ANP SECP256K1 PRIVATE KEY":
        return _derive_ec_private_key(raw_key, ec.SECP256K1())
    raise ValueError(f"unsupported legacy private key label: {label}")


def _load_legacy_public_key(label: str, raw_key: bytes):
    if label == "ANP ED25519 PUBLIC KEY":
        if len(raw_key) != 32:
            raise ValueError("invalid Ed25519 public key length")
        return ed25519.Ed25519PublicKey.from_public_bytes(raw_key)
    if label == "ANP X25519 PUBLIC KEY":
        if len(raw_key) != 32:
            raise ValueError("invalid X25519 public key length")
        return x25519.X25519PublicKey.from_public_bytes(raw_key)
    if label == "ANP SECP256R1 PUBLIC KEY":
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw_key)
    if label == "ANP SECP256K1 PUBLIC KEY":
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), raw_key)
    raise ValueError(f"unsupported legacy public key label: {label}")


def _derive_ec_private_key(raw_key: bytes, curve: ec.EllipticCurve):
    if not raw_key:
        raise ValueError("invalid EC private key length")
    return ec.derive_private_key(int.from_bytes(raw_key, "big"), curve)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert legacy ANP raw-key PEM to standard PKCS#8/SPKI PEM."
    )
    parser.add_argument("input", type=Path, help="Legacy ANP PEM file to convert")
    parser.add_argument("--output", type=Path, help="Path for the converted PEM file")
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Rewrite the input file and keep a .bak backup",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Do not create a .bak file when using --in-place",
    )
    args = parser.parse_args()

    if args.in_place and args.output:
        parser.error("--output cannot be used with --in-place")
    if not args.in_place and not args.output:
        parser.error("provide --output or --in-place")

    converted = convert_legacy_anp_pem(args.input.read_bytes())

    if args.in_place:
        if not args.no_backup:
            shutil.copy2(args.input, args.input.with_suffix(args.input.suffix + ".bak"))
        args.input.write_bytes(converted)
        print(f"converted {args.input} in place")
    else:
        args.output.write_bytes(converted)
        print(f"wrote {args.output}")


if __name__ == "__main__":
    main()
