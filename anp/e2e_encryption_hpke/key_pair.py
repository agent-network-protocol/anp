"""X25519 密钥对管理和 DID 文档公钥提取。"""

import base64
from typing import Optional, Tuple

import base58
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


def generate_x25519_key_pair() -> Tuple[X25519PrivateKey, X25519PublicKey]:
    """生成 X25519 密钥对。"""
    private_key = X25519PrivateKey.generate()
    return private_key, private_key.public_key()


def public_key_to_bytes(pk: X25519PublicKey) -> bytes:
    """X25519 公钥 → 32 字节原始格式。"""
    return pk.public_bytes_raw()


def public_key_from_bytes(data: bytes) -> X25519PublicKey:
    """32 字节原始格式 → X25519 公钥。"""
    return X25519PublicKey.from_public_bytes(data)


def private_key_to_bytes(sk: X25519PrivateKey) -> bytes:
    """X25519 私钥 → 32 字节原始格式。"""
    return sk.private_bytes_raw()


def private_key_from_bytes(data: bytes) -> X25519PrivateKey:
    """32 字节原始格式 → X25519 私钥。"""
    return X25519PrivateKey.from_private_bytes(data)


def public_key_to_multibase(pk: X25519PublicKey) -> str:
    """X25519 公钥 → multibase（z + base58btc）格式，用于 DID 文档。"""
    raw = public_key_to_bytes(pk)
    return "z" + base58.b58encode(raw).decode("ascii")


def public_key_from_multibase(multibase: str) -> X25519PublicKey:
    """multibase（z + base58btc）格式 → X25519 公钥。"""
    if not multibase.startswith("z"):
        raise ValueError(f"Unsupported multibase prefix: {multibase[0]!r}")
    raw = base58.b58decode(multibase[1:])
    return public_key_from_bytes(raw)


def extract_x25519_public_key_from_did_document(
    doc: dict, key_id: Optional[str] = None
) -> Tuple[X25519PublicKey, str]:
    """从 DID 文档的 keyAgreement 中提取 X25519 公钥。

    Args:
        doc: DID 文档 dict。
        key_id: 指定 keyAgreement 条目的 id，为 None 则取第一个。

    Returns:
        (public_key, key_id) 元组。

    Raises:
        ValueError: 未找到 X25519KeyAgreementKey2019 条目。
    """
    ka_refs = doc.get("keyAgreement", [])
    vms = doc.get("verificationMethod", [])

    # 构建 verification method 索引
    vm_map = {vm["id"]: vm for vm in vms if isinstance(vm, dict)}

    candidates = []
    for ref in ka_refs:
        if isinstance(ref, str):
            vm = vm_map.get(ref)
        elif isinstance(ref, dict):
            vm = ref
        else:
            continue
        if vm and vm.get("type") == "X25519KeyAgreementKey2019":
            candidates.append(vm)

    if not candidates:
        raise ValueError("DID document has no X25519KeyAgreementKey2019 in keyAgreement")

    if key_id:
        target = next((vm for vm in candidates if vm["id"] == key_id), None)
        if not target:
            raise ValueError(f"keyAgreement entry not found: {key_id}")
    else:
        target = candidates[0]

    multibase = target.get("publicKeyMultibase")
    if not multibase:
        raise ValueError("keyAgreement entry missing publicKeyMultibase")

    pk = public_key_from_multibase(multibase)
    return pk, target["id"]


def extract_signing_public_key_from_did_document(
    doc: dict, vm_id: str
) -> ec.EllipticCurvePublicKey:
    """从 DID 文档的 verificationMethod 中提取 secp256r1 签名公钥。

    Args:
        doc: DID 文档 dict。
        vm_id: verificationMethod 的 id。

    Returns:
        secp256r1 公钥。

    Raises:
        ValueError: 未找到指定条目或类型不匹配。
    """
    vms = doc.get("verificationMethod", [])
    target = next((vm for vm in vms if isinstance(vm, dict) and vm["id"] == vm_id), None)
    if not target:
        raise ValueError(f"verificationMethod not found: {vm_id}")

    expected_type = "EcdsaSecp256r1VerificationKey2019"
    if target.get("type") != expected_type:
        raise ValueError(
            f"Expected type {expected_type}, got {target.get('type')!r} for {vm_id}"
        )

    jwk = target.get("publicKeyJwk")
    if jwk:
        x = base64.urlsafe_b64decode(jwk["x"] + "==")
        y = base64.urlsafe_b64decode(jwk["y"] + "==")
        pub_numbers = ec.EllipticCurvePublicNumbers(
            x=int.from_bytes(x, "big"),
            y=int.from_bytes(y, "big"),
            curve=ec.SECP256R1(),
        )
        return pub_numbers.public_key()

    # publicKeyHex fallback
    hex_key = target.get("publicKeyHex") or target.get("public_key_hex")
    if hex_key:
        key_bytes = bytes.fromhex(hex_key)
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key_bytes)

    raise ValueError(f"Cannot extract public key from verificationMethod: {vm_id}")
