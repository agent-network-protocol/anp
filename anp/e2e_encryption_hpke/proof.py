"""EcdsaSecp256r1Signature2019 proof 签名。

与 anp/proof/proof.py 的 W3C proof 签名流程不同：
W3C 用 hash(options) || hash(document) 拼接后签名，
本协议直接对排除 proof_value 后的完整 JSON 做 JCS 规范化再签名。
"""

import base64
import copy
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict

import jcs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from anp.e2e_encryption_hpke.models import PROOF_TYPE


def _b64url_encode(data: bytes) -> str:
    """Base64URL 编码，无填充。"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64URL 解码（兼容有/无填充）。"""
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _strip_proof_value(content: Dict[str, Any]) -> Dict[str, Any]:
    """复制 content 并移除 proof.proof_value。"""
    result = copy.deepcopy(content)
    if "proof" in result and "proof_value" in result["proof"]:
        del result["proof"]["proof_value"]
    return result


def _sign_secp256r1(private_key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """ECDSA secp256r1 签名，返回 R||S 固定 64 字节。"""
    der_sig = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der_sig)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _verify_secp256r1(
    public_key: ec.EllipticCurvePublicKey, data: bytes, signature: bytes
) -> bool:
    """验证 ECDSA secp256r1 签名。"""
    try:
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        der_sig = utils.encode_dss_signature(r, s)
        public_key.verify(der_sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def generate_proof(
    content: Dict[str, Any],
    private_key: ec.EllipticCurvePrivateKey,
    verification_method: str,
) -> Dict[str, Any]:
    """为 content 生成 proof 签名。

    流程：构造 content（含 proof 但不含 proof_value）→ JCS 规范化
    → UTF-8 → ECDSA(SHA-256) → Base64URL

    Args:
        content: 待签名的 content dict，不含 proof 字段。
        private_key: secp256r1 签名私钥。
        verification_method: DID 文档中的验证方法 ID。

    Returns:
        含 proof 字段（包括 proof_value）的新 dict。
    """
    result = copy.deepcopy(content)
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result["proof"] = {
        "type": PROOF_TYPE,
        "created": created,
        "verification_method": verification_method,
    }

    # JCS 规范化 → UTF-8 → 签名
    canonical = jcs.canonicalize(result)
    signature = _sign_secp256r1(private_key, canonical)
    result["proof"]["proof_value"] = _b64url_encode(signature)

    return result


def verify_proof(
    content: Dict[str, Any],
    public_key: ec.EllipticCurvePublicKey,
    max_time_drift: int = 300,
) -> bool:
    """验证 content 的 proof 签名。

    Args:
        content: 含 proof 字段的 content dict。
        public_key: secp256r1 签名公钥。
        max_time_drift: 允许的最大时钟偏差（秒）。

    Returns:
        True 表示验证通过。
    """
    try:
        proof = content.get("proof")
        if not proof:
            logging.error("Content has no proof field")
            return False

        proof_value = proof.get("proof_value")
        if not proof_value:
            logging.error("Proof has no proof_value")
            return False

        proof_type = proof.get("type")
        if proof_type != PROOF_TYPE:
            logging.error(f"Unsupported proof type: {proof_type}")
            return False

        # 时间戳检查
        created = proof.get("created")
        if created and max_time_drift > 0:
            try:
                created_time = datetime.fromisoformat(
                    created.replace("Z", "+00:00")
                )
                now = datetime.now(timezone.utc)
                drift = abs((now - created_time).total_seconds())
                if drift > max_time_drift:
                    logging.error(f"Proof timestamp drift too large: {drift}s")
                    return False
            except (ValueError, TypeError):
                logging.error(f"Invalid proof timestamp: {created}")
                return False

        # 移除 proof_value → JCS 规范化 → 验证
        stripped = _strip_proof_value(content)
        canonical = jcs.canonicalize(stripped)
        signature = _b64url_decode(proof_value)

        return _verify_secp256r1(public_key, canonical, signature)

    except Exception as e:
        logging.error(f"Proof verification failed: {e}")
        return False
