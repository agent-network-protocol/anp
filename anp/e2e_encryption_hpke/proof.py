"""EcdsaSecp256r1Signature2019 proof 签名与校验。

与 anp/proof/proof.py 的 W3C proof 签名流程不同：
W3C 用 hash(options) || hash(document) 拼接后签名，
本协议直接对排除 proof_value 后的完整 JSON 做 JCS 规范化再签名。
"""

import base64
import copy
import logging
from datetime import datetime, timezone
from typing import Any, Dict

import jcs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from anp.e2e_encryption_hpke.models import PROOF_TYPE


DEFAULT_MAX_FUTURE_SKEW_SECONDS = 300
DEFAULT_MAX_PAST_AGE_SECONDS = 86400


class ProofValidationError(ValueError):
    """Raised when proof verification fails with a stable machine-readable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


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
    created: str | None = None,
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
    created_value = created or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    result["proof"] = {
        "type": PROOF_TYPE,
        "created": created_value,
        "verification_method": verification_method,
    }

    # JCS 规范化 → UTF-8 → 签名
    canonical = jcs.canonicalize(result)
    signature = _sign_secp256r1(private_key, canonical)
    result["proof"]["proof_value"] = _b64url_encode(signature)

    return result


def validate_proof(
    content: Dict[str, Any],
    public_key: ec.EllipticCurvePublicKey,
    *,
    max_past_age_seconds: int | None = DEFAULT_MAX_PAST_AGE_SECONDS,
    max_future_skew_seconds: int = DEFAULT_MAX_FUTURE_SKEW_SECONDS,
) -> None:
    """Validate content proof and raise a structured error on failure.

    Args:
        content: 含 proof 字段的 content dict。
        public_key: secp256r1 签名公钥。
        max_past_age_seconds: 允许的最大过去年龄（秒）。
            设为 ``None`` 或小于 0 表示跳过“过旧”检查。
        max_future_skew_seconds: 允许的最大未来时间偏移（秒）。

    Raises:
        ProofValidationError: proof 结构错误、时间戳非法或签名校验失败。
    """
    proof = content.get("proof")
    if not proof:
        raise ProofValidationError("proof_missing", "Content has no proof field")

    proof_value = proof.get("proof_value")
    if not proof_value:
        raise ProofValidationError("proof_value_missing", "Proof has no proof_value")

    proof_type = proof.get("type")
    if proof_type != PROOF_TYPE:
        raise ProofValidationError(
            "proof_type_invalid",
            f"Unsupported proof type: {proof_type}",
        )

    created = proof.get("created")
    if created:
        try:
            created_time = datetime.fromisoformat(created.replace("Z", "+00:00"))
        except (ValueError, TypeError) as exc:
            raise ProofValidationError(
                "proof_invalid_timestamp",
                f"Invalid proof timestamp: {created}",
            ) from exc

        now = datetime.now(timezone.utc)
        future_skew = (created_time - now).total_seconds()
        if max_future_skew_seconds >= 0 and future_skew > max_future_skew_seconds:
            raise ProofValidationError(
                "proof_from_future",
                f"Proof timestamp is too far in the future: {future_skew}s",
            )

        if max_past_age_seconds is not None and max_past_age_seconds >= 0:
            age_seconds = (now - created_time).total_seconds()
            if age_seconds > max_past_age_seconds:
                raise ProofValidationError(
                    "proof_expired",
                    f"Proof timestamp age too large: {age_seconds}s",
                )

    stripped = _strip_proof_value(content)
    canonical = jcs.canonicalize(stripped)
    try:
        signature = _b64url_decode(proof_value)
    except Exception as exc:
        raise ProofValidationError(
            "proof_value_invalid",
            "Proof value is not valid Base64URL data",
        ) from exc

    if not _verify_secp256r1(public_key, canonical, signature):
        raise ProofValidationError("proof_signature_invalid", "Proof signature verification failed")


def verify_proof(
    content: Dict[str, Any],
    public_key: ec.EllipticCurvePublicKey,
    max_time_drift: int | None = None,
    *,
    max_past_age_seconds: int | None = DEFAULT_MAX_PAST_AGE_SECONDS,
    max_future_skew_seconds: int = DEFAULT_MAX_FUTURE_SKEW_SECONDS,
) -> bool:
    """验证 content 的 proof 签名并兼容旧版 max_time_drift 参数。"""
    if max_time_drift is not None:
        if max_time_drift == 0:
            max_past_age_seconds = None
        else:
            max_past_age_seconds = max_time_drift
            max_future_skew_seconds = max_time_drift

    try:
        validate_proof(
            content,
            public_key,
            max_past_age_seconds=max_past_age_seconds,
            max_future_skew_seconds=max_future_skew_seconds,
        )
        return True
    except ProofValidationError as exc:
        logging.error("Proof verification failed (%s): %s", exc.code, exc)
        return False
