# -*- coding: utf-8 -*-
"""W3C Data Integrity Proof 示例

演示如何使用 anp.proof 模块为 JSON 文档生成和验证 W3C 标准的
Data Integrity Proof。

包含三个场景：
1. secp256k1 签名 — Agent 身份声明
2. Ed25519 签名 — Verifiable Credential
3. 篡改检测 — 验证数据完整性

运行方式：
    uv run python examples/python/proof_examples/proof_example.py
"""

import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from anp.proof import (
    PROOF_TYPE_ED25519,
    PROOF_TYPE_SECP256K1,
    generate_w3c_proof,
    verify_w3c_proof,
)


def print_json(label: str, obj: dict) -> None:
    """格式化打印 JSON 对象"""
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def example_secp256k1_agent_identity():
    """示例 1: 使用 secp256k1 为 Agent 身份声明签名

    场景：Agent Alice 声明自己的身份和能力，
    使用 secp256k1 私钥生成 W3C Proof，
    任何持有 Alice 公钥的第三方都可以离线验证。
    """
    print("\n" + "#" * 60)
    print("  示例 1: secp256k1 Agent 身份声明")
    print("#" * 60)

    # 1. 生成密钥对
    private_key = ec.generate_private_key(ec.SECP256K1())
    public_key = private_key.public_key()
    print("\n[Step 1] 生成 secp256k1 密钥对")

    # 2. 构造 Agent 身份声明文档
    agent_claim = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/secp256k1-2019/v1",
        ],
        "id": "did:wba:example.com:agents:alice",
        "type": "AgentIdentityClaim",
        "name": "Agent Alice",
        "capabilities": ["search", "booking", "payment"],
        "description": "一个可以帮您搜索和预订酒店的智能代理",
    }
    print_json("Step 2: Agent 身份声明文档（签名前）", agent_claim)

    # 3. 生成 Proof
    signed_claim = generate_w3c_proof(
        document=agent_claim,
        private_key=private_key,
        verification_method="did:wba:example.com:agents:alice#key-1",
        proof_purpose="assertionMethod",
    )
    print_json("Step 3: 生成 Proof 后的文档", signed_claim)

    # 4. 验证 Proof
    is_valid = verify_w3c_proof(signed_claim, public_key)
    print(f"\n[Step 4] 验证 Proof 结果: {'PASS' if is_valid else 'FAIL'}")
    assert is_valid, "secp256k1 proof 验证应通过"

    return signed_claim, public_key


def example_ed25519_verifiable_credential():
    """示例 2: 使用 Ed25519 签发 Verifiable Credential

    场景：Issuer（身份签发者）为 Agent Bob 签发一个
    Verifiable Credential，证明 Bob 具有某项能力认证。
    """
    print("\n" + "#" * 60)
    print("  示例 2: Ed25519 Verifiable Credential")
    print("#" * 60)

    # 1. Issuer 生成 Ed25519 密钥对
    issuer_private_key = ed25519.Ed25519PrivateKey.generate()
    issuer_public_key = issuer_private_key.public_key()
    print("\n[Step 1] Issuer 生成 Ed25519 密钥对")

    # 2. 构造 Verifiable Credential
    credential = {
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
        ],
        "type": ["VerifiableCredential", "AgentCapabilityCredential"],
        "issuer": "did:wba:issuer.example.com",
        "issuanceDate": "2026-02-08T00:00:00Z",
        "credentialSubject": {
            "id": "did:wba:example.com:agents:bob",
            "capability": "hotel-booking",
            "level": "certified",
            "maxTransactionAmount": {"currency": "CNY", "value": "10000"},
        },
    }
    print_json("Step 2: Verifiable Credential（签名前）", credential)

    # 3. Issuer 签名
    signed_vc = generate_w3c_proof(
        document=credential,
        private_key=issuer_private_key,
        verification_method="did:wba:issuer.example.com#key-1",
        proof_purpose="assertionMethod",
        domain="example.com",
    )
    print_json("Step 3: 签名后的 Verifiable Credential", signed_vc)

    # 4. Verifier 验证
    is_valid = verify_w3c_proof(
        signed_vc,
        issuer_public_key,
        expected_purpose="assertionMethod",
        expected_domain="example.com",
    )
    print(f"\n[Step 4] 验证 VC 结果: {'PASS' if is_valid else 'FAIL'}")
    assert is_valid, "Ed25519 VC proof 验证应通过"

    return signed_vc, issuer_public_key


def example_tamper_detection(signed_doc: dict, public_key):
    """示例 3: 篡改检测

    验证当文档被修改后，Proof 验证会失败。
    """
    print("\n" + "#" * 60)
    print("  示例 3: 篡改检测")
    print("#" * 60)

    import copy

    # 1. 验证原始文档
    is_valid = verify_w3c_proof(signed_doc, public_key)
    print(f"\n[Step 1] 原始文档验证: {'PASS' if is_valid else 'FAIL'}")
    assert is_valid

    # 2. 篡改文档内容
    tampered = copy.deepcopy(signed_doc)
    if "name" in tampered:
        tampered["name"] = "Agent Evil"
    elif "credentialSubject" in tampered:
        tampered["credentialSubject"]["level"] = "admin"

    is_valid = verify_w3c_proof(tampered, public_key)
    print(f"[Step 2] 篡改后文档验证: {'PASS' if is_valid else 'FAIL'}")
    assert not is_valid, "篡改后的文档验证应失败"

    # 3. 使用错误的密钥验证
    wrong_key = ec.generate_private_key(ec.SECP256K1()).public_key()
    # 只有当原始文档使用 secp256k1 时才测试
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        is_valid = verify_w3c_proof(signed_doc, wrong_key)
        print(f"[Step 3] 使用错误公钥验证: {'PASS' if is_valid else 'FAIL'}")
        assert not is_valid, "使用错误公钥验证应失败"

    print("\n所有篡改检测测试通过!")


def main():
    """运行所有示例"""
    print("=" * 60)
    print("  W3C Data Integrity Proof 示例")
    print("  基于 ANP (Agent Network Protocol) 实现")
    print("=" * 60)

    # 示例 1: secp256k1 Agent 身份声明
    signed_claim, claim_pk = example_secp256k1_agent_identity()

    # 示例 2: Ed25519 Verifiable Credential
    signed_vc, vc_pk = example_ed25519_verifiable_credential()

    # 示例 3: 篡改检测（使用示例 1 的结果）
    example_tamper_detection(signed_claim, claim_pk)

    print("\n" + "=" * 60)
    print("  所有示例运行成功!")
    print("=" * 60)


if __name__ == "__main__":
    main()
