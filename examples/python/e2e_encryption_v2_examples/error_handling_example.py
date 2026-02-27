# -*- coding: utf-8 -*-
"""E2EE V2 错误处理示例。

演示各种异常场景下 E2eeSession 和 E2eeKeyManager 的行为：
1. 在非 ACTIVE 状态尝试加密/解密
2. 用错误的密钥解密（发送方尝试解密自己发出的消息）
3. 重复发起握手（状态机违规）
4. 会话过期后尝试使用
5. 构建 E2EE 错误通知消息

运行方式：
    uv run python examples/python/e2e_encryption_v2_examples/error_handling_example.py
"""

import time

from cryptography.hazmat.primitives.asymmetric import ec

from anp.e2e_encryption_v2 import (
    E2eeSession,
    ErrorCode,
    build_error,
    detect_message_type,
)
from anp.utils.crypto_tool import generate_ec_key_pair, get_pem_from_private_key


def generate_did_key_pem() -> str:
    """生成 secp256r1 密钥对，返回 PEM 私钥。"""
    priv, _, _ = generate_ec_key_pair(ec.SECP256R1())
    return get_pem_from_private_key(priv)


def complete_handshake(alice: E2eeSession, bob: E2eeSession) -> None:
    """执行完整的 Alice <-> Bob 握手流程。"""
    _, source_hello = alice.initiate_handshake()
    (_, dest_hello), (_, bob_finished) = bob.process_source_hello(source_hello)
    _, alice_finished = alice.process_destination_hello(dest_hello)
    alice.process_finished(bob_finished)
    bob.process_finished(alice_finished)


def example_encrypt_before_active() -> None:
    """场景 1：在握手完成前尝试加密消息。"""
    print("\n" + "#" * 60)
    print("  场景 1：在非 ACTIVE 状态加密消息")
    print("#" * 60)

    alice = E2eeSession(
        "did:wba:example.com:user:alice",
        generate_did_key_pem(),
        "did:wba:example.com:user:bob",
    )
    print(f"[Alice] 当前状态: {alice.state.value}")

    try:
        alice.encrypt_message("text", "这条消息不应该发出去")
    except RuntimeError as e:
        print(f"[预期错误] RuntimeError: {e}")
        print("[说明] 必须完成握手（状态为 ACTIVE）才能加密消息")


def example_wrong_key_decrypt() -> None:
    """场景 2：用错误的密钥解密（发送方解密自己发出的消息）。"""
    print("\n" + "#" * 60)
    print("  场景 2：用错误的密钥解密")
    print("#" * 60)

    alice_did = "did:wba:example.com:user:alice"
    bob_did = "did:wba:example.com:user:bob"

    alice = E2eeSession(alice_did, generate_did_key_pem(), bob_did)
    bob = E2eeSession(bob_did, generate_did_key_pem(), alice_did)
    complete_handshake(alice, bob)

    # Alice 加密一条消息
    _, encrypted = alice.encrypt_message("text", "这是机密消息")
    print("[Alice] 已加密消息，尝试自己解密...")

    # Alice 自己解密会失败（send_key != recv_key）
    try:
        alice.decrypt_message(encrypted)
    except Exception as e:
        print(f"[预期错误] {type(e).__name__}: {e}")
        print("[说明] Alice 用 send_key 加密，自己的 recv_key 无法解密")
        print("[说明] 只有 Bob 使用对应的 recv_key 才能正确解密")

    # Bob 正确解密
    orig_type, plaintext = bob.decrypt_message(encrypted)
    print(f"[Bob] 正确解密: {plaintext}")


def example_duplicate_handshake() -> None:
    """场景 3：重复发起握手（状态机违规）。"""
    print("\n" + "#" * 60)
    print("  场景 3：重复发起握手")
    print("#" * 60)

    alice = E2eeSession(
        "did:wba:example.com:user:alice",
        generate_did_key_pem(),
        "did:wba:example.com:user:bob",
    )

    # 第一次发起握手
    alice.initiate_handshake()
    print(f"[Alice] 第一次握手已发起，状态: {alice.state.value}")

    # 尝试再次发起
    try:
        alice.initiate_handshake()
    except RuntimeError as e:
        print(f"[预期错误] RuntimeError: {e}")
        print("[说明] 已发起握手后不能重复发起，必须完成或重建会话")


def example_expired_session() -> None:
    """场景 4：会话过期检测与错误通知。"""
    print("\n" + "#" * 60)
    print("  场景 4：会话过期检测与错误通知")
    print("#" * 60)

    alice_did = "did:wba:example.com:user:alice"
    bob_did = "did:wba:example.com:user:bob"

    # 创建有效期极短的会话
    alice = E2eeSession(
        alice_did, generate_did_key_pem(), bob_did, default_expires=1
    )
    bob = E2eeSession(
        bob_did, generate_did_key_pem(), alice_did, default_expires=1
    )
    complete_handshake(alice, bob)

    print(f"[信息] 会话有效期: 1 秒")
    print(
        f"[信息] is_expired={alice.is_expired()}, "
        f"should_renew={alice.should_renew()}"
    )

    # 等待过期
    print("[等待] 等待 2 秒...")
    time.sleep(2)

    print(f"[过期后] is_expired={alice.is_expired()}")
    print(f"[过期后] should_renew={alice.should_renew()}")

    # 构建错误通知消息，发送给对端要求重新握手
    error_content = build_error(
        error_code=ErrorCode.KEY_EXPIRED.value,
        secret_key_id=alice.secret_key_id,
    )
    print("\n[构建错误通知] 密钥过期通知消息:")
    print(f"  error_code: {error_content['error_code']}")
    print(f"  secret_key_id: {error_content['secret_key_id']}")
    print("[说明] 应用层应发送此错误通知给对端，并重新发起握手")


def example_detect_message_type() -> None:
    """场景 5：消息类型检测。"""
    print("\n" + "#" * 60)
    print("  场景 5：消息类型检测")
    print("#" * 60)

    test_cases = [
        ("e2ee_hello", {"e2ee_type": "source_hello"}, "source_hello"),
        ("e2ee_hello", {"e2ee_type": "destination_hello"}, "destination_hello"),
        ("e2ee_finished", {"e2ee_type": "finished"}, "finished"),
        ("e2ee", {"secret_key_id": "xxx", "encrypted": {}}, "encrypted"),
        ("e2ee_error", {"error_code": "key_expired"}, "error"),
        ("unknown", {}, None),
    ]

    for type_field, content, expected in test_cases:
        result = detect_message_type(type_field, content)
        status = "OK" if result == expected else "FAIL"
        print(f"  [{status}] type={type_field:20s} -> {result}")
        assert result == expected

    print("\n[说明] detect_message_type 帮助应用层根据消息类型分派处理逻辑")


def main() -> None:
    """运行所有错误处理示例。"""
    print("=" * 60)
    print("  E2EE V2 错误处理示例")
    print("=" * 60)

    example_encrypt_before_active()
    example_wrong_key_decrypt()
    example_duplicate_handshake()
    example_expired_session()
    example_detect_message_type()

    print("\n" + "=" * 60)
    print("  所有错误处理示例运行成功!")
    print("=" * 60)


if __name__ == "__main__":
    main()
