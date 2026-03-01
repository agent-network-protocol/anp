# -*- coding: utf-8 -*-
"""E2EE HPKE 进阶示例：异常场景处理。

演示各种异常场景下 E2EE HPKE 模块的行为：
1. 在 IDLE 状态尝试加密消息
2. 用错误的签名公钥验证 e2ee_init
3. 重放已处理的消息（序号验证）
4. 会话过期检测 + 构建错误通知消息
5. 消息类型检测

运行方式：
    uv run python examples/python/e2e_encryption_hpke_examples/error_handling_example.py
"""

import time

from cryptography.hazmat.primitives.asymmetric import ec

from anp.e2e_encryption_hpke import (
    E2eeHpkeSession,
    ErrorCode,
    MessageType,
    SessionState,
    build_e2ee_error,
    detect_message_type,
    generate_x25519_key_pair,
)


def generate_keys():
    """生成 X25519 密钥协商对和 secp256r1 签名密钥对。"""
    x25519_sk, x25519_pk = generate_x25519_key_pair()
    signing_sk = ec.generate_private_key(ec.SECP256R1())
    signing_pk = signing_sk.public_key()
    return x25519_sk, x25519_pk, signing_sk, signing_pk


def create_active_session_pair(
    alice_did: str,
    bob_did: str,
    default_expires: int = 86400,
):
    """创建一对已激活的 E2eeHpkeSession。

    Returns:
        (alice_session, bob_session, alice_sign_pk, bob_sign_pk,
         alice_x25519_pk, bob_x25519_pk)
    """
    alice_x25519_sk, alice_x25519_pk, alice_sign_sk, alice_sign_pk = generate_keys()
    bob_x25519_sk, bob_x25519_pk, bob_sign_sk, bob_sign_pk = generate_keys()

    alice_session = E2eeHpkeSession(
        local_did=alice_did,
        peer_did=bob_did,
        local_x25519_private_key=alice_x25519_sk,
        local_x25519_key_id=f"{alice_did}#key-agreement-1",
        signing_private_key=alice_sign_sk,
        signing_verification_method=f"{alice_did}#key-1",
        default_expires=default_expires,
    )
    bob_session = E2eeHpkeSession(
        local_did=bob_did,
        peer_did=alice_did,
        local_x25519_private_key=bob_x25519_sk,
        local_x25519_key_id=f"{bob_did}#key-agreement-1",
        signing_private_key=bob_sign_sk,
        signing_verification_method=f"{bob_did}#key-1",
        default_expires=default_expires,
    )

    _, init_content = alice_session.initiate_session(
        peer_pk=bob_x25519_pk,
        peer_key_id=f"{bob_did}#key-agreement-1",
    )
    bob_session.process_init(init_content, alice_sign_pk)

    return (
        alice_session, bob_session,
        alice_sign_pk, bob_sign_pk,
        alice_x25519_pk, bob_x25519_pk,
    )


def example_encrypt_before_active() -> None:
    """场景 1：在 IDLE 状态尝试加密消息。"""
    print("\n" + "#" * 60)
    print("  场景 1：在 IDLE 状态加密消息")
    print("#" * 60)

    alice_x25519_sk, _, alice_sign_sk, _ = generate_keys()

    alice = E2eeHpkeSession(
        local_did="did:wba:example.com:user:alice",
        peer_did="did:wba:example.com:user:bob",
        local_x25519_private_key=alice_x25519_sk,
        local_x25519_key_id="did:wba:example.com:user:alice#key-agreement-1",
        signing_private_key=alice_sign_sk,
        signing_verification_method="did:wba:example.com:user:alice#key-1",
    )
    print(f"[Alice] 当前状态: {alice.state.value}")
    assert alice.state == SessionState.IDLE

    try:
        alice.encrypt_message("text", "这条消息不应该发出去")
    except RuntimeError as e:
        print(f"[预期错误] RuntimeError: {e}")
        print("[说明] 必须完成初始化（状态为 ACTIVE）才能加密消息")


def example_wrong_signing_key() -> None:
    """场景 2：用错误的签名公钥验证 e2ee_init。"""
    print("\n" + "#" * 60)
    print("  场景 2：用错误的签名公钥验证初始化消息")
    print("#" * 60)

    alice_x25519_sk, alice_x25519_pk, alice_sign_sk, alice_sign_pk = generate_keys()
    bob_x25519_sk, bob_x25519_pk, bob_sign_sk, bob_sign_pk = generate_keys()

    alice_did = "did:wba:example.com:user:alice"
    bob_did = "did:wba:example.com:user:bob"

    alice = E2eeHpkeSession(
        local_did=alice_did,
        peer_did=bob_did,
        local_x25519_private_key=alice_x25519_sk,
        local_x25519_key_id=f"{alice_did}#key-agreement-1",
        signing_private_key=alice_sign_sk,
        signing_verification_method=f"{alice_did}#key-1",
    )
    bob = E2eeHpkeSession(
        local_did=bob_did,
        peer_did=alice_did,
        local_x25519_private_key=bob_x25519_sk,
        local_x25519_key_id=f"{bob_did}#key-agreement-1",
        signing_private_key=bob_sign_sk,
        signing_verification_method=f"{bob_did}#key-1",
    )

    _, init_content = alice.initiate_session(
        peer_pk=bob_x25519_pk,
        peer_key_id=f"{bob_did}#key-agreement-1",
    )

    # 使用错误的签名公钥（Charlie 的密钥）
    _, _, _, charlie_sign_pk = generate_keys()

    try:
        bob.process_init(init_content, charlie_sign_pk)
    except ValueError as e:
        print(f"[预期错误] ValueError: {e}")
        print("[说明] 用错误的签名公钥验证 proof 失败，拒绝建立会话")


def example_replay_message() -> None:
    """场景 3：重放已处理的消息。"""
    print("\n" + "#" * 60)
    print("  场景 3：重放已处理的消息")
    print("#" * 60)

    alice_did = "did:wba:example.com:user:alice"
    bob_did = "did:wba:example.com:user:bob"

    alice, bob, _, _, _, _ = create_active_session_pair(alice_did, bob_did)

    # Alice 发送消息
    _, encrypted = alice.encrypt_message("text", "正常消息")
    print("[Alice] 已发送加密消息")

    # Bob 第一次解密成功
    orig_type, plaintext = bob.decrypt_message(encrypted)
    print(f"[Bob 第一次解密] 成功: {plaintext}")

    # Bob 重放同一条消息
    try:
        bob.decrypt_message(encrypted)
    except ValueError as e:
        print(f"[预期错误] ValueError: {e}")
        print("[说明] 严格模式下，已使用的序号会被拒绝，防止重放攻击")


def example_expired_session() -> None:
    """场景 4：会话过期检测 + 构建错误通知消息。"""
    print("\n" + "#" * 60)
    print("  场景 4：会话过期检测与错误通知")
    print("#" * 60)

    alice_did = "did:wba:example.com:user:alice"
    bob_did = "did:wba:example.com:user:bob"

    alice, _, _, _, _, _ = create_active_session_pair(
        alice_did, bob_did, default_expires=1
    )

    print(f"[信息] 会话有效期: 1 秒")
    print(f"[信息] is_expired={alice.is_expired()}")

    # 等待过期
    print("[等待] 等待 2 秒...")
    time.sleep(2)

    print(f"[过期后] is_expired={alice.is_expired()}")

    # 构建错误通知消息
    error_content = build_e2ee_error(
        error_code=ErrorCode.SESSION_EXPIRED.value,
        session_id=alice.session_id,
        message="Session has expired, please re-initialize",
    )
    print("\n[构建错误通知] 会话过期通知消息:")
    print(f"  error_code: {error_content['error_code']}")
    print(f"  session_id: {error_content['session_id']}")
    print(f"  message: {error_content['message']}")
    print("[说明] 应用层应发送此错误通知给对端，并重新发起初始化")


def example_detect_message_type() -> None:
    """场景 5：消息类型检测。"""
    print("\n" + "#" * 60)
    print("  场景 5：消息类型检测")
    print("#" * 60)

    test_cases = [
        ("e2ee_init", MessageType.E2EE_INIT),
        ("e2ee_msg", MessageType.E2EE_MSG),
        ("e2ee_rekey", MessageType.E2EE_REKEY),
        ("e2ee_error", MessageType.E2EE_ERROR),
        ("group_e2ee_key", MessageType.GROUP_E2EE_KEY),
        ("group_e2ee_msg", MessageType.GROUP_E2EE_MSG),
        ("group_epoch_advance", MessageType.GROUP_EPOCH_ADVANCE),
        ("unknown_type", None),
    ]

    for type_field, expected in test_cases:
        result = detect_message_type(type_field)
        status = "OK" if result == expected else "FAIL"
        print(f"  [{status}] type={type_field:25s} -> {result}")
        assert result == expected

    print("\n[说明] detect_message_type 帮助应用层根据消息类型分派处理逻辑")


def main() -> None:
    """运行所有错误处理示例。"""
    print("=" * 60)
    print("  E2EE HPKE 错误处理示例")
    print("=" * 60)

    example_encrypt_before_active()
    example_wrong_signing_key()
    example_replay_message()
    example_expired_session()
    example_detect_message_type()

    print("\n" + "=" * 60)
    print("  所有错误处理示例运行成功!")
    print("=" * 60)


if __name__ == "__main__":
    main()
