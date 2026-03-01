# -*- coding: utf-8 -*-
"""E2EE HPKE 进阶示例：HpkeKeyManager 会话生命周期管理。

演示如何使用 HpkeKeyManager 管理多个私聊和群聊 E2EE 会话，包括：
1. 基本私聊会话管理（注册 / 按 DID 对查找 / 按 session_id 查找）
2. 群聊会话管理（注册 / 按 group_did 查找）
3. 会话过期清理
4. 收到加密消息时通过 session_id 调度解密

运行方式：
    uv run python examples/python/e2e_encryption_hpke_examples/key_manager_example.py
"""

import time

from cryptography.hazmat.primitives.asymmetric import ec

from anp.e2e_encryption_hpke import (
    E2eeHpkeSession,
    GroupE2eeSession,
    HpkeKeyManager,
    SessionState,
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
    """创建一对已激活的 E2eeHpkeSession（完成初始化握手）。

    Returns:
        (alice_session, bob_session, alice_sign_pk, bob_sign_pk)
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

    return alice_session, bob_session, alice_sign_pk, bob_sign_pk


def example_basic_session_management() -> None:
    """场景 1：基本私聊会话管理。"""
    print("\n" + "#" * 60)
    print("  场景 1：基本私聊会话管理")
    print("#" * 60)

    alice_did = "did:wba:example.com:user:alice"
    bob_did = "did:wba:example.com:user:bob"

    manager = HpkeKeyManager()

    # 1. 创建并注册会话
    alice_session, _, _, _ = create_active_session_pair(alice_did, bob_did)
    assert alice_session.state == SessionState.ACTIVE
    manager.register_session(alice_session)
    print(f"[步骤 1] 注册会话: session_id={alice_session.session_id}")

    # 2. 按 DID 对查找
    found = manager.get_active_session(alice_did, bob_did)
    assert found is not None
    assert found.session_id == alice_session.session_id
    print(f"[步骤 2] 按 DID 对查找: 找到 session_id={found.session_id}")

    # 3. 按 session_id 查找
    found_by_id = manager.get_session_by_id(alice_session.session_id)
    assert found_by_id is not None
    print(f"[步骤 3] 按 session_id 查找: 找到 session_id={found_by_id.session_id}")

    # 4. 注册新会话替换旧会话
    new_alice, _, _, _ = create_active_session_pair(alice_did, bob_did)
    old_session_id = alice_session.session_id
    manager.register_session(new_alice)
    print(f"[步骤 4] 注册新会话: session_id={new_alice.session_id}")

    # 旧 session_id 应被清理
    old_found = manager.get_session_by_id(old_session_id)
    assert old_found is None
    print(f"[步骤 5] 旧会话 session_id={old_session_id} 已被替换")


def example_group_session_management() -> None:
    """场景 2：群聊会话管理。"""
    print("\n" + "#" * 60)
    print("  场景 2：群聊会话管理")
    print("#" * 60)

    group_did = "did:wba:example.com:group:team"
    alice_did = "did:wba:example.com:user:alice"

    alice_x25519_sk, _, alice_sign_sk, _ = generate_keys()

    manager = HpkeKeyManager()

    # 注册群聊会话
    group_session = GroupE2eeSession(
        group_did=group_did,
        local_did=alice_did,
        local_x25519_private_key=alice_x25519_sk,
        local_x25519_key_id=f"{alice_did}#key-agreement-1",
        signing_private_key=alice_sign_sk,
        signing_verification_method=f"{alice_did}#key-1",
    )
    manager.register_group_session(group_session)
    print(f"[步骤 1] 注册群聊会话: group_did={group_did}")

    # 按 group_did 查找
    found = manager.get_group_session(group_did)
    assert found is not None
    print(f"[步骤 2] 按 group_did 查找: 找到 epoch={found.epoch}")

    # 移除群聊会话
    manager.remove_group_session(group_did)
    gone = manager.get_group_session(group_did)
    assert gone is None
    print("[步骤 3] 群聊会话已移除")


def example_cleanup_expired() -> None:
    """场景 3：会话过期清理。"""
    print("\n" + "#" * 60)
    print("  场景 3：会话过期清理")
    print("#" * 60)

    alice_did = "did:wba:example.com:user:alice"
    bob_did = "did:wba:example.com:user:bob"

    manager = HpkeKeyManager()

    # 创建有效期 1 秒的会话
    alice_session, _, _, _ = create_active_session_pair(
        alice_did, bob_did, default_expires=1
    )
    manager.register_session(alice_session)
    print(f"[步骤 1] 创建有效期 1 秒的会话: session_id={alice_session.session_id}")

    # 验证当前可用
    active = manager.get_active_session(alice_did, bob_did)
    assert active is not None
    print(f"[步骤 2] 会话当前可用: is_expired={alice_session.is_expired()}")

    # 等待过期
    print("[步骤 3] 等待 2 秒让会话过期...")
    time.sleep(2)
    print(f"[步骤 4] is_expired={alice_session.is_expired()}")

    # get_active_session 自动过滤过期会话
    active = manager.get_active_session(alice_did, bob_did)
    assert active is None
    print("[步骤 5] get_active_session 返回 None（自动过滤过期会话）")

    # cleanup_expired 清理内部索引
    manager.cleanup_expired()
    by_id = manager.get_session_by_id(alice_session.session_id)
    assert by_id is None
    print("[步骤 6] cleanup_expired 完成，内部索引已清理")


def example_dispatch_by_session_id() -> None:
    """场景 4：收到加密消息时通过 session_id 调度解密。"""
    print("\n" + "#" * 60)
    print("  场景 4：通过 session_id 调度解密")
    print("#" * 60)

    alice_did = "did:wba:example.com:user:alice"
    bob_did = "did:wba:example.com:user:bob"

    alice_session, bob_session, _, _ = create_active_session_pair(alice_did, bob_did)

    alice_manager = HpkeKeyManager()
    bob_manager = HpkeKeyManager()
    alice_manager.register_session(alice_session)
    bob_manager.register_session(bob_session)
    print("[步骤 1] 双方握手完成并注册到各自的 KeyManager")

    # Alice 发送加密消息
    _, encrypted = alice_session.encrypt_message("text", "通过 KeyManager 调度解密的消息")
    session_id = encrypted["session_id"]
    print(f"[步骤 2] Alice 发送加密消息, session_id={session_id}")

    # Bob 通过 session_id 查找会话并解密
    session = bob_manager.get_session_by_id(session_id)
    assert session is not None
    orig_type, plaintext = session.decrypt_message(encrypted)
    print(f"[步骤 3] Bob 通过 KeyManager 调度解密:")
    print(f"  原始类型: {orig_type}")
    print(f"  明文: {plaintext}")
    assert plaintext == "通过 KeyManager 调度解密的消息"


def main() -> None:
    """运行所有 KeyManager 示例。"""
    print("=" * 60)
    print("  E2EE HPKE 进阶示例：HpkeKeyManager 会话生命周期管理")
    print("=" * 60)

    example_basic_session_management()
    example_group_session_management()
    example_cleanup_expired()
    example_dispatch_by_session_id()

    print("\n" + "=" * 60)
    print("  所有 KeyManager 示例运行成功!")
    print("=" * 60)


if __name__ == "__main__":
    main()
