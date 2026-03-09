# -*- coding: utf-8 -*-
"""E2EE V2 进阶示例：E2eeKeyManager 会话生命周期管理。

演示如何使用 E2eeKeyManager 管理多个 E2EE 会话的生命周期，包括：
1. 将握手中的会话注册为 pending
2. 握手完成后提升为 active
3. 按 DID 对查找活跃会话
4. 按 secret_key_id 查找会话（用于解密收到的消息）
5. 清理过期会话

运行方式：
    uv run python examples/python/e2e_encryption_v2_examples/key_manager_example.py
"""

import time

from cryptography.hazmat.primitives.asymmetric import ec

from anp.e2e_encryption_v2 import E2eeKeyManager, E2eeSession, SessionState
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


def example_basic_key_manager() -> None:
    """场景 1：KeyManager 基本流程 -- pending -> active -> 查找。"""
    print("\n" + "#" * 60)
    print("  场景 1：KeyManager 基本流程")
    print("#" * 60)

    alice_did = "did:wba:example.com:user:alice"
    bob_did = "did:wba:example.com:user:bob"
    alice_pem = generate_did_key_pem()
    bob_pem = generate_did_key_pem()

    manager = E2eeKeyManager()

    # 1. Alice 发起握手，注册为 pending
    alice = E2eeSession(alice_did, alice_pem, bob_did)
    _, source_hello = alice.initiate_handshake()
    manager.register_pending_session(alice)
    print(f"[步骤 1] 注册 pending 会话: session_id={alice.session_id}")

    # 2. 通过 session_id 查找 pending 会话
    found = manager.get_pending_session(alice.session_id)
    assert found is not None
    print(f"[步骤 2] 找到 pending 会话: {found.session_id}")

    # 3. Bob 处理 SourceHello
    bob = E2eeSession(bob_did, bob_pem, alice_did)
    (_, dest_hello), (_, bob_finished) = bob.process_source_hello(source_hello)

    # 4. Alice 处理 DestinationHello + Finished，握手完成
    _, alice_finished = alice.process_destination_hello(dest_hello)
    alice.process_finished(bob_finished)
    bob.process_finished(alice_finished)

    # 5. 将 pending 会话提升为 active
    manager.promote_pending_session(alice.session_id)
    print(f"[步骤 5] 已将会话提升为 active: key_id={alice.secret_key_id}")

    # 6. 按 DID 对查找活跃会话
    active = manager.get_active_session(alice_did, bob_did)
    assert active is not None
    print(f"[步骤 6] 按 DID 对查找: 找到 active 会话 key_id={active.secret_key_id}")

    # 7. 按 secret_key_id 查找（模拟收到加密消息后的查找过程）
    by_key = manager.get_session_by_key_id(alice.secret_key_id)
    assert by_key is not None
    print("[步骤 7] 按 secret_key_id 查找: 找到会话")

    # 8. 也注册 Bob 的会话（直接注册为 active，跳过 pending）
    manager.register_session(bob)
    active_bob = manager.get_active_session(bob_did, alice_did)
    assert active_bob is not None
    print("[步骤 8] Bob 的会话也已注册，可按 DID 对查找")


def example_multi_session_rotation() -> None:
    """场景 2：多会话密钥轮转 -- 超过 MAX_CONCURRENT_KEYS 时淘汰旧密钥。"""
    print("\n" + "#" * 60)
    print("  场景 2：多会话密钥轮转")
    print("#" * 60)

    alice_did = "did:wba:example.com:user:alice"
    bob_did = "did:wba:example.com:user:bob"

    manager = E2eeKeyManager()
    print(f"[信息] MAX_CONCURRENT_KEYS = {E2eeKeyManager.MAX_CONCURRENT_KEYS}")

    key_ids = []
    for i in range(3):
        alice_pem = generate_did_key_pem()
        bob_pem = generate_did_key_pem()
        alice = E2eeSession(alice_did, alice_pem, bob_did)
        bob = E2eeSession(bob_did, bob_pem, alice_did)
        complete_handshake(alice, bob)
        manager.register_session(alice)
        key_ids.append(alice.secret_key_id)
        print(f"[第 {i + 1} 次握手] 注册会话 key_id={alice.secret_key_id}")

    # 验证：第一个会话应该已被淘汰（MAX_CONCURRENT_KEYS=2）
    first_gone = manager.get_session_by_key_id(key_ids[0])
    assert first_gone is None
    print(f"\n[验证] 第 1 个会话 key_id={key_ids[0]} 已被淘汰")

    second_ok = manager.get_session_by_key_id(key_ids[1])
    assert second_ok is not None
    print(f"[验证] 第 2 个会话 key_id={key_ids[1]} 仍然可用")

    third_ok = manager.get_session_by_key_id(key_ids[2])
    assert third_ok is not None
    print(f"[验证] 第 3 个会话 key_id={key_ids[2]} 仍然可用")


def example_cleanup_expired() -> None:
    """场景 3：清理过期会话。"""
    print("\n" + "#" * 60)
    print("  场景 3：清理过期会话")
    print("#" * 60)

    alice_did = "did:wba:example.com:user:alice"
    bob_did = "did:wba:example.com:user:bob"
    alice_pem = generate_did_key_pem()
    bob_pem = generate_did_key_pem()

    manager = E2eeKeyManager()

    # 创建一个有效期极短的会话（1 秒）
    alice = E2eeSession(alice_did, alice_pem, bob_did, default_expires=1)
    bob = E2eeSession(bob_did, bob_pem, alice_did, default_expires=1)
    complete_handshake(alice, bob)
    manager.register_session(alice)
    print(f"[步骤 1] 创建有效期 1 秒的会话: key_id={alice.secret_key_id}")

    # 验证此时会话可用
    active = manager.get_active_session(alice_did, bob_did)
    assert active is not None
    print(f"[步骤 2] 会话当前可用: is_expired={alice.is_expired()}")

    # 等待会话过期
    print("[步骤 3] 等待 2 秒让会话过期...")
    time.sleep(2)
    print(f"[步骤 4] 会话已过期: is_expired={alice.is_expired()}")

    # 清理过期会话
    need_rehandshake = manager.cleanup_expired()
    print(f"[步骤 5] 清理完毕，需要重新握手的 DID 对: {need_rehandshake}")

    # 验证会话已被清理
    active = manager.get_active_session(alice_did, bob_did)
    assert active is None
    print("[步骤 6] 确认: 按 DID 对查找返回 None")


def example_dispatch_incoming_message() -> None:
    """场景 4：模拟接收消息时的 KeyManager 调度流程。"""
    print("\n" + "#" * 60)
    print("  场景 4：收到加密消息时的调度流程")
    print("#" * 60)

    alice_did = "did:wba:example.com:user:alice"
    bob_did = "did:wba:example.com:user:bob"
    alice_pem = generate_did_key_pem()
    bob_pem = generate_did_key_pem()

    alice_manager = E2eeKeyManager()
    bob_manager = E2eeKeyManager()

    # 双方完成握手并各自注册会话
    alice = E2eeSession(alice_did, alice_pem, bob_did)
    bob = E2eeSession(bob_did, bob_pem, alice_did)
    complete_handshake(alice, bob)
    alice_manager.register_session(alice)
    bob_manager.register_session(bob)
    print("[步骤 1] 双方握手完成并注册到各自的 KeyManager")

    # Alice 发送加密消息
    _, encrypted = alice.encrypt_message("text", "这条消息由 KeyManager 调度解密")
    secret_key_id = encrypted["secret_key_id"]
    print("[步骤 2] Alice 发送加密消息（已生成 secret_key_id）")

    # Bob 收到消息后，通过 secret_key_id 查找会话并解密
    session = bob_manager.get_session_by_key_id(secret_key_id)
    assert session is not None
    orig_type, plaintext = session.decrypt_message(encrypted)
    print("[步骤 3] Bob 通过 KeyManager 查找到会话并解密:")
    print(f"  原始类型: {orig_type}")
    print(f"  明文: {plaintext}")


def main() -> None:
    """运行所有 KeyManager 示例场景。"""
    print("=" * 60)
    print("  E2EE V2 进阶示例：E2eeKeyManager 会话生命周期管理")
    print("=" * 60)

    example_basic_key_manager()
    example_multi_session_rotation()
    example_cleanup_expired()
    example_dispatch_incoming_message()

    print("\n" + "=" * 60)
    print("  所有 KeyManager 示例运行成功!")
    print("=" * 60)


if __name__ == "__main__":
    main()
