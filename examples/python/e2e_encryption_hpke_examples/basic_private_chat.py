# -*- coding: utf-8 -*-
"""E2EE HPKE 基础示例：一步初始化 + 双向加密私聊。

演示 Alice 和 Bob 通过 HPKE（RFC 9180）完成一步初始化，
然后进行双向加密消息传输。与传输层完全解耦——所有方法
只接收和返回 dict，不涉及任何网络 IO。

运行方式：
    uv run python examples/python/e2e_encryption_hpke_examples/basic_private_chat.py
"""

import json

from cryptography.hazmat.primitives.asymmetric import ec

from anp.e2e_encryption_hpke import (
    E2eeHpkeSession,
    SessionState,
    generate_x25519_key_pair,
)


def print_json(label: str, obj: dict) -> None:
    """格式化打印 JSON 对象。"""
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def generate_keys():
    """生成 X25519 密钥协商对和 secp256r1 签名密钥对。

    Returns:
        (x25519_private, x25519_public, signing_private, signing_public)
    """
    x25519_sk, x25519_pk = generate_x25519_key_pair()
    signing_sk = ec.generate_private_key(ec.SECP256R1())
    signing_pk = signing_sk.public_key()
    return x25519_sk, x25519_pk, signing_sk, signing_pk


def main() -> None:
    """运行基础私聊加密通信示例。"""
    print("=" * 60)
    print("  E2EE HPKE 基础示例：一步初始化 + 双向加密私聊")
    print("=" * 60)

    # ----------------------------------------------------------------
    # 第一步：准备双方的 DID 身份和密钥
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第一步：生成双方的密钥对")
    print("#" * 60)

    alice_did = "did:wba:example.com:user:alice"
    bob_did = "did:wba:example.com:user:bob"

    alice_x25519_sk, alice_x25519_pk, alice_sign_sk, alice_sign_pk = generate_keys()
    bob_x25519_sk, bob_x25519_pk, bob_sign_sk, bob_sign_pk = generate_keys()

    alice_key_id = f"{alice_did}#key-agreement-1"
    bob_key_id = f"{bob_did}#key-agreement-1"
    alice_sign_vm = f"{alice_did}#key-1"
    bob_sign_vm = f"{bob_did}#key-1"

    print(f"[Alice] DID: {alice_did}")
    print(f"[Bob]   DID: {bob_did}")
    print("[准备] 双方已生成 X25519 密钥对（协商）+ secp256r1 密钥对（签名）")

    # ----------------------------------------------------------------
    # 第二步：Alice 发起会话初始化（生成 e2ee_init 消息）
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第二步：Alice 发起会话初始化")
    print("#" * 60)

    alice_session = E2eeHpkeSession(
        local_did=alice_did,
        peer_did=bob_did,
        local_x25519_private_key=alice_x25519_sk,
        local_x25519_key_id=alice_key_id,
        signing_private_key=alice_sign_sk,
        signing_verification_method=alice_sign_vm,
    )
    print(f"[Alice] 初始状态: {alice_session.state.value}")
    assert alice_session.state == SessionState.IDLE

    msg_type, init_content = alice_session.initiate_session(
        peer_pk=bob_x25519_pk,
        peer_key_id=bob_key_id,
    )
    print(f"[Alice] 发出消息类型: {msg_type}")
    print(f"[Alice] 会话状态: {alice_session.state.value}")
    assert alice_session.state == SessionState.ACTIVE
    print_json("e2ee_init 消息（传输给 Bob）", init_content)

    # ----------------------------------------------------------------
    # 第三步：Bob 处理 e2ee_init 消息
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第三步：Bob 处理初始化消息")
    print("#" * 60)

    bob_session = E2eeHpkeSession(
        local_did=bob_did,
        peer_did=alice_did,
        local_x25519_private_key=bob_x25519_sk,
        local_x25519_key_id=bob_key_id,
        signing_private_key=bob_sign_sk,
        signing_verification_method=bob_sign_vm,
    )

    bob_session.process_init(init_content, alice_sign_pk)
    print(f"[Bob] 处理完毕，会话状态: {bob_session.state.value}")
    assert bob_session.state == SessionState.ACTIVE
    print("[说明] HPKE 一步初始化：无需多轮握手，Bob 处理 e2ee_init 后立即进入 ACTIVE")

    # 验证双方 session_id 一致
    print(f"\n[验证] Alice session_id = {alice_session.session_id}")
    print(f"[验证] Bob   session_id = {bob_session.session_id}")
    assert alice_session.session_id == bob_session.session_id
    print("[验证] 双方 session_id 一致!")

    # ----------------------------------------------------------------
    # 第四步：双向加密通信
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第四步：双向加密通信")
    print("#" * 60)

    # Alice -> Bob
    msg_type, encrypted = alice_session.encrypt_message(
        "text", "你好 Bob！这是通过 HPKE 加密的消息。"
    )
    print(f"\n[Alice -> Bob] 加密消息类型: {msg_type}")
    print_json("加密后的 dict（传输给 Bob）", encrypted)

    orig_type, plaintext = bob_session.decrypt_message(encrypted)
    print(f"[Bob 收到] 原始类型: {orig_type}")
    print(f"[Bob 收到] 明文内容: {plaintext}")

    # Bob -> Alice
    msg_type2, encrypted2 = bob_session.encrypt_message(
        "text", "你好 Alice！收到了！"
    )
    orig_type2, plaintext2 = alice_session.decrypt_message(encrypted2)
    print(f"\n[Bob -> Alice] 原始类型: {orig_type2}")
    print(f"[Bob -> Alice] 明文内容: {plaintext2}")

    # ----------------------------------------------------------------
    # 第五步：多类型消息测试
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第五步：多类型消息测试")
    print("#" * 60)

    messages = [
        ("text", "纯文本消息"),
        ("image", '{"url": "https://example.com/photo.jpg", "width": 800}'),
        ("file", '{"name": "report.pdf", "size": 2048}'),
    ]
    for orig_t, content in messages:
        _, enc = alice_session.encrypt_message(orig_t, content)
        dec_type, dec_text = bob_session.decrypt_message(enc)
        print(f"  {orig_t}: {dec_text[:40]}... -> 解密成功")
        assert dec_type == orig_t
        assert dec_text == content

    # ----------------------------------------------------------------
    # 第六步：会话重建（Rekey）
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第六步：会话重建（Rekey）")
    print("#" * 60)

    old_session_id = alice_session.session_id
    rekey_type, rekey_content = alice_session.initiate_rekey(
        peer_pk=bob_x25519_pk,
        peer_key_id=bob_key_id,
    )
    print(f"[Alice] 发起 Rekey，消息类型: {rekey_type}")
    print(f"[Alice] 新 session_id: {alice_session.session_id}")
    assert alice_session.session_id != old_session_id

    bob_session.process_rekey(rekey_content, alice_sign_pk)
    print(f"[Bob] 处理 Rekey 完毕，会话状态: {bob_session.state.value}")
    assert alice_session.session_id == bob_session.session_id
    print("[验证] Rekey 后双方 session_id 一致!")

    # Rekey 后继续通信
    _, enc_after_rekey = alice_session.encrypt_message("text", "Rekey 后的消息")
    dec_t, dec_p = bob_session.decrypt_message(enc_after_rekey)
    print(f"[Rekey 后通信] {dec_t}: {dec_p}")
    assert dec_p == "Rekey 后的消息"

    # ----------------------------------------------------------------
    # 第七步：查看会话信息
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第七步：查看会话信息")
    print("#" * 60)
    print_json("Alice 会话信息", alice_session.get_session_info())
    print_json("Bob 会话信息", bob_session.get_session_info())

    print("\n" + "=" * 60)
    print("  基础私聊示例运行完毕!")
    print("=" * 60)


if __name__ == "__main__":
    main()
