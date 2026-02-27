# -*- coding: utf-8 -*-
"""E2EE V2 基础示例：完整握手 + 双向加密通信。

演示 Alice 和 Bob 通过 E2eeSession 完成 ECDHE 密钥协商，
然后进行双向加密消息传输。整个过程与传输层无关——所有方法
只接收和返回 dict，不涉及任何网络 IO。

运行方式：
    uv run python examples/python/e2e_encryption_v2_examples/basic_handshake.py
"""

import json

from cryptography.hazmat.primitives.asymmetric import ec

from anp.e2e_encryption_v2 import E2eeSession, SessionState
from anp.utils.crypto_tool import generate_ec_key_pair, get_pem_from_private_key


def print_json(label: str, obj: dict) -> None:
    """格式化打印 JSON 对象。"""
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def generate_did_key_pem() -> str:
    """生成一个 secp256r1 密钥对，返回 PEM 格式私钥字符串。"""
    private_key, _, _ = generate_ec_key_pair(ec.SECP256R1())
    return get_pem_from_private_key(private_key)


def main() -> None:
    """运行基础握手 + 双向加密通信示例。"""
    print("=" * 60)
    print("  E2EE V2 基础示例：完整握手 + 双向加密通信")
    print("=" * 60)

    # ----------------------------------------------------------------
    # 第一步：准备双方的 DID 身份和密钥
    # ----------------------------------------------------------------
    alice_did = "did:wba:example.com:user:alice"
    bob_did = "did:wba:example.com:user:bob"
    alice_pem = generate_did_key_pem()
    bob_pem = generate_did_key_pem()
    print("\n[准备] 为 Alice 和 Bob 生成 secp256r1 DID 密钥对")

    # ----------------------------------------------------------------
    # 第二步：Alice 创建会话并发起握手（生成 SourceHello）
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第二步：Alice 发起握手")
    print("#" * 60)

    alice_session = E2eeSession(
        local_did=alice_did,
        did_private_key_pem=alice_pem,
        peer_did=bob_did,
    )
    print(f"[Alice] 会话状态: {alice_session.state.value}")  # idle
    assert alice_session.state == SessionState.IDLE

    msg_type, source_hello = alice_session.initiate_handshake()
    print(f"[Alice] 发出消息类型: {msg_type}")
    print(f"[Alice] 会话状态: {alice_session.state.value}")  # handshake_initiated
    print_json("SourceHello 消息（传输给 Bob 的 dict）", source_hello)

    # ----------------------------------------------------------------
    # 第三步：Bob 收到 SourceHello，处理后返回 DestinationHello + Finished
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第三步：Bob 处理 SourceHello")
    print("#" * 60)

    bob_session = E2eeSession(
        local_did=bob_did,
        did_private_key_pem=bob_pem,
        peer_did=alice_did,
    )

    (dh_type, dest_hello), (bf_type, bob_finished) = (
        bob_session.process_source_hello(source_hello)
    )
    print("[Bob] 处理完毕，返回两条消息:")
    print(f"  - DestinationHello (type={dh_type})")
    print(f"  - Finished (type={bf_type})")
    print(f"[Bob] 会话状态: {bob_session.state.value}")  # handshake_completing

    # ----------------------------------------------------------------
    # 第四步：Alice 处理 DestinationHello，返回自己的 Finished
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第四步：Alice 处理 DestinationHello")
    print("#" * 60)

    af_type, alice_finished = alice_session.process_destination_hello(dest_hello)
    print(f"[Alice] 返回 Finished (type={af_type})")
    print(f"[Alice] 会话状态: {alice_session.state.value}")  # handshake_completing

    # ----------------------------------------------------------------
    # 第五步：双方处理对方的 Finished，握手完成
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第五步：双方处理 Finished，握手完成")
    print("#" * 60)

    alice_session.process_finished(bob_finished)
    print(f"[Alice] 会话状态: {alice_session.state.value}")  # active

    bob_session.process_finished(alice_finished)
    print(f"[Bob] 会话状态: {bob_session.state.value}")  # active

    # 验证双方协商出相同的密钥标识
    assert alice_session.state == SessionState.ACTIVE
    assert bob_session.state == SessionState.ACTIVE
    print(f"\n[验证] Alice secret_key_id = {alice_session.secret_key_id}")
    print(f"[验证] Bob   secret_key_id = {bob_session.secret_key_id}")
    assert alice_session.secret_key_id == bob_session.secret_key_id
    print("[验证] 双方 secret_key_id 一致!")

    # ----------------------------------------------------------------
    # 第六步：双向加密通信
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第六步：双向加密通信")
    print("#" * 60)

    # Alice -> Bob
    msg_type, encrypted = alice_session.encrypt_message(
        "text", "你好 Bob！这是加密消息。"
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

    # 多种消息类型
    print("\n[多类型消息测试]")
    messages = [
        ("text", "纯文本消息"),
        ("image", '{"url": "https://example.com/photo.jpg", "width": 800}'),
        ("file", '{"name": "合同.pdf", "size": 2048}'),
    ]
    for orig_t, content in messages:
        _, enc = alice_session.encrypt_message(orig_t, content)
        dec_type, dec_text = bob_session.decrypt_message(enc)
        print(f"  {orig_t}: {dec_text[:40]}... -> 解密成功")
        assert dec_type == orig_t
        assert dec_text == content

    # ----------------------------------------------------------------
    # 第七步：查看会话信息
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第七步：查看会话信息")
    print("#" * 60)
    print_json("Alice 会话信息", alice_session.get_session_info())
    print_json("Bob 会话信息", bob_session.get_session_info())

    print("\n" + "=" * 60)
    print("  基础示例运行完毕!")
    print("=" * 60)


if __name__ == "__main__":
    main()
