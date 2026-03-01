# -*- coding: utf-8 -*-
"""E2EE HPKE 进阶示例：三方群聊 Sender Key E2EE。

演示 Alice、Bob、Charlie 通过 HPKE Sender Key 协议进行群聊加密通信，
包括 Sender Key 生成、分发、加密群消息、Epoch 推进等完整流程。

运行方式：
    uv run python examples/python/e2e_encryption_hpke_examples/group_chat_example.py
"""

import json

from cryptography.hazmat.primitives.asymmetric import ec

from anp.e2e_encryption_hpke import (
    EpochReason,
    GroupE2eeSession,
    build_group_epoch_advance,
    generate_x25519_key_pair,
)


def print_json(label: str, obj: dict) -> None:
    """格式化打印 JSON 对象。"""
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"{'='*60}")
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def generate_keys():
    """生成 X25519 密钥协商对和 secp256r1 签名密钥对。"""
    x25519_sk, x25519_pk = generate_x25519_key_pair()
    signing_sk = ec.generate_private_key(ec.SECP256R1())
    signing_pk = signing_sk.public_key()
    return x25519_sk, x25519_pk, signing_sk, signing_pk


def main() -> None:
    """运行三方群聊 Sender Key E2EE 示例。"""
    print("=" * 60)
    print("  E2EE HPKE 进阶示例：三方群聊 Sender Key")
    print("=" * 60)

    group_did = "did:wba:example.com:group:team"

    # ----------------------------------------------------------------
    # 第一步：为三方生成密钥对
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第一步：生成三方密钥")
    print("#" * 60)

    alice_did = "did:wba:example.com:user:alice"
    bob_did = "did:wba:example.com:user:bob"
    charlie_did = "did:wba:example.com:user:charlie"

    alice_x25519_sk, alice_x25519_pk, alice_sign_sk, alice_sign_pk = generate_keys()
    bob_x25519_sk, bob_x25519_pk, bob_sign_sk, bob_sign_pk = generate_keys()
    charlie_x25519_sk, charlie_x25519_pk, charlie_sign_sk, charlie_sign_pk = (
        generate_keys()
    )

    alice_key_id = f"{alice_did}#key-agreement-1"
    bob_key_id = f"{bob_did}#key-agreement-1"
    charlie_key_id = f"{charlie_did}#key-agreement-1"

    print(f"[Alice]   DID: {alice_did}")
    print(f"[Bob]     DID: {bob_did}")
    print(f"[Charlie] DID: {charlie_did}")

    # ----------------------------------------------------------------
    # 第二步：创建 GroupE2eeSession
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第二步：创建群聊会话")
    print("#" * 60)

    alice_group = GroupE2eeSession(
        group_did=group_did,
        local_did=alice_did,
        local_x25519_private_key=alice_x25519_sk,
        local_x25519_key_id=alice_key_id,
        signing_private_key=alice_sign_sk,
        signing_verification_method=f"{alice_did}#key-1",
    )
    bob_group = GroupE2eeSession(
        group_did=group_did,
        local_did=bob_did,
        local_x25519_private_key=bob_x25519_sk,
        local_x25519_key_id=bob_key_id,
        signing_private_key=bob_sign_sk,
        signing_verification_method=f"{bob_did}#key-1",
    )
    charlie_group = GroupE2eeSession(
        group_did=group_did,
        local_did=charlie_did,
        local_x25519_private_key=charlie_x25519_sk,
        local_x25519_key_id=charlie_key_id,
        signing_private_key=charlie_sign_sk,
        signing_verification_method=f"{charlie_did}#key-1",
    )
    print(f"[群组] group_did: {group_did}")
    print(f"[群组] 初始 epoch: {alice_group.epoch}")

    # ----------------------------------------------------------------
    # 第三步：Alice 生成 Sender Key
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第三步：Alice 生成 Sender Key")
    print("#" * 60)

    alice_group.generate_sender_key()
    print(f"[Alice] 已生成 Sender Key，sender_key_id: {alice_group.local_sender_key_id}")

    # ----------------------------------------------------------------
    # 第四步：Alice 向 Bob、Charlie 分发 Sender Key
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第四步：Alice 分发 Sender Key 给 Bob 和 Charlie")
    print("#" * 60)

    # Alice -> Bob
    key_type, key_to_bob = alice_group.build_sender_key_distribution(
        recipient_did=bob_did,
        recipient_pk=bob_x25519_pk,
        recipient_key_id=bob_key_id,
    )
    print(f"[Alice -> Bob] 消息类型: {key_type}")
    print_json("Sender Key 分发消息（给 Bob）", key_to_bob)

    # Alice -> Charlie
    _, key_to_charlie = alice_group.build_sender_key_distribution(
        recipient_did=charlie_did,
        recipient_pk=charlie_x25519_pk,
        recipient_key_id=charlie_key_id,
    )
    print(f"\n[Alice -> Charlie] Sender Key 分发消息已构建")

    # ----------------------------------------------------------------
    # 第五步：Bob、Charlie 处理 Sender Key
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第五步：Bob 和 Charlie 处理 Sender Key")
    print("#" * 60)

    bob_group.process_sender_key(key_to_bob, alice_sign_pk)
    print("[Bob] 已接收并存储 Alice 的 Sender Key")

    charlie_group.process_sender_key(key_to_charlie, alice_sign_pk)
    print("[Charlie] 已接收并存储 Alice 的 Sender Key")

    # ----------------------------------------------------------------
    # 第六步：Alice 发送加密群消息，Bob 和 Charlie 解密
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第六步：Alice 发送加密群消息")
    print("#" * 60)

    msg_type, group_msg = alice_group.encrypt_group_message(
        "text", "大家好！这是群聊加密消息。"
    )
    print(f"[Alice] 发送群消息，类型: {msg_type}")
    print_json("加密后的群消息", group_msg)

    # Bob 解密
    bob_type, bob_plain = bob_group.decrypt_group_message(group_msg)
    print(f"\n[Bob 解密] 类型: {bob_type}, 内容: {bob_plain}")
    assert bob_plain == "大家好！这是群聊加密消息。"

    # Charlie 解密
    charlie_type, charlie_plain = charlie_group.decrypt_group_message(group_msg)
    print(f"[Charlie 解密] 类型: {charlie_type}, 内容: {charlie_plain}")
    assert charlie_plain == "大家好！这是群聊加密消息。"

    # ----------------------------------------------------------------
    # 第七步：Bob 生成并分发自己的 Sender Key，发送群消息
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第七步：Bob 也发送群消息")
    print("#" * 60)

    bob_group.generate_sender_key()
    print(f"[Bob] 已生成 Sender Key: {bob_group.local_sender_key_id}")

    # Bob -> Alice
    _, bob_key_to_alice = bob_group.build_sender_key_distribution(
        recipient_did=alice_did,
        recipient_pk=alice_x25519_pk,
        recipient_key_id=alice_key_id,
    )
    alice_group.process_sender_key(bob_key_to_alice, bob_sign_pk)
    print("[Alice] 已接收 Bob 的 Sender Key")

    # Bob -> Charlie
    _, bob_key_to_charlie = bob_group.build_sender_key_distribution(
        recipient_did=charlie_did,
        recipient_pk=charlie_x25519_pk,
        recipient_key_id=charlie_key_id,
    )
    charlie_group.process_sender_key(bob_key_to_charlie, bob_sign_pk)
    print("[Charlie] 已接收 Bob 的 Sender Key")

    # Bob 发送群消息
    _, bob_msg = bob_group.encrypt_group_message("text", "我是 Bob，也来发消息！")

    alice_t, alice_p = alice_group.decrypt_group_message(bob_msg)
    print(f"[Alice 解密] {alice_t}: {alice_p}")
    assert alice_p == "我是 Bob，也来发消息！"

    charlie_t, charlie_p = charlie_group.decrypt_group_message(bob_msg)
    print(f"[Charlie 解密] {charlie_t}: {charlie_p}")
    assert charlie_p == "我是 Bob，也来发消息！"

    # ----------------------------------------------------------------
    # 第八步：Epoch 推进（模拟成员变化后的密钥轮转）
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第八步：Epoch 推进")
    print("#" * 60)

    # Alice 作为管理员构建 epoch advance 消息
    epoch_content = build_group_epoch_advance(
        group_did=group_did,
        new_epoch=1,
        reason=EpochReason.KEY_ROTATION.value,
        signing_key=alice_sign_sk,
        verification_method=f"{alice_did}#key-1",
    )
    print_json("Epoch Advance 消息", epoch_content)

    # Bob 和 Charlie 处理 epoch advance
    bob_group.process_epoch_advance(epoch_content, alice_sign_pk)
    print(f"[Bob] Epoch 已推进到: {bob_group.epoch}")
    assert bob_group.epoch == 1

    charlie_group.process_epoch_advance(epoch_content, alice_sign_pk)
    print(f"[Charlie] Epoch 已推进到: {charlie_group.epoch}")
    assert charlie_group.epoch == 1

    # Alice 本地也推进 epoch
    alice_group.advance_epoch(1)
    print(f"[Alice] Epoch 已推进到: {alice_group.epoch}")
    assert alice_group.epoch == 1

    # ----------------------------------------------------------------
    # 第九步：新 epoch 下重新分发 Sender Key 并通信
    # ----------------------------------------------------------------
    print("\n" + "#" * 60)
    print("  第九步：新 epoch 下重新分发 Sender Key")
    print("#" * 60)

    # Alice 重新生成并分发 Sender Key
    alice_group.generate_sender_key()
    print(f"[Alice] 新 epoch Sender Key: {alice_group.local_sender_key_id}")

    _, new_key_to_bob = alice_group.build_sender_key_distribution(
        recipient_did=bob_did,
        recipient_pk=bob_x25519_pk,
        recipient_key_id=bob_key_id,
    )
    bob_group.process_sender_key(new_key_to_bob, alice_sign_pk)

    _, new_key_to_charlie = alice_group.build_sender_key_distribution(
        recipient_did=charlie_did,
        recipient_pk=charlie_x25519_pk,
        recipient_key_id=charlie_key_id,
    )
    charlie_group.process_sender_key(new_key_to_charlie, alice_sign_pk)
    print("[分发完成] Bob 和 Charlie 已接收新 epoch 的 Sender Key")

    # 新 epoch 下通信
    _, new_epoch_msg = alice_group.encrypt_group_message(
        "text", "新 epoch 下的加密消息！"
    )
    bob_t, bob_p = bob_group.decrypt_group_message(new_epoch_msg)
    print(f"[Bob 解密] {bob_t}: {bob_p}")
    assert bob_p == "新 epoch 下的加密消息！"

    charlie_t, charlie_p = charlie_group.decrypt_group_message(new_epoch_msg)
    print(f"[Charlie 解密] {charlie_t}: {charlie_p}")
    assert charlie_p == "新 epoch 下的加密消息！"

    print("\n" + "=" * 60)
    print("  群聊示例运行完毕!")
    print("=" * 60)


if __name__ == "__main__":
    main()
