"""消息解析和类型检测的单元测试。

使用构造的合法 dict 数据，不使用 mock。
"""

import unittest

from anp.e2e_encryption_hpke.message_parser import (
    detect_message_type,
    parse_e2ee_error,
    parse_e2ee_init,
    parse_e2ee_msg,
    parse_group_e2ee_key,
    parse_group_e2ee_msg,
    parse_group_epoch_advance,
)
from anp.e2e_encryption_hpke.models import MessageType


# 测试用的 proof 字典
_SAMPLE_PROOF = {
    "type": "EcdsaSecp256r1Signature2019",
    "created": "2026-01-01T00:00:00Z",
    "verification_method": "did:wba:example.com:user:alice#keys-1",
    "proof_value": "dGVzdA",
}


class TestDetectMessageType(unittest.TestCase):
    """测试 detect_message_type 函数。"""

    def test_detect_e2ee_init(self):
        self.assertEqual(
            detect_message_type("e2ee_init"), MessageType.E2EE_INIT
        )

    def test_detect_e2ee_msg(self):
        self.assertEqual(
            detect_message_type("e2ee_msg"), MessageType.E2EE_MSG
        )

    def test_detect_e2ee_rekey(self):
        self.assertEqual(
            detect_message_type("e2ee_rekey"), MessageType.E2EE_REKEY
        )

    def test_detect_e2ee_error(self):
        self.assertEqual(
            detect_message_type("e2ee_error"), MessageType.E2EE_ERROR
        )

    def test_detect_group_e2ee_key(self):
        self.assertEqual(
            detect_message_type("group_e2ee_key"), MessageType.GROUP_E2EE_KEY
        )

    def test_detect_group_e2ee_msg(self):
        self.assertEqual(
            detect_message_type("group_e2ee_msg"), MessageType.GROUP_E2EE_MSG
        )

    def test_detect_group_epoch_advance(self):
        self.assertEqual(
            detect_message_type("group_epoch_advance"),
            MessageType.GROUP_EPOCH_ADVANCE,
        )

    def test_detect_unknown_type_returns_none(self):
        self.assertIsNone(detect_message_type("unknown_type"))

    def test_detect_empty_string_returns_none(self):
        self.assertIsNone(detect_message_type(""))


class TestParseE2eeInit(unittest.TestCase):
    """测试 parse_e2ee_init 函数。"""

    def test_parse_valid_e2ee_init(self):
        """解析合法的 e2ee_init content 应返回 E2eeInitContent 实例。"""
        content = {
            "session_id": "abc123",
            "hpke_suite": "DHKEM-X25519-HKDF-SHA256/HKDF-SHA256/AES-128-GCM",
            "sender_did": "did:wba:example.com:user:alice",
            "recipient_did": "did:wba:example.com:user:bob",
            "recipient_key_id": "did:wba:example.com:user:bob#key-x25519-1",
            "enc": "dGVzdGVuYw==",
            "encrypted_seed": "dGVzdHNlZWQ=",
            "expires": 86400,
            "proof": _SAMPLE_PROOF,
        }
        parsed = parse_e2ee_init(content)

        self.assertEqual(parsed.session_id, "abc123")
        self.assertEqual(parsed.sender_did, "did:wba:example.com:user:alice")
        self.assertEqual(parsed.recipient_did, "did:wba:example.com:user:bob")
        self.assertEqual(parsed.enc, "dGVzdGVuYw==")
        self.assertEqual(parsed.encrypted_seed, "dGVzdHNlZWQ=")
        self.assertEqual(parsed.expires, 86400)
        self.assertEqual(parsed.proof.type, "EcdsaSecp256r1Signature2019")
        self.assertEqual(parsed.proof.proof_value, "dGVzdA")


class TestParseE2eeMsg(unittest.TestCase):
    """测试 parse_e2ee_msg 函数。"""

    def test_parse_valid_e2ee_msg(self):
        """解析合法的 e2ee_msg content 应返回 E2eeMsgContent 实例。"""
        content = {
            "session_id": "sess001",
            "seq": 1,
            "original_type": "text/plain",
            "ciphertext": "Y2lwaGVydGV4dA==",
        }
        parsed = parse_e2ee_msg(content)

        self.assertEqual(parsed.session_id, "sess001")
        self.assertEqual(parsed.seq, 1)
        self.assertEqual(parsed.original_type, "text/plain")
        self.assertEqual(parsed.ciphertext, "Y2lwaGVydGV4dA==")


class TestParseE2eeError(unittest.TestCase):
    """测试 parse_e2ee_error 函数。"""

    def test_parse_valid_e2ee_error_all_fields(self):
        """解析包含所有字段的 e2ee_error content。"""
        content = {
            "error_code": "session_not_found",
            "session_id": "sess001",
            "message": "Session does not exist",
        }
        parsed = parse_e2ee_error(content)

        self.assertEqual(parsed.error_code, "session_not_found")
        self.assertEqual(parsed.session_id, "sess001")
        self.assertEqual(parsed.message, "Session does not exist")

    def test_parse_valid_e2ee_error_minimal(self):
        """解析仅包含 error_code 的 e2ee_error content。"""
        content = {"error_code": "decryption_failed"}
        parsed = parse_e2ee_error(content)

        self.assertEqual(parsed.error_code, "decryption_failed")
        self.assertIsNone(parsed.session_id)
        self.assertIsNone(parsed.message)


class TestParseGroupE2eeKey(unittest.TestCase):
    """测试 parse_group_e2ee_key 函数。"""

    def test_parse_valid_group_e2ee_key(self):
        """解析合法的 group_e2ee_key content 应返回 GroupE2eeKeyContent 实例。"""
        content = {
            "group_did": "did:wba:example.com:group:dev-team",
            "epoch": 1,
            "sender_did": "did:wba:example.com:user:alice",
            "sender_key_id": "did:wba:example.com:user:alice#sender-key-1",
            "recipient_key_id": "did:wba:example.com:user:bob#key-x25519-1",
            "hpke_suite": "DHKEM-X25519-HKDF-SHA256/HKDF-SHA256/AES-128-GCM",
            "enc": "dGVzdGVuYw==",
            "encrypted_sender_key": "dGVzdGtleQ==",
            "expires": 86400,
            "proof": _SAMPLE_PROOF,
        }
        parsed = parse_group_e2ee_key(content)

        self.assertEqual(
            parsed.group_did, "did:wba:example.com:group:dev-team"
        )
        self.assertEqual(parsed.epoch, 1)
        self.assertEqual(parsed.sender_did, "did:wba:example.com:user:alice")
        self.assertEqual(parsed.enc, "dGVzdGVuYw==")
        self.assertEqual(parsed.encrypted_sender_key, "dGVzdGtleQ==")
        self.assertEqual(parsed.proof.type, "EcdsaSecp256r1Signature2019")


class TestParseGroupE2eeMsg(unittest.TestCase):
    """测试 parse_group_e2ee_msg 函数。"""

    def test_parse_valid_group_e2ee_msg(self):
        """解析合法的 group_e2ee_msg content 应返回 GroupE2eeMsgContent 实例。"""
        content = {
            "group_did": "did:wba:example.com:group:dev-team",
            "epoch": 1,
            "sender_did": "did:wba:example.com:user:alice",
            "sender_key_id": "did:wba:example.com:user:alice#sender-key-1",
            "seq": 42,
            "original_type": "application/json",
            "ciphertext": "ZW5jcnlwdGVk",
        }
        parsed = parse_group_e2ee_msg(content)

        self.assertEqual(
            parsed.group_did, "did:wba:example.com:group:dev-team"
        )
        self.assertEqual(parsed.epoch, 1)
        self.assertEqual(parsed.sender_did, "did:wba:example.com:user:alice")
        self.assertEqual(parsed.seq, 42)
        self.assertEqual(parsed.original_type, "application/json")
        self.assertEqual(parsed.ciphertext, "ZW5jcnlwdGVk")


class TestParseGroupEpochAdvance(unittest.TestCase):
    """测试 parse_group_epoch_advance 函数。"""

    def test_parse_valid_group_epoch_advance(self):
        """解析合法的 group_epoch_advance content 应返回 GroupEpochAdvanceContent 实例。"""
        content = {
            "group_did": "did:wba:example.com:group:dev-team",
            "new_epoch": 2,
            "reason": "member_added",
            "members_added": ["did:wba:example.com:user:charlie"],
            "proof": _SAMPLE_PROOF,
        }
        parsed = parse_group_epoch_advance(content)

        self.assertEqual(
            parsed.group_did, "did:wba:example.com:group:dev-team"
        )
        self.assertEqual(parsed.new_epoch, 2)
        self.assertEqual(parsed.reason, "member_added")
        self.assertEqual(
            parsed.members_added, ["did:wba:example.com:user:charlie"]
        )
        self.assertIsNone(parsed.members_removed)
        self.assertEqual(parsed.proof.type, "EcdsaSecp256r1Signature2019")

    def test_parse_group_epoch_advance_minimal(self):
        """解析不包含可选字段的 group_epoch_advance content。"""
        content = {
            "group_did": "did:wba:example.com:group:dev-team",
            "new_epoch": 3,
            "reason": "key_rotation",
            "proof": _SAMPLE_PROOF,
        }
        parsed = parse_group_epoch_advance(content)

        self.assertEqual(parsed.new_epoch, 3)
        self.assertEqual(parsed.reason, "key_rotation")
        self.assertIsNone(parsed.members_added)
        self.assertIsNone(parsed.members_removed)


if __name__ == "__main__":
    unittest.main()
