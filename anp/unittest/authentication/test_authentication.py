"""
Unit tests for DID WBA authentication

Tests cover:
- DID document creation and resolution
- Authentication header generation and verification
- Version compatibility (1.0 vs 1.1)
- Cross-version authentication scenarios
- Signature verification
"""

import json
import logging
import os
import unittest
from pathlib import Path

from anp.authentication import (
    create_did_wba_document,
    extract_auth_header_parts,
    generate_auth_header,
    generate_auth_json,
    resolve_did_wba_document_sync,
    verify_auth_header_signature,
    verify_auth_json_signature,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Setup logging
logging.basicConfig(level=logging.WARNING)


class TestDIDDocumentCreation(unittest.TestCase):
    """测试 DID 文档创建"""

    def test_create_did_document_basic(self):
        """测试创建基本 DID 文档"""
        did_document, keys = create_did_wba_document("example.com")

        # 验证 DID 格式
        self.assertEqual(did_document["id"], "did:wba:example.com")
        self.assertIn("verificationMethod", did_document)
        self.assertIn("authentication", did_document)

        # 验证密钥对
        self.assertIn("key-1", keys)
        private_key_pem, public_key_pem = keys["key-1"]
        self.assertTrue(private_key_pem.startswith(b"-----BEGIN PRIVATE KEY-----"))
        self.assertTrue(public_key_pem.startswith(b"-----BEGIN PUBLIC KEY-----"))

    def test_create_did_document_with_path(self):
        """测试创建带路径的 DID 文档"""
        did_document, keys = create_did_wba_document(
            "example.com", path_segments=["user", "alice"]
        )

        self.assertEqual(did_document["id"], "did:wba:example.com:user:alice")


class TestAuthenticationHeaderVersion(unittest.TestCase):
    """测试不同版本的认证头"""

    @classmethod
    def setUpClass(cls):
        """设置测试用的 DID 文档和密钥"""
        cls.did_document, cls.keys = create_did_wba_document("example.com")
        cls.private_key_pem, cls.public_key_pem = cls.keys["key-1"]
        cls.service_domain = "service.example.com"

    def _sign_callback(self, content: bytes, verification_method: str) -> bytes:
        """签名回调函数"""
        private_key = serialization.load_pem_private_key(
            self.private_key_pem, password=None
        )
        signature = private_key.sign(content, ec.ECDSA(hashes.SHA256()))
        return signature

    def test_version_1_0_uses_service_field(self):
        """测试版本 1.0 使用 service 字段"""
        auth_header = generate_auth_header(
            self.did_document, self.service_domain, self._sign_callback, version="1.0"
        )

        # 验证包含版本号
        self.assertIn('v="1.0"', auth_header)

        # 验证签名
        is_valid, message = verify_auth_header_signature(
            auth_header, self.did_document, self.service_domain
        )
        self.assertTrue(is_valid, f"版本 1.0 验证失败: {message}")

    def test_version_1_1_uses_aud_field(self):
        """测试版本 1.1 使用 aud 字段"""
        auth_header = generate_auth_header(
            self.did_document, self.service_domain, self._sign_callback, version="1.1"
        )

        # 验证包含版本号
        self.assertIn('v="1.1"', auth_header)

        # 验证签名
        is_valid, message = verify_auth_header_signature(
            auth_header, self.did_document, self.service_domain
        )
        self.assertTrue(is_valid, f"版本 1.1 验证失败: {message}")

    def test_version_1_2_uses_aud_field(self):
        """测试版本 1.2 使用 aud 字段"""
        auth_header = generate_auth_header(
            self.did_document, self.service_domain, self._sign_callback, version="1.2"
        )

        # 验证包含版本号
        self.assertIn('v="1.2"', auth_header)

        # 验证签名
        is_valid, message = verify_auth_header_signature(
            auth_header, self.did_document, self.service_domain
        )
        self.assertTrue(is_valid, f"版本 1.2 验证失败: {message}")

    def test_default_version_is_1_0(self):
        """测试默认版本是 1.0"""
        auth_header = generate_auth_header(
            self.did_document, self.service_domain, self._sign_callback
        )

        # 验证默认版本
        self.assertIn('v="1.0"', auth_header)

        # 验证签名
        is_valid, message = verify_auth_header_signature(
            auth_header, self.did_document, self.service_domain
        )
        self.assertTrue(is_valid, f"默认版本验证失败: {message}")

    def test_backward_compatibility_no_version(self):
        """测试向后兼容性:没有版本号的旧格式"""
        # 生成版本 1.0 的认证头
        auth_header = generate_auth_header(
            self.did_document, self.service_domain, self._sign_callback, version="1.0"
        )

        # 移除版本号以模拟旧格式
        auth_header_old = auth_header.replace('v="1.0", ', "")

        # 验证签名(应该默认使用 service 字段)
        is_valid, message = verify_auth_header_signature(
            auth_header_old, self.did_document, self.service_domain
        )
        self.assertTrue(is_valid, f"向后兼容性验证失败: {message}")


class TestCrossVersionAuthentication(unittest.TestCase):
    """测试跨版本认证场景"""

    @classmethod
    def setUpClass(cls):
        """设置测试用的 DID 文档和密钥"""
        cls.did_document, cls.keys = create_did_wba_document("example.com")
        cls.private_key_pem, cls.public_key_pem = cls.keys["key-1"]
        cls.service_domain = "service.example.com"

    def _sign_callback(self, content: bytes, verification_method: str) -> bytes:
        """签名回调函数"""
        private_key = serialization.load_pem_private_key(
            self.private_key_pem, password=None
        )
        signature = private_key.sign(content, ec.ECDSA(hashes.SHA256()))
        return signature

    def test_v1_0_client_to_v1_0_server(self):
        """测试 1.0 客户端到 1.0 服务器"""
        # 客户端生成 1.0 版本的认证头
        auth_header = generate_auth_header(
            self.did_document, self.service_domain, self._sign_callback, version="1.0"
        )

        # 服务器验证(使用相同的 service_domain)
        is_valid, message = verify_auth_header_signature(
            auth_header, self.did_document, self.service_domain
        )
        self.assertTrue(is_valid, f"1.0→1.0 验证失败: {message}")

    def test_v1_1_client_to_v1_1_server(self):
        """测试 1.1 客户端到 1.1 服务器"""
        # 客户端生成 1.1 版本的认证头
        auth_header = generate_auth_header(
            self.did_document, self.service_domain, self._sign_callback, version="1.1"
        )

        # 服务器验证(使用相同的 service_domain)
        is_valid, message = verify_auth_header_signature(
            auth_header, self.did_document, self.service_domain
        )
        self.assertTrue(is_valid, f"1.1→1.1 验证失败: {message}")

    def test_v1_0_client_to_v1_1_server_fails(self):
        """测试 1.0 客户端到 1.1 服务器(应该失败,因为签名字段不匹配)"""
        # 客户端使用 1.0 版本(使用 service 字段签名)
        auth_header = generate_auth_header(
            self.did_document, self.service_domain, self._sign_callback, version="1.0"
        )

        # 手动修改版本号为 1.1(但签名仍然是基于 service 字段)
        # 这会导致验证失败,因为服务器会期望 aud 字段
        auth_header_modified = auth_header.replace('v="1.0"', 'v="1.1"')

        # 服务器验证(应该失败)
        is_valid, message = verify_auth_header_signature(
            auth_header_modified, self.did_document, self.service_domain
        )
        self.assertFalse(is_valid, "1.0→1.1 应该验证失败(签名字段不匹配)")

    def test_v1_1_client_to_v1_0_server_fails(self):
        """测试 1.1 客户端到 1.0 服务器(应该失败,因为签名字段不匹配)"""
        # 客户端使用 1.1 版本(使用 aud 字段签名)
        auth_header = generate_auth_header(
            self.did_document, self.service_domain, self._sign_callback, version="1.1"
        )

        # 手动修改版本号为 1.0(但签名仍然是基于 aud 字段)
        auth_header_modified = auth_header.replace('v="1.1"', 'v="1.0"')

        # 服务器验证(应该失败)
        is_valid, message = verify_auth_header_signature(
            auth_header_modified, self.did_document, self.service_domain
        )
        self.assertFalse(is_valid, "1.1→1.0 应该验证失败(签名字段不匹配)")


class TestJSONAuthentication(unittest.TestCase):
    """测试 JSON 格式认证"""

    @classmethod
    def setUpClass(cls):
        """设置测试用的 DID 文档和密钥"""
        cls.did_document, cls.keys = create_did_wba_document("example.com")
        cls.private_key_pem, cls.public_key_pem = cls.keys["key-1"]
        cls.service_domain = "service.example.com"

    def _sign_callback(self, content: bytes, verification_method: str) -> bytes:
        """签名回调函数"""
        private_key = serialization.load_pem_private_key(
            self.private_key_pem, password=None
        )
        signature = private_key.sign(content, ec.ECDSA(hashes.SHA256()))
        return signature

    def test_json_uses_v_field(self):
        """测试 JSON 使用 v 字段而不是 version"""
        auth_json_str = generate_auth_json(
            self.did_document, self.service_domain, self._sign_callback, version="1.1"
        )
        auth_json = json.loads(auth_json_str)

        # 验证使用 v 字段
        self.assertIn("v", auth_json)
        self.assertNotIn("version", auth_json)
        self.assertEqual(auth_json["v"], "1.1")

    def test_json_version_1_0(self):
        """测试 JSON 版本 1.0"""
        auth_json_str = generate_auth_json(
            self.did_document, self.service_domain, self._sign_callback, version="1.0"
        )

        is_valid, message = verify_auth_json_signature(
            auth_json_str, self.did_document, self.service_domain
        )
        self.assertTrue(is_valid, f"JSON 1.0 验证失败: {message}")

    def test_json_version_1_1(self):
        """测试 JSON 版本 1.1"""
        auth_json_str = generate_auth_json(
            self.did_document, self.service_domain, self._sign_callback, version="1.1"
        )

        is_valid, message = verify_auth_json_signature(
            auth_json_str, self.did_document, self.service_domain
        )
        self.assertTrue(is_valid, f"JSON 1.1 验证失败: {message}")


class TestPublicDIDAuthentication(unittest.TestCase):
    """使用公共测试 DID 文档进行测试"""

    @classmethod
    def setUpClass(cls):
        """加载公共测试 DID 文档和私钥"""
        # 获取项目根目录 (从 authentication/ 目录需要回退3级到项目根)
        project_root = Path(__file__).parent.parent.parent.parent
        did_doc_path = project_root / "docs" / "did_public" / "public-did-doc.json"
        private_key_path = (
            project_root / "docs" / "did_public" / "public-private-key.pem"
        )

        # 加载 DID 文档
        with open(did_doc_path, "r") as f:
            cls.did_document = json.load(f)

        # 加载私钥
        with open(private_key_path, "rb") as f:
            cls.private_key_pem = f.read()

        cls.service_domain = "didhost.cc"

    def _sign_callback(self, content: bytes, verification_method: str) -> bytes:
        """签名回调函数"""
        private_key = serialization.load_pem_private_key(
            self.private_key_pem, password=None
        )
        signature = private_key.sign(content, ec.ECDSA(hashes.SHA256()))
        return signature

    def test_public_did_version_1_0(self):
        """测试使用公共 DID 文档的 1.0 版本认证"""
        auth_header = generate_auth_header(
            self.did_document, self.service_domain, self._sign_callback, version="1.0"
        )

        is_valid, message = verify_auth_header_signature(
            auth_header, self.did_document, self.service_domain
        )
        self.assertTrue(is_valid, f"公共 DID 1.0 验证失败: {message}")

    def test_public_did_version_1_1(self):
        """测试使用公共 DID 文档的 1.1 版本认证"""
        auth_header = generate_auth_header(
            self.did_document, self.service_domain, self._sign_callback, version="1.1"
        )

        is_valid, message = verify_auth_header_signature(
            auth_header, self.did_document, self.service_domain
        )
        self.assertTrue(is_valid, f"公共 DID 1.1 验证失败: {message}")

    def test_public_did_json_format(self):
        """测试使用公共 DID 文档的 JSON 格式认证"""
        auth_json_str = generate_auth_json(
            self.did_document, self.service_domain, self._sign_callback, version="1.1"
        )

        is_valid, message = verify_auth_json_signature(
            auth_json_str, self.did_document, self.service_domain
        )
        self.assertTrue(is_valid, f"公共 DID JSON 验证失败: {message}")


class TestAuthHeaderParsing(unittest.TestCase):
    """测试认证头解析"""

    def test_extract_auth_header_with_version(self):
        """测试提取带版本号的认证头"""
        auth_header = (
            'DIDWba v="1.1", did="did:wba:example.com", nonce="abc123", '
            'timestamp="2025-12-25T12:00:00Z", verification_method="key-1", '
            'signature="test_signature"'
        )

        did, nonce, timestamp, vm, sig, version = extract_auth_header_parts(
            auth_header
        )

        self.assertEqual(did, "did:wba:example.com")
        self.assertEqual(nonce, "abc123")
        self.assertEqual(timestamp, "2025-12-25T12:00:00Z")
        self.assertEqual(vm, "key-1")
        self.assertEqual(sig, "test_signature")
        self.assertEqual(version, "1.1")

    def test_extract_auth_header_without_version(self):
        """测试提取不带版本号的认证头(向后兼容)"""
        auth_header = (
            'DIDWba did="did:wba:example.com", nonce="abc123", '
            'timestamp="2025-12-25T12:00:00Z", verification_method="key-1", '
            'signature="test_signature"'
        )

        did, nonce, timestamp, vm, sig, version = extract_auth_header_parts(
            auth_header
        )

        self.assertEqual(version, "1.0")  # 默认应该是 1.0


if __name__ == "__main__":
    unittest.main()
