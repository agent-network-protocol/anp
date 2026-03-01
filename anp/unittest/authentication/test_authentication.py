"""
Unit tests for DID WBA authentication

Tests cover:
- DID document creation and resolution
- Authentication header generation and verification
- Version compatibility (1.0 vs 1.1)
- Cross-version authentication scenarios
- Signature verification
"""

import base64
import json
import logging
import os
import unittest
from pathlib import Path

from anp.authentication import (
    compute_jwk_fingerprint,
    create_did_wba_document,
    create_did_wba_document_with_key_binding,
    extract_auth_header_parts,
    generate_auth_header,
    generate_auth_json,
    resolve_did_wba_document_sync,
    verify_auth_header_signature,
    verify_auth_json_signature,
    verify_did_key_binding,
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

    def test_default_version_is_1_1(self):
        """测试默认版本是 1.1"""
        auth_header = generate_auth_header(
            self.did_document, self.service_domain, self._sign_callback
        )

        # 验证默认版本
        self.assertIn('v="1.1"', auth_header)

        # 验证签名
        is_valid, message = verify_auth_header_signature(
            auth_header, self.did_document, self.service_domain
        )
        self.assertTrue(is_valid, f"默认版本验证失败: {message}")

    def test_backward_compatibility_no_version(self):
        """测试向后兼容性:没有版本号的旧格式"""
        # 生成版本 1.1 的认证头(使用 aud 字段)
        auth_header = generate_auth_header(
            self.did_document, self.service_domain, self._sign_callback, version="1.1"
        )

        # 移除版本号以模拟没有版本号的格式
        auth_header_no_version = auth_header.replace('v="1.1", ', "")

        # 验证签名(应该默认使用 aud 字段，因为默认版本已改为 1.1)
        is_valid, message = verify_auth_header_signature(
            auth_header_no_version, self.did_document, self.service_domain
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

        self.assertEqual(version, "1.1")  # 默认应该是 1.1


class TestKeyBoundDIDCreation(unittest.TestCase):
    """测试 key-bound DID 文档创建和验证"""

    def test_create_key_bound_did_document(self):
        """测试创建 key-bound DID 文档，验证 DID 格式包含 k1_ 前缀"""
        did_document, keys = create_did_wba_document_with_key_binding("example.com")

        did = did_document["id"]
        # DID 应包含 k1_ 前缀
        self.assertIn(":k1_", did)
        # DID 应以 did:wba:example.com:user:k1_ 开头
        self.assertTrue(did.startswith("did:wba:example.com:user:k1_"))

        # 验证密钥对存在
        self.assertIn("key-1", keys)
        private_key_pem, public_key_pem = keys["key-1"]
        self.assertTrue(private_key_pem.startswith(b"-----BEGIN PRIVATE KEY-----"))
        self.assertTrue(public_key_pem.startswith(b"-----BEGIN PUBLIC KEY-----"))

    def test_fingerprint_length_is_43(self):
        """测试 fingerprint 长度为 43 字符"""
        did_document, _ = create_did_wba_document_with_key_binding("example.com")

        did = did_document["id"]
        # 提取最后一个段
        last_segment = did.split(":")[-1]
        self.assertTrue(last_segment.startswith("k1_"))
        fingerprint = last_segment[3:]
        self.assertEqual(len(fingerprint), 43)

    def test_custom_path_prefix(self):
        """测试自定义 path_prefix"""
        did_document, _ = create_did_wba_document_with_key_binding(
            "example.com", path_prefix=["agent"]
        )

        did = did_document["id"]
        self.assertTrue(did.startswith("did:wba:example.com:agent:k1_"))

    def test_default_path_prefix_is_user(self):
        """测试默认 path_prefix 为 ['user']"""
        did_document, _ = create_did_wba_document_with_key_binding("example.com")

        did = did_document["id"]
        parts = did.split(":")
        # parts: ['did', 'wba', 'example.com', 'user', 'k1_...']
        self.assertEqual(parts[3], "user")

    def test_multi_segment_path_prefix(self):
        """测试多段 path_prefix"""
        did_document, _ = create_did_wba_document_with_key_binding(
            "example.com", path_prefix=["org", "team"]
        )

        did = did_document["id"]
        self.assertTrue(did.startswith("did:wba:example.com:org:team:k1_"))

    def test_verify_did_key_binding_passes(self):
        """测试 verify_did_key_binding 对正确的 key-bound DID 验证通过"""
        did_document, _ = create_did_wba_document_with_key_binding("example.com")

        did = did_document["id"]
        public_key_jwk = did_document["verificationMethod"][0]["publicKeyJwk"]

        self.assertTrue(verify_did_key_binding(did, public_key_jwk))

    def test_verify_did_key_binding_fails_on_tampered_key(self):
        """测试篡改公钥后 verify_did_key_binding 失败"""
        did_document, _ = create_did_wba_document_with_key_binding("example.com")

        did = did_document["id"]
        # 生成一个不同的密钥
        other_key = ec.generate_private_key(ec.SECP256K1())
        other_public = other_key.public_key()
        numbers = other_public.public_numbers()
        import base64
        tampered_jwk = {
            "kty": "EC",
            "crv": "secp256k1",
            "x": base64.urlsafe_b64encode(numbers.x.to_bytes(32, 'big')).rstrip(b'=').decode('ascii'),
            "y": base64.urlsafe_b64encode(numbers.y.to_bytes(32, 'big')).rstrip(b'=').decode('ascii'),
        }

        self.assertFalse(verify_did_key_binding(did, tampered_jwk))

    def test_verify_did_key_binding_skips_non_k1_prefix(self):
        """测试 u1_ 前缀的 DID 跳过 key binding 校验"""
        # u1_ 前缀表示用户自选 ID，不需要 key binding 校验
        did = "did:wba:example.com:user:u1_alice"
        # 任何 JWK 都应返回 True（因为不是 k1_ 前缀）
        fake_jwk = {"kty": "EC", "crv": "secp256k1", "x": "fake", "y": "fake"}
        self.assertTrue(verify_did_key_binding(did, fake_jwk))

    def test_verify_did_key_binding_skips_plain_id(self):
        """测试普通 DID（无特殊前缀）跳过 key binding 校验"""
        did = "did:wba:example.com:user:alice"
        fake_jwk = {"kty": "EC", "crv": "secp256k1", "x": "fake", "y": "fake"}
        self.assertTrue(verify_did_key_binding(did, fake_jwk))

    def test_key_bound_did_with_port(self):
        """测试带端口号的 key-bound DID"""
        did_document, _ = create_did_wba_document_with_key_binding(
            "example.com", port=8080
        )

        did = did_document["id"]
        self.assertIn("%3A8080", did)
        self.assertIn(":k1_", did)

    def test_key_bound_did_with_services(self):
        """测试带 service 的 key-bound DID"""
        did_document, _ = create_did_wba_document_with_key_binding(
            "example.com",
            agent_description_url="https://example.com/ad.json",
            services=[{"id": "#custom", "type": "Custom", "serviceEndpoint": "https://example.com/custom"}],
        )

        self.assertIn("service", did_document)
        self.assertEqual(len(did_document["service"]), 2)

    def test_key_bound_did_has_proof(self):
        """测试 key-bound DID 文档包含 proof"""
        did_document, _ = create_did_wba_document_with_key_binding("example.com")
        self.assertIn("proof", did_document)


class TestJWKFingerprint(unittest.TestCase):
    """测试 JWK Fingerprint 计算"""

    def test_fingerprint_stability(self):
        """测试同一个 key 多次计算 fingerprint 结果一致"""
        private_key = ec.generate_private_key(ec.SECP256K1())
        public_key = private_key.public_key()

        fp1 = compute_jwk_fingerprint(public_key)
        fp2 = compute_jwk_fingerprint(public_key)
        fp3 = compute_jwk_fingerprint(public_key)

        self.assertEqual(fp1, fp2)
        self.assertEqual(fp2, fp3)

    def test_different_keys_produce_different_fingerprints(self):
        """测试不同 key 产生不同 fingerprint"""
        key1 = ec.generate_private_key(ec.SECP256K1()).public_key()
        key2 = ec.generate_private_key(ec.SECP256K1()).public_key()

        fp1 = compute_jwk_fingerprint(key1)
        fp2 = compute_jwk_fingerprint(key2)

        self.assertNotEqual(fp1, fp2)

    def test_fingerprint_is_43_chars(self):
        """测试 fingerprint 长度始终为 43 字符"""
        for _ in range(10):
            key = ec.generate_private_key(ec.SECP256K1()).public_key()
            fp = compute_jwk_fingerprint(key)
            self.assertEqual(len(fp), 43, f"Fingerprint length should be 43, got {len(fp)}: {fp}")

    def test_fingerprint_is_base64url(self):
        """测试 fingerprint 只包含 base64url 字符（无 padding）"""
        import re
        key = ec.generate_private_key(ec.SECP256K1()).public_key()
        fp = compute_jwk_fingerprint(key)

        # base64url 字符集: A-Z, a-z, 0-9, -, _
        self.assertTrue(re.match(r'^[A-Za-z0-9_-]+$', fp), f"Invalid base64url chars in: {fp}")
        # 无 padding
        self.assertNotIn('=', fp)

    def test_fixed_32_byte_encoding(self):
        """测试 x/y 坐标使用固定 32 字节编码（即使前导字节为 0）

        通过大量生成密钥来测试，确保 fingerprint 始终稳定为 43 字符，
        说明底层使用了固定长度编码。
        """
        for _ in range(50):
            key = ec.generate_private_key(ec.SECP256K1()).public_key()
            fp = compute_jwk_fingerprint(key)
            self.assertEqual(len(fp), 43)


class TestJWKCoordinateEncoding(unittest.TestCase):
    """测试 DID 文档中 JWK 坐标编码长度"""

    def test_key1_jwk_coordinates_are_32_bytes(self):
        """验证 key-1 (secp256k1) JWK 的 x/y base64url 解码后长度恒为 32 字节。"""
        for _ in range(20):
            did_document, keys = create_did_wba_document("example.com")
            vm_key1 = did_document["verificationMethod"][0]
            jwk = vm_key1["publicKeyJwk"]

            # base64url 解码（补齐 padding）
            x_bytes = base64.urlsafe_b64decode(jwk["x"] + "==")
            y_bytes = base64.urlsafe_b64decode(jwk["y"] + "==")

            self.assertEqual(
                len(x_bytes), 32,
                f"x coordinate should be 32 bytes, got {len(x_bytes)}"
            )
            self.assertEqual(
                len(y_bytes), 32,
                f"y coordinate should be 32 bytes, got {len(y_bytes)}"
            )


if __name__ == "__main__":
    unittest.main()
