"""Tests for W3C Proof integration in DID WBA document creation and resolution.

Tests cover:
- DID document creation includes valid proof field
- Proof verification succeeds for unmodified documents
- Proof verification fails for tampered documents
- resolve_did_wba_document verify_proof parameter behavior
"""

import copy
import json
import unittest
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from anp.authentication.did_wba import (
    create_did_wba_document,
    resolve_did_wba_document,
    _extract_public_key,
)
from anp.proof import verify_w3c_proof


class TestCreateDIDDocumentWithProof(unittest.TestCase):
    """测试 create_did_wba_document 生成的文档包含 proof"""

    def setUp(self):
        self.did_document, self.keys = create_did_wba_document(
            "example.com", path_segments=["agents", "alice"]
        )

    def test_did_document_has_proof_field(self):
        """测试生成的 DID 文档包含 proof 字段"""
        self.assertIn("proof", self.did_document)

    def test_proof_has_required_w3c_fields(self):
        """测试 proof 包含所有 W3C Data Integrity 必需字段"""
        proof = self.did_document["proof"]
        self.assertEqual(proof["type"], "EcdsaSecp256k1Signature2019")
        self.assertIn("created", proof)
        self.assertIn("verificationMethod", proof)
        self.assertEqual(proof["proofPurpose"], "assertionMethod")
        self.assertIn("proofValue", proof)

    def test_proof_verification_method_matches_did(self):
        """测试 proof 的 verificationMethod 与 DID 文档一致"""
        proof = self.did_document["proof"]
        did = self.did_document["id"]
        self.assertEqual(proof["verificationMethod"], f"{did}#key-1")

    def test_proof_verifies_with_public_key(self):
        """测试使用对应公钥可以验证 proof"""
        _, public_key_pem = self.keys["key-1"]
        public_key = serialization.load_pem_public_key(public_key_pem)
        self.assertTrue(verify_w3c_proof(self.did_document, public_key))

    def test_proof_verifies_with_extracted_public_key(self):
        """测试使用从文档 verificationMethod 提取的公钥验证 proof"""
        vm = self.did_document["verificationMethod"][0]
        public_key = _extract_public_key(vm)
        self.assertTrue(verify_w3c_proof(self.did_document, public_key))

    def test_tampered_id_fails_verification(self):
        """测试篡改 DID 文档 id 后 proof 验证失败"""
        _, public_key_pem = self.keys["key-1"]
        public_key = serialization.load_pem_public_key(public_key_pem)

        tampered = copy.deepcopy(self.did_document)
        tampered["id"] = "did:wba:example.com:agents:eve"
        self.assertFalse(verify_w3c_proof(tampered, public_key))

    def test_tampered_verification_method_fails(self):
        """测试篡改 verificationMethod 后 proof 验证失败"""
        _, public_key_pem = self.keys["key-1"]
        public_key = serialization.load_pem_public_key(public_key_pem)

        tampered = copy.deepcopy(self.did_document)
        tampered["verificationMethod"][0]["controller"] = "did:wba:evil.com"
        self.assertFalse(verify_w3c_proof(tampered, public_key))

    def test_tampered_proof_value_fails(self):
        """测试篡改 proofValue 后验证失败"""
        _, public_key_pem = self.keys["key-1"]
        public_key = serialization.load_pem_public_key(public_key_pem)

        tampered = copy.deepcopy(self.did_document)
        pv = tampered["proof"]["proofValue"]
        tampered["proof"]["proofValue"] = "AAAA" + pv[4:]
        self.assertFalse(verify_w3c_proof(tampered, public_key))

    def test_wrong_public_key_fails(self):
        """测试使用错误公钥验证失败"""
        wrong_key = ec.generate_private_key(ec.SECP256K1()).public_key()
        self.assertFalse(verify_w3c_proof(self.did_document, wrong_key))

    def test_document_without_path_segments_has_proof(self):
        """测试无路径段的 DID 文档也包含 proof"""
        doc, keys = create_did_wba_document("example.com")
        self.assertIn("proof", doc)
        _, public_key_pem = keys["key-1"]
        public_key = serialization.load_pem_public_key(public_key_pem)
        self.assertTrue(verify_w3c_proof(doc, public_key))

    def test_document_with_service_has_proof(self):
        """测试包含 service 的 DID 文档也包含有效 proof"""
        doc, keys = create_did_wba_document(
            "example.com",
            path_segments=["user", "bob"],
            agent_description_url="https://example.com/ad.json",
        )
        self.assertIn("proof", doc)
        self.assertIn("service", doc)
        _, public_key_pem = keys["key-1"]
        public_key = serialization.load_pem_public_key(public_key_pem)
        self.assertTrue(verify_w3c_proof(doc, public_key))


def _make_aiohttp_session_mock(did_document):
    """构建 aiohttp.ClientSession 的 mock，正确模拟 async context manager 行为。"""
    mock_response = MagicMock()
    mock_response.raise_for_status = MagicMock()

    async def mock_json():
        return did_document

    mock_response.json = mock_json

    @asynccontextmanager
    async def mock_get(*args, **kwargs):
        yield mock_response

    mock_session = MagicMock()
    mock_session.get = mock_get

    @asynccontextmanager
    async def mock_session_cm(*args, **kwargs):
        yield mock_session

    return mock_session_cm


class TestResolveDIDDocumentWithProofVerification(unittest.IsolatedAsyncioTestCase):
    """测试 resolve_did_wba_document 的 proof 验证功能"""

    def setUp(self):
        self.did_document, self.keys = create_did_wba_document(
            "example.com", path_segments=["user", "alice"]
        )
        self.did = self.did_document["id"]

    async def _mock_resolve(self, did_document, verify_proof=False):
        """模拟 resolve 流程，mock aiohttp HTTP 请求"""
        mock_session_cm = _make_aiohttp_session_mock(did_document)
        with patch("anp.authentication.did_wba.aiohttp.ClientSession", mock_session_cm):
            result = await resolve_did_wba_document(
                self.did, verify_proof=verify_proof
            )
        return result

    async def test_resolve_without_verify_proof(self):
        """测试不开启 verify_proof 时正常返回文档"""
        result = await self._mock_resolve(self.did_document, verify_proof=False)
        self.assertIsNotNone(result)
        self.assertEqual(result["id"], self.did)

    async def test_resolve_with_verify_proof_valid(self):
        """测试开启 verify_proof 且文档 proof 有效时返回文档"""
        result = await self._mock_resolve(self.did_document, verify_proof=True)
        self.assertIsNotNone(result)
        self.assertEqual(result["id"], self.did)

    async def test_resolve_with_verify_proof_tampered(self):
        """测试开启 verify_proof 且文档被篡改时返回 None"""
        tampered = copy.deepcopy(self.did_document)
        # 篡改 authentication 字段导致 proof 失效
        tampered["authentication"] = ["did:wba:evil.com#key-1"]
        result = await self._mock_resolve(tampered, verify_proof=True)
        self.assertIsNone(result)

    async def test_resolve_with_verify_proof_no_proof_field(self):
        """测试开启 verify_proof 但文档无 proof 字段时正常返回"""
        doc_without_proof = {k: v for k, v in self.did_document.items() if k != "proof"}
        result = await self._mock_resolve(doc_without_proof, verify_proof=True)
        self.assertIsNotNone(result)

    async def test_resolve_without_verify_proof_tampered_still_returns(self):
        """测试不开启 verify_proof 时，即使文档被篡改也返回文档"""
        tampered = copy.deepcopy(self.did_document)
        tampered["authentication"] = ["did:wba:evil.com#key-1"]
        result = await self._mock_resolve(tampered, verify_proof=False)
        self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main()
