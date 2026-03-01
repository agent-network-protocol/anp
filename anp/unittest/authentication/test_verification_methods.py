"""Tests for new verification method classes (secp256r1, X25519)."""

import base64
import unittest

import base58
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes

from anp.authentication.verification_methods import (
    EcdsaSecp256r1VerificationKey2019,
    X25519KeyAgreementKey2019,
    create_verification_method,
)


class TestEcdsaSecp256r1VerificationKey(unittest.TestCase):
    """Test EcdsaSecp256r1VerificationKey2019."""

    def setUp(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()

    def test_sign_and_verify(self):
        """Sign with secp256r1 and verify with verification method."""
        content = b"test message for secp256r1"

        # Sign
        signature_der = self.private_key.sign(content, ec.ECDSA(hashes.SHA256()))
        signature_str = EcdsaSecp256r1VerificationKey2019.encode_signature(signature_der)

        # Verify
        vm = EcdsaSecp256r1VerificationKey2019(self.public_key)
        self.assertTrue(vm.verify_signature(content, signature_str))

    def test_verify_wrong_content_fails(self):
        """Verification should fail for wrong content."""
        content = b"correct content"
        wrong_content = b"wrong content"

        signature_der = self.private_key.sign(content, ec.ECDSA(hashes.SHA256()))
        signature_str = EcdsaSecp256r1VerificationKey2019.encode_signature(signature_der)

        vm = EcdsaSecp256r1VerificationKey2019(self.public_key)
        self.assertFalse(vm.verify_signature(wrong_content, signature_str))

    def test_from_dict_jwk(self):
        """Create from JWK dict."""
        numbers = self.public_key.public_numbers()
        x = base64.urlsafe_b64encode(numbers.x.to_bytes(32, 'big')).rstrip(b'=').decode()
        y = base64.urlsafe_b64encode(numbers.y.to_bytes(32, 'big')).rstrip(b'=').decode()

        method_dict = {
            "type": "EcdsaSecp256r1VerificationKey2019",
            "publicKeyJwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": x,
                "y": y,
            },
        }

        vm = EcdsaSecp256r1VerificationKey2019.from_dict(method_dict)
        self.assertIsNotNone(vm)

        # Verify a signature
        content = b"jwk test"
        sig_der = self.private_key.sign(content, ec.ECDSA(hashes.SHA256()))
        sig_str = EcdsaSecp256r1VerificationKey2019.encode_signature(sig_der)
        self.assertTrue(vm.verify_signature(content, sig_str))

    def test_from_dict_multibase(self):
        """Create from multibase dict."""
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        compressed = self.public_key.public_bytes(
            encoding=Encoding.X962,
            format=PublicFormat.CompressedPoint,
        )
        multibase = "z" + base58.b58encode(compressed).decode()

        method_dict = {
            "type": "EcdsaSecp256r1VerificationKey2019",
            "publicKeyMultibase": multibase,
        }

        vm = EcdsaSecp256r1VerificationKey2019.from_dict(method_dict)
        self.assertIsNotNone(vm)

    def test_from_dict_wrong_crv_raises(self):
        """JWK with wrong crv should raise ValueError."""
        method_dict = {
            "type": "EcdsaSecp256r1VerificationKey2019",
            "publicKeyJwk": {
                "kty": "EC",
                "crv": "secp256k1",
                "x": "AAAA",
                "y": "AAAA",
            },
        }
        with self.assertRaises(ValueError):
            EcdsaSecp256r1VerificationKey2019.from_dict(method_dict)

    def test_factory_creates_secp256r1(self):
        """create_verification_method should handle EcdsaSecp256r1VerificationKey2019."""
        numbers = self.public_key.public_numbers()
        x = base64.urlsafe_b64encode(numbers.x.to_bytes(32, 'big')).rstrip(b'=').decode()
        y = base64.urlsafe_b64encode(numbers.y.to_bytes(32, 'big')).rstrip(b'=').decode()

        method_dict = {
            "type": "EcdsaSecp256r1VerificationKey2019",
            "publicKeyJwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": x,
                "y": y,
            },
        }

        vm = create_verification_method(method_dict)
        self.assertIsInstance(vm, EcdsaSecp256r1VerificationKey2019)


class TestX25519KeyAgreementKey(unittest.TestCase):
    """Test X25519KeyAgreementKey2019."""

    def test_from_dict_multibase(self):
        """Create from multibase dict."""
        from anp.e2e_encryption_hpke.key_pair import (
            generate_x25519_key_pair,
            public_key_to_multibase,
        )

        _, pub = generate_x25519_key_pair()
        multibase = public_key_to_multibase(pub)

        method_dict = {
            "type": "X25519KeyAgreementKey2019",
            "publicKeyMultibase": multibase,
        }

        vm = X25519KeyAgreementKey2019.from_dict(method_dict)
        self.assertIsNotNone(vm)

    def test_verify_signature_raises(self):
        """verify_signature should raise NotImplementedError."""
        from anp.e2e_encryption_hpke.key_pair import (
            generate_x25519_key_pair,
            public_key_to_multibase,
        )

        _, pub = generate_x25519_key_pair()
        multibase = public_key_to_multibase(pub)

        method_dict = {
            "type": "X25519KeyAgreementKey2019",
            "publicKeyMultibase": multibase,
        }

        vm = X25519KeyAgreementKey2019.from_dict(method_dict)
        with self.assertRaises(NotImplementedError):
            vm.verify_signature(b"test", "sig")

    def test_encode_signature_raises(self):
        """encode_signature should raise NotImplementedError."""
        with self.assertRaises(NotImplementedError):
            X25519KeyAgreementKey2019.encode_signature(b"test")

    def test_factory_creates_x25519(self):
        """create_verification_method should handle X25519KeyAgreementKey2019."""
        from anp.e2e_encryption_hpke.key_pair import (
            generate_x25519_key_pair,
            public_key_to_multibase,
        )

        _, pub = generate_x25519_key_pair()
        multibase = public_key_to_multibase(pub)

        method_dict = {
            "type": "X25519KeyAgreementKey2019",
            "publicKeyMultibase": multibase,
        }

        vm = create_verification_method(method_dict)
        self.assertIsInstance(vm, X25519KeyAgreementKey2019)

    def test_from_dict_no_multibase_raises(self):
        """Missing publicKeyMultibase should raise ValueError."""
        method_dict = {
            "type": "X25519KeyAgreementKey2019",
            "publicKeyJwk": {"kty": "OKP"},
        }
        with self.assertRaises(ValueError):
            X25519KeyAgreementKey2019.from_dict(method_dict)


if __name__ == "__main__":
    unittest.main()
