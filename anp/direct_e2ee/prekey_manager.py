"""Prekey helpers for direct_e2ee."""

from __future__ import annotations

import base64
import time
from typing import Any, Callable, Dict, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from anp.authentication.did_wba import _extract_public_key
from anp.e2e_encryption_hpke.key_pair import extract_x25519_public_key_from_did_document
from anp.proof import generate_w3c_proof, verify_w3c_proof

from .errors import DirectE2eeError
from .models import MTI_DIRECT_E2EE_SUITE, PrekeyBundle, SignedPrekey
from .store import FileSignedPrekeyStore

RPCClient = Callable[[str, Dict[str, Any]], Dict[str, Any]]


def _b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class PrekeyManager:
    """Manage signed prekeys and bundle publication."""

    def __init__(
        self,
        local_did: str,
        static_key_agreement_id: str,
        signing_private_key: ed25519.Ed25519PrivateKey,
        signing_verification_method: str,
        signed_prekey_store: FileSignedPrekeyStore,
        rpc_client: Optional[RPCClient] = None,
    ) -> None:
        self._local_did = local_did
        self._static_key_agreement_id = static_key_agreement_id
        self._signing_private_key = signing_private_key
        self._signing_verification_method = signing_verification_method
        self._signed_prekey_store = signed_prekey_store
        self._rpc_client = rpc_client

    def generate_signed_prekey(
        self,
        key_id: str,
        expires_at: str,
    ) -> tuple[X25519PrivateKey, SignedPrekey]:
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes_raw()
        metadata = SignedPrekey(
            key_id=key_id,
            public_key_b64u=_b64u_encode(public_key),
            expires_at=expires_at,
        )
        self._signed_prekey_store.save_signed_prekey(key_id, private_key, metadata)
        return private_key, metadata

    def build_prekey_bundle(
        self,
        signed_prekey: SignedPrekey,
        bundle_id: Optional[str] = None,
        created: Optional[str] = None,
    ) -> PrekeyBundle:
        bundle_id = bundle_id or f"spk-{int(time.time())}-{signed_prekey.key_id}"
        unsigned_bundle = {
            "bundle_id": bundle_id,
            "owner_did": self._local_did,
            "suite": MTI_DIRECT_E2EE_SUITE,
            "static_key_agreement_id": self._static_key_agreement_id,
            "signed_prekey": signed_prekey.to_dict(),
        }
        signed_bundle = generate_w3c_proof(
            unsigned_bundle,
            self._signing_private_key,
            self._signing_verification_method,
            proof_purpose="assertionMethod",
            created=created,
        )
        return PrekeyBundle(
            bundle_id=bundle_id,
            owner_did=self._local_did,
            suite=MTI_DIRECT_E2EE_SUITE,
            static_key_agreement_id=self._static_key_agreement_id,
            signed_prekey=signed_prekey,
            proof=signed_bundle["proof"],
        )

    def publish_prekey_bundle(self, bundle: PrekeyBundle) -> Dict[str, Any]:
        if self._rpc_client is None:
            raise DirectE2eeError("RPC client is not configured", "rpc_unavailable")
        return self._rpc_client(
            "direct.e2ee.publish_prekey_bundle",
            {
                "meta": {
                    "anp_version": "1.0",
                    "profile": "anp.direct.e2ee.v1",
                    "security_profile": "transport-protected",
                    "sender_did": self._local_did,
                    "operation_id": f"op-publish-{bundle.bundle_id}",
                },
                "body": {
                    "prekey_bundle": bundle.to_dict(),
                },
            },
        )

    def ensure_fresh_prekey_bundle(self) -> PrekeyBundle:
        latest = self._signed_prekey_store.load_latest_signed_prekey()
        if latest is None:
            _, signed_prekey = self.generate_signed_prekey(
                "spk-initial",
                "2030-01-01T00:00:00Z",
            )
            bundle = self.build_prekey_bundle(signed_prekey)
            if self._rpc_client is not None:
                self.publish_prekey_bundle(bundle)
            return bundle
        _, metadata = latest
        bundle = self.build_prekey_bundle(metadata)
        if self._rpc_client is not None:
            self.publish_prekey_bundle(bundle)
        return bundle

    @staticmethod
    def verify_prekey_bundle(bundle: PrekeyBundle, did_document: Dict[str, Any]) -> None:
        key_agreement_ids = {
            item if isinstance(item, str) else item.get("id")
            for item in did_document.get("keyAgreement", [])
        }
        if bundle.static_key_agreement_id not in key_agreement_ids:
            raise DirectE2eeError(
                "static_key_agreement_id must appear in DID document keyAgreement",
                "bundle_invalid",
            )
        verification_method = bundle.proof.get("verificationMethod")
        if not verification_method:
            raise DirectE2eeError("proof.verificationMethod is required", "bundle_invalid")
        vm_entry = next(
            (
                entry
                for entry in did_document.get("verificationMethod", [])
                if isinstance(entry, dict) and entry.get("id") == verification_method
            ),
            None,
        )
        if vm_entry is None:
            raise DirectE2eeError("proof verificationMethod not found", "bundle_invalid")
        public_key = _extract_public_key(vm_entry)
        if not verify_w3c_proof(bundle.to_dict(), public_key):
            raise DirectE2eeError("bundle proof verification failed", "bundle_invalid")

    @staticmethod
    def extract_recipient_static_key(
        did_document: Dict[str, Any],
        key_id: str,
    ) -> tuple[X25519PublicKey, str]:
        return extract_x25519_public_key_from_did_document(did_document, key_id)
