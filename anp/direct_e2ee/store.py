"""File-backed stores for Direct E2EE state."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .errors import DirectE2eeError
from .models import DirectSessionState, SignedPrekey


class FileSessionStore:
    """Persist direct E2EE sessions as JSON files."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def save_session(self, session: DirectSessionState) -> None:
        path = self._root / f"{session.session_id}.json"
        path.write_text(json.dumps(session.to_dict(), ensure_ascii=False, indent=2))

    def load_session(self, session_id: str) -> DirectSessionState:
        path = self._root / f"{session_id}.json"
        if not path.exists():
            raise DirectE2eeError(f"Session not found: {session_id}", "session_not_found")
        return DirectSessionState.from_dict(json.loads(path.read_text()))

    def delete_session(self, session_id: str) -> None:
        path = self._root / f"{session_id}.json"
        if path.exists():
            path.unlink()

    def find_by_peer_did(self, peer_did: str) -> Optional[DirectSessionState]:
        for path in self._root.glob("*.json"):
            data = json.loads(path.read_text())
            if data.get("peer_did") == peer_did:
                return DirectSessionState.from_dict(data)
        return None


class FileSignedPrekeyStore:
    """Persist signed prekeys and metadata to disk."""

    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def save_signed_prekey(
        self,
        key_id: str,
        private_key: X25519PrivateKey,
        metadata: SignedPrekey,
    ) -> None:
        (self._root / f"{key_id}.pem").write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        (self._root / f"{key_id}.json").write_text(
            json.dumps(metadata.to_dict(), ensure_ascii=False, indent=2)
        )
        (self._root / "latest.txt").write_text(key_id)

    def load_signed_prekey(self, key_id: str) -> Tuple[X25519PrivateKey, SignedPrekey]:
        pem_path = self._root / f"{key_id}.pem"
        meta_path = self._root / f"{key_id}.json"
        if not pem_path.exists() or not meta_path.exists():
            raise DirectE2eeError(f"Signed prekey not found: {key_id}", "signed_prekey_not_found")
        private_key = serialization.load_pem_private_key(
            pem_path.read_bytes(),
            password=None,
        )
        if not isinstance(private_key, X25519PrivateKey):
            raise DirectE2eeError(
                f"Stored key is not X25519: {key_id}",
                "signed_prekey_invalid",
            )
        return private_key, SignedPrekey(**json.loads(meta_path.read_text()))

    def load_latest_signed_prekey(self) -> Optional[Tuple[X25519PrivateKey, SignedPrekey]]:
        latest_path = self._root / "latest.txt"
        if not latest_path.exists():
            return None
        return self.load_signed_prekey(latest_path.read_text().strip())
