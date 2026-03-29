# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import logging
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from .did_wba import generate_auth_header
from .http_signatures import generate_http_signature_headers


class DIDWbaAuthHeader:
    """Client helper for DID-WBA authentication headers and token caching."""

    def __init__(
        self,
        did_document_path: str,
        private_key_path: str,
        auth_mode: str = "http_signatures",
    ):
        """Initialize the DID authentication client.

        Args:
            did_document_path: Path to the DID document file.
            private_key_path: Path to the private key file.
            auth_mode: Authentication mode. Supported values are:
                - "http_signatures": Use HTTP Message Signatures (default)
                - "legacy_didwba": Use the legacy Authorization header scheme
                - "auto": Alias of "http_signatures" for forward compatibility
        """
        self.did_document_path = did_document_path
        self.private_key_path = private_key_path
        self.auth_mode = auth_mode

        self.did_document = None
        self.tokens: Dict[str, str] = {}

        logging.info("DIDWbaAuthHeader initialized with auth mode %s", auth_mode)

    def _get_domain(self, server_url: str) -> str:
        """Extract domain from URL."""
        parsed_url = urlparse(server_url)
        return parsed_url.netloc.split(":")[0]

    @staticmethod
    def _get_header_case_insensitive(
        headers: Dict[str, str], name: str
    ) -> Optional[str]:
        lower_name = name.lower()
        for key, value in headers.items():
            if key.lower() == lower_name:
                return value
        return None

    def _load_did_document(self) -> Dict[str, Any]:
        """Load and cache the DID document from disk."""
        if self.did_document is not None:
            return self.did_document

        try:
            with open(self.did_document_path, "r", encoding="utf-8") as file_obj:
                import json

                self.did_document = json.load(file_obj)
            logging.info("Loaded DID document from %s", self.did_document_path)
            return self.did_document
        except Exception as exc:
            logging.error("Error loading DID document: %s", exc)
            raise

    def _load_private_key(self) -> Any:
        """Load the private key from disk."""
        try:
            with open(self.private_key_path, "rb") as file_obj:
                private_key_data = file_obj.read()
            return serialization.load_pem_private_key(private_key_data, password=None)
        except Exception as exc:
            logging.error("Error loading private key: %s", exc)
            raise

    def _sign_callback(self, content: bytes, method_fragment: str) -> bytes:
        """Sign arbitrary bytes with the loaded private key."""
        try:
            private_key = self._load_private_key()
            if isinstance(private_key, ec.EllipticCurvePrivateKey):
                signature = private_key.sign(content, ec.ECDSA(hashes.SHA256()))
            elif isinstance(private_key, ed25519.Ed25519PrivateKey):
                signature = private_key.sign(content)
            else:
                raise TypeError(
                    f"Unsupported private key type: {type(private_key).__name__}"
                )
            logging.debug(
                "Signed authentication content with method fragment %s",
                method_fragment,
            )
            return signature
        except Exception as exc:
            logging.error("Error signing content: %s", exc)
            raise

    def _generate_legacy_auth_header(self, domain: str) -> Dict[str, str]:
        """Generate a legacy DIDWba Authorization header."""
        did_document = self._load_did_document()
        auth_header = generate_auth_header(did_document, domain, self._sign_callback)
        logging.info("Generated legacy DIDWba Authorization header for %s", domain)
        return {"Authorization": auth_header}

    def _generate_http_signature_header(
        self,
        server_url: str,
        method: str,
        headers: Optional[Dict[str, str]] = None,
        body: Any = None,
    ) -> Dict[str, str]:
        """Generate HTTP Message Signatures headers for a request."""
        did_document = self._load_did_document()
        auth_headers = generate_http_signature_headers(
            did_document=did_document,
            request_url=server_url,
            request_method=method,
            sign_callback=self._sign_callback,
            headers=headers,
            body=body,
        )
        logging.info("Generated HTTP signature headers for %s %s", method, server_url)
        return auth_headers

    def get_auth_header(
        self,
        server_url: str,
        force_new: bool = False,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Any = None,
    ) -> Dict[str, str]:
        """Get authentication headers for a request.

        When a token is cached and force_new is False, this method returns
        an Authorization Bearer header. Otherwise it generates either new HTTP
        signature headers or a legacy DIDWba Authorization header depending on
        auth_mode.
        """
        domain = self._get_domain(server_url)
        if domain in self.tokens and not force_new:
            token = self.tokens[domain]
            logging.info("Using cached Bearer token for %s", domain)
            return {"Authorization": f"Bearer {token}"}

        normalized_mode = self.auth_mode.lower()
        if normalized_mode in {"http_signatures", "auto"}:
            return self._generate_http_signature_header(
                server_url=server_url,
                method=method,
                headers=headers,
                body=body,
            )
        if normalized_mode == "legacy_didwba":
            return self._generate_legacy_auth_header(domain)
        raise ValueError(
            "auth_mode must be one of: http_signatures, legacy_didwba, auto"
        )

    @staticmethod
    def _parse_authentication_info(header_value: str) -> Dict[str, str]:
        """Parse Authentication-Info key/value pairs."""
        import re

        parts = re.findall(r'(\w+)=("[^"]*"|[^,]+)', header_value)
        result: Dict[str, str] = {}
        for key, raw_value in parts:
            value = raw_value.strip()
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            result[key] = value
        return result

    def update_token(self, server_url: str, headers: Dict[str, str]) -> Optional[str]:
        """Update the cached token from response headers."""
        domain = self._get_domain(server_url)

        authentication_info = self._get_header_case_insensitive(
            headers, "Authentication-Info"
        )
        if authentication_info:
            info = self._parse_authentication_info(authentication_info)
            access_token = info.get("access_token")
            token_type = info.get("token_type", "Bearer")
            if access_token and token_type.lower() == "bearer":
                self.tokens[domain] = access_token
                logging.info(
                    "Updated token from Authentication-Info for %s", domain
                )
                return access_token

        auth_header = self._get_header_case_insensitive(headers, "Authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            token = auth_header[7:]
            self.tokens[domain] = token
            logging.info("Updated token from Authorization header for %s", domain)
            return token

        logging.debug("No bearer token found in response headers for %s", domain)
        return None

    def clear_token(self, server_url: str) -> None:
        """Clear token for the specified domain."""
        domain = self._get_domain(server_url)
        if domain in self.tokens:
            del self.tokens[domain]
            logging.info("Cleared token for %s", domain)

    def clear_all_tokens(self) -> None:
        """Clear all cached tokens."""
        self.tokens.clear()
        logging.info("Cleared all cached tokens")
