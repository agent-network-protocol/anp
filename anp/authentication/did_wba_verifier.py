"""SDK entry for DID-WBA verification and Bearer JWT handling.

This module provides a framework-agnostic verifier class that can:
- Verify new DID-WBA HTTP Message Signatures requests
- Verify legacy DIDWba Authorization headers
- Issue JWT access tokens upon successful DID verification
- Verify Bearer JWT tokens
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import jwt

from .did_wba import (
    extract_auth_header_parts,
    resolve_did_wba_document,
    validate_did_document_binding,
    verify_auth_header_signature,
)
from .http_signatures import extract_signature_metadata, verify_http_message_signature

logger = logging.getLogger(__name__)


class DidWbaVerifierError(Exception):
    """Domain error carrying an HTTP-like status code."""

    def __init__(
        self,
        message: str,
        status_code: int = 400,
        headers: Optional[dict[str, str]] = None,
    ):
        super().__init__(message)
        self.status_code = status_code
        self.headers = headers or {}


@dataclass
class DidWbaVerifierConfig:
    """Configuration for DidWbaVerifier."""

    jwt_private_key: str | None = None
    jwt_public_key: str | None = None
    jwt_algorithm: str = "RS256"
    access_token_expire_minutes: int = 60

    nonce_expiration_minutes: int = 6
    timestamp_expiration_minutes: int = 5

    external_nonce_validator: Callable[[str, str], Any] | None = None

    allowed_domains: list[str] | None = None
    allow_http_signatures: bool = True
    allow_legacy_didwba: bool = True
    emit_authentication_info_header: bool = True
    emit_legacy_authorization_header: bool = True
    require_nonce_for_http_signatures: bool = True


class DidWbaVerifier:
    """Verify DID-WBA authentication requests and Bearer tokens."""

    def __init__(self, config: DidWbaVerifierConfig | None = None):
        self.config = config or DidWbaVerifierConfig()
        self._valid_server_nonces: dict[str, datetime] = {}

    @staticmethod
    def _get_header_case_insensitive(
        headers: dict[str, str], name: str
    ) -> Optional[str]:
        lower_name = name.lower()
        for key, value in headers.items():
            if key.lower() == lower_name:
                return value
        return None

    @staticmethod
    def _normalize_headers(headers: Any) -> dict[str, str]:
        if headers is None:
            return {}
        return {str(key): str(value) for key, value in dict(headers).items()}

    @staticmethod
    def _extract_domain_from_url(url: str) -> str:
        parsed = urlparse(url)
        return parsed.hostname or parsed.netloc.split(":")[0]

    @staticmethod
    def _build_authentication_info(token: str, expires_in_seconds: int) -> str:
        return (
            f'access_token="{token}", '
            f'token_type="Bearer", '
            f"expires_in={expires_in_seconds}"
        )

    def _build_success_result(
        self,
        did: str,
        auth_scheme: str,
        access_token: Optional[str] = None,
    ) -> dict[str, Any]:
        response_headers: dict[str, str] = {}
        if access_token is not None:
            expires_in_seconds = self.config.access_token_expire_minutes * 60
            if self.config.emit_authentication_info_header:
                response_headers["Authentication-Info"] = self._build_authentication_info(
                    access_token,
                    expires_in_seconds,
                )
            if self.config.emit_legacy_authorization_header:
                response_headers["Authorization"] = f"Bearer {access_token}"

        result: dict[str, Any] = {
            "did": did,
            "auth_scheme": auth_scheme,
            "response_headers": response_headers,
        }
        if access_token is not None:
            result["access_token"] = access_token
            result["token_type"] = "bearer"
        return result

    def _build_challenge_headers(
        self,
        domain: str,
        error: str,
        description: str,
    ) -> dict[str, str]:
        headers = {
            "WWW-Authenticate": (
                f'DIDWba realm="{domain}", '
                f'error="{error}", '
                f'error_description="{description}"'
            )
        }
        if self.config.allow_http_signatures:
            headers["Accept-Signature"] = (
                'sig1=("@method" "@target-uri" "@authority" "content-digest");'
                'created;expires;nonce;keyid'
            )
        return headers

    def _is_authentication_authorized(
        self, did_document: dict[str, Any], verification_method_id: str
    ) -> bool:
        authentication = did_document.get("authentication", [])
        verification_methods = {
            vm.get("id"): vm
            for vm in did_document.get("verificationMethod", [])
            if isinstance(vm, dict) and vm.get("id")
        }
        for entry in authentication:
            if isinstance(entry, str) and entry == verification_method_id:
                return True
            if isinstance(entry, dict) and entry.get("id") == verification_method_id:
                return True
            if isinstance(entry, str) and entry in verification_methods and entry == verification_method_id:
                return True
        return False

    def _validate_did_binding(self, did_document: dict[str, Any]) -> None:
        if validate_did_document_binding(did_document):
            return
        raise DidWbaVerifierError(
            "DID binding verification failed",
            status_code=401,
        )

    def _verify_legacy_timestamp(self, timestamp_str: str) -> bool:
        try:
            request_time = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            current_time = datetime.now(timezone.utc)
            if request_time - current_time > timedelta(minutes=1):
                return False
            if (
                current_time - request_time
                > timedelta(minutes=self.config.timestamp_expiration_minutes)
            ):
                return False
            return True
        except Exception as exc:
            logger.error("Error verifying legacy timestamp: %s", exc)
            return False

    def _verify_http_signature_time_window(
        self, created: int, expires: Optional[int]
    ) -> bool:
        current_timestamp = int(datetime.now(timezone.utc).timestamp())
        if created > current_timestamp + 60:
            return False
        if current_timestamp - created > self.config.timestamp_expiration_minutes * 60:
            return False
        if expires is not None and expires < current_timestamp:
            return False
        return True

    async def _is_valid_server_nonce(self, did: str, nonce: str) -> bool:
        validator = self.config.external_nonce_validator
        if validator is not None:
            try:
                result = validator(did, nonce)
                if inspect.isawaitable(result):
                    result = await result
                return bool(result)
            except Exception as exc:
                logger.error("External nonce validator error: %s", exc)
                return False

        current_time = datetime.now(timezone.utc)
        expired = [
            key
            for key, issued_at in self._valid_server_nonces.items()
            if current_time - issued_at
            > timedelta(minutes=self.config.nonce_expiration_minutes)
        ]
        for key in expired:
            del self._valid_server_nonces[key]

        cache_key = f"{did}:{nonce}"
        if cache_key in self._valid_server_nonces:
            logger.warning("Nonce already used for DID %s", did)
            return False

        self._valid_server_nonces[cache_key] = current_time
        return True

    async def verify_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | str | None = None,
        domain: Optional[str] = None,
    ) -> dict[str, Any]:
        """Verify an HTTP request carrying DID-WBA authentication."""
        normalized_headers = self._normalize_headers(headers)
        auth_header = self._get_header_case_insensitive(normalized_headers, "Authorization")
        signature_input = self._get_header_case_insensitive(
            normalized_headers, "Signature-Input"
        )
        signature_header = self._get_header_case_insensitive(normalized_headers, "Signature")
        request_domain = domain or self._extract_domain_from_url(url)

        if auth_header and auth_header.startswith("Bearer "):
            return self._handle_bearer_auth(auth_header)

        if signature_input or signature_header:
            if not self.config.allow_http_signatures:
                raise DidWbaVerifierError(
                    "HTTP Message Signatures authentication is disabled",
                    status_code=401,
                    headers=self._build_challenge_headers(
                        request_domain,
                        "invalid_request",
                        "HTTP Message Signatures authentication is disabled.",
                    ),
                )
            return await self._handle_http_signature_auth(
                method=method,
                url=url,
                headers=normalized_headers,
                body=body,
                domain=request_domain,
            )

        if auth_header:
            if not self.config.allow_legacy_didwba:
                raise DidWbaVerifierError(
                    "Legacy DIDWba authentication is disabled",
                    status_code=401,
                    headers=self._build_challenge_headers(
                        request_domain,
                        "invalid_request",
                        "Legacy DIDWba authentication is disabled.",
                    ),
                )
            return await self._handle_legacy_did_auth(auth_header, request_domain)

        raise DidWbaVerifierError("Missing authentication headers", status_code=401)

    async def verify_auth_header(
        self, authorization: str, domain: str
    ) -> dict[str, Any]:
        """Backward-compatible wrapper for Authorization-only verification."""
        return await self.verify_request(
            method="GET",
            url=f"https://{domain}/",
            headers={"Authorization": authorization},
            body=b"",
            domain=domain,
        )

    async def _handle_http_signature_auth(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | str | None,
        domain: str,
    ) -> dict[str, Any]:
        try:
            metadata = extract_signature_metadata(headers)
            params = metadata["params"]
            keyid = params.get("keyid")
            if not isinstance(keyid, str) or "#" not in keyid:
                raise DidWbaVerifierError(
                    "Invalid Signature-Input keyid",
                    status_code=401,
                    headers=self._build_challenge_headers(
                        domain,
                        "invalid_verification_method",
                        "Signature-Input keyid is missing or invalid.",
                    ),
                )
            did = keyid.split("#", 1)[0]
        except DidWbaVerifierError:
            raise
        except Exception as exc:
            raise DidWbaVerifierError(
                f"Invalid signature metadata: {exc}",
                status_code=401,
                headers=self._build_challenge_headers(
                    domain,
                    "invalid_request",
                    "Signature metadata is invalid.",
                ),
            ) from exc

        did_document = await resolve_did_wba_document(did)
        if not did_document:
            raise DidWbaVerifierError(
                "Failed to resolve DID document",
                status_code=401,
                headers=self._build_challenge_headers(
                    domain,
                    "invalid_did",
                    "Failed to resolve DID document.",
                ),
            )

        self._validate_did_binding(did_document)
        if not self._is_authentication_authorized(did_document, keyid):
            raise DidWbaVerifierError(
                "Verification method is not authorized for authentication",
                status_code=403,
            )

        is_valid, message, verification_result = verify_http_message_signature(
            did_document=did_document,
            request_method=method,
            request_url=url,
            headers=headers,
            body=body,
        )
        if not is_valid:
            raise DidWbaVerifierError(
                message,
                status_code=401,
                headers=self._build_challenge_headers(
                    domain,
                    "invalid_signature",
                    message,
                ),
            )

        created = verification_result.get("created")
        expires = verification_result.get("expires")
        nonce = verification_result.get("nonce")
        if not self._verify_http_signature_time_window(created, expires):
            raise DidWbaVerifierError(
                "HTTP signature timestamp is expired or invalid",
                status_code=401,
                headers=self._build_challenge_headers(
                    domain,
                    "invalid_timestamp",
                    "HTTP signature timestamp is expired or invalid.",
                ),
            )
        if self.config.require_nonce_for_http_signatures and not nonce:
            raise DidWbaVerifierError(
                "HTTP signature nonce is required",
                status_code=401,
                headers=self._build_challenge_headers(
                    domain,
                    "invalid_nonce",
                    "HTTP signature nonce is required.",
                ),
            )
        if nonce and not await self._is_valid_server_nonce(did, nonce):
            raise DidWbaVerifierError(
                "Invalid or expired nonce",
                status_code=401,
                headers=self._build_challenge_headers(
                    domain,
                    "invalid_nonce",
                    "Nonce has already been used or expired.",
                ),
            )

        access_token = self._create_access_token({"sub": did})
        return self._build_success_result(
            did=did,
            auth_scheme="http_signatures",
            access_token=access_token,
        )

    async def _handle_legacy_did_auth(
        self, authorization: str, domain: str
    ) -> dict[str, Any]:
        try:
            header_parts = extract_auth_header_parts(authorization)
        except ValueError as exc:
            raise DidWbaVerifierError(
                "Invalid authorization header format",
                status_code=401,
                headers=self._build_challenge_headers(
                    domain,
                    "invalid_request",
                    "Legacy DIDWba authorization header format is invalid.",
                ),
            ) from exc
        if not header_parts:
            raise DidWbaVerifierError("Invalid authorization header format", status_code=401)

        did, nonce, timestamp, verification_method, _, _ = header_parts
        if not self._verify_legacy_timestamp(timestamp):
            raise DidWbaVerifierError(
                "Timestamp expired or invalid",
                status_code=401,
                headers=self._build_challenge_headers(
                    domain,
                    "invalid_timestamp",
                    "Legacy DIDWba timestamp is expired or invalid.",
                ),
            )
        if not await self._is_valid_server_nonce(did, nonce):
            raise DidWbaVerifierError(
                "Invalid or expired nonce",
                status_code=401,
                headers=self._build_challenge_headers(
                    domain,
                    "invalid_nonce",
                    "Legacy DIDWba nonce has already been used or expired.",
                ),
            )

        did_document = await resolve_did_wba_document(did)
        if not did_document:
            raise DidWbaVerifierError(
                "Failed to resolve DID document",
                status_code=401,
                headers=self._build_challenge_headers(
                    domain,
                    "invalid_did",
                    "Failed to resolve DID document.",
                ),
            )

        self._validate_did_binding(did_document)
        keyid = f"{did}#{verification_method}"
        if not self._is_authentication_authorized(did_document, keyid):
            raise DidWbaVerifierError(
                "Verification method is not authorized for authentication",
                status_code=403,
            )

        try:
            is_valid, message = verify_auth_header_signature(
                auth_header=authorization,
                did_document=did_document,
                service_domain=domain,
            )
        except Exception as exc:
            raise DidWbaVerifierError(
                f"Error verifying signature: {exc}",
                status_code=401,
                headers=self._build_challenge_headers(
                    domain,
                    "invalid_signature",
                    "Legacy DIDWba signature verification failed.",
                ),
            ) from exc
        if not is_valid:
            raise DidWbaVerifierError(
                f"Invalid signature: {message}",
                status_code=403,
                headers=self._build_challenge_headers(
                    domain,
                    "invalid_signature",
                    message,
                ),
            )

        access_token = self._create_access_token({"sub": did})
        return self._build_success_result(
            did=did,
            auth_scheme="legacy_didwba",
            access_token=access_token,
        )

    def _create_access_token(
        self, data: dict[str, Any], expires_delta: timedelta | None = None
    ) -> str:
        if not self.config.jwt_private_key:
            raise DidWbaVerifierError(
                "Internal server error during token generation",
                status_code=500,
            )

        payload = data.copy()
        now = datetime.now(timezone.utc)
        payload.update({"iat": now})
        exp = now + (
            expires_delta or timedelta(minutes=self.config.access_token_expire_minutes)
        )
        payload.update({"exp": exp})
        return jwt.encode(
            payload,
            self.config.jwt_private_key,
            algorithm=self.config.jwt_algorithm,
        )

    def _handle_bearer_auth(self, token_header_value: str) -> dict[str, Any]:
        try:
            token = (
                token_header_value[7:]
                if token_header_value.startswith("Bearer ")
                else token_header_value
            )
            if not self.config.jwt_public_key:
                raise DidWbaVerifierError(
                    "Internal server error during token verification",
                    status_code=500,
                )

            payload = jwt.decode(
                token,
                self.config.jwt_public_key,
                algorithms=[self.config.jwt_algorithm],
            )
            for claim in ("sub", "iat", "exp"):
                if claim not in payload:
                    raise DidWbaVerifierError(
                        f"Invalid token payload: missing '{claim}' field",
                        status_code=401,
                    )

            did = payload["sub"]
            if not isinstance(did, str) or not did.startswith("did:wba:"):
                raise DidWbaVerifierError("Invalid DID format", status_code=401)

            now = datetime.now(timezone.utc)
            issued_at = (
                datetime.fromtimestamp(payload["iat"], tz=timezone.utc)
                if isinstance(payload["iat"], (int, float))
                else payload["iat"]
            )
            expires_at = (
                datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
                if isinstance(payload["exp"], (int, float))
                else payload["exp"]
            )
            tolerance = timedelta(seconds=5)
            if issued_at > now + tolerance:
                raise DidWbaVerifierError("Token issued in the future", status_code=401)
            if expires_at <= now - tolerance:
                raise DidWbaVerifierError("Token has expired", status_code=401)
            return self._build_success_result(did=did, auth_scheme="bearer")
        except DidWbaVerifierError:
            raise
        except jwt.ExpiredSignatureError as exc:
            logger.error("JWT token has expired")
            raise DidWbaVerifierError("Token has expired", status_code=401) from exc
        except jwt.InvalidTokenError as exc:
            logger.error("JWT token error: %s", exc)
            raise DidWbaVerifierError("Invalid token", status_code=401) from exc
        except Exception as exc:
            logger.error("Error during token authentication: %s", exc)
            raise DidWbaVerifierError("Authentication error", status_code=500) from exc
