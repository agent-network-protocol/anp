"""
SDK entry for DID WBA verification and Bearer JWT handling.

This module provides a framework-agnostic verifier class that:
- Verifies DID WBA Authorization headers (nonce, timestamp, signature)
- Issues JWT access tokens upon successful DID verification
- Verifies Bearer JWT tokens

All configuration is passed in via constructor arguments. No application-level
configuration or framework primitives (e.g., FastAPI Request) are used here.
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

# External DID WBA auth helpers (3rd-party dependency)
from agent_connect.authentication import (
    extract_auth_header_parts,
    resolve_did_wba_document,
    verify_auth_header_signature,
)

logger = logging.getLogger(__name__)


class DidWbaVerifierError(Exception):
    """Domain error carrying an HTTP-like status code."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


@dataclass
class DidWbaVerifierConfig:
    """Configuration for DidWbaVerifier.

    All fields are optional; sensible defaults are applied when omitted.
    Keys should be provided as PEM strings when signing/verifying JWTs.
    """

    # JWT configuration
    jwt_private_key: str | None = None
    jwt_public_key: str | None = None
    jwt_algorithm: str = "RS256"
    access_token_expire_minutes: int = 60

    # DID timestamp/nonce verification
    # Nonce expiration cleanup time should generally be one minute longer than timestamp timeout to prevent boundary condition attacks
    nonce_expiration_minutes: int = 6
    timestamp_expiration_minutes: int = 5

    # Optional external nonce validator callback: (did:str, nonce:str) -> bool | Awaitable[bool]
    external_nonce_validator: Callable[[str, str], Any] | None = None


class DidWbaVerifier:
    """Verify Authorization headers for DID WBA and Bearer JWT.

    Usage:
        verifier = DidWbaVerifier(
            DidWbaVerifierConfig(
                jwt_private_key=...,  # PEM string
                jwt_public_key=...,   # PEM string
                jwt_algorithm="RS256",
                access_token_expire_minutes=60,
                nonce_expiration_minutes=5,
                timestamp_expiration_minutes=5,
            )
        )

        # DID WBA header verification → issues JWT on success
        result = await verifier.verify_auth_header(authorization, domain)
    """

    def __init__(self, config: DidWbaVerifierConfig | None = None):
        self.config = config or DidWbaVerifierConfig()
        # Track server nonces to prevent replay (per verifier instance)
        self._valid_server_nonces: dict[str, datetime] = {}

    # ------------------------
    # Public API
    # ------------------------
    async def verify_auth_header(
        self, authorization: str, domain: str
    ) -> dict[str, Any]:
        """Verify an HTTP Authorization header.

        - If header starts with "Bearer ", validate the JWT and return {"did": ...}.
        - Otherwise, treat as DID WBA header, validate, issue JWT, and return
          {"access_token": token, "token_type": "bearer", "did": did}.

        Args:
            authorization: Full Authorization header value
            domain: Service domain used during DID signature verification

        Returns:
            Dict with verification result

        Raises:
            DidWbaVerifierError: On verification failures
        """
        if not authorization:
            raise DidWbaVerifierError("Missing authorization header", status_code=401)

        if authorization.startswith("Bearer "):
            return self._handle_bearer_auth(authorization)

        return await self._handle_did_auth(authorization, domain)

    # ------------------------
    # DID WBA flow
    # ------------------------
    async def _handle_did_auth(self, authorization: str, domain: str) -> dict[str, Any]:
        logger.info(
            "Processing DID WBA authentication - domain: %s, Authorization header: %s",
            domain,
            authorization,
        )

        # Extract header parts
        header_parts = extract_auth_header_parts(authorization)
        if not header_parts:
            raise DidWbaVerifierError(
                "Invalid authorization header format", status_code=401
            )

        # Unpack order: (did, nonce, timestamp, verification_method, signature)
        did, nonce, timestamp, verification_method, signature = header_parts
        logger.info(
            "Processing DID WBA authentication - DID: %s, Verification Method: %s",
            did,
            verification_method,
        )

        # Verify timestamp
        if not self._verify_timestamp(timestamp):
            raise DidWbaVerifierError("Timestamp expired or invalid", status_code=401)

        # Verify nonce validity (external preferred; falls back to internal)
        if not await self._is_valid_server_nonce(did, nonce):
            logger.error("Invalid or expired nonce: %s", nonce)
            raise DidWbaVerifierError("Invalid or expired nonce", status_code=401)

        # Resolve DID document
        did_document = await resolve_did_wba_document(did)
        if not did_document:
            raise DidWbaVerifierError("Failed to resolve DID document", status_code=401)

        logger.info("Successfully resolved DID document: %s", did)

        # Verify signature
        try:
            is_valid, message = verify_auth_header_signature(
                auth_header=authorization,
                did_document=did_document,
                service_domain=domain,
            )
            logger.info(
                "Signature verification result: %s, message: %s", is_valid, message
            )
            if not is_valid:
                raise DidWbaVerifierError(
                    f"Invalid signature: {message}", status_code=401
                )
        except DidWbaVerifierError:
            raise
        except Exception as exc:  # Defensive: wrap any unforeseen issues
            logger.error("Error verifying signature: %s", exc)
            raise DidWbaVerifierError(
                f"Error verifying signature: {exc}", status_code=401
            )

        # Generate access token
        access_token = self._create_access_token(data={"sub": did})
        logger.info("Authentication successful, access token generated")

        return {"access_token": access_token, "token_type": "bearer", "did": did}

    def _verify_timestamp(self, timestamp_str: str) -> bool:
        """Verify if a timestamp is within the allowed period."""
        try:
            request_time = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            current_time = datetime.now(UTC)
            # Reject timestamps too far in the future (> 1 minute ahead of server time)
            if request_time - current_time > timedelta(minutes=1):
                logger.error(
                    "Timestamp is too far in the future. Current: %s, Request: %s, Ahead by: %s seconds",
                    current_time,
                    request_time,
                    (request_time - current_time).total_seconds(),
                )
                return False

            # Expired if older than configured window
            past_diff = current_time - request_time
            if past_diff > timedelta(minutes=self.config.timestamp_expiration_minutes):
                logger.error(
                    "Timestamp expired. Current: %s, Request: %s, Older by: %s seconds",
                    current_time,
                    request_time,
                    past_diff.total_seconds(),
                )
                return False

            return True
        except Exception as exc:
            logger.error("Error verifying timestamp: %s", exc)
            return False

    async def _is_valid_server_nonce(self, did: str, nonce: str) -> bool:
        """Validate nonce via external callback if provided; otherwise use internal one-time check.

        - If external validator exists, only it is used.
        - If not, perform internal anti-replay check and mark nonce as used.
        """
        validator = self.config.external_nonce_validator
        if validator is not None:
            try:
                result = validator(did, nonce)
                if inspect.isawaitable(result):
                    result = await result
                accepted = bool(result)
                if accepted:
                    logger.info(
                        "External nonce validator accepted nonce: %s for DID: %s",
                        nonce,
                        did,
                    )
                else:
                    logger.warning(
                        "External nonce validator rejected nonce: %s for DID: %s",
                        nonce,
                        did,
                    )
                return accepted
            except Exception as exc:
                logger.error("External nonce validator error: %s", exc)
                return False

        # Internal validation path
        current_time = datetime.now(UTC)

        # Clean up expired nonces
        expired = [
            n
            for n, t in self._valid_server_nonces.items()
            if current_time - t
            > timedelta(minutes=self.config.nonce_expiration_minutes)
        ]
        for n in expired:
            del self._valid_server_nonces[n]

        # If nonce was already used, reject it
        if nonce in self._valid_server_nonces:
            logger.warning("Nonce already used: %s", nonce)
            return False

        # Mark nonce as used
        self._valid_server_nonces[nonce] = current_time
        logger.info("Nonce accepted and marked as used: %s", nonce)
        return True

    # ------------------------
    # JWT flow
    # ------------------------
    def _create_access_token(
        self, data: dict[str, Any], expires_delta: timedelta | None = None
    ) -> str:
        """Create a new JWT access token (RS256 by default)."""
        if not self.config.jwt_private_key:
            logger.error("Failed to load JWT private key")
            raise DidWbaVerifierError(
                "Internal server error during token generation", status_code=500
            )

        payload = data.copy()
        now = datetime.now(UTC)
        payload.update({"iat": now})
        exp = now + (
            expires_delta or timedelta(minutes=self.config.access_token_expire_minutes)
        )
        payload.update({"exp": exp})

        token = jwt.encode(
            payload, self.config.jwt_private_key, algorithm=self.config.jwt_algorithm
        )
        return token

    def _handle_bearer_auth(self, token_header_value: str) -> dict[str, Any]:
        """Validate a Bearer token and return DID information."""
        try:
            token = (
                token_header_value[7:]
                if token_header_value.startswith("Bearer ")
                else token_header_value
            )

            if not self.config.jwt_public_key:
                logger.error("Failed to load JWT public key")
                raise DidWbaVerifierError(
                    "Internal server error during token verification", status_code=500
                )

            payload = jwt.decode(
                token,
                self.config.jwt_public_key,
                algorithms=[self.config.jwt_algorithm],
            )

            # Basic claims validation
            for claim in ("sub", "iat", "exp"):
                if claim not in payload:
                    raise DidWbaVerifierError(
                        f"Invalid token payload: missing '{claim}' field",
                        status_code=401,
                    )

            did = payload["sub"]
            if not isinstance(did, str) or not did.startswith("did:wba:"):
                raise DidWbaVerifierError("Invalid DID format", status_code=401)

            # Additional time validation (PyJWT already checks exp)
            now = datetime.now(UTC)
            issued_at = (
                datetime.fromtimestamp(payload["iat"], tz=UTC)
                if isinstance(payload["iat"], int | float)
                else payload["iat"]
            )
            expires_at = (
                datetime.fromtimestamp(payload["exp"], tz=UTC)
                if isinstance(payload["exp"], int | float)
                else payload["exp"]
            )

            tolerance = timedelta(seconds=5)
            if issued_at > now + tolerance:
                raise DidWbaVerifierError("Token issued in the future", status_code=401)
            if expires_at <= now - tolerance:
                raise DidWbaVerifierError("Token has expired", status_code=401)

            return {"did": did}

        except DidWbaVerifierError:
            raise
        except jwt.ExpiredSignatureError:
            logger.error("JWT token has expired")
            raise DidWbaVerifierError("Token has expired", status_code=401)
        except jwt.InvalidTokenError as exc:
            logger.error("JWT token error: %s", exc)
            raise DidWbaVerifierError("Invalid token", status_code=401)
        except Exception as exc:
            logger.error("Error during token authentication: %s", exc)
            raise DidWbaVerifierError("Authentication error", status_code=500)
