"""DID WBA HTTP Server Example.

This example demonstrates how to create a FastAPI HTTP server with DID WBA
authentication middleware. The server provides protected API endpoints that
require DID authentication and exempt endpoints for health checks.

Usage:
    uv run python examples/python/did_wba_examples/http_server.py

The server will start on http://localhost:8080 and provide:
- GET /health - Health check endpoint (no auth required)
- GET /api/protected - Protected endpoint (requires DID auth)
- GET /api/user-info - Returns authenticated user info (requires DID auth)
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Callable, Dict

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from anp.authentication import did_wba_verifier as verifier_module
from anp.authentication.did_wba_verifier import DidWbaVerifier, DidWbaVerifierConfig
from anp.openanp.middleware import auth_middleware

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def project_root() -> Path:
    """Return repository root inferred from this file location."""
    return Path(__file__).resolve().parents[3]


def load_text(path: Path) -> str:
    """Read a UTF-8 text file."""
    return path.read_text(encoding="utf-8")


def load_json(path: Path) -> Dict[str, Any]:
    """Load JSON content as a dictionary."""
    return json.loads(load_text(path))


def create_local_did_resolver(did_document: Dict[str, Any]) -> Callable:
    """Create a local DID resolver that returns the provided DID document.

    This is used for offline demonstration purposes.
    """

    async def local_resolver(did: str) -> Dict[str, Any]:
        """Return the static DID document used by this example."""
        if did != did_document["id"]:
            raise ValueError(f"Unsupported DID: {did}")
        return did_document

    return local_resolver


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    root = project_root()
    did_document_path = root / "docs/did_public/public-did-doc.json"
    jwt_private_key_path = root / "docs/jwt_rs256/RS256-private.pem"
    jwt_public_key_path = root / "docs/jwt_rs256/RS256-public.pem"

    did_document = load_json(did_document_path)

    local_resolver = create_local_did_resolver(did_document)
    verifier_module.resolve_did_wba_document = local_resolver  # type: ignore

    config = DidWbaVerifierConfig(
        jwt_private_key=load_text(jwt_private_key_path),
        jwt_public_key=load_text(jwt_public_key_path),
        jwt_algorithm="RS256",
        access_token_expire_minutes=60,
    )
    verifier = DidWbaVerifier(config)

    exempt_paths = ["/health", "/docs", "/openapi.json", "/favicon.ico"]

    app = FastAPI(
        title="DID WBA HTTP Server Example",
        description="HTTP server with DID WBA authentication",
        version="1.0.0",
    )

    @app.middleware("http")
    async def did_wba_auth_middleware(
        request: Request, call_next: Callable
    ) -> JSONResponse:
        """DID WBA authentication middleware."""
        return await auth_middleware(
            request, call_next, verifier, exempt_paths=exempt_paths
        )

    @app.get("/health")
    async def health_check() -> Dict[str, str]:
        """Health check endpoint (no authentication required)."""
        return {"status": "healthy", "service": "did-wba-http-server"}

    @app.get("/api/protected")
    async def protected_endpoint(request: Request) -> Dict[str, Any]:
        """Protected endpoint that requires DID authentication."""
        did = getattr(request.state, "did", None)
        auth_result = getattr(request.state, "auth_result", None)

        return {
            "message": "Authentication successful!",
            "did": did,
            "token_type": auth_result.get("token_type") if auth_result else None,
        }

    @app.get("/api/user-info")
    async def user_info_endpoint(request: Request) -> Dict[str, Any]:
        """Returns detailed information about the authenticated user."""
        did = getattr(request.state, "did", None)
        auth_result = getattr(request.state, "auth_result", None)

        return {
            "did": did,
            "authenticated": did is not None,
            "auth_method": (
                "bearer" if auth_result and "access_token" not in auth_result else "did"
            ),
            "details": {
                "did_method": did.split(":")[1] if did else None,
                "did_identifier": did.split(":")[-1] if did else None,
            },
        }

    return app


def main() -> None:
    """Run the HTTP server."""
    logger.info("Starting DID WBA HTTP Server...")
    logger.info("Server will be available at http://localhost:8080")
    logger.info("Protected endpoints require DID WBA authentication")
    logger.info("Press Ctrl+C to stop the server")

    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")


if __name__ == "__main__":
    main()
