"""
DID WBA authentication middleware for FastAPI.

Provides authentication middleware and dependency for protecting API endpoints.
"""

import logging
from typing import Callable, Optional

from fastapi import Header, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from anp.authentication.did_wba_verifier import (
    DidWbaVerifier,
    DidWbaVerifierConfig,
    DidWbaVerifierError,
)

logger = logging.getLogger(__name__)

# Paths that should skip authentication
AUTH_EXCLUDED_PATHS = [
    "/ad.json",
    "/docs",
    "/openapi.json",
    "/favicon.ico"
]


class AuthMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware for DID WBA authentication.
    
    Can be added to FastAPI app with app.add_middleware().
    """
    
    def __init__(
        self,
        app,
        verifier: DidWbaVerifier,
        domain: str,
        minimum_size: int = 500
    ):
        """
        Initialize authentication middleware.
        
        Args:
            app: FastAPI application
            verifier: DidWbaVerifier instance
            domain: Service domain for DID verification
            minimum_size: Minimum response size to process (optional optimization)
        """
        super().__init__(app)
        self.verifier = verifier
        self.domain = domain
        self.minimum_size = minimum_size
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process request through authentication middleware.

        Args:
            request: Incoming request
            call_next: Next middleware/handler

        Returns:
            Response
        """
        # Skip authentication for excluded paths
        for excluded_path in AUTH_EXCLUDED_PATHS:
            if request.url.path == excluded_path or request.url.path.endswith(excluded_path):
                logger.debug(f"Skipping auth for excluded path: {request.url.path}")
                response = await call_next(request)
                return response

        # For now, middleware is passive - actual auth is done via dependencies
        # This can be extended to add request-level auth checking if needed
        response = await call_next(request)
        return response
    
    async def verify_auth_header(
        self,
        authorization: Optional[str] = Header(None)
    ) -> dict:
        """
        Verify Authorization header using DID WBA.
        
        This function is used as a FastAPI dependency.
        
        Args:
            authorization: Authorization header value
            
        Returns:
            Dictionary with verification result (including 'did')
            
        Raises:
            HTTPException: If authentication fails
        """
        if not authorization:
            logger.warning("Missing authorization header")
            raise HTTPException(
                status_code=401,
                detail="Missing authorization header",
                headers={"WWW-Authenticate": "DIDWba"}
            )
        
        try:
            result = await self.verifier.verify_auth_header(authorization, self.domain)
            logger.info(f"Authentication successful for DID: {result.get('did')}")
            return result
        
        except DidWbaVerifierError as e:
            logger.error(f"Authentication failed: {str(e)}")
            raise HTTPException(
                status_code=e.status_code,
                detail=str(e),
                headers={"WWW-Authenticate": "DIDWba"}
            )
        
        except Exception as e:
            logger.error(f"Unexpected authentication error: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=500,
                detail="Internal authentication error",
                headers={"WWW-Authenticate": "DIDWba"}
            )


def create_auth_middleware(
    domain: str,
    jwt_private_key: Optional[str] = None,
    jwt_public_key: Optional[str] = None,
    external_nonce_validator: Optional[Callable] = None,
    config: Optional[DidWbaVerifierConfig] = None,
    minimum_size: int = 500
) -> AuthMiddleware:
    """
    Create authentication middleware instance.
    
    Args:
        domain: Service domain for DID verification
        jwt_private_key: JWT private key in PEM format
        jwt_public_key: JWT public key in PEM format
        external_nonce_validator: External nonce validation function
        config: Optional custom DidWbaVerifierConfig
        minimum_size: Minimum response size for middleware processing
        
    Returns:
        AuthMiddleware instance with verify_auth_header method
    """
    # Create verifier config
    if config is None:
        config = DidWbaVerifierConfig(
            jwt_private_key=jwt_private_key,
            jwt_public_key=jwt_public_key,
            jwt_algorithm="RS256",
            access_token_expire_minutes=60,
            nonce_expiration_minutes=6,
            timestamp_expiration_minutes=5
        )
    
    verifier = DidWbaVerifier(config)
    
    # Create actual middleware instance for immediate use
    class ReadyAuthMiddleware:
        """Auth middleware ready to use."""
        
        def __init__(self):
            self.verifier = verifier
            self.domain = domain
            self.minimum_size = minimum_size
            # Create a temporary middleware for verify_auth_header
            self._temp_middleware = AuthMiddleware(None, verifier, domain, minimum_size)
        
        def __call__(self, app):
            """Called when added to FastAPI via add_middleware."""
            return AuthMiddleware(app, self.verifier, self.domain, self.minimum_size)
        
        async def verify_auth_header(
            self,
            authorization: Optional[str] = Header(None)
        ) -> dict:
            """
            Verify Authorization header - can be used as FastAPI dependency.
            
            Args:
                authorization: Authorization header value
                
            Returns:
                Authentication result dictionary
            """
            return await self._temp_middleware.verify_auth_header(authorization)
    
    return ReadyAuthMiddleware()
