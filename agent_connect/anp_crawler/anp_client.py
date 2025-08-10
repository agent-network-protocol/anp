"""
ANP HTTP Client Module

This module provides HTTP client functionality with DID authentication support.
It reuses the authentication capabilities from the existing ANPTool.
"""

import logging
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import aiohttp

# Import configuration and utilities from the project structure
sys.path.append(str(Path(__file__).parent.parent.parent))

from ..authentication import DIDWbaAuthHeader

logger = logging.getLogger(__name__)


class ANPClient:
    """
    HTTP client for ANP protocol with DID authentication.

    This class provides HTTP request functionality while reusing the DID authentication
    mechanism from the existing ANPTool implementation.
    """

    def __init__(
        self,
        did_document_path: str,
        private_key_path: str
    ):
        """
        Initialize ANP client with DID authentication.

        Args:
            did_document_path: Path to DID document file
            private_key_path: Path to private key file
        """
        self.did_document_path = did_document_path
        self.private_key_path = private_key_path
        self.auth_client = None

        # Initialize DID authentication client
        self._initialize_auth_client()

    def _initialize_auth_client(self):
        """Initialize DID authentication client."""
        # Check if paths are empty and raise exception if they are
        if not self.did_document_path or self.did_document_path.strip() == "":
            raise ValueError("DID document path cannot be empty")

        if not self.private_key_path or self.private_key_path.strip() == "":
            raise ValueError("Private key path cannot be empty")

        logger.info(
            f"ANPClient initialized - DID document path: {self.did_document_path}, "
            f"private key path: {self.private_key_path}"
        )

        try:
            self.auth_client = DIDWbaAuthHeader(
                did_document_path=self.did_document_path,
                private_key_path=self.private_key_path
            )
            logger.info("DID authentication client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize DID authentication client: {str(e)}")
            self.auth_client = None

    async def fetch_url(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Fetch content from a URL with DID authentication.

        Args:
            url: URL to fetch
            method: HTTP method (default: GET)
            headers: Additional HTTP headers
            params: URL query parameters
            body: Request body for POST/PUT requests

        Returns:
            Dictionary containing:
            {
                "success": bool,
                "text": str,           # Response text content
                "content_type": str,   # Content-Type header
                "encoding": str,       # Response encoding
                "status_code": int,    # HTTP status code
                "url": str            # Final URL (after redirects)
            }
        """
        if headers is None:
            headers = {}
        if params is None:
            params = {}

        logger.info(f"ANP request: {method} {url}")

        # Add basic request headers
        if "Content-Type" not in headers and method in ["POST", "PUT", "PATCH"]:
            headers["Content-Type"] = "application/json"

        # Add DID authentication
        if self.auth_client:
            try:
                auth_headers = self.auth_client.get_auth_header(url)
                headers.update(auth_headers)
            except Exception as e:
                logger.error(f"Failed to get authentication header: {str(e)}")

        # Set reasonable timeout for requests
        timeout = aiohttp.ClientTimeout(total=30, connect=10, sock_read=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Prepare request parameters
            request_kwargs = {
                "url": url,
                "headers": headers,
                "params": params,
            }

            # If there is a request body and the method supports it, add the request body
            if body is not None and method in ["POST", "PUT", "PATCH"]:
                request_kwargs["json"] = body

            # Execute request
            http_method = getattr(session, method.lower())

            try:
                async with http_method(**request_kwargs) as response:
                    logger.info(f"ANP response: status code {response.status}")

                    # Check response status
                    if (
                        response.status == 401
                        and "Authorization" in headers
                        and self.auth_client
                    ):
                        logger.warning(
                            "Authentication failed (401), trying to get authentication again"
                        )
                        # If authentication fails and a token was used, clear the token and retry
                        self.auth_client.clear_token(url)
                        # Get authentication header again
                        headers.update(
                            self.auth_client.get_auth_header(url, force_new=True)
                        )
                        # Execute request again
                        request_kwargs["headers"] = headers
                        async with http_method(**request_kwargs) as retry_response:
                            logger.info(
                                f"ANP retry response: status code {retry_response.status}"
                            )
                            return await self._process_response(retry_response, url)

                    return await self._process_response(response, url)
            except aiohttp.ClientError as e:
                logger.error(f"HTTP request failed: {str(e)}")
                return {
                    "success": False,
                    "error": f"HTTP request failed: {str(e)}",
                    "status_code": 500,
                    "url": url,
                    "text": "",
                    "content_type": "",
                    "encoding": "utf-8"
                }

    async def _process_response(self, response, url):
        """Process HTTP response and return standardized result."""
        # If authentication is successful, update the token
        if response.status == 200 and self.auth_client:
            try:
                self.auth_client.update_token(url, dict(response.headers))
            except Exception as e:
                logger.error(f"Failed to update token: {str(e)}")

        # Get response content type
        content_type = response.headers.get("Content-Type", "").lower()

        # Get response text
        text = await response.text()

        # Determine encoding
        encoding = "utf-8"
        if response.charset:
            encoding = response.charset

        # Build result
        result = {
            "success": response.status == 200,
            "status_code": response.status,
            "url": str(url),
            "text": text,
            "content_type": content_type,
            "encoding": encoding
        }

        # Add error information if request failed
        if response.status != 200:
            result["error"] = f"HTTP {response.status}: {response.reason}"

        return result

    async def get_content_info(self, url: str) -> Dict[str, Any]:
        """
        Get basic content information without downloading the full content.
        Uses HEAD request to get metadata.

        Args:
            url: URL to check

        Returns:
            Dictionary containing content metadata
        """
        try:
            # Set reasonable timeout for requests
            timeout = aiohttp.ClientTimeout(total=30, connect=10, sock_read=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.head(url) as response:
                    content_type = response.headers.get("Content-Type", "")
                    content_length = response.headers.get("Content-Length", "0")

                    return {
                        "success": True,
                        "url": url,
                        "content_type": content_type,
                        "content_length": int(content_length) if content_length.isdigit() else 0,
                        "status_code": response.status
                    }
        except Exception as e:
            logger.error(f"Failed to get content info for {url}: {str(e)}")
            return {
                "success": False,
                "url": url,
                "error": str(e),
                "content_type": "",
                "content_length": 0,
                "status_code": 500
            }