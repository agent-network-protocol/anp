"""
Unified ANP node that can operate as both JSON-RPC server and client.

This module provides the :class:`ANPNode` class which wraps an existing FastANP
server instance and adds ANPClient (client) capabilities.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional
import uvicorn
from fastapi import FastAPI

from anp.anp_crawler.anp_client import ANPClient
from anp.fastanp import FastANP
from anp.fastanp.interface_manager import InterfaceProxy

logger = logging.getLogger(__name__)


class ANPNode:
    """
    ANP node that wraps a FastANP server and adds client capabilities.
    
    Usage:
        # First, create your FastANP server (FastAPI app auto-created)
        anp = FastANP(name="My Server", description="...", did="...", agent_domain="...")
        
        # Then wrap it with ANPNode to add client capabilities
        node = ANPNode(
            fastanp=anp,
            did_document_path="path/to/did.json",
            private_key_path="path/to/key.pem",
            host="0.0.0.0",
            port=8000,
        )
        
        # Use both server and client capabilities
        await node.start()
        ad = await node.fetch("http://other-server:8000/ad.json")
    """

    def __init__(
        self,
        *,
        fastanp: FastANP,
        did_document_path: Optional[str] = None,
        private_key_path: Optional[str] = None,
        host: str = "0.0.0.0",
        port: int = 8000,
        client_enabled: bool = True,
        log_level: str = "info",
        agent_description_path: str = "/ad.json",
        client: Optional[ANPClient] = None,
    ) -> None:
        """
        Initialize the ANP node by wrapping an existing FastANP instance.
        
        Args:
            fastanp: Existing FastANP instance to wrap (required)
            did_document_path: Path to DID document (required if client not provided)
            private_key_path: Path to private key (required if client not provided)
            host: Server host (default: "0.0.0.0")
            port: Server port (default: 8000)
            client_enabled: Whether to enable client mode (default: True)
            log_level: Logging level (default: "info")
            agent_description_path: Agent description path (default: "/ad.json")
            client: Optional pre-configured ANPClient instance to reuse
        """
        if not isinstance(fastanp, FastANP):
            raise TypeError("fastanp must be a FastANP instance")
        
        self._fastanp = fastanp
        self._app = fastanp.app
        self.name = fastanp.name
        self.description = fastanp.description
        self.did = fastanp.did
        self.agent_domain = fastanp.agent_domain
        
        # Expose FastANP decorators
        self.interface = fastanp.interface
        self.information = fastanp.information
        
        # Initialize client
        if client_enabled:
            if client is not None:
                self._client = client
            else:
                if not did_document_path or not private_key_path:
                    raise ValueError(
                        "did_document_path and private_key_path are required "
                        "when client_enabled=True and no client is provided."
                    )
                self._client = ANPClient(
                    did_document_path=did_document_path,
                    private_key_path=private_key_path,
                )
        else:
            self._client = None
        
        self._agent_description_path = agent_description_path
        self.client_enabled = client_enabled
        self.host = host
        self.port = port
        self.log_level = log_level
        
        # Server state
        self._uvicorn_server: Optional[uvicorn.Server] = None
        self._server_task: Optional[asyncio.Task] = None
        self._start_lock = asyncio.Lock()
        
        # Register ad.json route if it doesn't already exist
        self._register_agent_description_route_if_needed()

    async def start(self) -> None:
        """Start the FastAPI/uvicorn server in non-blocking mode."""
        if self._uvicorn_server and self._server_task and not self._server_task.done():
            logger.debug("ANP node server is already running.")
            return

        async with self._start_lock:
            if self._uvicorn_server and self._server_task and not self._server_task.done():
                return

            config = uvicorn.Config(
                self._app,
                host=self.host,
                port=self.port,
                log_level=self.log_level,
                loop="asyncio",
                lifespan="on",
            )
            self._uvicorn_server = uvicorn.Server(config)
            self._server_task = asyncio.create_task(self._uvicorn_server.serve())

            while not self._uvicorn_server.started and not self._uvicorn_server.should_exit:
                await asyncio.sleep(0.1)

            if self._uvicorn_server.should_exit:
                raise RuntimeError("Failed to start ANP node server.")

            logger.info("ANP node server started on %s:%s", self.host, self.port)

    async def stop(self) -> None:
        """Gracefully stop the server."""
        if not self._uvicorn_server:
            return

        self._uvicorn_server.should_exit = True
        if self._server_task:
            await self._server_task
        self._uvicorn_server = None
        self._server_task = None
        logger.info("ANP node server stopped.")

    async def call_jsonrpc(
        self,
        endpoint_url: str,
        method: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Call a JSON-RPC method exposed by another ANP node."""
        if not self.client_enabled or not self._client:
            raise RuntimeError("Client mode is disabled; cannot call remote methods.")

        response = await self._client.call_jsonrpc(
            server_url=endpoint_url,
            method=method,
            params=params or {},
        )
        if not response.get("success"):
            raise RuntimeError(response.get("error") or "Remote JSON-RPC call failed.")
        return response["result"]

    async def fetch(
        self,
        endpoint_url: str,
    ) -> Dict[str, Any]:
        """
        Fetch any JSON endpoint (agent description or information) from another node.

        Args:
            endpoint_url: Absolute URL to the JSON endpoint (e.g., "http://host/ad.json")
        """
        if not self.client_enabled or not self._client:
            raise RuntimeError("Client mode is disabled; cannot fetch remote endpoints.")

        result = await self._client.fetch(endpoint_url)
        if not result.get("success"):
            raise RuntimeError(result.get("error") or "Failed to fetch endpoint.")
        return result["data"] or {}

    def get_common_header(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Proxy to FastANP.get_common_header."""
        return self._fastanp.get_common_header(*args, **kwargs)

    @property
    def interfaces(self) -> Dict[Any, InterfaceProxy]:
        """Expose FastANP registered interfaces."""
        return self._fastanp.interfaces

    @property
    def app(self) -> FastAPI:
        """Return the FastAPI application."""
        return self._app

    def _register_agent_description_route_if_needed(self) -> None:
        """Register the `/ad.json` route only if it doesn't already exist."""
        # Check if route already exists
        for route in self._app.routes:
            if hasattr(route, 'path') and route.path == self._agent_description_path:
                # Route already exists, skip registration
                return
        
        # Register the route
        @self._app.get(self._agent_description_path, tags=["agent"])
        async def get_agent_description() -> Dict[str, Any]:
            return self._build_agent_description()

    def _build_agent_description(self) -> Dict[str, Any]:
        """Compose the Agent Description payload using FastANP data."""
        ad = self._fastanp.get_common_header(agent_description_path=self._agent_description_path)
        ad["interfaces"] = [
            proxy.link_summary for proxy in self._fastanp.interfaces.values()
        ]
        # Use InformationManager to get all registered information items
        # Exclude ad.json to avoid circular reference
        ad["Infomations"] = self._fastanp.get_information_list(
            exclude_paths=[self._agent_description_path]
        )
        return ad



__all__ = ["ANPNode"]
