"""
Unified ANP node that can operate as both JSON-RPC server and client.

This module provides the :class:`ANPNode` class which composes FastANP (server)
and ANPCrawler/ANPClient (client) capabilities into a single lifecycle object.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, Dict, Optional, Union
from urllib.parse import urljoin

import uvicorn
from fastapi import FastAPI

from anp.anp_crawler.anp_crawler import ANPCrawler
from anp.anp_crawler.anp_interface import ANPInterface
from anp.authentication.did_wba import resolve_did_wba_document
from anp.authentication.did_wba_verifier import DidWbaVerifierConfig
from anp.fastanp import FastANP
from anp.fastanp.interface_manager import InterfaceProxy

logger = logging.getLogger(__name__)

InterfaceMap = Dict[str, ANPInterface]


class ANPNode:
    """ANP node that can act as both server and client."""

    def __init__(
        self,
        *,
        name: str,
        description: str,
        did: str,
        did_document_path: str,
        private_key_path: str,
        agent_domain: str,
        host: str = "0.0.0.0",
        port: int = 8000,
        server_enabled: bool = True,
        client_enabled: bool = True,
        enable_auth_middleware: bool = True,
        auth_config: Optional[DidWbaVerifierConfig] = None,
        jsonrpc_server_path: str = "/rpc",
        jsonrpc_server_name: Optional[str] = None,
        jsonrpc_server_description: Optional[str] = None,
        api_version: str = "1.0.0",
        app: Optional[FastAPI] = None,
        crawler_cache_enabled: bool = True,
        log_level: str = "info",
    ) -> None:
        """Initialize the ANP node."""
        self.name = name
        self.description = description
        self.did = did
        self.agent_domain = agent_domain
        self.host = host
        self.port = port
        self.server_enabled = server_enabled
        self.client_enabled = client_enabled
        self.log_level = log_level

        self._app: Optional[FastAPI] = None
        self._fastanp: Optional[FastANP] = None
        self._uvicorn_server: Optional[uvicorn.Server] = None
        self._server_task: Optional[asyncio.Task] = None
        self._start_lock = asyncio.Lock()

        self._crawler: Optional[ANPCrawler] = (
            ANPCrawler(
                did_document_path=did_document_path,
                private_key_path=private_key_path,
                cache_enabled=crawler_cache_enabled,
            )
            if client_enabled
            else None
        )
        self._interface_cache: Dict[str, InterfaceMap] = {}
        self._agent_description_cache: Dict[str, str] = {}
        self._discovery_locks: Dict[str, asyncio.Lock] = {}

        if server_enabled:
            self._app = app or FastAPI(title=name, description=description)
            self._fastanp = FastANP(
                app=self._app,
                name=name,
                description=description,
                did=did,
                agent_domain=agent_domain,
                owner=None,
                jsonrpc_server_path=jsonrpc_server_path,
                jsonrpc_server_name=jsonrpc_server_name,
                jsonrpc_server_description=jsonrpc_server_description,
                enable_auth_middleware=enable_auth_middleware,
                auth_config=auth_config,
                api_version=api_version,
            )
            self.interface = self._fastanp.interface
        else:
            self._app = None
            self._fastanp = None
            self.interface = self._disabled_server_interface

    async def start(self) -> None:
        """Start the FastAPI/uvicorn server in non-blocking mode."""
        if not self.server_enabled:
            logger.info("Server mode is disabled; start() is a no-op.")
            return

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
        if not self.server_enabled:
            return

        if not self._uvicorn_server:
            return

        self._uvicorn_server.should_exit = True
        if self._server_task:
            await self._server_task
        self._uvicorn_server = None
        self._server_task = None
        logger.info("ANP node server stopped.")

    async def call_interface(
        self,
        target_did: str,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Call a remote JSON-RPC method exposed by another ANP node."""
        interface = await self.discover_interface(target_did, method)
        if timeout is not None:
            logger.warning("ANPNode.call_interface timeout parameter is currently unused.")
        return await interface.execute(params or {})

    async def discover_interface(
        self,
        target_did: str,
        method: Optional[str] = None,
    ) -> Union[ANPInterface, InterfaceMap]:
        """Discover and cache interfaces for the target DID."""
        if not self.client_enabled or not self._crawler:
            raise RuntimeError("Client mode is disabled; cannot discover interfaces.")

        cached = self._interface_cache.get(target_did)
        if cached and method and method in cached:
            return cached[method]
        if cached and method is None:
            return cached

        lock = self._discovery_locks.setdefault(target_did, asyncio.Lock())
        async with lock:
            cached = self._interface_cache.get(target_did)
            if cached and method and method in cached:
                return cached[method]
            if cached and method is None:
                return cached

            interfaces = await self._fetch_interfaces_for_did(target_did)
            self._interface_cache[target_did] = interfaces

            if method:
                if method not in interfaces:
                    raise ValueError(f"Method '{method}' not found for DID {target_did}")
                return interfaces[method]

            return interfaces

    def get_common_header(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Proxy to FastANP.get_common_header."""
        if not self._fastanp:
            raise RuntimeError("Server mode is disabled; get_common_header is unavailable.")
        return self._fastanp.get_common_header(*args, **kwargs)

    @property
    def interfaces(self) -> Dict[Callable, InterfaceProxy]:
        """Expose FastANP registered interfaces."""
        if not self._fastanp:
            raise RuntimeError("Server mode is disabled; interfaces are unavailable.")
        return self._fastanp.interfaces

    @property
    def app(self) -> FastAPI:
        """Return the FastAPI application."""
        if not self._app:
            raise RuntimeError("Server mode is disabled; FastAPI app is unavailable.")
        return self._app

    async def _fetch_interfaces_for_did(self, target_did: str) -> InterfaceMap:
        """Fetch and cache ANP interfaces for the provided DID."""
        ad_url = await self._resolve_agent_description_url(target_did)
        _, interfaces = await self._crawler.fetch_text(ad_url)
        if not interfaces:
            raise RuntimeError(f"No interfaces found in agent description {ad_url}")

        interface_map: InterfaceMap = {}
        for tool in interfaces:
            tool_name = tool.get("function", {}).get("name")
            if not tool_name:
                continue
            anp_interface = self._crawler._anp_interfaces.get(tool_name)
            if not anp_interface:
                continue
            method_name = anp_interface.method_name or tool_name
            interface_map[method_name] = anp_interface

        if not interface_map:
            raise RuntimeError(f"Failed to build interface map for DID {target_did}")

        return interface_map

    async def _resolve_agent_description_url(self, target_did: str) -> str:
        """Resolve the Agent Description URL for a DID."""
        if target_did in self._agent_description_cache:
            return self._agent_description_cache[target_did]

        did_document = await resolve_did_wba_document(target_did)
        if not did_document:
            raise RuntimeError(f"Failed to resolve DID document for {target_did}")

        services = did_document.get("service", [])
        endpoint = None
        for service in services:
            if service.get("type") == "AgentDescription":
                endpoint = service.get("serviceEndpoint")
                break

        if not endpoint:
            raise ValueError(f"No AgentDescription service defined for DID {target_did}")

        endpoint = endpoint.rstrip("/")
        if endpoint.endswith(".json"):
            ad_url = endpoint
        else:
            ad_url = urljoin(f"{endpoint}/", "ad.json")

        self._agent_description_cache[target_did] = ad_url
        return ad_url

    def _disabled_server_interface(self, *args: Any, **kwargs: Any) -> Callable:
        raise RuntimeError("Server mode is disabled; interface decorator is unavailable.")


__all__ = ["ANPNode"]