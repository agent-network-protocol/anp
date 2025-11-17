"""
Unified ANP node that can operate as both JSON-RPC server and client.

This module provides the :class:`ANPNode` class which composes FastANP (server)
and ANPCrawler/ANPClient (client) capabilities into a single lifecycle object.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Dict, List, Optional
from urllib.parse import urljoin

import uvicorn
from fastapi import FastAPI

from anp.anp_crawler.anp_client import ANPClient
from anp.authentication.did_wba_verifier import DidWbaVerifierConfig
from anp.fastanp import FastANP
from anp.fastanp.interface_manager import InterfaceProxy

logger = logging.getLogger(__name__)


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
        log_level: str = "info",
        agent_description_path: str = "/ad.json",
        initial_information: Optional[List[Dict[str, str]]] = None,
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

        self._client: Optional[ANPClient] = (
            ANPClient(
                did_document_path=did_document_path,
                private_key_path=private_key_path,
            )
            if client_enabled
            else None
        )
        self._agent_description_path = agent_description_path
        self._information_links: List[Dict[str, str]] = list(initial_information or [])

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
            self.information = self._information_decorator
            self._register_agent_description_route()
        else:
            self._app = None
            self._fastanp = None
            self.interface = self._disabled_server_interface
            self.information: Callable[..., Any] = self._disabled_server_interface

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

    async def fetch_agent_description(
        self,
        base_url: str,
        *,
        ad_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Fetch `ad.json` from another ANP node."""
        if not self.client_enabled or not self._client:
            raise RuntimeError("Client mode is disabled; cannot fetch agent description.")

        ad_endpoint = ad_path or self._agent_description_path
        ad_url = urljoin(self._normalize_base_url(base_url), ad_endpoint.lstrip("/"))
        result = await self._client.fetch(ad_url)
        if not result.get("success"):
            raise RuntimeError(result.get("error") or "Failed to fetch agent description.")
        return result["data"] or {}

    async def call_remote_method(
        self,
        base_url: str,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        *,
        rpc_path: str = "/rpc",
    ) -> Dict[str, Any]:
        """Call a JSON-RPC method exposed by another ANP node."""
        if not self.client_enabled or not self._client:
            raise RuntimeError("Client mode is disabled; cannot call remote methods.")

        rpc_url = self._resolve_rpc_url(base_url, rpc_path)
        response = await self._client.call_jsonrpc(
            server_url=rpc_url,
            method=method,
            params=params or {},
        )
        if not response.get("success"):
            raise RuntimeError(response.get("error") or "Remote JSON-RPC call failed.")
        return response["result"]

    async def fetch_information_endpoint(
        self,
        base_url: str,
        path: str,
    ) -> Dict[str, Any]:
        """Fetch a JSON information endpoint exposed by another ANP node."""
        if not self.client_enabled or not self._client:
            raise RuntimeError("Client mode is disabled; cannot fetch information endpoints.")

        info_url = urljoin(self._normalize_base_url(base_url), path.lstrip("/"))
        response = await self._client.fetch(info_url)
        if not response.get("success"):
            raise RuntimeError(response.get("error") or "Failed to fetch information endpoint.")
        return response["data"]

    def get_common_header(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Proxy to FastANP.get_common_header."""
        if not self._fastanp:
            raise RuntimeError("Server mode is disabled; get_common_header is unavailable.")
        return self._fastanp.get_common_header(*args, **kwargs)

    def register_information_endpoint(
        self,
        *,
        path: str,
        description: str,
        absolute_url: Optional[str] = None,
    ) -> None:
        """Record a custom information endpoint for inclusion in `ad.json`."""
        if not self._fastanp:
            raise RuntimeError("Server mode is disabled; cannot register information endpoints.")

        base_url = self._fastanp.base_url
        info_url = absolute_url or urljoin(self._normalize_base_url(base_url), path.lstrip("/"))
        entry = {
            "type": "Information",
            "description": description,
            "url": info_url,
        }
        # Replace existing entry if same URL to keep metadata fresh.
        self._information_links = [item for item in self._information_links if item.get("url") != info_url]
        self._information_links.append(entry)

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

    def _information_decorator(
        self,
        path: str,
        *,
        description: str,
        tags: Optional[List[str]] = None,
    ) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
        """Register an information endpoint and decorate a FastAPI handler."""
        if not self._app:
            raise RuntimeError("Server mode is disabled; cannot register information routes.")

        def decorator(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[Any]]:
            route = self._app.get(path, tags=tags or ["information"])(func)
            self.register_information_endpoint(path=path, description=description)
            return route

        return decorator

    def _register_agent_description_route(self) -> None:
        """Automatically register the `/ad.json` route mirroring the example server."""
        if not self._app or not self._fastanp:
            return

        @self._app.get(self._agent_description_path, tags=["agent"])
        async def get_agent_description() -> Dict[str, Any]:
            return self._build_agent_description()

    def _build_agent_description(self) -> Dict[str, Any]:
        """Compose the Agent Description payload using FastANP data."""
        if not self._fastanp:
            raise RuntimeError("Server mode is disabled; cannot build agent description.")

        ad = self._fastanp.get_common_header(agent_description_path=self._agent_description_path)
        ad["interfaces"] = [
            proxy.link_summary for proxy in self._fastanp.interfaces.values()
        ]
        ad["Infomations"] = list(self._information_links)
        return ad

    def _normalize_base_url(self, base_url: str) -> str:
        """Ensure base URLs always end with a slash for `urljoin` compatibility."""
        base_url = base_url.rstrip("/")
        if "://" not in base_url:
            raise ValueError(f"Invalid base URL: {base_url}")
        return f"{base_url}/"

    def _resolve_rpc_url(self, base_url: str, rpc_path: str) -> str:
        """Resolve absolute RPC endpoint from a base URL or existing RPC URL."""
        if base_url.endswith("/rpc") or base_url.endswith(".rpc"):
            return base_url
        return urljoin(self._normalize_base_url(base_url), rpc_path.lstrip("/"))

    def _disabled_server_interface(self, *args: Any, **kwargs: Any) -> Callable:
        raise RuntimeError("Server mode is disabled; interface decorator is unavailable.")


__all__ = ["ANPNode"]