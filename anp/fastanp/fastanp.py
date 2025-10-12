"""
FastANP - Fast Agent Network Protocol framework.

A plugin-based framework for building ANP agents with FastAPI.
FastAPI is the main framework, FastANP provides helper tools and automation.
"""

import logging
from typing import Any, Callable, Dict, Optional
from urllib.parse import urlparse

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from anp.authentication.did_wba_verifier import DidWbaVerifierConfig

from .ad_generator import ADGenerator
from .interface_manager import InterfaceManager, InterfaceProxy
from .middleware import create_auth_middleware

logger = logging.getLogger(__name__)


class FastANP:
    """
    FastANP plugin for building ANP agents with FastAPI.
    
    Provides automatic OpenRPC generation, JSON-RPC endpoint handling,
    context injection, and authentication middleware.
    """
    
    def __init__(
        self,
        app: FastAPI,
        name: str,
        description: str,
        base_url: str,
        did: str,
        owner: Optional[Dict[str, str]] = None,
        jsonrpc_server_url: str = "/rpc",
        jsonrpc_server_name: Optional[str] = None,
        jsonrpc_server_description: Optional[str] = None,
        enable_auth_middleware: bool = True,
        auth_config: Optional[DidWbaVerifierConfig] = None,
        api_version: str = "1.0.0",
        **kwargs
    ):
        """
        Initialize FastANP plugin.

        Args:
            app: FastAPI application instance
            name: Agent name
            description: Agent description
            base_url: Base URL for this agent (e.g., "https://example.com")
            did: DID identifier (required)
            owner: Owner information dictionary
            jsonrpc_server_url: JSON-RPC endpoint path (default: "/rpc")
            jsonrpc_server_name: JSON-RPC server name (defaults to agent name)
            jsonrpc_server_description: JSON-RPC server description
            enable_auth_middleware: Whether to enable auth middleware
            auth_config: Optional DidWbaVerifierConfig for authentication configuration
            api_version: API version
            **kwargs: Additional arguments
        """
        self.app = app
        self.name = name
        self.description = description
        self.base_url = base_url.rstrip('/')
        self.owner = owner
        self.jsonrpc_server_url = jsonrpc_server_url
        self.api_version = api_version
        self.did = did
        self.require_auth = enable_auth_middleware  # For backward compatibility

        # Extract domain from base_url for DID verification
        parsed_url = urlparse(self.base_url)
        self.domain = parsed_url.netloc or parsed_url.path

        # Initialize AD generator
        self.ad_generator = ADGenerator(
            name=name,
            description=description,
            did=did,
            base_url=self.base_url,
            owner=owner
        )

        # Initialize Interface manager
        self.interface_manager = InterfaceManager(
            api_title=jsonrpc_server_name or name,
            api_version=api_version,
            api_description=jsonrpc_server_description or description
        )

        # Initialize authentication middleware
        self.auth_middleware = None
        if enable_auth_middleware:
            # If auth_config is not provided, create it from jwt key paths
            if auth_config is None:
                raise ValueError(
                    "auth_config is required when enable_auth_middleware=True. "
                    "Please provide a DidWbaVerifierConfig instance with JWT keys."
                )

            self.auth_middleware = create_auth_middleware(config=auth_config)
            # Automatically register auth middleware to FastAPI app
            self.app.middleware("http")(self.auth_middleware)
            logger.info(f"Registered auth middleware for domain: {self.domain}")
        
        # Automatically register JSON-RPC endpoint
        # No need to pass auth_dependency as middleware handles auth in request.state
        self.interface_manager.register_jsonrpc_endpoint(
            app=self.app,
            rpc_path=jsonrpc_server_url
        )
        
        # Interfaces dictionary (function -> InterfaceProxy)
        self._interfaces_dict: Dict[Callable, InterfaceProxy] = {}
        
        logger.info(f"Initialized FastANP plugin: {name} ({did})")
    
    @property
    def interfaces(self) -> Dict[Callable, InterfaceProxy]:
        """
        Get interfaces dictionary for accessing interface metadata.
        
        Returns:
            Dictionary mapping functions to InterfaceProxy objects
        """
        # Lazy-create proxies as needed
        for func, registered_func in self.interface_manager.functions.items():
            if func not in self._interfaces_dict:
                self._interfaces_dict[func] = self.interface_manager.create_interface_proxy(
                    func=func,
                    base_url=self.base_url,
                    rpc_endpoint=self.jsonrpc_server_url
                )
        
        return self._interfaces_dict
    
    def get_common_header(self, ad_url: Optional[str] = None) -> Dict[str, Any]:
        """
        Get common header fields for Agent Description.
        
        Users can extend this with their own Infomations and interfaces.
        
        Args:
            ad_url: URL of the ad.json endpoint (optional)
            
        Returns:
            Agent Description common header dictionary
        """
        return self.ad_generator.generate_common_header(
            ad_url=ad_url,
            require_auth=self.require_auth
        )
    
    def interface(
        self,
        path: str,
        description: Optional[str] = None,
        humanAuthorization: bool = False
    ) -> Callable:
        """
        Decorator to register a function as an ANP interface.
        
        Automatically registers the OpenRPC document endpoint and adds
        the function to the JSON-RPC dispatcher.
        
        Args:
            path: OpenRPC document URL path (e.g., "/info/search_rooms.json")
            description: Method description (uses docstring if not provided)
            humanAuthorization: Whether human authorization is required
            
        Returns:
            Decorator function
            
        Example:
            @anp.interface("/info/hello.json", description="Say hello")
            def hello(name: str) -> dict:
                return {"message": f"Hello, {name}!"}
        """
        def decorator(func: Callable) -> Callable:
            # Register the function with interface manager
            self.interface_manager.register_function(
                func=func,
                path=path,
                description=description,
                humanAuthorization=humanAuthorization
            )
            
            # Automatically register GET endpoint for OpenRPC document
            @self.app.get(path, tags=["openrpc"])
            async def get_openrpc_doc():
                """Get OpenRPC document for this interface."""
                proxy = self.interfaces[func]
                return JSONResponse(content=proxy.openrpc_doc)
            
            logger.info(f"Registered OpenRPC document endpoint: GET {path}")
            
            return func
        
        return decorator
