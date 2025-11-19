"""
FastANP - Fast Agent Network Protocol framework.

A plugin-based framework for building ANP agents with FastAPI.
FastAPI is the main framework, FastANP provides helper tools and automation.
"""

import asyncio
import logging
from typing import Any, Callable, Dict, List, Optional

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from anp.authentication.did_wba_verifier import DidWbaVerifierConfig

from .ad_generator import ADGenerator
from .information import InformationManager
from .interface_manager import InterfaceManager, InterfaceProxy
from .middleware import create_auth_middleware
from .utils import normalize_agent_domain

logger = logging.getLogger(__name__)


class FastANP:
    """
    FastANP plugin for building ANP agents with FastAPI.
    
    Provides automatic OpenRPC generation, JSON-RPC endpoint handling,
    context injection, and authentication middleware.
    """
    
    def __init__(
        self,
        name: str,
        description: str,
        did: str,
        agent_domain: str,
        owner: Optional[Dict[str, str]] = None,
        jsonrpc_server_path: str = "/rpc",
        jsonrpc_server_name: Optional[str] = None,
        jsonrpc_server_description: Optional[str] = None,
        enable_auth_middleware: bool = True,
        auth_config: Optional[DidWbaVerifierConfig] = None,
        api_version: str = "1.0.0",
        app: Optional[FastAPI] = None,
        **kwargs
    ):
        """
        Initialize FastANP plugin.

        Args:
            app: Optional FastAPI application instance. If omitted, FastANP will
                create one automatically using the provided metadata.
            name: Agent name
            description: Agent description
            agent_domain: Agent domain (e.g., "https://example.com")
            did: DID identifier (required)
            owner: Owner information dictionary
            jsonrpc_server_path: JSON-RPC endpoint path (default: "/rpc"). Full path constructed from agent_domain.
            jsonrpc_server_name: JSON-RPC server name (defaults to agent name)
            jsonrpc_server_description: JSON-RPC server description
            enable_auth_middleware: Whether to enable auth middleware
            auth_config: Optional DidWbaVerifierConfig for authentication configuration
            api_version: API version
            **kwargs: Additional arguments
        """
        # Allow FastANP to create FastAPI app automatically when not provided
        self.app = app or FastAPI(
            title=name,
            description=description,
            version=api_version
        )
        self.name = name
        self.description = description

        # 规范化 agent_domain，处理各种输入格式
        # 例如: "a.com" -> "https://a.com", "localhost:8000" -> "http://localhost:8000"
        self.agent_domain, self.domain = normalize_agent_domain(agent_domain)

        self.owner = owner
        self.jsonrpc_server_path = jsonrpc_server_path
        self.api_version = api_version
        self.did = did
        self.require_auth = enable_auth_middleware  # For backward compatibility

        # Construct base_url from agent_domain (for backward compatibility in some places)
        self.base_url = self.agent_domain

        # Initialize AD generator
        self.ad_generator = ADGenerator(
            name=name,
            description=description,
            did=did,
            agent_domain=self.agent_domain,
            owner=owner
        )

        # Initialize Interface manager
        self.interface_manager = InterfaceManager(
            api_title=jsonrpc_server_name or name,
            api_version=api_version,
            api_description=jsonrpc_server_description or description
        )
        
        # Initialize Information manager
        self.information_manager = InformationManager()

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
            rpc_path=jsonrpc_server_path
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
                    rpc_endpoint=self.jsonrpc_server_path
                )
        
        return self._interfaces_dict
    
    def get_common_header(
        self,
        agent_description_path: str = "/ad.json",
        ad_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get common header fields for Agent Description.

        Users can extend this with their own Infomations and interfaces.

        Args:
            agent_description_path: Agent description path (包含ad.json, default: "/ad.json")
            ad_url: URL of the ad.json endpoint (optional)

        Returns:
            Agent Description common header dictionary
        """
        return self.ad_generator.generate_common_header(
            agent_description_path=agent_description_path,
            ad_url=ad_url,
            require_auth=self.require_auth
        )
    
    def get_information_list(self, exclude_paths: Optional[List[str]] = None) -> List[Dict[str, str]]:
        """
        Get list of all Information items for ad.json.
        
        Uses InformationManager.get_information_list() to retrieve all
        registered information items (both static and dynamic).
        
        Args:
            exclude_paths: Optional list of paths to exclude (e.g., ["/ad.json"])
        
        Returns:
            List of information item dictionaries with type, description, and url
            
        Example:
            @app.get("/ad.json")
            def get_ad():
                ad = anp.get_common_header()
                ad["Infomations"] = anp.get_information_list(exclude_paths=["/ad.json"])
                ad["interfaces"] = [anp.interfaces[my_func].link_summary]
                return ad
        """
        all_items = self.information_manager.get_information_list(self.base_url)
        
        if exclude_paths:
            # Filter out excluded paths
            exclude_paths_set = {path if path.startswith('/') else f'/{path}' for path in exclude_paths}
            all_items = [
                item for item in all_items
                if not any(item['url'].endswith(path) for path in exclude_paths_set)
            ]
        
        return all_items
    
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
    
    def information(
        self,
        path: str,
        type: str = "Information",
        description: Optional[str] = None,
        **kwargs
    ) -> Callable:
        """
        Decorator to register an Information endpoint using InformationManager.
        
        Registers the route with FastAPI and adds it to InformationManager
        for automatic inclusion in ad.json.
        
        Args:
            path: URL path (e.g., "/info/hotel.json")
            type: Information type (default: "Information")
            description: Description (uses function docstring if not provided)
            **kwargs: Additional keyword arguments passed to app.get()
            
        Returns:
            Decorator function
            
        Example:
            @anp.information("/info/hello.json", description="Hello message")
            def get_hello():
                return {"message": "Hello!"}
            
            @anp.information("/info/rooms.json", type="Product", description="Room catalog")
            def get_rooms():
                return {"rooms": [...]}
        """
        def decorator(func: Callable) -> Callable:
            # Extract description from docstring if not provided
            desc = description or (func.__doc__ or "").strip().split('\n')[0] or f"Information at {path}"
            
            # Create handler that calls the function
            async def async_handler():
                if asyncio.iscoroutinefunction(func):
                    content = await func()
                else:
                    content = func()
                return JSONResponse(content=content)
            
            def sync_handler():
                content = func()
                return JSONResponse(content=content)
            
            # Determine if function is async and create appropriate handler
            handler = async_handler if asyncio.iscoroutinefunction(func) else sync_handler
            
            # Register route with FastAPI
            self.app.add_api_route(
                path,
                handler,
                methods=["GET"],
                tags=kwargs.get("tags", ["information"]),
                summary=desc,
                **{k: v for k, v in kwargs.items() if k != "tags"}
            )
            
            # Add to InformationManager for ad.json inclusion
            # For dynamic content from functions, we store None as content
            # The route handler will call the function when accessed
            self.information_manager.add_dynamic(
                type=type,
                description=desc,
                path=path,
                content=None  # Content comes from function call
            )
            
            logger.info(f"Registered Information endpoint: GET {path} (type: {type})")
            
            return func
        
        return decorator