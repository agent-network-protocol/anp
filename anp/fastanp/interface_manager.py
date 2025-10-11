"""
Interface manager for converting Python functions to OpenRPC interfaces.

Handles function signature parsing, OpenRPC generation, JSON-RPC endpoint registration,
and automatic context injection.
"""

import inspect
import logging
from typing import Any, Callable, Dict, Optional, Type

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .context import Context, SessionManager
from .utils import (
    extract_pydantic_models_from_signature,
    get_function_name_from_callable,
    normalize_url,
    parse_docstring,
    pydantic_to_json_schema,
    python_type_to_json_schema,
)

logger = logging.getLogger(__name__)


class InterfaceProxy:
    """
    Proxy object for accessing interface metadata and OpenRPC documents.
    
    Provides convenient properties for different representation modes.
    """
    
    def __init__(
        self,
        func: Callable,
        openrpc_doc: Dict[str, Any],
        path: str,
        base_url: str,
        description: str
    ):
        """
        Initialize interface proxy.
        
        Args:
            func: The Python function
            openrpc_doc: OpenRPC document for this interface
            path: OpenRPC document URL path
            base_url: Base URL for constructing full URLs
            description: Interface description
        """
        self.func = func
        self.path = path
        self.base_url = base_url
        self.description = description
        self._openrpc_doc = openrpc_doc
    
    @property
    def link_summary(self) -> dict:
        """
        Get link-style interface summary for ad.json.
        
        Returns:
            Interface item with URL reference
        """
        return {
            "type": "StructuredInterface",
            "protocol": "openrpc",
            "description": self.description,
            "url": normalize_url(self.base_url, self.path)
        }
    
    @property
    def content(self) -> dict:
        """
        Get embedded-style interface content for ad.json.
        
        Returns:
            Interface item with embedded OpenRPC document
        """
        return {
            "type": "StructuredInterface",
            "protocol": "openrpc",
            "description": self.description,
            "content": self._openrpc_doc
        }
    
    @property
    def openrpc_doc(self) -> dict:
        """
        Get raw OpenRPC document.
        
        Returns:
            OpenRPC document dictionary
        """
        return self._openrpc_doc


class RegisteredFunction:
    """Represents a registered function with its metadata."""
    
    def __init__(
        self,
        func: Callable,
        name: str,
        path: str,
        description: str,
        humanAuthorization: bool = False
    ):
        """
        Initialize registered function.
        
        Args:
            func: The Python function
            name: Function name (for OpenRPC method name)
            path: OpenRPC document URL path
            description: Function description
            humanAuthorization: Whether human authorization is required
        """
        self.func = func
        self.name = name
        self.path = path
        self.description = description
        self.humanAuthorization = humanAuthorization
        self.pydantic_models: Dict[str, Type[BaseModel]] = {}
        self.has_context_param = False
        
        # Parse function signature
        self._parse_signature()
    
    def _parse_signature(self) -> None:
        """Parse function signature to extract parameters and return type."""
        sig = inspect.signature(self.func)
        
        # Extract docstring
        _, param_docs = parse_docstring(self.func)
        
        # Parse parameters
        self.params = []
        for param_name, param in sig.parameters.items():
            if param_name == 'self':
                continue
            
            # Check if this is a Context parameter
            if param.annotation == Context or (
                hasattr(param.annotation, '__name__') and 
                param.annotation.__name__ == 'Context'
            ):
                self.has_context_param = True
                continue  # Don't include Context in OpenRPC params
            
            param_type = param.annotation if param.annotation != inspect.Parameter.empty else str
            param_required = param.default == inspect.Parameter.empty
            param_desc = param_docs.get(param_name, f"Parameter: {param_name}")
            
            # Check if this is a Pydantic model
            schema = python_type_to_json_schema(param_type, param_name)
            
            # If it's a reference, store the model
            if "$ref" in str(schema):
                if inspect.isclass(param_type) and issubclass(param_type, BaseModel):
                    self.pydantic_models[param_type.__name__] = param_type
            
            self.params.append({
                "name": param_name,
                "description": param_desc,
                "required": param_required,
                "schema": schema
            })
        
        # Parse return type
        return_type = sig.return_annotation if sig.return_annotation != inspect.Signature.empty else dict
        self.result_schema = python_type_to_json_schema(return_type, "result")
        
        # Extract Pydantic models from entire signature
        all_models = extract_pydantic_models_from_signature(self.func)
        self.pydantic_models.update(all_models)
    
    def to_openrpc_method(self) -> Dict[str, Any]:
        """
        Convert to OpenRPC method definition.
        
        Returns:
            OpenRPC method dictionary
        """
        return {
            "name": self.name,
            "summary": self.description[:100] if len(self.description) > 100 else self.description,
            "description": self.description,
            "params": self.params,
            "result": {
                "name": f"{self.name}Result",
                "description": f"Result of {self.name}",
                "schema": self.result_schema
            }
        }


class InterfaceManager:
    """Manages Interface registration and OpenRPC generation."""
    
    def __init__(
        self,
        api_title: str = "API",
        api_version: str = "1.0.0",
        api_description: str = ""
    ):
        """
        Initialize Interface manager.
        
        Args:
            api_title: API title for OpenRPC info
            api_version: API version
            api_description: API description
        """
        self.api_title = api_title
        self.api_version = api_version
        self.api_description = api_description
        self.functions: Dict[Callable, RegisteredFunction] = {}
        self.registered_names: set = set()
        self.session_manager = SessionManager()
    
    def register_function(
        self,
        func: Callable,
        path: str,
        description: Optional[str] = None,
        humanAuthorization: bool = False
    ) -> RegisteredFunction:
        """
        Register a function as an interface method.
        
        Args:
            func: Python function to register
            path: OpenRPC document URL path
            description: Method description (uses docstring if not provided)
            humanAuthorization: Whether human authorization is required
            
        Returns:
            RegisteredFunction object
            
        Raises:
            ValueError: If function name already registered
        """
        func_name = get_function_name_from_callable(func)
        
        # Check for duplicate function names
        if func_name in self.registered_names:
            raise ValueError(
                f"Function name '{func_name}' is already registered. "
                f"Function names must be globally unique."
            )
        
        # Use provided description or extract from docstring
        if description is None:
            desc, _ = parse_docstring(func)
            description = desc if desc else f"Method: {func_name}"
        
        registered_func = RegisteredFunction(
            func=func,
            name=func_name,
            path=path,
            description=description,
            humanAuthorization=humanAuthorization
        )
        
        self.functions[func] = registered_func
        self.registered_names.add(func_name)
        logger.info(f"Registered function: {func_name} at {path}")
        
        return registered_func
    
    def get_function(self, func: Callable) -> Optional[RegisteredFunction]:
        """
        Get registered function by callable.
        
        Args:
            func: Function callable
            
        Returns:
            RegisteredFunction or None
        """
        return self.functions.get(func)
    
    def generate_openrpc_for_function(
        self,
        registered_func: RegisteredFunction,
        base_url: str,
        rpc_endpoint: str = "/rpc"
    ) -> Dict[str, Any]:
        """
        Generate OpenRPC document for a single function.
        
        Args:
            registered_func: RegisteredFunction object
            base_url: Base URL for the agent
            rpc_endpoint: JSON-RPC endpoint path
            
        Returns:
            OpenRPC document dictionary
        """
        # Collect method
        method = registered_func.to_openrpc_method()
        
        # Collect Pydantic model schemas
        schemas = {}
        for model_name, model_class in registered_func.pydantic_models.items():
            if model_name not in schemas:
                schema = pydantic_to_json_schema(model_class)
                # Remove the top-level wrapper if present
                if 'properties' in schema:
                    schemas[model_name] = {
                        "type": "object",
                        "properties": schema.get('properties', {}),
                        "required": schema.get('required', [])
                    }
                    if 'description' in schema:
                        schemas[model_name]['description'] = schema['description']
                else:
                    schemas[model_name] = schema
        
        # Build OpenRPC document
        openrpc_doc = {
            "openrpc": "1.3.2",
            "info": {
                "title": registered_func.name,
                "version": self.api_version,
                "description": registered_func.description,
                "x-anp-protocol-type": "ANP",
                "x-anp-protocol-version": "1.0.0"
            },
            "security": [
                {"didwba": []}
            ],
            "servers": [
                {
                    "name": "Production Server",
                    "url": normalize_url(base_url, rpc_endpoint),
                    "description": "Production server for API"
                }
            ],
            "methods": [method],
            "components": {
                "securitySchemes": {
                    "didwba": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "DID-WBA",
                        "description": "DID-WBA authentication scheme"
                    }
                }
            }
        }
        
        # Add schemas if any Pydantic models were found
        if schemas:
            openrpc_doc["components"]["schemas"] = schemas
        
        return openrpc_doc
    
    def create_interface_proxy(
        self,
        func: Callable,
        base_url: str,
        rpc_endpoint: str = "/rpc"
    ) -> InterfaceProxy:
        """
        Create InterfaceProxy for a registered function.
        
        Args:
            func: Function callable
            base_url: Base URL for the agent
            rpc_endpoint: JSON-RPC endpoint path
            
        Returns:
            InterfaceProxy object
        """
        registered_func = self.functions.get(func)
        if not registered_func:
            raise ValueError(f"Function {func} is not registered")
        
        openrpc_doc = self.generate_openrpc_for_function(
            registered_func,
            base_url,
            rpc_endpoint
        )
        
        return InterfaceProxy(
            func=func,
            openrpc_doc=openrpc_doc,
            path=registered_func.path,
            base_url=base_url,
            description=registered_func.description
        )
    
    def register_jsonrpc_endpoint(
        self,
        app: FastAPI,
        rpc_path: str = "/rpc"
    ) -> None:
        """
        Register unified JSON-RPC endpoint with FastAPI.
        
        Auth is handled by middleware and stored in request.state.
        
        Args:
            app: FastAPI application instance
            rpc_path: JSON-RPC endpoint path
        """
        # Define JSON-RPC handler
        async def handle_jsonrpc(request: Request):
            """Handle JSON-RPC 2.0 requests with automatic context injection."""
            # Create function name to RegisteredFunction mapping dynamically
            func_map = {rf.name: rf for rf in self.functions.values()}
            
            try:
                body = await request.json()
            except Exception as e:
                return JSONResponse(
                    status_code=400,
                    content={
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32700,
                            "message": "Parse error",
                            "data": str(e)
                        },
                        "id": None
                    }
                )
            
            # Validate JSON-RPC request
            if not isinstance(body, dict):
                return JSONResponse(
                    status_code=400,
                    content={
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32600,
                            "message": "Invalid Request"
                        },
                        "id": None
                    }
                )
            
            request_id = body.get("id", None)
            method_name = body.get("method")
            params = body.get("params", {})
            
            # Check if method exists
            if method_name not in func_map:
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32601,
                            "message": "Method not found",
                            "data": f"Method '{method_name}' does not exist"
                        },
                        "id": request_id
                    }
                )
            
            # Execute the method
            try:
                registered_func = func_map[method_name]
                func = registered_func.func
                
                # Get auth result from request.state (set by middleware)
                auth_result = getattr(request.state, 'auth_result', None)
                
                # Prepare parameters with type conversion
                final_params = {}
                sig = inspect.signature(func)
                
                for param_name, param in sig.parameters.items():
                    if param_name == 'self':
                        continue
                    
                    # Check if this is a Context parameter
                    if param.annotation == Context or (
                        hasattr(param.annotation, '__name__') and 
                        param.annotation.__name__ == 'Context'
                    ):
                        # Will be injected below
                        continue
                    
                    # Check if this is a Request parameter
                    if param.annotation == Request or (
                        hasattr(param.annotation, '__name__') and 
                        param.annotation.__name__ == 'Request'
                    ):
                        # Will be injected below
                        continue
                    
                    # Get the parameter value from JSON-RPC params
                    if param_name in params:
                        param_value = params[param_name]
                        param_type = param.annotation
                        
                        # Convert dict to Pydantic model if needed
                        if (param_type != inspect.Parameter.empty and
                            inspect.isclass(param_type) and
                            issubclass(param_type, BaseModel) and
                            isinstance(param_value, dict)):
                            try:
                                param_value = param_type(**param_value)
                            except Exception as e:
                                logger.warning(f"Failed to convert param {param_name} to {param_type}: {e}")
                        
                        final_params[param_name] = param_value
                
                # Inject Context if needed
                if registered_func.has_context_param:
                    # Extract DID from auth_result (or request.state)
                    did = getattr(request.state, 'did', None)
                    if did is None and auth_result:
                        did = auth_result.get('did', 'anonymous')
                    if did is None:
                        did = 'anonymous'
                    
                    # Get or create session based on DID only
                    session = self.session_manager.get_or_create(
                        did=did,
                        anonymous=(did == 'anonymous')
                    )
                    
                    # Create Context
                    context = Context(
                        session=session,
                        did=did,
                        request=request,
                        auth_result=auth_result
                    )
                    
                    # Find context parameter name and inject
                    for param_name, param in sig.parameters.items():
                        if param.annotation == Context or (
                            hasattr(param.annotation, '__name__') and 
                            param.annotation.__name__ == 'Context'
                        ):
                            final_params[param_name] = context
                            break
                
                # Inject Request if needed
                for param_name, param in sig.parameters.items():
                    if param.annotation == Request or (
                        hasattr(param.annotation, '__name__') and 
                        param.annotation.__name__ == 'Request'
                    ):
                        final_params[param_name] = request
                        break
                
                # Call function with params
                if inspect.iscoroutinefunction(func):
                    result = await func(**final_params)
                else:
                    result = func(**final_params)
                
                # Return successful response
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "result": result,
                        "id": request_id
                    }
                )
            
            except TypeError as e:
                logger.warning(f"Invalid params for method {method_name}: {str(e)}")
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32602,
                            "message": "Invalid params",
                            "data": str(e)
                        },
                        "id": request_id
                    }
                )
            except Exception as e:
                logger.error(f"Error executing method {method_name}: {str(e)}", exc_info=True)
                return JSONResponse(
                    status_code=500,
                    content={
                        "jsonrpc": "2.0",
                        "error": {
                            "code": -32603,
                            "message": "Internal error",
                            "data": str(e)
                        },
                        "id": request_id
                    }
                )
        
        # Register JSON-RPC endpoint
        # Auth is handled by middleware, no dependency needed
        app.add_api_route(
            rpc_path,
            handle_jsonrpc,
            methods=["POST"],
            tags=["rpc"]
        )
        
        logger.info(f"Registered JSON-RPC endpoint at {rpc_path}")
