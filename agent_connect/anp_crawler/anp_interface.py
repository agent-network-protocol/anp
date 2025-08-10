"""
ANP Interface Module

This module provides functionality to convert JSON-RPC and OpenRPC interface formats
to OpenAI Tools JSON format, and execute tool calls by sending HTTP requests.
"""

import logging
import json
from typing import Dict, Any, Optional, List
from .anp_client import ANPClient

logger = logging.getLogger(__name__)


class ANPInterface:
    """
    Represents a single ANP interface that can execute tool calls.
    Each instance corresponds to one OpenAI tool function.
    """
    
    def __init__(self, tool_name: str, interface_data: Dict[str, Any], anp_client: ANPClient):
        """
        Initialize ANP interface for a specific tool.
        
        Args:
            tool_name: The OpenAI tool function name
            interface_data: Original interface metadata
            anp_client: ANP client for HTTP requests
        """
        self.tool_name = tool_name
        self.interface_data = interface_data
        self.anp_client = anp_client
        
        # Extract key information
        self.method_name = interface_data.get("method_name", "")
        self.servers = interface_data.get("servers", [])
        if not self.servers and "parent_servers" in interface_data:
            self.servers = interface_data["parent_servers"]
    
    async def execute(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute this interface with given arguments.
        
        Args:
            arguments: Arguments to pass to the tool
            
        Returns:
            Dictionary containing execution result
        """
        if not self.servers:
            return {
                "success": False,
                "error": f"No servers defined for tool: {self.tool_name}",
                "tool_name": self.tool_name
            }
        
        # Use the first server
        server = self.servers[0]
        server_url = server.get("url", "")
        
        if not server_url:
            return {
                "success": False,
                "error": f"No server URL found for tool: {self.tool_name}",
                "tool_name": self.tool_name
            }
        
        if not self.method_name:
            return {
                "success": False,
                "error": f"No method name found for tool: {self.tool_name}",
                "tool_name": self.tool_name
            }
        
        try:
            # Process arguments to handle string JSON values
            processed_arguments = {}
            for key, value in arguments.items():
                if isinstance(value, str):
                    # Try to parse as JSON if it looks like JSON
                    if (value.startswith('{') and value.endswith('}')) or \
                       (value.startswith('[') and value.endswith(']')):
                        try:
                            parsed_value = json.loads(value)
                            processed_arguments[key] = parsed_value
                            logger.info(f"Parsed JSON parameter {key}: {value} -> {parsed_value}")
                        except json.JSONDecodeError:
                            processed_arguments[key] = value
                            logger.warning(f"Failed to parse JSON parameter {key}: {value}")
                    else:
                        processed_arguments[key] = value
                else:
                    processed_arguments[key] = value
            
            logger.info(f"🔵 [ANP INTERFACE] Original arguments: {arguments}")
            logger.info(f"🔵 [ANP INTERFACE] Processed arguments: {processed_arguments}")
            
            # Build JSON-RPC request
            rpc_request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": self.method_name,
                "params": processed_arguments
            }
            
            logger.info(f"🔵 [ANP INTERFACE] Executing tool call: {self.tool_name} -> {self.method_name} at {server_url}")
            logger.info(f"🔵 [ANP INTERFACE] JSON-RPC request payload: {json.dumps(rpc_request, ensure_ascii=False, indent=2)}")
            
            # Send HTTP POST request
            response = await self.anp_client.fetch_url(
                url=server_url,
                method="POST",
                headers={"Content-Type": "application/json"},
                body=rpc_request
            )
            
            if not response.get("success", False):
                logger.error(f"❌ [ANP INTERFACE] HTTP request failed: {response}")
                return {
                    "success": False,
                    "error": f"HTTP request failed: {response.get('error', 'Unknown error')}",
                    "url": server_url,
                    "method": self.method_name,
                    "tool_name": self.tool_name
                }
            
            # Parse JSON-RPC response
            try:
                response_text = response.get("text", "")
                logger.info(f"🟢 [ANP INTERFACE] HTTP response status: {response.get('status_code')}")
                logger.info(f"🟢 [ANP INTERFACE] HTTP response text: {response_text}")
                
                if not response_text:
                    logger.error("Empty response text from server")
                    return {
                        "success": False,
                        "error": "Empty response from server",
                        "url": server_url,
                        "method": self.method_name,
                        "tool_name": self.tool_name
                    }
                
                rpc_response = json.loads(response_text)
                
                if "error" in rpc_response:
                    return {
                        "success": False,
                        "error": f"JSON-RPC error: {rpc_response['error']}",
                        "url": server_url,
                        "method": self.method_name,
                        "tool_name": self.tool_name
                    }
                
                # Successful response
                return {
                    "success": True,
                    "result": rpc_response.get("result"),
                    "url": server_url,
                    "method": self.method_name,
                    "tool_name": self.tool_name
                }
                
            except json.JSONDecodeError as e:
                return {
                    "success": False,
                    "error": f"Failed to parse JSON-RPC response: {str(e)}",
                    "url": server_url,
                    "method": self.method_name,
                    "tool_name": self.tool_name
                }
                
        except Exception as e:
            logger.error(f"Error executing tool call {self.tool_name}: {str(e)}")
            return {
                "success": False,
                "error": f"Execution error: {str(e)}",
                "url": server_url,
                "method": self.method_name,
                "tool_name": self.tool_name
            }


class ANPInterfaceConverter:
    """
    Converter for transforming JSON-RPC and OpenRPC interfaces to OpenAI Tools format.
    
    Supported conversions:
    - openrpc → OpenAI Tools
    - OpenRPC → OpenAI Tools
    """
    
    def __init__(self):
        """Initialize the interface converter."""
        pass
    
    def convert_to_openai_tools(self, interface_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Convert JSON-RPC or OpenRPC interface definition to OpenAI Tools format.
        
        Args:
            interface_data: Interface definition from parser
            
        Returns:
            OpenAI Tools format dictionary or None if conversion fails
            {
                "type": "function",
                "function": {
                    "name": str,
                    "description": str,
                    "parameters": {
                        "type": "object",
                        "properties": {...},
                        "required": [...]
                    }
                }
            }
        """
        interface_type = interface_data.get("type", "unknown")
        
        # Handle different interface types
        if interface_type == "jsonrpc_method":
            try:
                result = self._convert_jsonrpc_method(interface_data)
                if result:
                    logger.debug(f"Successfully converted {interface_type} to OpenAI Tools format")
                return result
            except Exception as e:
                logger.error(f"Failed to convert {interface_type}: {str(e)}")
                return None
        elif interface_type == "openrpc_method":
            try:
                result = self._convert_openrpc_method(interface_data)
                if result:
                    logger.debug(f"Successfully converted {interface_type} to OpenAI Tools format")
                return result
            except Exception as e:
                logger.error(f"Failed to convert {interface_type}: {str(e)}")
                return None
        else:
            logger.warning(f"Unsupported interface type: {interface_type}. Only JSON-RPC and OpenRPC methods are supported.")
            return None
    
    def create_anp_interface(self, interface_data: Dict[str, Any], anp_client: ANPClient) -> Optional[ANPInterface]:
        """
        Create an ANPInterface instance from interface data.
        
        Args:
            interface_data: Interface definition from parser
            anp_client: ANP client for HTTP requests
            
        Returns:
            ANPInterface instance or None if creation fails
        """
        # First convert to OpenAI tools to get the tool name
        openai_tool = self.convert_to_openai_tools(interface_data)
        if not openai_tool:
            return None
        
        tool_name = openai_tool["function"]["name"]
        return ANPInterface(tool_name, interface_data, anp_client)
    
    def _convert_jsonrpc_method(self, interface_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert JSON-RPC method to OpenAI Tools format."""
        method_name = interface_data.get("method_name", "unknown_method")
        description = interface_data.get("description", f"JSON-RPC method: {method_name}")
        params = interface_data.get("params", {})
        
        # Convert JSON-RPC parameters to JSON Schema
        parameters = self._convert_jsonrpc_params_to_schema(params)
        
        return {
            "type": "function",
            "function": {
                "name": self._sanitize_function_name(method_name),
                "description": description,
                "parameters": parameters
            }
        }
    
    def _convert_openrpc_method(self, interface_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert OpenRPC method to OpenAI Tools format."""
        method_name = interface_data.get("method_name", "unknown_method")
        
        # Use description, fall back to summary if description is empty
        description = interface_data.get("description", "")
        if not description:
            description = interface_data.get("summary", f"OpenRPC method: {method_name}")
        
        params = interface_data.get("params", [])
        components = interface_data.get("components", {})
        
        # Convert OpenRPC parameters to JSON Schema
        parameters = self._convert_openrpc_params_to_schema(params, components)
        
        return {
            "type": "function",
            "function": {
                "name": self._sanitize_function_name(method_name),
                "description": description,
                "parameters": parameters
            }
        }
    
    def _convert_jsonrpc_params_to_schema(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Convert JSON-RPC parameters to JSON Schema format."""
        if not params:
            return {
                "type": "object",
                "properties": {},
                "required": []
            }
        
        # If params is already a schema-like structure
        if "type" in params:
            return params
        
        # Convert named parameters to schema
        properties = {}
        required = []
        
        for param_name, param_def in params.items():
            if isinstance(param_def, dict):
                properties[param_name] = param_def
                if param_def.get("required", False):
                    required.append(param_name)
            else:
                # Simple parameter
                properties[param_name] = {
                    "type": "string",
                    "description": f"Parameter: {param_name}"
                }
        
        return {
            "type": "object",
            "properties": properties,
            "required": required
        }
    
    def _convert_openrpc_params_to_schema(self, params: List[Dict[str, Any]], components: Dict[str, Any] = None) -> Dict[str, Any]:
        """Convert OpenRPC parameters array to JSON Schema format."""
        if not params:
            return {
                "type": "object",
                "properties": {},
                "required": []
            }
        
        if components is None:
            components = {}
        
        properties = {}
        required = []
        
        for param in params:
            if not isinstance(param, dict):
                continue
                
            param_name = param.get("name", "")
            param_description = param.get("description", "")
            param_required = param.get("required", False)
            param_schema = param.get("schema", {})
            
            if param_name:
                # Use the schema from the parameter, or create a basic string schema
                if param_schema:
                    # Resolve any $ref references in the schema
                    property_def = self._resolve_schema_refs(param_schema, components)
                else:
                    property_def = {"type": "string"}
                
                # Add description to the property if not already present
                if param_description and "description" not in property_def:
                    property_def["description"] = param_description
                
                properties[param_name] = property_def
                
                # Add to required list if marked as required
                if param_required:
                    required.append(param_name)
        
        return {
            "type": "object",
            "properties": properties,
            "required": required
        }
    
    def _sanitize_function_name(self, name: str) -> str:
        """Sanitize function name to comply with OpenAI Tools requirements."""
        if not name:
            return "unknown_function"
        
        # Replace invalid characters with underscores
        import re
        sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', name)
        
        # Ensure it starts with a letter or underscore
        if sanitized and not sanitized[0].isalpha() and sanitized[0] != '_':
            sanitized = f"fn_{sanitized}"
        
        # Ensure it's not empty
        if not sanitized:
            sanitized = "unknown_function"
        
        # Limit length (OpenAI has limits)
        if len(sanitized) > 64:
            sanitized = sanitized[:64]
        
        return sanitized
    
    def _resolve_schema_refs(self, schema: Dict[str, Any], components: Dict[str, Any]) -> Dict[str, Any]:
        """
        Resolve $ref references in a JSON Schema.
        
        Args:
            schema: The schema that may contain $ref references
            components: The components section from OpenRPC document
            
        Returns:
            Schema with all $ref references resolved
        """
        if not isinstance(schema, dict):
            return schema
        
        # If this is a $ref, resolve it
        if "$ref" in schema:
            ref_path = schema["$ref"]
            resolved_schema = self._resolve_ref(ref_path, components)
            if resolved_schema:
                # Recursively resolve any refs in the resolved schema
                return self._resolve_schema_refs(resolved_schema, components)
            else:
                logger.warning(f"Could not resolve $ref: {ref_path}")
                return {"type": "object", "description": f"Unresolved reference: {ref_path}"}
        
        # If this is a regular schema, check for nested refs
        resolved_schema = {}
        for key, value in schema.items():
            if key == "properties" and isinstance(value, dict):
                # Resolve refs in properties
                resolved_properties = {}
                for prop_name, prop_schema in value.items():
                    resolved_properties[prop_name] = self._resolve_schema_refs(prop_schema, components)
                resolved_schema[key] = resolved_properties
            elif key == "items" and isinstance(value, dict):
                # Resolve refs in array items
                resolved_schema[key] = self._resolve_schema_refs(value, components)
            elif isinstance(value, dict):
                # Resolve refs in nested objects
                resolved_schema[key] = self._resolve_schema_refs(value, components)
            elif isinstance(value, list):
                # Resolve refs in lists
                resolved_list = []
                for item in value:
                    if isinstance(item, dict):
                        resolved_list.append(self._resolve_schema_refs(item, components))
                    else:
                        resolved_list.append(item)
                resolved_schema[key] = resolved_list
            else:
                # Keep primitive values as-is
                resolved_schema[key] = value
        
        return resolved_schema
    
    def _resolve_ref(self, ref_path: str, components: Dict[str, Any]) -> Dict[str, Any]:
        """
        Resolve a single $ref reference.
        
        Args:
            ref_path: The reference path (e.g., "#/components/schemas/Room")
            components: The components section from OpenRPC document
            
        Returns:
            The referenced schema or None if not found
        """
        if not ref_path.startswith("#/"):
            logger.warning(f"Unsupported reference format: {ref_path}")
            return None
        
        # Parse the reference path
        # Format: #/components/schemas/SchemaName
        path_parts = ref_path[2:].split("/")  # Remove "#/" and split
        
        if len(path_parts) < 3 or path_parts[0] != "components":
            logger.warning(f"Invalid reference path: {ref_path}")
            return None
        
        try:
            # Navigate to the referenced schema
            current = components
            for part in path_parts[1:]:  # Skip "components"
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    logger.warning(f"Reference not found: {ref_path}")
                    return None
            
            return current if isinstance(current, dict) else None
            
        except Exception as e:
            logger.error(f"Error resolving reference {ref_path}: {str(e)}")
            return None