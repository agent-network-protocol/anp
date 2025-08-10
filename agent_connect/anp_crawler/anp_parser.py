"""
ANP Document Parser Module

This module provides simple document parsing functionality for JSON format.
"""

import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class ANPDocumentParser:
    """
    Simple parser for ANP protocol documents, focusing on JSON format only.
    """
    
    def __init__(self):
        """Initialize the document parser."""
        pass
    
    def parse_document(self, content: str, content_type: str, source_url: str) -> Dict[str, Any]:
        """
        Parse JSON document content and extract interface information.
        
        Args:
            content: Raw document content
            content_type: MIME type of the content
            source_url: Source URL of the document
            
        Returns:
            Dictionary containing:
            {
                "interfaces": List[Dict],    # Interface definitions found
            }
        """
        logger.info(f"Parsing document from {source_url}")
        
        interfaces = []
        
        try:
            # Try to parse as JSON
            data = json.loads(content)
            
            # Check if it's an OpenRPC interface document
            if self._is_openrpc_interface(data):
                interfaces = self._extract_openrpc_interfaces(data)
            
            # Check if it's an Agent Description with interfaces
            elif isinstance(data, dict) and "interfaces" in data:
                interfaces = self._extract_interfaces_from_agent_description(data)
            
            # Check if it's a direct JSON-RPC interface (legacy format)
            elif self._is_jsonrpc_interface(data):
                interfaces = [self._extract_jsonrpc_interface(data)]
                
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON content: {str(e)}")
        
        return {
            "interfaces": interfaces
        }
    
    def _extract_interfaces_from_agent_description(self, data: Dict) -> List[Dict]:
        """Extract interfaces from Agent Description document."""
        interfaces = []
        
        # Extract global servers information from agent description (may be used by embedded interfaces)
        global_servers = []
        if "servers" in data:
            global_servers = data["servers"]
        
        # Extract interfaces from the interfaces field
        if "interfaces" in data:
            for interface_def in data["interfaces"]:
                # Check if this is a StructuredInterface with OpenRPC content
                if (interface_def.get("type") == "StructuredInterface" and 
                    interface_def.get("protocol") == "openrpc" and 
                    "content" in interface_def):
                    
                    # Extract OpenRPC interfaces from embedded content
                    content = interface_def["content"]
                    if isinstance(content, dict) and self._is_openrpc_interface(content):
                        embedded_interfaces = self._extract_openrpc_interfaces(content)
                        
                        # If embedded interfaces don't have servers, use global servers
                        for embedded_interface in embedded_interfaces:
                            if not embedded_interface.get("servers") and global_servers:
                                embedded_interface["parent_servers"] = global_servers
                        
                        interfaces.extend(embedded_interfaces)
                    else:
                        logger.warning(f"Invalid OpenRPC content in StructuredInterface: {interface_def.get('description', 'unknown')}")
                else:
                    # Regular interface definition (URL-based)
                    interface_info = {
                        "type": interface_def.get("type", "unknown"),
                        "protocol": interface_def.get("protocol", "unknown"),
                        "url": interface_def.get("url", ""),
                        "description": interface_def.get("description", ""),
                        "version": interface_def.get("version", ""),
                        "source": "agent_description"
                    }
                    
                    # Add servers information if available
                    if global_servers:
                        interface_info["parent_servers"] = global_servers
                    
                    interfaces.append(interface_info)
        
        return interfaces
    
    def _is_jsonrpc_interface(self, data: Dict) -> bool:
        """Check if JSON data is a JSON-RPC interface."""
        return (
            isinstance(data, dict) and (
                "jsonrpc" in data or
                "methods" in data or
                ("id" in data and "method" in data)
            )
        )
    
    def _extract_jsonrpc_interface(self, data: Dict) -> Dict[str, Any]:
        """Extract JSON-RPC interface information."""
        # Extract methods from JSON-RPC specification
        methods = data.get("methods", [])
        if not methods and "method" in data:
            # Single method definition
            methods = [data]
        
        # Return the first method for simplicity
        if methods and isinstance(methods[0], dict):
            method = methods[0]
            return {
                "type": "jsonrpc_method",
                "protocol": "JSON-RPC 2.0",
                "method_name": method.get("method", method.get("name", "")),
                "description": method.get("description", ""),
                "params": method.get("params", {}),
                "returns": method.get("returns", {}),
                "source": "jsonrpc_interface"
            }
        
        return {}
    
    def _is_openrpc_interface(self, data: Dict) -> bool:
        """Check if JSON data is an OpenRPC interface document."""
        return (
            isinstance(data, dict) and
            "openrpc" in data and
            "methods" in data and
            isinstance(data["methods"], list)
        )
    
    def _extract_openrpc_interfaces(self, data: Dict) -> List[Dict]:
        """Extract interfaces from OpenRPC document."""
        interfaces = []
        
        methods = data.get("methods", [])
        components = data.get("components", {})
        servers = data.get("servers", [])  # Extract servers information
        
        for method in methods:
            if isinstance(method, dict):
                interfaces.append({
                    "type": "openrpc_method",
                    "protocol": "openrpc",
                    "method_name": method.get("name", ""),
                    "summary": method.get("summary", ""),
                    "description": method.get("description", ""),
                    "params": method.get("params", []),
                    "result": method.get("result", {}),
                    "components": components,  # Include components for $ref resolution
                    "servers": servers,  # Include servers for execution
                    "source": "openrpc_interface"
                })
        
        return interfaces