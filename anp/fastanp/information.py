"""
Information document manager.

Manages static and dynamic Information documents, registers routes, and handles document trees.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from .utils import normalize_url


class InformationItem:
    """Represents a single Information document."""
    
    def __init__(
        self,
        type: str,
        description: str,
        path: str,
        file_path: Optional[str] = None,
        content: Optional[Any] = None
    ):
        """
        Initialize Information item.
        
        Args:
            type: Information type (Product, Information, VideoObject, etc.)
            description: Description of this information
            path: URL path (e.g., "/info/hotel.json")
            file_path: Path to static JSON file (for static mode)
            content: Python dict/list content (for dynamic mode)
        """
        self.type = type
        self.description = description
        self.path = path if path.startswith('/') else f'/{path}'
        self.file_path = file_path
        self.content = content
        self.is_static = file_path is not None
    
    def get_content(self) -> Any:
        """
        Get the content of this information item.
        
        Returns:
            Content as Python object (dict/list)
            
        Raises:
            FileNotFoundError: If static file doesn't exist
            json.JSONDecodeError: If static file is not valid JSON
        """
        if self.is_static:
            # Load from file
            file_path_obj = Path(self.file_path)
            if not file_path_obj.exists():
                raise FileNotFoundError(f"Information file not found: {self.file_path}")
            
            with open(file_path_obj, 'r', encoding='utf-8') as f:
                return json.load(f)
        else:
            # Return dynamic content
            return self.content
    
    def to_dict(self, base_url: str) -> Dict[str, str]:
        """
        Convert to dictionary for inclusion in ad.json.
        
        Args:
            base_url: Base URL to construct full URL
            
        Returns:
            Dictionary with type, description, and url
        """
        return {
            "type": self.type,
            "description": self.description,
            "url": normalize_url(base_url, self.path)
        }


class InformationManager:
    """Manages Information documents for an ANP agent."""
    
    def __init__(self):
        """Initialize Information manager."""
        self.items: List[InformationItem] = []
    
    def add_static(
        self,
        type: str,
        description: str,
        path: str,
        file_path: str
    ) -> None:
        """
        Add a static Information item from a file.
        
        Args:
            type: Information type
            description: Description of this information
            path: URL path (e.g., "/info/hotel.json")
            file_path: Path to JSON file
        """
        item = InformationItem(
            type=type,
            description=description,
            path=path,
            file_path=file_path
        )
        self.items.append(item)
    
    def add_dynamic(
        self,
        type: str,
        description: str,
        path: str,
        content: Any
    ) -> None:
        """
        Add a dynamic Information item from Python object.
        
        Args:
            type: Information type
            description: Description of this information
            path: URL path (e.g., "/products/rooms.json")
            content: Python dict or list
        """
        item = InformationItem(
            type=type,
            description=description,
            path=path,
            content=content
        )
        self.items.append(item)
    
    def register_routes(self, app: FastAPI) -> None:
        """
        Register all Information endpoints with FastAPI.
        
        Args:
            app: FastAPI application instance
        """
        for item in self.items:
            # Create a closure to capture the current item
            def make_handler(info_item: InformationItem):
                async def handler():
                    try:
                        content = info_item.get_content()
                        return JSONResponse(content=content)
                    except FileNotFoundError as e:
                        return JSONResponse(
                            status_code=404,
                            content={"error": str(e)}
                        )
                    except json.JSONDecodeError as e:
                        return JSONResponse(
                            status_code=500,
                            content={"error": f"Invalid JSON in file: {str(e)}"}
                        )
                    except Exception as e:
                        return JSONResponse(
                            status_code=500,
                            content={"error": f"Internal server error: {str(e)}"}
                        )
                return handler
            
            # Register the route
            app.add_api_route(
                item.path,
                make_handler(item),
                methods=["GET"],
                tags=["information"],
                summary=item.description
            )
    
    def get_information_list(self, base_url: str) -> List[Dict[str, str]]:
        """
        Get list of all Information items for ad.json.
        
        Args:
            base_url: Base URL for constructing full URLs
            
        Returns:
            List of information item dictionaries
        """
        return [item.to_dict(base_url) for item in self.items]

