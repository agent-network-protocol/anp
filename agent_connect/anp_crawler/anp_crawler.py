"""
ANP Crawler Management Module

This module provides the main interface for interacting with ANP (Agent Network Protocol) resources.
It manages crawling sessions, caches results, and coordinates different components.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

from .anp_client import ANPClient
from .anp_interface import ANPInterface, ANPInterfaceConverter
from .anp_parser import ANPDocumentParser

logger = logging.getLogger(__name__)


class ANPCrawler:
    """
    Main Crawler class for ANP crawling and content fetching.

    This class provides unified interfaces for fetching different types of content
    and extracting interface definitions in OpenAI Tools format.
    """

    def __init__(
        self,
        did_document_path: str,
        private_key_path: str,
        cache_enabled: bool = True
    ):
        """
        Initialize ANP session with DID authentication.

        Args:
            did_document_path: Path to DID document file
            private_key_path: Path to private key file
            cache_enabled: Whether to enable URL caching
        """
        self.did_document_path = did_document_path
        self.private_key_path = private_key_path
        self.cache_enabled = cache_enabled

        # Initialize components
        self._client = None  # ANPClient instance
        self._parser = None  # ANPDocumentParser instance
        self._interface_converter = None  # ANPInterfaceConverter instance

        # Session state
        self._visited_urls: set = set()
        self._cache: Dict[str, Any] = {}
        self._agent_description_uri: Optional[str] = None  # Track first URL as agent description URI

        # ANP Interfaces storage (tool_name -> ANPInterface)
        self._anp_interfaces: Dict[str, ANPInterface] = {}

        # Initialize components
        self._initialize_components()

    def _initialize_components(self):
        """Initialize internal components."""
        logger.info("Initializing ANP session components")

        # Initialize HTTP client with DID authentication
        self._client = ANPClient(
            did_document_path=self.did_document_path,
            private_key_path=self.private_key_path
        )

        # Initialize document parser
        self._parser = ANPDocumentParser()

        # Initialize interface converter
        self._interface_converter = ANPInterfaceConverter()

        logger.info("ANP session components initialized successfully")

    async def fetch_text(self, url: str) -> Tuple[Dict, List]:
        """
        Fetch text content (JSON, YAML, plain text, etc.) from a URL.

        This method handles:
        - Agent Description files (JSON-LD)
        - Interface definition files (JSON-RPC, YAML, MCP)
        - Plain text documents

        Args:
            url: URL to fetch content from

        Returns:
            tuple: (content_json, interfaces_list)
            - content_json: Dictionary with agentDescriptionURI, contentURI, content
            - interfaces_list: List of interfaces in OpenAI Tools format
        """
        logger.info(f"Fetching text content from: {url}")

        # Set agent description URI on first fetch
        if self._agent_description_uri is None:
            self._agent_description_uri = self._remove_url_params(url)

        # Check cache first
        if self.cache_enabled:
            cached_result = self._cache_get(url)
            if cached_result:
                logger.info(f"Using cached result for: {url}")
                return cached_result

        try:
            # Add to visited URLs
            self._visited_urls.add(url)

            # Fetch content using HTTP client
            response_data = await self._client.fetch_url(url)

            if not response_data.get("success", False):
                error_content = {
                    "agentDescriptionURI": self._agent_description_uri or self._remove_url_params(url),
                    "contentURI": self._remove_url_params(url),
                    "content": f"Error: {response_data.get('error', 'Unknown error')}"
                }
                return error_content, []

            # Extract text content
            raw_text = response_data.get("text", "")
            content_type = response_data.get("content_type", "")

            # Parse document to extract interfaces
            parsed_data = self._parser.parse_document(raw_text, content_type, url)

            # Convert interfaces to OpenAI Tools format and create ANPInterface instances
            interfaces_list = []
            if parsed_data.get("interfaces"):
                for interface_data in parsed_data["interfaces"]:
                    converted_interface = self._interface_converter.convert_to_openai_tools(interface_data)
                    if converted_interface:
                        interfaces_list.append(converted_interface)

                        # Create and store ANPInterface instance
                        anp_interface = self._interface_converter.create_anp_interface(interface_data, self._client)
                        if anp_interface:
                            self._anp_interfaces[anp_interface.tool_name] = anp_interface
                            logger.debug(f"Created ANPInterface for tool: {anp_interface.tool_name}")

            # Build content JSON according to new format
            content_json = {
                "agentDescriptionURI": self._agent_description_uri,
                "contentURI": self._remove_url_params(url),
                "content": raw_text
            }

            result = (content_json, interfaces_list)

            # Cache the result
            if self.cache_enabled:
                self._cache_set(url, result)

            logger.info(f"Successfully fetched text content from: {url}, found {len(interfaces_list)} interfaces")
            logger.info(f"Interfaces: {interfaces_list}")
            logger.info(f"Content: {content_json}")
            return result

        except Exception as e:
            logger.error(f"Error fetching text content from {url}: {str(e)}")

            error_content = {
                "agentDescriptionURI": self._agent_description_uri or self._remove_url_params(url),
                "contentURI": self._remove_url_params(url),
                "content": f"Error: {str(e)}"
            }
            return error_content, []

    async def fetch_image(self, url: str) -> Tuple[Dict, List]:
        """
        Fetch image information without downloading the actual file.

        Args:
            url: URL of the image

        Returns:
            tuple: (image_info_json, interfaces_list)
            - image_info_json: Dictionary containing image metadata
                {
                    "success": bool,
                    "source_url": str,
                    "url": str,  # Same as source_url
                    "description": str,
                    "metadata": {
                        "file_size": int,
                        "format": str,
                        "width": int,
                        "height": int,
                        "timestamp": str
                    }
                }
            - interfaces_list: Usually empty list for images
        """
        pass

    async def fetch_video(self, url: str) -> Tuple[Dict, List]:
        """
        Fetch video information without downloading the actual file.

        Args:
            url: URL of the video

        Returns:
            tuple: (video_info_json, interfaces_list)
            - video_info_json: Dictionary containing video metadata
                {
                    "success": bool,
                    "source_url": str,
                    "url": str,
                    "description": str,
                    "thumbnail": str,  # Optional thumbnail URL
                    "metadata": {
                        "file_size": int,
                        "format": str,
                        "duration": int,  # Duration in seconds
                        "resolution": str,  # e.g., "1920x1080"
                        "timestamp": str
                    }
                }
            - interfaces_list: Usually empty list for videos
        """
        pass

    async def fetch_audio(self, url: str) -> Tuple[Dict, List]:
        """
        Fetch audio information without downloading the actual file.

        Args:
            url: URL of the audio file

        Returns:
            tuple: (audio_info_json, interfaces_list)
            - audio_info_json: Dictionary containing audio metadata
                {
                    "success": bool,
                    "source_url": str,
                    "url": str,
                    "description": str,
                    "metadata": {
                        "file_size": int,
                        "format": str,
                        "duration": int,  # Duration in seconds
                        "bitrate": int,  # Bitrate in kbps
                        "timestamp": str
                    }
                }
            - interfaces_list: Usually empty list for audio files
        """
        pass

    async def fetch_auto(self, url: str) -> Tuple[Dict, List]:
        """
        Automatically detect content type and call the appropriate fetch method.

        This method:
        1. Makes a HEAD request to check Content-Type
        2. Calls the appropriate fetch_* method based on content type
        3. Falls back to fetch_text for unknown types

        Args:
            url: URL to fetch

        Returns:
            tuple: (content_json, interfaces_list) based on detected type
        """
        pass

    def _cache_get(self, url: str) -> Optional[Tuple[Dict, List]]:
        """Get cached result for a URL."""
        if not self.cache_enabled:
            return None
        return self._cache.get(url)

    def _cache_set(self, url: str, result: Tuple[Dict, List]):
        """Cache result for a URL."""
        if not self.cache_enabled:
            return
        self._cache[url] = result
        logger.debug(f"Cached result for URL: {url}")

    def get_visited_urls(self) -> List[str]:
        """Get list of all visited URLs in this session."""
        return list(self._visited_urls)

    def clear_cache(self):
        """Clear the session cache."""
        self._cache.clear()
        self._visited_urls.clear()
        logger.info("Session cache cleared")

    def get_cache_size(self) -> int:
        """Get the number of cached entries."""
        return len(self._cache)

    def is_url_visited(self, url: str) -> bool:
        """Check if a URL has been visited in this session."""
        return url in self._visited_urls

    def _remove_url_params(self, url: str) -> str:
        """Remove query parameters from URL."""
        try:
            parsed = urlparse(url)
            # Remove query parameters and fragment
            cleaned = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                '',  # params
                '',  # query
                ''   # fragment
            ))
            return cleaned
        except Exception as e:
            logger.warning(f"Failed to parse URL {url}: {str(e)}")
            return url

    async def execute_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a tool call by name with given arguments.

        This method finds the corresponding ANPInterface for the tool and executes
        the JSON-RPC request to the appropriate server.

        Args:
            tool_name: The OpenAI tool function name
            arguments: Dictionary of arguments to pass to the tool

        Returns:
            Dictionary containing execution result
        """
        logger.info(f"Executing tool call: {tool_name}")

        # Find the ANPInterface for this tool
        anp_interface = self._anp_interfaces.get(tool_name)
        if not anp_interface:
            return {
                "success": False,
                "error": f"No ANPInterface found for tool: {tool_name}",
                "tool_name": tool_name
            }

        return await anp_interface.execute(arguments)

    def get_tool_interface_info(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """
        Get stored interface metadata for a tool.

        Args:
            tool_name: The OpenAI tool function name

        Returns:
            Interface metadata dictionary or None if not found
        """
        anp_interface = self._anp_interfaces.get(tool_name)
        if not anp_interface:
            return None

        return {
            "tool_name": anp_interface.tool_name,
            "method_name": anp_interface.method_name,
            "servers": anp_interface.servers,
            "interface_data": anp_interface.interface_data
        }

    def list_available_tools(self) -> List[str]:
        """
        Get list of all available tool names that can be executed.

        Returns:
            List of tool names
        """
        return list(self._anp_interfaces.keys())

    def clear_tool_interfaces(self):
        """
        Clear all stored tool interface mappings.

        This is useful when starting a new session or when you want to
        reset the tool mappings.
        """
        self._anp_interfaces.clear()
        logger.info("Cleared all tool interface mappings")