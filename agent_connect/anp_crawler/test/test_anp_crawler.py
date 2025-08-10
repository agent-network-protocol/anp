"""
ANP Crawler Comprehensive Test Suite

Tests all functionality of anp_crawler.py and related modules including:
- ANPCrawler session management
- Text content fetching and parsing
- Interface extraction and conversion
- Multimedia content handling
- Caching mechanisms
- Error handling
"""

import unittest
import asyncio
import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import sys

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent.parent))

from octopus.anp_sdk.anp_crawler.anp_crawler import ANPCrawler
from octopus.anp_sdk.anp_crawler.anp_client import ANPClient
from octopus.anp_sdk.anp_crawler.anp_parser import ANPDocumentParser
from octopus.anp_sdk.anp_crawler.anp_interface import ANPInterface


class TestANPCrawler(unittest.IsolatedAsyncioTestCase):
    """Test cases for ANPCrawler class and related components."""
    
    def setUp(self):
        """Set up test environment."""
        # Load test data
        self.test_data_dir = Path(__file__).parent
        
        # Load Agent Description test data
        with open(self.test_data_dir / "test_data_agent_description.json", "r") as f:
            self.agent_description_data = json.load(f)
        
        # Load OpenRPC test data
        with open(self.test_data_dir / "test_data_openrpc.json", "r") as f:
            self.openrpc_data = json.load(f)
        
        # Load embedded OpenRPC test data
        with open(self.test_data_dir / "test_data_embedded_openrpc.json", "r") as f:
            self.embedded_openrpc_data = json.load(f)
        
        # Mock DID paths for testing
        self.mock_did_document_path = "test/did.json"
        self.mock_private_key_path = "test/private_key.json"
        
        # Test URLs
        self.test_agent_url = "https://grand-hotel.com/agents/hotel-assistant"
        self.test_openrpc_url = "https://grand-hotel.com/api/services-interface.json"
        self.test_embedded_openrpc_url = "https://hotel-services.com/agents/booking-assistant"
        self.test_image_url = "https://grand-hotel.com/media/hotel-image.jpg"
        self.test_video_url = "https://grand-hotel.com/media/hotel-tour-video.mp4"
        self.test_audio_url = "https://grand-hotel.com/media/hotel-audio.mp3"
    
    @patch('octopus.anp_sdk.anp_crawler.anp_client.DIDWbaAuthHeader')
    def test_anp_crawler_initialization(self, mock_auth_header):
        """Test ANPCrawler initialization."""
        mock_auth_header.return_value = MagicMock()
        
        # Test successful initialization
        crawler = ANPCrawler(
            did_document_path=self.mock_did_document_path,
            private_key_path=self.mock_private_key_path,
            cache_enabled=True
        )
        
        self.assertIsNotNone(crawler._client)
        self.assertIsNotNone(crawler._parser)
        self.assertIsNotNone(crawler._interface_converter)
        self.assertTrue(crawler.cache_enabled)
        self.assertEqual(len(crawler._visited_urls), 0)
        self.assertEqual(len(crawler._cache), 0)
    
    @patch('octopus.anp_sdk.anp_crawler.anp_client.DIDWbaAuthHeader')
    async def test_fetch_text_agent_description(self, mock_auth_header):
        """Test fetching Agent Description document."""
        mock_auth_header.return_value = MagicMock()
        
        # Create crawler instance
        crawler = ANPCrawler(
            did_document_path=self.mock_did_document_path,
            private_key_path=self.mock_private_key_path
        )
        
        # Mock HTTP response
        mock_response = {
            "success": True,
            "text": json.dumps(self.agent_description_data),
            "content_type": "application/json",
            "status_code": 200,
            "url": self.test_agent_url
        }
        
        crawler._client.fetch_url = AsyncMock(return_value=mock_response)
        
        # Execute fetch_text
        content_json, interfaces_list = await crawler.fetch_text(self.test_agent_url)
        
        # Verify content_json structure
        self.assertIn("agentDescriptionURI", content_json)
        self.assertIn("contentURI", content_json)
        self.assertIn("content", content_json)
        self.assertEqual(content_json["agentDescriptionURI"], self.test_agent_url)
        self.assertEqual(content_json["contentURI"], self.test_agent_url)
        
        # Verify interfaces extraction from Agent Description
        self.assertIsInstance(interfaces_list, list)
        # Agent Description should extract interface URLs but not actual tools yet
        # (would need to fetch the interface files)
    
    @patch('octopus.anp_sdk.anp_crawler.anp_client.DIDWbaAuthHeader')
    async def test_fetch_text_openrpc_document(self, mock_auth_header):
        """Test fetching and parsing OpenRPC document."""
        mock_auth_header.return_value = MagicMock()
        
        # Create crawler instance
        crawler = ANPCrawler(
            did_document_path=self.mock_did_document_path,
            private_key_path=self.mock_private_key_path
        )
        
        # Mock HTTP response for OpenRPC document
        mock_response = {
            "success": True,
            "text": json.dumps(self.openrpc_data),
            "content_type": "application/json",
            "status_code": 200,
            "url": self.test_openrpc_url
        }
        
        crawler._client.fetch_url = AsyncMock(return_value=mock_response)
        
        # Execute fetch_text
        content_json, interfaces_list = await crawler.fetch_text(self.test_openrpc_url)
        
        # Verify content structure
        self.assertEqual(content_json["contentURI"], self.test_openrpc_url)
        self.assertEqual(content_json["content"], json.dumps(self.openrpc_data))
        
        # Verify interfaces extraction and conversion
        self.assertIsInstance(interfaces_list, list)
        self.assertGreater(len(interfaces_list), 0)
        
        # Check that interfaces are in OpenAI Tools format
        for interface in interfaces_list:
            self.assertEqual(interface["type"], "function")
            self.assertIn("function", interface)
            self.assertIn("name", interface["function"])
            self.assertIn("description", interface["function"])
            self.assertIn("parameters", interface["function"])
    
    @patch('octopus.anp_sdk.anp_crawler.anp_client.DIDWbaAuthHeader')
    async def test_fetch_text_with_ref_resolution(self, mock_auth_header):
        """Test OpenRPC $ref resolution in schemas."""
        mock_auth_header.return_value = MagicMock()
        
        # Create crawler instance
        crawler = ANPCrawler(
            did_document_path=self.mock_did_document_path,
            private_key_path=self.mock_private_key_path
        )
        
        # Mock HTTP response
        mock_response = {
            "success": True,
            "text": json.dumps(self.openrpc_data),
            "content_type": "application/json",
            "status_code": 200,
            "url": self.test_openrpc_url
        }
        
        crawler._client.fetch_url = AsyncMock(return_value=mock_response)
        
        # Execute fetch_text
        content_json, interfaces_list = await crawler.fetch_text(self.test_openrpc_url)
        
        # Find interface with $ref resolution (makeReservation method)
        found_ref_resolution = False
        for interface in interfaces_list:
            if interface["function"]["name"] == "makeReservation":
                params = interface["function"]["parameters"]
                properties = params.get("properties", {})
                
                # Check reservationData parameter
                if "reservationData" in properties:
                    reservation_data = properties["reservationData"]
                    rd_properties = reservation_data.get("properties", {})
                    
                    # Check if guestInfo has been resolved from $ref
                    if "guestInfo" in rd_properties:
                        guest_info = rd_properties["guestInfo"]
                        if "properties" in guest_info:
                            # This should be resolved from $ref to actual schema
                            found_ref_resolution = True
                            self.assertIn("firstName", guest_info["properties"])
                            self.assertIn("lastName", guest_info["properties"])
                            self.assertIn("email", guest_info["properties"])
                            break
        
        # At least one $ref should have been resolved
        self.assertTrue(found_ref_resolution, "$ref references should be resolved")
    
    @patch('octopus.anp_sdk.anp_crawler.anp_client.DIDWbaAuthHeader')
    async def test_fetch_text_embedded_openrpc(self, mock_auth_header):
        """Test fetching Agent Description with embedded OpenRPC content."""
        mock_auth_header.return_value = MagicMock()
        
        # Create crawler instance
        crawler = ANPCrawler(
            did_document_path=self.mock_did_document_path,
            private_key_path=self.mock_private_key_path
        )
        
        # Mock HTTP response for Agent Description with embedded OpenRPC
        mock_response = {
            "success": True,
            "text": json.dumps(self.embedded_openrpc_data),
            "content_type": "application/json",
            "status_code": 200,
            "url": self.test_embedded_openrpc_url
        }
        
        crawler._client.fetch_url = AsyncMock(return_value=mock_response)
        
        # Execute fetch_text
        content_json, interfaces_list = await crawler.fetch_text(self.test_embedded_openrpc_url)
        
        # Verify content structure
        self.assertEqual(content_json["contentURI"], self.test_embedded_openrpc_url)
        self.assertEqual(content_json["content"], json.dumps(self.embedded_openrpc_data))
        
        # Verify embedded OpenRPC interfaces extraction
        self.assertIsInstance(interfaces_list, list)
        self.assertGreater(len(interfaces_list), 0)
        
        # Should find checkAvailability and createBooking methods
        method_names = [interface["function"]["name"] for interface in interfaces_list]
        self.assertIn("checkAvailability", method_names)
        self.assertIn("createBooking", method_names)
        
        # Verify $ref resolution in embedded OpenRPC
        booking_interface = None
        for interface in interfaces_list:
            if interface["function"]["name"] == "createBooking":
                booking_interface = interface
                break
        
        self.assertIsNotNone(booking_interface, "createBooking interface should be found")
        
        # Check that $ref references are resolved
        params = booking_interface["function"]["parameters"]
        properties = params.get("properties", {})
        
        if "bookingDetails" in properties:
            booking_details = properties["bookingDetails"]
            bd_properties = booking_details.get("properties", {})
            
            # Check if guestInfo has been resolved from $ref
            if "guestInfo" in bd_properties:
                guest_info = bd_properties["guestInfo"]
                self.assertIn("properties", guest_info, "$ref for guestInfo should be resolved")
                self.assertIn("firstName", guest_info["properties"])
                self.assertIn("email", guest_info["properties"])
    
    @patch('octopus.anp_sdk.anp_crawler.anp_client.DIDWbaAuthHeader')
    async def test_fetch_text_error_handling(self, mock_auth_header):
        """Test error handling in fetch_text."""
        mock_auth_header.return_value = MagicMock()
        
        # Create crawler instance
        crawler = ANPCrawler(
            did_document_path=self.mock_did_document_path,
            private_key_path=self.mock_private_key_path
        )
        
        # Mock HTTP error response
        mock_response = {
            "success": False,
            "error": "HTTP 404: Not Found",
            "status_code": 404,
            "url": self.test_agent_url
        }
        
        crawler._client.fetch_url = AsyncMock(return_value=mock_response)
        
        # Execute fetch_text
        content_json, interfaces_list = await crawler.fetch_text(self.test_agent_url)
        
        # Verify error handling
        self.assertIn("Error:", content_json["content"])
        self.assertEqual(len(interfaces_list), 0)
    
    @patch('octopus.anp_sdk.anp_crawler.anp_client.DIDWbaAuthHeader')
    async def test_fetch_image(self, mock_auth_header):
        """Test fetch_image method (pass implementation)."""
        mock_auth_header.return_value = MagicMock()
        
        # Create crawler instance
        crawler = ANPCrawler(
            did_document_path=self.mock_did_document_path,
            private_key_path=self.mock_private_key_path
        )
        
        # Execute fetch_image
        result = await crawler.fetch_image(self.test_image_url)
        
        # Should return None for pass implementation
        self.assertIsNone(result)
    
    @patch('octopus.anp_sdk.anp_crawler.anp_client.DIDWbaAuthHeader')
    async def test_fetch_video(self, mock_auth_header):
        """Test fetch_video method (pass implementation)."""
        mock_auth_header.return_value = MagicMock()
        
        # Create crawler instance
        crawler = ANPCrawler(
            did_document_path=self.mock_did_document_path,
            private_key_path=self.mock_private_key_path
        )
        
        # Execute fetch_video
        result = await crawler.fetch_video(self.test_video_url)
        
        # Should return None for pass implementation
        self.assertIsNone(result)
    
    @patch('octopus.anp_sdk.anp_crawler.anp_client.DIDWbaAuthHeader')
    async def test_fetch_audio(self, mock_auth_header):
        """Test fetch_audio method (pass implementation)."""
        mock_auth_header.return_value = MagicMock()
        
        # Create crawler instance
        crawler = ANPCrawler(
            did_document_path=self.mock_did_document_path,
            private_key_path=self.mock_private_key_path
        )
        
        # Execute fetch_audio
        result = await crawler.fetch_audio(self.test_audio_url)
        
        # Should return None for pass implementation
        self.assertIsNone(result)
    
    @patch('octopus.anp_sdk.anp_crawler.anp_client.DIDWbaAuthHeader')
    async def test_fetch_auto(self, mock_auth_header):
        """Test fetch_auto method (pass implementation)."""
        mock_auth_header.return_value = MagicMock()
        
        # Create crawler instance
        crawler = ANPCrawler(
            did_document_path=self.mock_did_document_path,
            private_key_path=self.mock_private_key_path
        )
        
        # Execute fetch_auto
        result = await crawler.fetch_auto(self.test_agent_url)
        
        # Should return None for pass implementation
        self.assertIsNone(result)
    
    @patch('octopus.anp_sdk.anp_crawler.anp_client.DIDWbaAuthHeader')
    async def test_caching_functionality(self, mock_auth_header):
        """Test URL caching functionality."""
        mock_auth_header.return_value = MagicMock()
        
        # Create crawler instance with caching enabled
        crawler = ANPCrawler(
            did_document_path=self.mock_did_document_path,
            private_key_path=self.mock_private_key_path,
            cache_enabled=True
        )
        
        # Mock HTTP response
        mock_response = {
            "success": True,
            "text": json.dumps(self.agent_description_data),
            "content_type": "application/json",
            "status_code": 200,
            "url": self.test_agent_url
        }
        
        crawler._client.fetch_url = AsyncMock(return_value=mock_response)
        
        # First fetch - should call HTTP client
        await crawler.fetch_text(self.test_agent_url)
        self.assertEqual(crawler._client.fetch_url.call_count, 1)
        self.assertEqual(crawler.get_cache_size(), 1)
        
        # Second fetch - should use cache
        await crawler.fetch_text(self.test_agent_url)
        self.assertEqual(crawler._client.fetch_url.call_count, 1)  # Still 1, not called again
        
        # Test cache clearing
        crawler.clear_cache()
        self.assertEqual(crawler.get_cache_size(), 0)
        self.assertEqual(len(crawler.get_visited_urls()), 0)
    
    @patch('octopus.anp_sdk.anp_crawler.anp_client.DIDWbaAuthHeader')
    def test_session_management(self, mock_auth_header):
        """Test session management functionality."""
        mock_auth_header.return_value = MagicMock()
        
        # Create crawler instance
        crawler = ANPCrawler(
            did_document_path=self.mock_did_document_path,
            private_key_path=self.mock_private_key_path
        )
        
        # Test initial state
        self.assertEqual(len(crawler.get_visited_urls()), 0)
        self.assertFalse(crawler.is_url_visited(self.test_agent_url))
        
        # Manually add URL to visited (simulating fetch)
        crawler._visited_urls.add(self.test_agent_url)
        
        # Test URL tracking
        self.assertEqual(len(crawler.get_visited_urls()), 1)
        self.assertTrue(crawler.is_url_visited(self.test_agent_url))
        self.assertIn(self.test_agent_url, crawler.get_visited_urls())
    
    def test_url_parameter_removal(self):
        """Test URL parameter removal functionality."""
        # Test with mock since we need to access private method
        with patch('octopus.anp_sdk.anp_crawler.anp_client.DIDWbaAuthHeader'):
            crawler = ANPCrawler(
                did_document_path=self.mock_did_document_path,
                private_key_path=self.mock_private_key_path
            )
            
            # Test URL with parameters
            url_with_params = "https://example.com/path?param1=value1&param2=value2#fragment"
            expected_clean_url = "https://example.com/path"
            
            clean_url = crawler._remove_url_params(url_with_params)
            self.assertEqual(clean_url, expected_clean_url)
            
            # Test URL without parameters
            url_without_params = "https://example.com/path"
            clean_url = crawler._remove_url_params(url_without_params)
            self.assertEqual(clean_url, url_without_params)


class TestANPDocumentParser(unittest.TestCase):
    """Test cases for ANPDocumentParser class."""
    
    def setUp(self):
        """Set up test environment."""
        self.parser = ANPDocumentParser()
        
        # Load test data
        test_data_dir = Path(__file__).parent
        with open(test_data_dir / "test_data_agent_description.json", "r") as f:
            self.agent_description_data = json.load(f)
        with open(test_data_dir / "test_data_openrpc.json", "r") as f:
            self.openrpc_data = json.load(f)
        with open(test_data_dir / "test_data_embedded_openrpc.json", "r") as f:
            self.embedded_openrpc_data = json.load(f)
    
    def test_parse_agent_description(self):
        """Test parsing Agent Description document."""
        content = json.dumps(self.agent_description_data)
        result = self.parser.parse_document(content, "application/json", "test_url")
        
        self.assertIn("interfaces", result)
        interfaces = result["interfaces"]
        self.assertGreater(len(interfaces), 0)
        
        # Check interface structure
        for interface in interfaces:
            self.assertIn("type", interface)
            self.assertIn("protocol", interface)
            self.assertIn("url", interface)
            self.assertEqual(interface["source"], "agent_description")
    
    def test_parse_openrpc_document(self):
        """Test parsing OpenRPC document."""
        content = json.dumps(self.openrpc_data)
        result = self.parser.parse_document(content, "application/json", "test_url")
        
        self.assertIn("interfaces", result)
        interfaces = result["interfaces"]
        self.assertGreater(len(interfaces), 0)
        
        # Check OpenRPC interface structure
        for interface in interfaces:
            self.assertEqual(interface["type"], "openrpc_method")
            self.assertEqual(interface["protocol"], "openrpc")
            self.assertIn("method_name", interface)
            self.assertIn("params", interface)
            self.assertIn("components", interface)
            self.assertEqual(interface["source"], "openrpc_interface")
    
    def test_parse_embedded_openrpc_document(self):
        """Test parsing Agent Description with embedded OpenRPC content."""
        content = json.dumps(self.embedded_openrpc_data)
        result = self.parser.parse_document(content, "application/json", "test_url")
        
        self.assertIn("interfaces", result)
        interfaces = result["interfaces"]
        self.assertGreater(len(interfaces), 0)
        
        # Should find methods from embedded OpenRPC content
        method_names = [interface["method_name"] for interface in interfaces if interface["type"] == "openrpc_method"]
        self.assertIn("checkAvailability", method_names)
        self.assertIn("createBooking", method_names)
        
        # Check embedded OpenRPC interface structure
        for interface in interfaces:
            if interface["type"] == "openrpc_method":
                self.assertEqual(interface["protocol"], "openrpc")
                self.assertIn("method_name", interface)
                self.assertIn("params", interface)
                self.assertIn("components", interface)
                self.assertEqual(interface["source"], "openrpc_interface")
    
    def test_parse_invalid_json(self):
        """Test parsing invalid JSON content."""
        invalid_content = "{ invalid json"
        result = self.parser.parse_document(invalid_content, "application/json", "test_url")
        
        self.assertIn("interfaces", result)
        self.assertEqual(len(result["interfaces"]), 0)


class TestANPInterface(unittest.TestCase):
    """Test cases for ANPInterface class."""
    
    def setUp(self):
        """Set up test environment."""
        self.converter = ANPInterface()
    
    def test_convert_openrpc_method(self):
        """Test converting OpenRPC method to OpenAI Tools format."""
        # Mock OpenRPC method data
        openrpc_method = {
            "type": "openrpc_method",
            "method_name": "searchRooms",
            "description": "Search available hotel rooms",
            "params": [
                {
                    "name": "searchCriteria",
                    "description": "Room search criteria",
                    "required": True,
                    "schema": {
                        "type": "object",
                        "properties": {
                            "checkIn": {
                                "type": "string",
                                "format": "date"
                            },
                            "guests": {
                                "type": "integer"
                            }
                        },
                        "required": ["checkIn", "guests"]
                    }
                }
            ],
            "components": {}
        }
        
        result = self.converter.convert_to_openai_tools(openrpc_method)
        
        # Verify OpenAI Tools format
        self.assertEqual(result["type"], "function")
        self.assertIn("function", result)
        
        function_def = result["function"]
        self.assertEqual(function_def["name"], "searchRooms")
        self.assertEqual(function_def["description"], "Search available hotel rooms")
        self.assertIn("parameters", function_def)
        
        # Verify parameters structure
        params = function_def["parameters"]
        self.assertEqual(params["type"], "object")
        self.assertIn("properties", params)
        self.assertIn("required", params)
    
    def test_convert_with_ref_resolution(self):
        """Test conversion with $ref resolution."""
        # Mock OpenRPC method with $ref
        openrpc_method = {
            "type": "openrpc_method",
            "method_name": "makeReservation",
            "description": "Create hotel reservation",
            "params": [
                {
                    "name": "reservationData",
                    "required": True,
                    "schema": {
                        "type": "object",
                        "properties": {
                            "guestInfo": {
                                "$ref": "#/components/schemas/GuestInfo"
                            }
                        }
                    }
                }
            ],
            "components": {
                "schemas": {
                    "GuestInfo": {
                        "type": "object",
                        "properties": {
                            "firstName": {"type": "string"},
                            "lastName": {"type": "string"},
                            "email": {"type": "string", "format": "email"}
                        },
                        "required": ["firstName", "lastName", "email"]
                    }
                }
            }
        }
        
        result = self.converter.convert_to_openai_tools(openrpc_method)
        
        # Verify $ref resolution
        params = result["function"]["parameters"]
        properties = params["properties"]
        
        self.assertIn("reservationData", properties)
        reservation_data = properties["reservationData"]
        self.assertIn("properties", reservation_data)
        
        guest_info = reservation_data["properties"]["guestInfo"]
        self.assertIn("properties", guest_info)
        self.assertIn("firstName", guest_info["properties"])
        self.assertIn("lastName", guest_info["properties"])
        self.assertIn("email", guest_info["properties"])
    
    def test_function_name_sanitization(self):
        """Test function name sanitization."""
        test_cases = [
            ("search-rooms", "search_rooms"),
            ("123invalid", "fn_123invalid"),
            ("special!chars@", "special_chars_"),
            ("", "unknown_function"),
            ("a" * 100, "a" * 64)  # Length limit
        ]
        
        for input_name, expected in test_cases:
            result = self.converter._sanitize_function_name(input_name)
            self.assertEqual(result, expected)
    
    def test_unsupported_interface_type(self):
        """Test handling unsupported interface types."""
        unsupported_interface = {
            "type": "unsupported_type",
            "method_name": "test"
        }
        
        result = self.converter.convert_to_openai_tools(unsupported_interface)
        self.assertIsNone(result)


if __name__ == "__main__":
    # Configure logging
    import logging
    logging.basicConfig(level=logging.INFO)
    
    # Create test loader
    loader = unittest.TestLoader()
    
    # Create test suite  
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTests(loader.loadTestsFromTestCase(TestANPCrawler))
    suite.addTests(loader.loadTestsFromTestCase(TestANPDocumentParser))
    suite.addTests(loader.loadTestsFromTestCase(TestANPInterface))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print(f"\n{'='*50}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    if result.testsRun > 0:
        success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100)
        print(f"Success rate: {success_rate:.1f}%")
    print(f"{'='*50}")
    
    # Exit with appropriate code
    if result.failures or result.errors:
        print("\n❌ Some tests failed!")
        exit(1)
    else:
        print("\n✅ All tests passed!")
        exit(0)