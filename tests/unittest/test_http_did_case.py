# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.


import unittest
from unittest.mock import AsyncMock, patch

from agent_connect.didallclient import DIDAllClient


class TestDIDAllClient(unittest.TestCase):
    def setUp(self):
        self.did_service_url = "https://example.com/did"
        self.api_key = "test_api_key"
        self.client = DIDAllClient(self.did_service_url, self.api_key)

    @patch('didall.didallclient.did_generate')
    @patch('didall.didallclient.get_pem_from_private_key')
    @patch('aiohttp.ClientSession.post', new_callable=AsyncMock)
    async def test_register_did_document(self, mock_post, mock_get_pem, mock_did_generate):
        # Set up mock function return values
        mock_did_generate.return_value = (None, None, "did:example:123", "{}")
        mock_get_pem.return_value = "mock_pem_key"
        mock_post.return_value.__aenter__.return_value.status = 200
        mock_post.return_value.__aenter__.return_value.text = AsyncMock(return_value="{}")

        # Call the function
        private_key_pem, did, did_document_json = await self.client.generate_register_did_document("wss://example.com/endpoint")

        # Assertions
        self.assertEqual(private_key_pem, "mock_pem_key")
        self.assertEqual(did, "did:example:123")
        self.assertEqual(did_document_json, "{}")
        mock_post.assert_called_once()

    @patch('aiohttp.ClientSession.get', new_callable=AsyncMock)
    async def test_get_did_document(self, mock_get):
        # Set up mock function return values
        mock_get.return_value.__aenter__.return_value.status = 200
        mock_get.return_value.__aenter__.return_value.text = AsyncMock(return_value='{"id": "did:example:123"}')

        # Call the function
        did_document = await self.client.get_did_document("did:example:123")

        # Assertions
        self.assertEqual(did_document, '{"id": "did:example:123"}')
        mock_get.assert_called_once()

    @patch('didall.didallclient.did_generate')
    @patch('didall.didallclient.get_pem_from_private_key')
    @patch('requests.post')
    def test_register_did_document_sync(self, mock_post, mock_get_pem, mock_did_generate):
        # Set up mock function return values
        mock_did_generate.return_value = (None, None, "did:example:123", "{}")
        mock_get_pem.return_value = "mock_pem_key"
        mock_post.return_value.status_code = 200
        mock_post.return_value.text = "{}"

        # Call the function
        private_key_pem, did, did_document_json = self.client.register_did_document_sync("wss://example.com/endpoint")

        # Assertions
        self.assertEqual(private_key_pem, "mock_pem_key")
        self.assertEqual(did, "did:example:123")
        self.assertEqual(did_document_json, "{}")
        mock_post.assert_called_once()

    @patch('requests.get')
    def test_get_did_document_sync(self, mock_get):
        # Set up mock function return values
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = '{"id": "did:example:123"}'

        # Call the function
        did_document = self.client.get_did_document_sync("did:example:123")

        # Assertions
        self.assertEqual(did_document, '{"id": "did:example:123"}')
        mock_get.assert_called_once()

if __name__ == '__main__':
    unittest.main()
