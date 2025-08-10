# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.


import asyncio
import json
import unittest
from unittest.mock import AsyncMock, patch

from agent_connect.utils.crypto_tool import get_pem_from_private_key
from agent_connect.utils.did_generate import did_generate
from agent_connect.wss_message_client import WssMessageClient


class TestWssMessageService(unittest.TestCase):
    def setUp(self):
        self.wss_url = "wss://example.com/ws"
        self.api_key = "test_api_key"
        self.wss_service = WssMessageClient(self.wss_url, self.api_key)
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
    def tearDown(self):
        # Close the event loop at the end of the test
        self.loop.close()

    @patch('websockets.connect', new_callable=AsyncMock)
    def test_connect(self, mock_connect):
        """Test if the connect function correctly calls websockets.connect and handles authentication"""
        mock_connect.return_value = AsyncMock()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.wss_service.connect())
        mock_connect.assert_called_with(self.wss_url, extra_headers={"Authorization": f"Bearer {self.api_key}"})
        self.assertIsNotNone(self.wss_service.websocket)

    @patch('websockets.connect', new_callable=AsyncMock)
    @patch('asyncio.sleep', side_effect=asyncio.CancelledError)
    def test_send_heartbeat(self, mock_sleep, mock_connect):
        """Test if the heartbeat sending function works as expected"""
        mock_websocket = AsyncMock()
        mock_connect.return_value = mock_websocket
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.wss_service.connect())
        with self.assertRaises(asyncio.CancelledError):
            loop.run_until_complete(self.wss_service.send_heartbeat())
        mock_websocket.send.assert_called()

    def test_close(self):
        """Test the connection closing function"""
        self.wss_service.websocket = AsyncMock()
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.wss_service.close())
        self.wss_service.websocket.close.assert_called()

    @patch('utils.did_generate.did_generate')
    def test_register_routers(self, mock_did_generate):
        """Test if the register_routers method correctly handles DID generation and registration"""
        # Set up mock did_generate return value
        mock_private_key = AsyncMock()
        mock_public_key = AsyncMock()
        mock_did = "did:example:123"
        mock_did_document_json = '{"id": "did:example:123"}'
        mock_did_generate.return_value = (mock_private_key, mock_public_key, mock_did, mock_did_document_json)

        # Set WebSocket to AsyncMock
        self.wss_service.websocket = AsyncMock()

        # Call register_routers method
        private_key, public_key, mock_did, did_document_json = did_generate("wss://example.com/endpoint")
        pem_key = get_pem_from_private_key(private_key)

        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.wss_service.register_routers([(pem_key, did_document_json)]))

        # Construct expected message, not directly using ANY
        expected_message = {
            "version": "1.0",
            "type": "register",
            "routers": [{
                "router": mock_did,
                "proof": {
                    "type": "EcdsaSecp256r1Signature2019",
                    "proofPurpose": "assertionMethod",
                }
            }]
        }

        # Manually verify fields containing ANY
        actual_call_args = self.wss_service.websocket.send.call_args[0][0]
        actual_message = json.loads(actual_call_args)

        # Verify dynamic fields
        self.assertTrue(isinstance(actual_message['timestamp'], str))
        self.assertTrue(isinstance(actual_message['messageId'], str))
        self.assertTrue(isinstance(actual_message['routers'][0]['nonce'], str))
        self.assertTrue(isinstance(actual_message['routers'][0]['proof']['created'], str))
        self.assertTrue(isinstance(actual_message['routers'][0]['proof']['verificationMethod'], str))
        self.assertTrue(isinstance(actual_message['routers'][0]['proof']['proofValue'], str))


if __name__ == '__main__':
    unittest.main()
