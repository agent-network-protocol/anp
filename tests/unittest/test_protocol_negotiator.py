# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import asyncio
import json
import logging
import unittest
from unittest.mock import AsyncMock, MagicMock

from agent_connect.meta_protocol.protocol_negotiator import (
    NegotiationHistoryEntry,
    NegotiationStatus,
    NegotiatorRole,
    ProtocolNegotiator,
)
from agent_connect.utils.llm.base_llm import BaseLLM


class TestProtocolNegotiator(unittest.TestCase):
    def setUp(self):
        # Mock LLM client
        self.mock_llm = MagicMock(spec=BaseLLM)
        self.mock_llm.model_name = "gpt-4-turbo-preview"
        self.mock_llm.client = MagicMock()

        # Mock capability info callback
        self.mock_capability_callback = AsyncMock()

        # Create negotiator instance
        self.negotiator = ProtocolNegotiator(
            llm=self.mock_llm,
            get_capability_info_callback=self.mock_capability_callback
        )

        # Test data
        self.test_requirement = "Create a protocol for user authentication"
        self.test_input = "Username and password in JSON format"
        self.test_output = "Authentication token in JSON format"

        # Sample protocol content
        self.sample_protocol = """
# Requirements
User authentication protocol with username/password

# Protocol Flow
1. Client sends credentials
2. Server validates and returns token

# Data Format
## Request Format
{
    "username": "string",
    "password": "string"
}

## Response Format
{
    "token": "string",
    "expires_in": "number"
}

# Error Handling
Standard HTTP status codes
"""

    async def test_generate_initial_protocol(self):
        """Test initial protocol generation"""
        # Mock LLM response
        self.mock_llm.async_generate_response = AsyncMock(
            return_value=self.sample_protocol
        )

        # Generate initial protocol
        protocol, status, round_num = await self.negotiator.generate_initial_protocol(
            self.test_requirement,
            self.test_input,
            self.test_output
        )

        # Verify results
        self.assertEqual(status, NegotiationStatus.NEGOTIATING)
        self.assertEqual(round_num, 1)
        self.assertEqual(protocol, self.sample_protocol)
        self.assertEqual(self.negotiator.role, NegotiatorRole.REQUESTER)

        # Verify negotiation history
        self.assertEqual(len(self.negotiator.negotiation_history), 1)
        self.assertEqual(
            self.negotiator.negotiation_history[0]["candidate_protocols"],
            self.sample_protocol
        )

    async def test_evaluate_as_provider(self):
        """Test protocol evaluation as provider"""
        # Setup initial state
        self.negotiator.role = NegotiatorRole.PROVIDER
        self.negotiator.negotiation_round = 1

        # Add initial history entry
        self.negotiator.negotiation_history.append(
            NegotiationHistoryEntry(
                round=1,
                candidate_protocols="Initial protocol",
                modification_summary=None
            )
        )

        # Mock LLM response
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(
                message=MagicMock(
                    content=json.dumps({
                        "status": "negotiating",
                        "candidate_protocol": self.sample_protocol,
                        "modification_summary": "Added error handling details"
                    }),
                    tool_calls=None
                )
            )
        ]
        self.mock_llm.client.chat.completions.create = AsyncMock(
            return_value=mock_response
        )

        # Evaluate protocol
        result, round_num = await self.negotiator.evaluate_protocol_proposal(
            NegotiationStatus.NEGOTIATING,
            2,  # counterparty_round
            self.sample_protocol,
            "Previous modifications"
        )

        # Verify results
        self.assertEqual(result.status, NegotiationStatus.NEGOTIATING)
        self.assertEqual(result.candidate_protocol, self.sample_protocol)
        self.assertEqual(result.modification_summary, "Added error handling details")
        self.assertEqual(round_num, 2)  # round should be incremented

    async def test_evaluate_as_requester(self):
        """Test protocol evaluation as requester"""
        # Setup initial state
        self.negotiator.role = NegotiatorRole.REQUESTER
        self.negotiator.requirement = self.test_requirement
        self.negotiator.input_description = self.test_input
        self.negotiator.output_description = self.test_output
        self.negotiator.negotiation_round = 1

        # Add initial history entry
        self.negotiator.negotiation_history.append(
            NegotiationHistoryEntry(
                round=1,
                candidate_protocols="Initial protocol",
                modification_summary=None
            )
        )

        # Mock LLM response
        mock_response = MagicMock()
        mock_response.choices = [
            MagicMock(
                message=MagicMock(
                    content=json.dumps({
                        "status": "accepted",
                        "candidate_protocol": "",
                        "modification_summary": "Protocol accepted"
                    })
                )
            )
        ]
        self.mock_llm.client.chat.completions.create = AsyncMock(
            return_value=mock_response
        )

        # Evaluate protocol
        result, round_num = await self.negotiator.evaluate_protocol_proposal(
            NegotiationStatus.NEGOTIATING,
            2,  # counterparty_round
            self.sample_protocol,
            "Previous modifications"
        )

        # Verify results
        self.assertEqual(result.status, NegotiationStatus.ACCEPTED)
        self.assertEqual(result.modification_summary, "Protocol accepted")
        self.assertEqual(round_num, 2)  # round should be incremented

    async def test_invalid_round_number(self):
        """Test protocol evaluation with invalid round number"""
        self.negotiator.negotiation_round = 1

        result, round_num = await self.negotiator.evaluate_protocol_proposal(
            NegotiationStatus.NEGOTIATING,
            4,  # invalid round number (should be 2)
            self.sample_protocol,
            None
        )

        self.assertEqual(result.status, NegotiationStatus.REJECTED)
        self.assertIn("Invalid round number", result.modification_summary)
        self.assertEqual(round_num, 1)  # round should not be incremented

    async def test_get_capability_info(self):
        """Test capability info retrieval"""
        # Mock callback response
        self.mock_capability_callback.return_value = "System can handle the requirements"

        # Get capability info
        result = await self.negotiator.get_capability_info(
            self.test_requirement,
            self.test_input,
            self.test_output
        )

        # Verify results
        self.assertEqual(result, "System can handle the requirements")
        self.mock_capability_callback.assert_called_once_with(
            self.test_requirement,
            self.test_input,
            self.test_output
        )

def run_async_test(coro):
    """Helper function to run async tests"""
    # Run the asynchronous coroutine using asyncio.run() (Python 3.7+)
    return asyncio.run(coro)

if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
    )

    # Run tests
    unittest.main()