# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import asyncio
import json
import logging
import os
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent.parent))

from openai import AsyncAzureOpenAI

from agent_connect.meta_protocol.meta_protocol import MetaProtocol, ProtocolType
from agent_connect.meta_protocol.protocol_negotiator import NegotiationStatus
from agent_connect.utils.llm.base_llm import AzureLLM
from agent_connect.utils.log_base import set_log_color_level
from tests.test_code.config import (
    AZURE_OPENAI_API_KEY,
    AZURE_OPENAI_DEPLOYMENT,
    AZURE_OPENAI_ENDPOINT,
    AZURE_OPENAI_MODEL_NAME,
    validate_config,
)


# Mock callback function for sending data
async def mock_send_callback(data: bytes) -> None:
    """Mock callback function for sending data"""
    logging.info(f"Mock sending data: {data}")

# Mock callback function for getting capability information
async def mock_capability_info(requirement: str,
                             input_description: str,
                             output_description: str) -> str:
    """Mock callback function for getting capability information"""
    logging.info(f"Requirement: {requirement}")
    logging.info(f"Input description: {input_description}")
    logging.info(f"Output description: {output_description}")
    return """
    Capability Assessment:
    - Requirements: Can fully meet the specified requirements
    - Input Format: Can process all specified input fields
    - Output Format: Can generate all required output fields
    - No significant limitations or constraints identified
    """

def get_llm_instance() -> AzureLLM:
    """Return Azure OpenAI LLM instance"""
    validate_config()

    client = AsyncAzureOpenAI(
        api_key=AZURE_OPENAI_API_KEY,
        api_version="2024-02-01",
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        azure_deployment=AZURE_OPENAI_DEPLOYMENT,
    )

    return AzureLLM(client=client, model_name=AZURE_OPENAI_MODEL_NAME)

async def test_negotiate_protocol():
    """Test protocol negotiation functionality"""
    try:
        # Get LLM instance
        llm = get_llm_instance()

        # Get current file directory path
        current_dir = os.path.dirname(os.path.abspath(__file__))

        # Create MetaProtocol instance with protocol_code_path
        meta_protocol = MetaProtocol(
            send_callback=mock_send_callback,
            get_capability_info_callback=mock_capability_info,
            llm=llm,
            protocol_code_path=os.path.join(current_dir, "generated_code_test")
        )

        # Define test protocol requirements
        requirement = """
        Design an API interface for retrieving user education history.
        - API should support retrieving education history for a single user
        - Education history should include: school name, major, degree, achievements, start time, end time
        - Must support error handling and parameter validation
        """

        input_description = """
        Input parameters should include:
        - user_id: User ID (string)
        - include_details: Whether to include detailed information (boolean, optional)
        """

        output_description = """
        Output should include:
        - List of education history, each containing:
        * institution: School name
        * major: Major
        * degree: Degree (Bachelor/Master/Doctorate)
        * achievements: Achievements
        * start_date: Start time (YYYY-MM-DD)
        * end_date: End time (YYYY-MM-DD)
        - Support for pagination and error message return
        """

        # Start protocol negotiation coroutine
        negotiation_task = asyncio.create_task(
            meta_protocol.negotiate_protocol(
                requirement=requirement,
                input_description=input_description,
                output_description=output_description
            )
        )

        # Simulate receiving protocol negotiation messages
        async def simulate_negotiation_messages():
            await asyncio.sleep(1)

            message1 = {
                "action": "protocolNegotiation",
                "sequenceId": 2,
                "candidateProtocols": "API Protocol Definition...",  # Add actual protocol content
                "status": NegotiationStatus.ACCEPTED.value
            }

            protocol_type_byte = bytes([ProtocolType.META.value << 6])
            message_bytes = protocol_type_byte + json.dumps(message1).encode('utf-8')

            await meta_protocol.handle_meta_data(message_bytes)

        # Start simulated message receiving coroutine
        message_task = asyncio.create_task(simulate_negotiation_messages())

        # Wait for protocol negotiation to complete
        success, module_path = await negotiation_task
        await message_task

        # Verify negotiation results
        if success:
            logging.info("Protocol negotiation and code generation successful!")
            logging.info(f"Generated code path: {module_path}")
            assert os.path.exists(module_path), "Generated code file does not exist"
        else:
            logging.error("Protocol negotiation or code generation failed!")

    except Exception as e:
        logging.error(f"Error occurred during testing: {str(e)}", exc_info=True)
        raise

async def main():
    """Main test function"""
    set_log_color_level(logging.INFO)
    await test_negotiate_protocol()

if __name__ == "__main__":
    asyncio.run(main())