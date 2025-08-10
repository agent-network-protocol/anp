# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import asyncio
import json
import logging
import shutil
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent.parent))

from openai import AsyncAzureOpenAI

from agent_connect.meta_protocol.code_generator.code_generator import (
    ProtocolCodeGenerator,
)
from agent_connect.utils.llm.base_llm import AzureLLM, BaseLLM
from agent_connect.utils.log_base import set_log_color_level
from tests.test_code.config import (
    AZURE_OPENAI_API_KEY,
    AZURE_OPENAI_DEPLOYMENT,
    AZURE_OPENAI_ENDPOINT,
    AZURE_OPENAI_MODEL_NAME,
    validate_config,
)

protocol_doc = '''

# Requirements

Design an API protocol to retrieve educational background information for a single user. This protocol should:
- Allow fetching educational background details for a specified user based on `user_id`.
- The educational background must include the institution name, major, degree, achievements, start and end dates.
- Support error handling and parameter validation.
- Implement pagination for retrieved data.

# Protocol Flow

## Interaction Flow

1. **Request**: The client sends a request to the server containing `user_id` and an optional parameter `include_details` to specify whether detailed information is required.
2. **Validation**: The server validates the input parameters.
3. **Fetch Data**: Upon successful validation, the server retrieves the educational experience data.
4. **Response**: The server sends back a response containing the educational details or an error message if applicable.

# Data Format

## Request Message Format

The request message is in JSON format with the following structure:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "messageType": {
      "type": "string",
      "const": "getUserEducation"
    },
    "messageId": {
      "type": "string",
      "format": "uuid"
    },
    "userId": {
      "type": "string"
    },
    "includeDetails": {
      "type": "boolean",
      "default": false
    },
    "page": {
      "type": "integer",
      "minimum": 1,
      "default": 1
    },
    "pageSize": {
      "type": "integer",
      "minimum": 1,
      "default": 10
    }
  },
  "required": ["messageType", "messageId", "userId"],
  "additionalProperties": false
}
'''

def get_llm_instance() -> BaseLLM:
    """Return an Azure OpenAI LLM instance"""
    client = AsyncAzureOpenAI(
        api_key=AZURE_OPENAI_API_KEY,
        api_version="2024-02-01",
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        azure_deployment=AZURE_OPENAI_DEPLOYMENT,
    )
    return AzureLLM(client=client, model_name=AZURE_OPENAI_MODEL_NAME)

async def test_code_generator():
    """Test the complete functionality of the code generator"""

    # Validate configuration
    validate_config()

    # Create a temporary output directory
    output_path = Path(__file__).parent / "generated_code_test"
    if output_path.exists():
        shutil.rmtree(output_path)
    output_path.mkdir(parents=True)

    try:
        # Create an LLM instance
        llm = get_llm_instance()

        # Create a code generator instance
        logging.info("\n=== Initialize code generator ===")
        generator = ProtocolCodeGenerator(
            llm=llm,
            protocol_doc=protocol_doc,
            output_path=str(output_path)
        )

        # Test complete generation process
        logging.info("\n=== Test complete generation process ===")
        await generator.generate()

        # Validate generated files
        module_name = generator._module_name
        if not module_name:
            raise ValueError("Module name not generated")

        module_path = output_path / module_name

        # Validate required files
        required_files = [
            "__init__.py",
            "meta_data.json",
            "protocol_document.md",
            "requester.py",
            "requester_description.json",
            "provider.py",
            "provider_description.json"
        ]

        for file in required_files:
            file_path = module_path / file
            if not file_path.exists():
                raise FileNotFoundError(f"Required file not generated: {file}")
            logging.info(f"Validate file exists: {file}")

        # Validate meta_data.json content
        with open(module_path / "meta_data.json", "r", encoding="utf-8") as f:
            meta_data = json.load(f)
            logging.info("\nmeta_data.json content:")
            logging.info(json.dumps(meta_data, indent=2))

        logging.info("\n=== Test completed ===")
        logging.info(f"Generated code located at: {output_path}")

    except Exception as e:
        logging.error(f"Error during test: {str(e)}", exc_info=True)
    finally:
        # Clean up temporary directory (optional, uncomment to keep generated files)
        # if output_path.exists():
        #     shutil.rmtree(output_path)
        pass

if __name__ == "__main__":
    set_log_color_level(logging.INFO)
    asyncio.run(test_code_generator())