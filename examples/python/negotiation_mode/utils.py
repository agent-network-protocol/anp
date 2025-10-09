# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import importlib
import json
import os
import sys
from typing import Any, Dict

g_current_dir: str = os.path.dirname(os.path.abspath(__file__))
sys.path.append(g_current_dir)
# sys.path.append(g_current_dir + "/../../")

from config import (
    AZURE_OPENAI_API_KEY,
    AZURE_OPENAI_DEPLOYMENT,
    AZURE_OPENAI_ENDPOINT,
    AZURE_OPENAI_MODEL_NAME,
    validate_config,
)
from openai import AsyncAzureOpenAI

from anp.simple_node import SimpleNegotiationNode
from anp.utils.llm.base_llm import AzureLLM, BaseLLM
from anp.utils.llm_output_processer import extract_code_from_llm_output

g_current_dir: str = os.path.dirname(os.path.abspath(__file__))

def generate_did_info(node: SimpleNegotiationNode, json_filename: str) -> None:
    """Generate or load DID information for a node

    Args:
        node: The SimpleNegotiationNode instance
        json_filename: Name of the JSON file to store DID info (e.g. "alice.json")
    """
    json_path: str = os.path.join(g_current_dir, json_filename)

    if os.path.exists(json_path):
        print(f"Loading existing DID information from {json_filename}")
        with open(json_path, "r") as f:
            info: Dict[str, str] = json.load(f)
        node.set_did_info(info["private_key_pem"], info["did"], info["did_document_json"])
    else:
        print(f"Generating new DID information for {json_filename}")
        private_key_pem: str
        did: str
        did_document_json: str
        private_key_pem, did, did_document_json = node.generate_did_document()
        node.set_did_info(private_key_pem, did, did_document_json)

        with open(json_path, "w") as f:
            json.dump({
                "private_key_pem": private_key_pem,
                "did": did,
                "did_document_json": did_document_json
            }, f)

def get_llm_instance() -> AzureLLM:
    """Return the Azure OpenAI LLM instance"""
    validate_config()

    client: AsyncAzureOpenAI = AsyncAzureOpenAI(
        api_key=AZURE_OPENAI_API_KEY,
        api_version="2024-02-01",
        azure_endpoint=AZURE_OPENAI_ENDPOINT,
        azure_deployment=AZURE_OPENAI_DEPLOYMENT,
    )

    return AzureLLM(client=client, model_name=AZURE_OPENAI_MODEL_NAME)

def load_bob_did() -> str:
    """Load Bob's DID from the JSON file"""
    bob_json_path: str = os.path.join(g_current_dir, "bob.json")
    with open(bob_json_path, "r") as f:
        bob_info: Dict[str, str] = json.load(f)
    return bob_info["did"]

async def generate_code_for_protocol_requester_interface(llm: BaseLLM,
                                         interface_description: Dict[str, Any],
                                         code_path: str) -> str:
    """Generate protocol interface code based on interface description

    Args:
        llm: LLM instance
        interface_description: Interface description dictionary
        code_path: Path to save the generated code

    Returns:
        str: Generated code string
    """

    system_prompt = """You are a professional Python developer.
# Please generate async function code based on interface description. Code must meet the following requirements:
1. Function definition: async def call_requester_interface(requester: RequesterBase) -> dict[str, Any]
2. Function must be async (async def)
3. Function name must be call_requester_interface
4. Function input parameter is RequesterBase instance
5. RequesterBase import method: from anp.app_protocols import RequesterBase
6. Call instance's send_request method in function, and construct appropriate test parameters based on description
7. send_request definition: async def send_request(self, input: dict[str, Any]) -> dict[str, Any]:
7. Function returns dictionary from send_request method
8. Follow Google Python Style Guide

# Output Format
Output code wrapped in three backticks, code in between must be runnable Python code. Do not generate any content besides code.
Example:

```python
XXXX
```
"""

    user_prompt = f"""Please generate code based on the following interface description:
{json.dumps(interface_description, indent=2)}

The generated code should include complete async function definitions, type hints and comments.
"""

    print(f"Generating protocol requester interface code: {system_prompt}")
    print(f"Generating protocol requester interface code: {user_prompt}")

    code = await llm.async_generate_response(system_prompt, user_prompt)

    print(f"Generated protocol requester interface code: {code}")

    code = extract_code_from_llm_output(code)

    # Check if the directory exists, if not, create it
    directory = os.path.dirname(code_path)
    if not os.path.exists(directory):
        os.makedirs(directory)

    if code_path:
        with open(code_path, "w") as f:
            f.write(code)

    # Dynamically load the Python code from the specified path
    spec = importlib.util.spec_from_file_location("requester_module", code_path)
    requester_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(requester_module)

    # Start a coroutine to call the function defined in the dynamically loaded module
    if hasattr(requester_module, 'call_requester_interface'):
        return requester_module.call_requester_interface
    else:
        print("Function 'call_requester_interface' not found in the loaded module.")
        return None

async def generate_code_for_protocol_provider_callback(
    llm: BaseLLM,
    callback_description: Dict[str, Any],
    code_path: str
) -> str:
    """Generate provider callback function code based on callback description

    Args:
        llm: LLM instance
        callback_description: Callback function description dictionary
        code_path: Path to save generated code

    Returns:
        str: Generated callback handler function
    """
    # Build system prompt
    system_prompt = """You are a professional Python developer.
# Please generate async callback function code based on the callback function description. The code needs to meet the following requirements:
1. Function definition: async def provider_callback(message: dict[str, Any]) -> dict[str, Any]
2. Function must be async (async def)
3. Function name must be provider_callback
4. Function parameters must match the parameter definitions in callback description
5. Function needs to return appropriate response data, you can construct test data
6. Follow Google Python Style Guide
7. Generated callback function should include basic parameter validation and error handling

# Output Format
Output code should be wrapped in triple backticks, with runnable Python code in between. Do not generate any content besides the code.
Example:

```python
XXXX
```
"""
    # Build user prompt
    user_prompt = f"""Please generate code based on the following callback function description:
{json.dumps(callback_description, indent=2)}

The generated code should include complete async function definition, type hints and comments.
"""


    print(f"Generating protocol provider callback function code: {system_prompt}")
    print(f"Generating protocol provider callback function code: {user_prompt}")
    # Call LLM to generate code
    code = await llm.async_generate_response(system_prompt, user_prompt)

    print(f"Generated protocol provider callback function code: {code}")

    code = extract_code_from_llm_output(code)

    # Ensure directory exists
    directory = os.path.dirname(code_path)
    if not os.path.exists(directory):
        os.makedirs(directory)

    # Save generated code
    if code_path:
        with open(code_path, "w") as f:
            f.write(code)

    # Dynamically load generated code
    spec = importlib.util.spec_from_file_location("provider_module", code_path)
    provider_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(provider_module)

    # Return generated callback function
    if hasattr(provider_module, 'provider_callback'):
        return provider_module.provider_callback
    else:
        print("Function 'provider_callback' not found in the loaded module.")
        return None

