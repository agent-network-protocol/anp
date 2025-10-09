# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import json
import logging
from typing import Any, Dict, Tuple

from anp.utils.llm.base_llm import BaseLLM
from anp.utils.llm_output_processer import extract_code_from_llm_output

REQUESTER_DESCRIPTION_PROMPT = """
As an experienced protocol architect and system developer, please help us analyze the protocol documentation thoroughly to build accurate and comprehensive API description files.

# Our Goals:
Through your professional perspective, extract core interface information from protocol documentation and convert it into structured JSON descriptions.

# Please pay special attention to the following points:
1. Interface Requirements
  - Please design a module name based on protocol documentation, like "user_education_info_protocol"
  - Please design a class name based on protocol documentation, like "ProtocolRequester"
  - Include a send_request method in the class for sending requests and returning data
  - Deeply analyze protocol documentation to design send_request method parameters, typically including all parameters from request protocol
  - Design send_request method return value, which typically includes request success status and result data
    - Return value must use dict type
    - Must include code field, code value depends on protocol documentation, typically using HTTP status codes
    - Additional fields can be added after code field to return request result data or error information
    - Carefully analyze response message data, some are only used internally in protocol and should not be returned, like messageType, messageId etc.
  - Interface design should be concise, clear and easy to use

2. Protocol Semantics Understanding
  - Deeply understand business rules in protocol documentation
  - Focus on request/response data structure design
  - Capture exception handling and edge cases

3. Interface Description Generation
  - Use JSON Schema specification to describe interfaces
  - Ensure description completeness and accuracy
  - Add clear comments and usage instructions

# Output Requirements:
1. Maintain standardization and readability of JSON structure
2. Ensure description contains all necessary fields
3. Provide comprehensive comments and explanations
4. Validate correctness of description file

**Note:** Output JSON structure only, do not output any other content

# Output Example:
{
  "version": "1.0",
  "module_name": "user_education_info_protocol",
  "definitions": [
    {
      "type": "class",
      "class": {
        "name": "ProtocolRequester",
        "description": "requester class",
        "interfaces": [
          {
            "type": "function",
            "function": {
              "name": "send_request",
              "description": "Send request to get user educational background",
              "parameters": {
                "type": "object",
                "properties": {
                  "user_id": {
                    "type": "string",
                    "description": "Unique user identifier"
                  },
                  "page": {
                    "type": "integer",
                    "description": "Page number",
                    "default": 1,
                    "minimum": 1
                  }
                },
                "required": ["user_id"]
              },
              "returns": {
                "type": "object",
                "properties": {
                  "code": {
                    "type": "integer",
                    "description": "HTTP status code"
                  },
                  "data": {
                    "type": "object",
                    "properties": {
                      "institution": {
                        "type": "string",
                        "description": "Name of the educational institution"
                      },
                      "major": {
                        "type": "string",
                        "description": "Major field of study"
                      },
                      "degree": {
                        "type": "string",
                        "enum": ["Bachelor", "Master", "Doctorate"],
                        "description": "Type of degree obtained"
                      }
                    },
                    "required": ["institution", "major", "degree"]
                  },
                  "error_message": {
                    "type": "string",
                    "description": "Error message, only if code is not 200"
                  }
                },
                "required": ["code"]
              }
            }
          }
        ]
      }
    }
  ]
}
"""

# Prompts for code generation
REQUESTER_CLASS_PROMPT = '''
You are a senior Python developer. Please help me generate a protocol requester class based on the protocol documentation and API documentation.

# Protocol Requester Class Description
The protocol documentation describes the request and response message formats, while the API documentation describes the requester class and core interface definitions.
Based on the above information, implement a protocol requester class that can construct request messages, send requests, process response messages, and return results based on the response messages.

# The base class for the protocol requester is defined as follows:
```
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Optional, Awaitable
import asyncio

class RequesterBase(ABC):
    """Base class for protocol requesters"""

    def __init__(self):
        self._send_callback: Optional[Callable[[bytes], Awaitable[None]]] = None
        self.received_messages: list[bytes] = []
        self.messages_event = asyncio.Event()

    def set_send_callback(self, callback: Callable[[bytes], Awaitable[None]]) -> None:
        """Set async callback function for sending binary messages

        Args:
            callback: Async function that takes binary data (bytes) as input and sends
                     it through the transport layer. The function should be a coroutine
                     and handle the actual sending mechanism and any potential errors.
                     Returns Awaitable.
        """
        self._send_callback = callback

    async def handle_message(self, message: bytes) -> None:
        """Handle received message, called by the class user

        Args:
            message: Received binary message data
        """
        self.received_messages.append(message)
        self.messages_event.set()

    @abstractmethod
    async def send_request(self, input: dict[str, Any]) -> dict[str, Any]:
        """Send request message

        Args:
            input: Request input data
        Returns:
            dict: Request output data from response message
        """
        pass
```

# Please generate the requester class according to the following requirements:
1. The class must inherit from RequesterBase, import RequesterBase class using:
```
from anp.app_protocols import RequesterBase
```

2. The class name should use the class name defined in the API documentation

3. Code requirements:
  - Follow Google Python Style Guide
  - Use type annotations
  - Include complete class and method documentation
  - Use logging module to record logs (in English), do not set logging configuration
  - Handle exceptions and edge cases properly
  - Ensure code testability and robustness
  - Internal method names should start with underscore (_)
  - Automatically import required modules, like Optional, Any, etc.

4. Please implement all abstract methods

5. If needed, you can add necessary internal methods and internal attributes

## Core method: send_request
This class needs to implement the abstract method send_request from the parent class. This method is used to initiate protocol request messages with the following requirements:
1. Strictly implement according to the send_request method definition in parent class and API documentation, including parameter names, types and return values
2. This method will construct the request protocol, call self._send_callback to send the request protocol, then wait for asyncio.Event until response is received
3. After receiving the response message, process and return results according to protocol documentation
4. Must handle the following error cases:
  - Network timeout (set according to protocol documentation, default 15 seconds)
  - Message format error
  - Parameter validation failure
  - If protocol response does not contain code field, generate appropriate HTTP status code based on response content and business logic
5. Method example (pseudocode) as follows:
```
async def send_request(self, input: dict[str, Any]) -> dict[str, Any]:
    # Construct request protocol
    request_message = self._construct_request_message(input)

    # Send request protocol
    await self._send_callback(request_message)

    # Wait for response
    if not self.received_messages:
        try:
            # Wait for new message with timeout, timeout set according to protocol doc
            await asyncio.wait_for(self.messages_event.wait(), timeout=15)
            # Clear event for next wait
            self.messages_event.clear()
        except asyncio.TimeoutError:
            logging.error(f"Protocol negotiation timeout\nStack trace:\n{traceback.format_exc()}")
            return {"code": 504, "error_message": "Protocol negotiation timeout"}

    # Process response and return result

```
6. For self.received_messages and self.messages_event.wait(), always check if self.received_messages is empty first. If it is empty, call self.messages_event.wait() to wait for a message; otherwise, directly process self.received_messages.

# Output format
Output code in the following format, code is wrapped with three backticks.
An example output is as follows (XXXX is runnable Python code):

```python
XXXX
```
'''

async def _generate_requester_class(
    protocol_doc: str,
    api_doc: str,
    llm: BaseLLM
) -> Tuple[str, str]:
    # Use REQUESTER_CLASS_PROMPT as system prompt
    system_prompt = REQUESTER_CLASS_PROMPT

    user_prompt = f'''
Please generate a requester class based on the following protocol documentation:

--[ protocol documentation ]--
{protocol_doc}
--[END]--

--[ API documentation ]--
{api_doc}
--[END]--
'''

    # Call OpenAI API
    content = await llm.async_generate_response(system_prompt, user_prompt)

    logging.info(f"Generated requester code: {content}")

    requester_code = extract_code_from_llm_output(content)
    if not requester_code:
        logging.error("Failed to extract requester code from LLM output")
        return ""

    return requester_code

async def _generate_requester_description(
    protocol_doc: Dict[str, Any],
    llm: BaseLLM
) -> str:
    """Generate requester description JSON based on protocol documentation and generated requester code

    Args:
        protocol_doc: Protocol documentation dictionary
        llm: LLM instance

    Returns:
        str: Requester description JSON string
    """

    system_prompt = REQUESTER_DESCRIPTION_PROMPT

    user_prompt = f'''
Please generate a requester description JSON based on the following protocol documentation and requester code:

--[ protocol documentation ]--
{protocol_doc}
--[END]--'''

    logging.info(f"Generating requester description system prompt: {system_prompt}")
    logging.info(f"Generating requester description user prompt: {user_prompt}")

    response = await llm.client.chat.completions.create(
        model=llm.model_name,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        response_format={"type": "json_object"}
    )

    logging.info(f"Generated requester description: {response.choices[0].message.content}")

    return response.choices[0].message.content

async def generate_requester_code(
    protocol_doc: Dict[str, Any],
    llm: BaseLLM
) -> Tuple[str, str, str]:

    # Generate requester class code and description
    description_json = await _generate_requester_description(protocol_doc, llm)
    description_dict = json.loads(description_json)  # Convert to JSON
    module_name = description_dict.get("module_name", "protocol_module")

    requester_code = await _generate_requester_class(protocol_doc, description_dict, llm)

    return module_name, requester_code, description_json
