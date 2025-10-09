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

PROVIDER_DESCRIPTION_PROMPT = """
As an experienced protocol architect and system developer, please help us analyze protocol documentation to build accurate and comprehensive Python API description documents.

# Our Goals:
Through your professional perspective, extract core interface information from protocol documentation and convert it into structured JSON descriptions for AI code understanding or generation.

# Please pay special attention to the following points:
1. Interface Requirements
  - Please design a module name based on protocol documentation, like "user_education_info_protocol"
  - Please design a class name based on protocol documentation, like "ProtocolProvider"
  - Define set_protocol_callback method for setting protocol message handling callback:
    - Method definition: def set_protocol_callback(self, callback: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]) -> None:
    - Function parameter requirements: Input parameter is dictionary type (dict[str, Any]), containing received protocol messages and other necessary data
    - Function return value requirements: Return dictionary type (dict[str, Any]), containing processing results and other necessary data. Dictionary must include code field using HTTP status codes to indicate processing results
    - Please carefully analyze protocol documentation to determine callback parameters and return dictionary field values. Some fields are only used internally in protocol and should not be returned through parameters or callback functions, such as messageType, messageId, etc.
    - Callback function must be asynchronous (Awaitable)
  - Only describe one method in API documentation: set_protocol_callback

2. Protocol Semantics Understanding
  - Deep understanding of business rules in protocol documentation
  - Focus on request/response data structure design
  - Capture exception handling and edge cases

3. Interface Description Generation
  - Use JSON Schema specification to describe interfaces
  - Detailed description of fields in parameters and return value dictionaries, including type, description, default value, minimum, maximum, enums etc.
  - If field is object type, use properties to describe attributes until property values are basic types
  - Ensure completeness and accuracy of descriptions
  - Add clear comments and usage instructions

# Output Requirements:
1. Maintain standardization and readability of JSON structure
2. Ensure description contains all necessary fields
3. Provide comprehensive comments and explanations
4. Validate correctness of description file

**Note:** Only output JSON structure, do not output any other content

# Output Example:
{
  "version": "1.0",
  "module_name": "user_education_info_protocol",
  "definitions": [
    {
      "type": "class",
      "class": {
        "name": "ProtocolProvider",
        "description": "protocol provider class",
        "interfaces": [
          {
            "type": "function",
            "function": {
              "name": "set_protocol_callback",
              "description": "Set async callback function for handling protocol messages",
              "parameters": {
                "type": "object",
                "properties": {
                  "callback": {
                    "type": "function",
                    "description": "Async function that processes protocol messages",
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
                },
                "required": ["callback"]
              }
            }
          }
        ]
      }
    }
  ]
}
"""

PROVIDER_CLASS_PROMPT = '''
You are a senior Python developer. Please help me generate a protocol provider class based on the protocol documentation and API documentation.

# Protocol Provider Class Description
The protocol documentation describes the request and response message formats, while the API documentation describes the provider class and core interface definitions.
Based on this information, implement a protocol provider class that can handle received request messages, call callback functions to process business logic or obtain data, and send response messages.

# The base class definition for the protocol provider is as follows:
```
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Optional, Awaitable

class ProviderBase(ABC):
    """Base class for protocol providers"""

    def __init__(self):
        self._send_callback: Optional[Callable[[bytes], Awaitable[None]]] = None
        self._protocol_callback: Optional[Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]] = None

    def set_send_callback(self, callback: Callable[[bytes], Awaitable[None]]) -> None:
        """Set async callback function for sending binary messages

        Args:
            callback: Async function that takes binary data (bytes) as input and sends
                     it through the transport layer. The function should be a coroutine
                     and handle the actual sending mechanism and any potential errors.
                     Returns Awaitable.
        """
        self._send_callback = callback

    def set_protocol_callback(self, callback: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]) -> None:
        """Set async callback function for handling protocol messages

        Args:
            callback: Async function that takes a dictionary (dict[str, Any]) as input and returns a dictionary (dict[str, Any]).
                      Input dictionary contains the received protocol message and other necessary data.
                      Output dictionary contains the processed result and other necessary data. It must include a code field
                      to identify the status code of the processing result, using HTTP status codes as values.
        """
        self._protocol_callback = callback

    @abstractmethod
    async def handle_message(self, message: bytes) -> None:
        """Handle received message, then call protocol callback function.
           if message is error, call send_callback to send error message.
        Args:
            message: Received binary message data
        """
        pass
```

# Please generate provider class according to the following requirements:
1. Class must inherit from ProviderBase, import ProviderBase class as follows:
```
from anp.app_protocols import ProviderBase
```

2. Class name should use the class name defined in API documentation

3. Code requirements:
  - Follow Google Python Style Guide
  - Use type annotations
  - Include complete class and method documentation
  - Use logging module to record logs (in English), do not set logging configuration
  - Handle exceptions and edge cases properly
  - Ensure code testability and robustness
  - Internal method names should start with underscore (_)
  - Automatically import required modules, like Optional, Any, etc.

4. Implement all abstract methods

5. Add necessary internal methods and attributes if needed

## Core method: handle_message
This class needs to implement the abstract method handle_message from parent class. Requirements:
1. Strictly implement according to handle_message method definition in parent class and API documentation, including parameter names and types
2. This method will parse received messages, call self._protocol_callback to handle business logic, then construct and send response messages
3. If message id is needed in protocol, record request value and include it in response. callback return dictionary donot include message id
3. Must handle the following error cases:
  - Message format error
  - Parameter validation failure
  - Callback function call exception
4. Method example (pseudocode) as follows:
```
async def handle_message(self, message: bytes) -> None:
    try:
        # Parse received message and convert to callback function dictionary parameters
        # If message id is needed in protocol, record request value and include it in response. Otherwise, do not record
        callback_input_dict, message_id = self._parse_message(message)

        # Call protocol callback function to handle business logic
        if self._protocol_callback:
            result = await self._protocol_callback(callback_input_dict)

            # Parse and construct response message based on callback return dictionary
            response_message = self._construct_response_message(result, message_id)

            # Send response
            if self._send_callback:
                await self._send_callback(response_message)
        else:
            logging.error("Protocol callback not set")
            error_message = self._construct_error_message(500, "Internal server error")
            await self._send_callback(error_message)

    except Exception as e:
        logging.error(f"Failed to handle message: {str(e)}\nStack trace:\n{traceback.format_exc()}")
        error_message = self._construct_error_message(400, str(e))
        await self._send_callback(error_message)
```

# Output Format
Output code in the following format, code is wrapped with three backticks.
An example output is as follows (XXXX is runnable Python code):

```python
XXXX
```
'''

async def _generate_provider_class(
    protocol_doc: str,
    api_doc: str,
    llm: BaseLLM
) -> Tuple[str, str]:
    # 使用 PROVIDER_CLASS_PROMPT 作为系统提示词
    system_prompt = PROVIDER_CLASS_PROMPT

    user_prompt = f'''
Please generate a provider class based on the following protocol documentation:

--[ protocol documentation ]--
{protocol_doc}
--[END]--

--[ API documentation ]--
{api_doc}
--[END]--
'''

    content = await llm.async_generate_response(system_prompt, user_prompt)

    logging.info(f'Generated provider class: {content}')

    provider_code = extract_code_from_llm_output(content)
    if not provider_code:
        logging.error("Failed to extract provider code from LLM output")
        return ""

    return provider_code

async def _generate_provider_description(
    protocol_doc: Dict[str, Any],
    llm: BaseLLM
) -> str:
    """Generate provider description JSON based on protocol documentation

    Args:
        protocol_doc: Protocol documentation dictionary
        llm: LLM instance

    Returns:
        str: Provider description JSON string
    """
    system_prompt = PROVIDER_DESCRIPTION_PROMPT

    user_prompt = f'''
Please generate provider description JSON based on the following protocol documentation:

--[ protocol documentation ]--
{protocol_doc}
--[END]--'''

    logging.info(f"Generating provider description system prompt: {system_prompt}")
    logging.info(f"Generating provider description user prompt: {user_prompt}")

    response = await llm.client.chat.completions.create(
        model=llm.model_name,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        response_format={"type": "json_object"}
    )

    logging.info(f"Generated provider description: {response.choices[0].message.content}")

    return response.choices[0].message.content

async def generate_provider_code(
    protocol_doc: Dict[str, Any],
    llm: BaseLLM
) -> Tuple[str, str, str]:

    description_json = await _generate_provider_description(protocol_doc, llm)
    description_dict = json.loads(description_json)
    module_name = description_dict.get("module_name", "protocol_module")

    provider_code = await _generate_provider_class(protocol_doc, description_json, llm)

    return module_name, provider_code, description_json










