# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import asyncio
import logging
import os
import sys
from typing import Any, Dict

g_current_dir: str = os.path.dirname(os.path.abspath(__file__))
sys.path.append(g_current_dir)
# sys.path.append(g_current_dir + "/../../")

from utils import (
    generate_code_for_protocol_provider_callback,
    generate_did_info,
    get_llm_instance,
)

from anp.app_protocols import ProviderBase
from anp.simple_node import ProviderSession, SimpleNegotiationNode
from anp.utils.log_base import set_log_color_level


# Mock callback function for getting capability information
async def mock_capability_info(requirement: str,
                             input_description: str,
                             output_description: str) -> str:
    """Mock callback function for getting capability information"""
    logging.info(f"Requirement: {requirement}")
    logging.info(f"Input description: {input_description}")
    logging.info(f"Output description: {output_description}")
    await asyncio.sleep(0.01)
    return """
    Capability Assessment:
    - Requirements: Can fully meet the specified requirements
    - Input Format: Can process all specified input fields
    - Output Format: Can generate all required output fields
    - No significant limitations or constraints identified
    """

async def new_provider_negotiation_session_callback(provider_session: ProviderSession) -> None:
    """Process new negotiation sessions"""
    print(f"New negotiation session from DID: {provider_session.remote_did}")

    # note: check remote did permission

    # generate the protocol callback process code
    python_code_path = os.path.join(g_current_dir, "workflow_code/provider_flow.py")
    provider_instance: ProviderBase = provider_session.provider_instance
    protocol_callback_description: Dict[str, Any] = provider_session.protocol_callback_description

    # 设置协议处理代码回调，并将代码和协议hash值保存，以便后面使用
    protocol_callback_code = await generate_code_for_protocol_provider_callback(llm=get_llm_instance(),
                                                                                callback_description=protocol_callback_description,
                                                                                code_path=python_code_path)

    # 设置回调函数，用于响应请求
    provider_instance.set_protocol_callback(protocol_callback_code)

    # notify the remote side that code generation has been completed,
    # and wait for the remote side to confirm
    success: bool = await provider_session.code_generated()
    if success:
        print("Code generation completed successfully")
    else:
        print("Code generation failed")

    # wait for protocol processing
    while True:
        await asyncio.sleep(1)

async def main() -> None:
    # create the node for Bob
    bob_node: SimpleNegotiationNode = SimpleNegotiationNode(
        host_domain="localhost",
        llm=get_llm_instance(),
        host_port="8001",
        host_ws_path="/ws",
        protocol_code_path=os.path.join(g_current_dir, "protocol_code"),
        new_provider_session_callback=new_provider_negotiation_session_callback,
        get_capability_info_callback=mock_capability_info
    )

    # generate the DID information for Bob
    generate_did_info(bob_node, "bob.json")
    print(f"Bob's DID: {bob_node.simple_node.did}")

    # start the node
    bob_node.run()

    while True:
        # process other system tasks
        await asyncio.sleep(1)

    # finally stop the node
    await bob_node.stop()

if __name__ == "__main__":
    set_log_color_level(logging.INFO)
    asyncio.run(main())



    # callback_description = '''{
    #                 "type": "function",
    #                 "description": "Async function that processes education history retrieval messages",
    #                 "parameters": {
    #                   "type": "object",
    #                   "properties": {
    #                     "userId": {
    #                       "type": "string",
    #                       "description": "Unique identifier of the user"
    #                     },
    #                     "includeDetails": {
    #                       "type": "boolean",
    #                       "description": "Flag indicating whether to include detailed information",
    #                       "default": false
    #                     },
    #                     "page": {
    #                       "type": "integer",
    #                       "description": "Page number for pagination",
    #                       "minimum": 1,
    #                       "default": 1
    #                     },
    #                     "pageSize": {
    #                       "type": "integer",
    #                       "description": "Number of records per page",
    #                       "minimum": 1,
    #                       "default": 10
    #                     }
    #                   },
    #                   "required": ["userId"]
    #                 },
    #                 "returns": {
    #                   "type": "object",
    #                   "properties": {
    #                     "code": {
    #                       "type": "integer",
    #                       "description": "HTTP status code indicating the result of the request"
    #                     },
    #                     "message": {
    #                       "type": "string",
    #                       "description": "Description of the response code"
    #                     },
    #                     "educationHistory": {
    #                       "type": "array",
    #                       "description": "Array of education history records",
    #                       "items": {
    #                         "type": "object",
    #                         "properties": {
    #                           "institution": {
    #                             "type": "string",
    #                             "description": "Name of the educational institution"
    #                           },
    #                           "major": {
    #                             "type": "string",
    #                             "description": "Major field of study"
    #                           },
    #                           "degree": {
    #                             "type": "string",
    #                             "enum": ["Bachelor", "Master", "Doctorate"],
    #                             "description": "Type of degree obtained"
    #                           },
    #                           "achievements": {
    #                             "type": "string",
    #                             "description": "Notable achievements during study"
    #                           },
    #                           "startDate": {
    #                             "type": "string",
    #                             "format": "date",
    #                             "description": "Start date of the education period"
    #                           },
    #                           "endDate": {
    #                             "type": "string",
    #                             "format": "date",
    #                             "description": "End date of the education period"
    #                           }
    #                         },
    #                         "required": ["institution", "major", "degree", "startDate", "endDate"]
    #                       }
    #                     },
    #                     "pagination": {
    #                       "type": "object",
    #                       "properties": {
    #                         "page": {
    #                           "type": "integer",
    #                           "description": "Current page number"
    #                         },
    #                         "pageSize": {
    #                           "type": "integer",
    #                           "description": "Number of records per page"
    #                         },
    #                         "totalPages": {
    #                           "type": "integer",
    #                           "description": "Total number of pages available"
    #                         },
    #                         "totalRecords": {
    #                           "type": "integer",
    #                           "description": "Total number of records available"
    #                         }
    #                       },
    #                       "required": ["page", "pageSize", "totalPages", "totalRecords"]
    #                     },
    #                     "error_message": {
    #                       "type": "string",
    #                       "description": "Error message if the code indicates a client or server error"
    #                     }
    #                   },
    #                   "required": ["code", "message"]
    #                 }
    #               }'''

    # callback_description = json.loads(callback_description)

    # callback_code = asyncio.run(generate_code_for_protocol_provider_callback(llm=get_llm_instance(),
    #                                                                            callback_description=callback_description,
    #                                                                            code_path=os.path.join(g_current_dir, "workflow_code/provider_flow.py")))

    # print(callback_code)


