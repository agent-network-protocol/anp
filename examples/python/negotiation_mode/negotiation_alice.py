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
    generate_code_for_protocol_requester_interface,
    generate_did_info,
    get_llm_instance,
    load_bob_did,
)

from anp.app_protocols import RequesterBase
from anp.simple_node import RequesterSession, SimpleNegotiationNode
from anp.utils.log_base import set_log_color_level

# Define protocol requirements
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

async def main() -> None:
    llm=get_llm_instance()
    # create the node for Alice
    alice_node: SimpleNegotiationNode = SimpleNegotiationNode(
        host_domain="localhost",
        llm=llm,
        host_port="8000",
        host_ws_path="/ws",
        protocol_code_path=os.path.join(g_current_dir, "protocol_code")
    )

    # generate the DID information for Alice
    generate_did_info(alice_node, "alice.json")
    print(f"Alice's DID: {alice_node.simple_node.did}")

    # load the DID information for Bob
    bob_did: str = load_bob_did()

    # start the node
    alice_node.run()

    # connect to Bob, and negotiate the protocol
    requester_session: RequesterSession = await alice_node.connect_to_did_with_negotiation(bob_did,
                                                                          requirement,
                                                                          input_description,
                                                                          output_description)

    # get the requester instance and the interface description
    requester_instance: RequesterBase = requester_session.requester_instance
    interface_description: Dict[str, Any] = requester_session.send_request_description

    # notify the remote side that code generation has been completed, and wait for the remote side to confirm
    success: bool = await requester_session.code_generated()
    print(f"Code generated: {success}")
    print(f"Interface description: {interface_description}")

    # generate the code for the protocol interface
    python_code_path = os.path.join(g_current_dir, "workflow_code/requester_flow.py")
    call_requester_interface = await generate_code_for_protocol_requester_interface(llm,
                                                     interface_description,
                                                     python_code_path)


    # call the protocol interface to send request, and print the response
    if call_requester_interface is not None:
        response = await call_requester_interface(requester_instance)
        print('\n-------------------------------------------------')
        print(f"Response from requester interface: {response}")
        print('-------------------------------------------------')

    while True:
        # process other system tasks
        await asyncio.sleep(1)

    # finally stop the node
    await alice_node.stop()

if __name__ == "__main__":
    set_log_color_level(logging.INFO)
    asyncio.run(main())


    # import json
    # str_json = '''
    #       {
    #         "type": "function",
    #         "function": {
    #           "name": "send_request",
    #           "description": "Send request to retrieve user's education history",
    #           "parameters": {
    #             "type": "object",
    #             "properties": {
    #               "user_id": {
    #                 "type": "string",
    #                 "description": "Unique identifier of the user"
    #               },
    #               "include_details": {
    #                 "type": "boolean",
    #                 "description": "Flag to include detailed information",
    #                 "default": false
    #               },
    #               "page": {
    #                 "type": "integer",
    #                 "description": "Page number for pagination",
    #                 "minimum": 1,
    #                 "default": 1
    #               },
    #               "page_size": {
    #                 "type": "integer",
    #                 "description": "Number of records per page",
    #                 "minimum": 1,
    #                 "default": 10
    #               }
    #             },
    #             "required": ["user_id"]
    #           },
    #           "returns": {
    #             "type": "object",
    #             "properties": {
    #               "code": {
    #                 "type": "integer",
    #                 "description": "HTTP status code indicating the result of the request"
    #               },
    #               "message": {
    #                 "type": "string",
    #                 "description": "Description of the response code, typically included when the code is not 200"
    #               },
    #               "education_history": {
    #                 "type": "array",
    #                 "description": "Array of education history records, only present if response code is 200",
    #                 "items": {
    #                   "type": "object",
    #                   "properties": {
    #                     "institution": {
    #                       "type": "string",
    #                       "description": "Name of the educational institution"
    #                     },
    #                     "major": {
    #                       "type": "string",
    #                       "description": "Major of study"
    #                     },
    #                     "degree": {
    #                       "type": "string",
    #                       "enum": ["Bachelor", "Master", "Doctorate"],
    #                       "description": "Type of degree obtained"
    #                     },
    #                     "achievements": {
    #                       "type": "string",
    #                       "description": "Notable achievements"
    #                     },
    #                     "start_date": {
    #                       "type": "string",
    #                       "format": "date",
    #                       "description": "Start date of the education period"
    #                     },
    #                     "end_date": {
    #                       "type": "string",
    #                       "format": "date",
    #                       "description": "End date of the education period"
    #                     }
    #                   },
    #                   "required": ["institution", "major", "degree", "start_date", "end_date"]
    #                 }
    #               },
    #               "pagination": {
    #                 "type": "object",
    #                 "description": "Pagination details, included when response code is 200",
    #                 "properties": {
    #                   "page": {
    #                     "type": "integer",
    #                     "description": "Current page number"
    #                   },
    #                   "page_size": {
    #                     "type": "integer",
    #                     "description": "Number of records per page"
    #                   },
    #                   "total_pages": {
    #                     "type": "integer",
    #                     "description": "Total number of pages available"
    #                   },
    #                   "total_records": {
    #                     "type": "integer",
    #                     "description": "Total number of records available"
    #                   }
    #                 },
    #                 "required": ["page", "page_size", "total_pages", "total_records"]
    #               }
    #             },
    #             "required": ["code"]
    #           }
    #         }
    #       }'''

    # interface_description = json.loads(str_json)

    # asyncio.run(generate_code_for_protocol_interface(get_llm_instance(),
    #                                       interface_description,
    #                                       os.path.join(g_current_dir, "workflow_code/requester.py")))


