# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import argparse
import asyncio
import json
import os
import sys

current_script_path = os.path.abspath(__file__)
current_directory = os.path.dirname(current_script_path)
sys.path.append(current_directory)
sys.path.append(current_directory + "/../")

from agent_connect.authentication import DIDAllClient

MESSAGE_WSS_URL = "wss://message.agent-network-protocol.com/ws"
DID_HTTP_URL = 'https://did.agent-network-protocol.com'
# DID_HTTP_URL = 'http://127.0.0.1:9000'
TEST_API_KEY = '10090.bo9JAoRCAbQV43FD8kzX5SyEgxCs2R9z'   # Test API key, daily limit of 1000 tests

def get_output_filename():
    parser = argparse.ArgumentParser(description='Generate and store DID information')
    parser.add_argument('filename', nargs='?', help='Output filename')
    args = parser.parse_args()
    if args.filename:
        return os.path.join(current_directory, args.filename)
    else:
        file_name = input("Please enter the filename to save DID information: ")
        return os.path.join(current_directory, file_name)

async def main():
    output_filename = get_output_filename()
    print(f"Output filename: {output_filename}")

    # Initialize DID service client
    did_client = DIDAllClient(DID_HTTP_URL, TEST_API_KEY)

    # Generate and register DID and router
    # One router can provide service for multiple DIDs
    router_private_key_pem, router_did, router_document = await did_client.generate_register_did_document(MESSAGE_WSS_URL)
    if not router_private_key_pem or not router_did or not router_document:
        print("Router DID document generation failed")
        return

    did_private_key_pem, did, did_document = await did_client.generate_register_did_document(MESSAGE_WSS_URL, router_did)
    if not did_private_key_pem or not did or not did_document:
        print("DID registration failed")
        return

    # Store DID information in a file
    did_info = {
        "router": {
            "private_key": router_private_key_pem,
            "did": router_did,
            "document": router_document
        },
        "user": {
            "private_key": did_private_key_pem,
            "did": did,
            "document": did_document
        }
    }

    with open(output_filename, 'w') as f:
        json.dump(did_info, f, indent=2)

    print(f"\n\n************** DID created successfully and saved to {output_filename}! **************\n\n")

if __name__ == "__main__":
    asyncio.run(main())
