# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import asyncio
import json
import os
import sys
import traceback

current_script_path = os.path.abspath(__file__)
current_directory = os.path.dirname(current_script_path)

from agent_connect.e2e_encryption import WssMessageSDK

MESSAGE_WSS_URL = "wss://message.agent-network-protocol.com/ws"
# MESSAGE_WSS_URL = "ws://127.0.0.1:9000/ws"
TEST_API_KEY = '10090.bo9JAoRCAbQV43FD8kzX5SyEgxCs2R9z'   # Test API key, daily limit of 1000 tests


sdk_short_term_key_callback_list = []

def sdk_short_term_key_callback(local_did, remote_did, secret_key_json):
    print(f"SDK short_term_key_callback: {local_did}, {remote_did}, {secret_key_json}")
    sdk_short_term_key_callback_list.append((local_did, remote_did, secret_key_json))


def get_router_and_user_info(file_name="alice.json"):
    file_path = os.path.join(current_directory, file_name)

    if not os.path.exists(file_path):
        print(f"File {file_path} does not exist")
        return None, None, None, None, None, None

    try:
        with open(file_path, 'r') as f:
            data = json.load(f)

        router_private_key = data['router']['private_key']
        router_did = data['router']['did']
        router_document = data['router']['document']

        user_private_key = data['user']['private_key']
        user_did = data['user']['did']
        user_document = data['user']['document']

        return router_private_key, router_did, router_document, user_private_key, user_did, user_document
    except Exception as e:
        print(f"Error occurred while reading file: {e}")
        return None, None, None, None, None, None

async def main(file_name="alice.json"):
    router_private_key, router_did, router_document, \
    user_private_key, user_did, user_document = get_router_and_user_info(file_name)
    if not router_private_key or not user_private_key:
        return

    sdk = await WssMessageSDK.create(
        MESSAGE_WSS_URL,
        TEST_API_KEY,
        [(router_private_key, router_document)],
        sdk_short_term_key_callback
    )

    # Set private key and DID
    sdk.insert_did_private_key(router_did, router_private_key)
    sdk.insert_did_private_key(user_did, user_private_key)

    # Start async task to call SDK's recv method
    async def sdk_recv(sdk):
        while True:
            print("-------------sdk recv")
            source_did, destination_did, msg = await sdk.recv_data()
            print(f"\n\n----------Received message: {source_did} -> {destination_did}: {msg}")

            await sdk.send_data(msg, destination_did, source_did)
            print(f"\n\n----------Sent message: {destination_did} -> {source_did}: {msg}")

    task = asyncio.create_task(sdk_recv(sdk))

    while True:
        await asyncio.sleep(1)


if __name__ == "__main__":
    try:
        # Retrieve the configuration file path from command-line parameters, if not available, use the default path
        file_name = sys.argv[1] if len(sys.argv) > 1 else "simple_node/alice.json"

        # Run the main program
        asyncio.run(main(file_name))
    except KeyboardInterrupt:
        print("\nThe program was interrupted by the user.")
    except Exception as e:
        print(f"run error: {e}")
        traceback.print_exc()