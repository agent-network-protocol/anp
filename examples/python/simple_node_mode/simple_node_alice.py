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

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
# sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/../../")

from agent_connect.simple_node import SimpleNode, SimpleNodeSession
from agent_connect.utils.log_base import set_log_color_level


def generate_did_info(alice_node: SimpleNode):
    # Check if alice.json exists
    current_dir = os.path.dirname(os.path.abspath(__file__))  # Get the current file's directory
    alice_json_path = os.path.join(current_dir, "alice.json")  # Construct the path to alice.json

    if os.path.exists(alice_json_path):
        print("Loading existing Alice DID information")
        with open(alice_json_path, "r") as f:
            alice_info = json.load(f)
        alice_node.set_did_info(alice_info["private_key_pem"], alice_info["did"], alice_info["did_document_json"])
    else:
        print("Generating new Alice DID information")
        private_key_pem, did, did_document_json = alice_node.generate_did_document()
        alice_node.set_did_info(private_key_pem, did, did_document_json)

        # Save Alice's DID information
        with open(alice_json_path, "w") as f:
            json.dump({
                "private_key_pem": private_key_pem,
                "did": did,
                "did_document_json": did_document_json
            }, f)

async def ws_new_session_callback(simple_session: SimpleNodeSession):
    print(f"New session established with DID: {simple_session.remote_did}")

async def main():
    # 使用新的接口创建节点，只指定ws路径
    alice_node = SimpleNode(
        host_domain="localhost",
        new_session_callback=ws_new_session_callback,
        host_port="8001",
        host_ws_path="/ws"
    )

    generate_did_info(alice_node)

    print(f"Alice's DID: {alice_node.did}")

    # Start the node
    alice_node.run()

    # Read bob's DID
    current_dir = os.path.dirname(os.path.abspath(__file__))  # Get the current file's directory
    bob_json_path = os.path.join(current_dir, "bob.json")  # Construct the path to alice.json
    with open(bob_json_path, "r") as f:
        bob_info = json.load(f)
    bob_did = bob_info["did"]

    try:
        # Connect to bob
        alice_session = await alice_node.connect_to_did(bob_did)

        # Send message to bob
        message = "Hello bob, I'm Alice!"
        success = await alice_session.send_message(message)
        if success:
            print(f"Successfully sent message to {bob_did}")
        else:
            print(f"Failed to send message to {bob_did}")

        # Wait for bob's reply
        while True:
            reply = await alice_session.receive_message()
            reply = reply.decode('utf-8') if reply else None
            print(f"Received reply content: {reply}")

    except asyncio.CancelledError:
        print("Alice node is shutting down...")
    finally:
        await alice_node.stop()

if __name__ == "__main__":
    set_log_color_level(logging.INFO)
    asyncio.run(main())
