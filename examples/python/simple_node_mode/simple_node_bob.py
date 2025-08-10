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


def generate_did_info(bob_node: SimpleNode):
    # Check if bob.json exists
    current_dir = os.path.dirname(os.path.abspath(__file__))  # Get the current file's directory
    bob_json_path = os.path.join(current_dir, "bob.json")  # Construct the path to bob.json

    if os.path.exists(bob_json_path):
        # Load existing DID information if available
        print("Loading existing Bob DID information")
        with open(bob_json_path, "r") as f:
            bob_info = json.load(f)
        bob_node.set_did_info(bob_info["private_key_pem"], bob_info["did"], bob_info["did_document_json"])
    else:

        # Generate new DID information
        print("Generating new Bob DID information")
        private_key_pem, did, did_document_json = bob_node.generate_did_document()
        bob_node.set_did_info(private_key_pem, did, did_document_json)

        # Save Bob's DID information
        with open(bob_json_path, "w") as f:
            json.dump({
                "private_key_pem": private_key_pem,
                "did": did,
                "did_document_json": did_document_json
            }, f)


async def ws_new_session_callback(simple_session: SimpleNodeSession):
    print(f"New session established from {simple_session.remote_did}")

    while True:
        message = await simple_session.receive_message()
        message = message.decode('utf-8') if message else None
        print(f"Received message content: {message}")

        # Send reply
        reply = f"Hello {simple_session.remote_did}, I'm Bob!"
        success = await simple_session.send_message(reply)

        if success:
            print(f"Successfully replied to {simple_session.remote_did}")
        else:
            print(f"Failed to reply to {simple_session.remote_did}")

async def main():
    # 使用新的接口创建节点，只指定ws路径
    bob_node = SimpleNode(
        host_domain="localhost",
        new_session_callback=ws_new_session_callback,
        host_port="8000",
        host_ws_path="/ws"
    )
    generate_did_info(bob_node)

    print(f"Bob's DID: {bob_node.did}")

    # Start the node
    bob_node.run()

    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        print("Bob node is shutting down...")
    finally:
        await bob_node.stop()

if __name__ == "__main__":
    set_log_color_level(logging.INFO)
    asyncio.run(main())
