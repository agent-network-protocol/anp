# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

# This is a client example used to test whether your server supports DID WBA authentication.
# It uses a pre-created DID document and private key to access a test interface on your server.
# If it returns 200, it indicates that the server supports DID WBA authentication.

import asyncio
import json
import logging
from pathlib import Path

import aiohttp

from agent_connect.authentication import DIDWbaAuthHeader
from agent_connect.utils.log_base import set_log_color_level

# TODO: Change to your own server domain.
TEST_DOMAIN = "service.agent-network-protocol.com"

async def test_did_auth(url: str, auth_client: DIDWbaAuthHeader) -> tuple[bool, str]:
    """Test DID authentication and get token"""
    try:
        # Get authentication header
        auth_headers = auth_client.get_auth_header(url)

        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                headers=auth_headers
            ) as response:
                # Update token
                token = auth_client.update_token(url, dict(response.headers))
                print(f"Response status: {response.status}")
                return response.status == 200, token or ''
    except Exception as e:
        logging.error("DID authentication test failed: %s", e)
        return False, ''

async def main():
    # Get project root directory
    current_dir = Path(__file__).parent.absolute()
    project_root = current_dir.parent.parent.parent

    # Set DID document and private key paths
    did_document_path = project_root / "examples" / "use_did_test_public" / "did.json"
    private_key_path = project_root / "examples" / "use_did_test_public" / "key-1_private.pem"

    # Check if files exist
    if not did_document_path.exists():
        logging.error(f"DID document does not exist: {did_document_path}")
        return

    if not private_key_path.exists():
        logging.error(f"Private key file does not exist: {private_key_path}")
        return

    # Read DID document to get DID
    with open(did_document_path, 'r') as f:
        did_document = json.load(f)
        client_did = did_document.get('id')
        logging.info(f"Using DID: {client_did}")

    # Create DIDWbaAuthHeader instance
    logging.info("Creating DIDWbaAuthHeader instance...")
    auth_client = DIDWbaAuthHeader(
        did_document_path=str(did_document_path),
        private_key_path=str(private_key_path)
    )

    # Test DID authentication
    test_url = f"https://{TEST_DOMAIN}/wba/test"
    logging.info(f"Testing DID authentication at: {test_url}")
    auth_success, token = await test_did_auth(test_url, auth_client)

    if auth_success:
        logging.info("DID authentication test successful!")
        if token:
            logging.info(f"Received token: {token}")
        else:
            logging.info("No token received from server")
    else:
        logging.error("DID authentication test failed")

if __name__ == "__main__":
    set_log_color_level(logging.INFO)
    asyncio.run(main())




