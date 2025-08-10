# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

# This is a basic example of how to use DID WBA authentication.
# It first creates a DID document and private keys.
# Then it uploads the DID document to the server.
# Then it generates an authentication header and tests the DID authentication.

import asyncio
import json
import logging
import secrets
import sys
from pathlib import Path

import aiohttp

from agent_connect.authentication import DIDWbaAuthHeader, create_did_wba_document
from agent_connect.utils.log_base import set_log_color_level

_is_local_testing = False

# TODO: Change to your own server domain.
# Or use the test domain we provide (currently using service.agent-network-protocol.com, will later change to agent-network-protocol.com)
# SERVER_DOMAIN = "pi-unlimited.com"
SERVER_DOMAIN = "service.agent-network-protocol.com"

def convert_url_for_local_testing(url: str) -> str:
    if _is_local_testing:
        url = url.replace('https://', 'http://')
        url = url.replace(SERVER_DOMAIN, '127.0.0.1:9000')
    return url

async def upload_did_document(url: str, did_document: dict) -> bool:
    """Upload DID document to server"""
    try:
        local_url = convert_url_for_local_testing(url)
        logging.info("Converting URL from %s to %s", url, local_url)

        async with aiohttp.ClientSession() as session:
            async with session.put(
                local_url,
                json=did_document,
                headers={'Content-Type': 'application/json'}
            ) as response:
                logging.info("Upload DID document response: %s", response)
                return response.status == 200
    except Exception as e:
        logging.error("Failed to upload DID document: %s", e)
        return False

async def download_did_document(url: str) -> dict:
    """Download DID document from server"""
    try:
        local_url = convert_url_for_local_testing(url)
        logging.info("Converting URL from %s to %s", url, local_url)

        async with aiohttp.ClientSession() as session:
            async with session.get(local_url) as response:
                if response.status == 200:
                    return await response.json()
                logging.warning("Failed to download DID document, status: %d", response.status)
                return None
    except Exception as e:
        logging.error("Failed to download DID document: %s", e)
        return None

async def test_did_auth(url: str, auth_client: DIDWbaAuthHeader) -> tuple[bool, str]:
    """Test DID authentication and get token"""
    try:
        local_url = convert_url_for_local_testing(url)
        logging.info("Converting URL from %s to %s", url, local_url)

        # 获取认证头
        auth_headers = auth_client.get_auth_header(local_url)

        async with aiohttp.ClientSession() as session:
            async with session.get(
                local_url,
                headers=auth_headers
            ) as response:
                # 更新令牌
                token = auth_client.update_token(local_url, dict(response.headers))
                return response.status == 200, token or ''
    except Exception as e:
        logging.error("DID authentication test failed: %s", e)
        return False, ''

def save_private_key(unique_id: str, keys: dict, did_document: dict) -> str:
    """Save private keys and DID document to user directory and return the user directory path"""
    current_dir = Path(__file__).parent.absolute()
    user_dir = current_dir / "did_keys" / f"user_{unique_id}"
    # Create parent directories if they don't exist
    user_dir.mkdir(parents=True, exist_ok=True)

    # Save private keys
    for method_fragment, (private_key_bytes, _) in keys.items():
        private_key_path = user_dir / f"{method_fragment}_private.pem"
        with open(private_key_path, 'wb') as f:
            f.write(private_key_bytes)
        logging.info("Saved private key '%s' to %s", method_fragment, private_key_path)

    # Save DID document
    did_path = user_dir / "did.json"
    with open(did_path, 'w', encoding='utf-8') as f:
        json.dump(did_document, f, indent=2)
    logging.info("Saved DID document to %s", did_path)

    return str(user_dir)

async def main(unique_id: str = None, agent_description_url: str = None):
    """
    Main function to demonstrate DID WBA authentication

    Args:
        unique_id: Optional unique identifier for the user
        agent_description_url: Optional URL for agent description
    """
    # 1. Generate unique identifier (8 bytes = 16 hex characters) if not provided
    if unique_id is None:
        unique_id = secrets.token_hex(8)

    # 2. Set server information
    server_domain = SERVER_DOMAIN
    base_path = f"/wba/user/{unique_id}"
    did_path = f"{base_path}/did.json"

    # 3. Create DID document
    logging.info("Creating DID document...")
    did_document, keys = create_did_wba_document(
        hostname=server_domain,
        path_segments=["wba", "user", unique_id],
        agent_description_url=agent_description_url
    )

    # 4. Save private keys and DID document
    user_dir = save_private_key(unique_id, keys, did_document)
    did_document_path = str(Path(user_dir) / "did.json")
    private_key_path = str(Path(user_dir) / "key-1_private.pem")

    # 5. Upload DID document (This should be stored on your server)
    document_url = f"https://{server_domain}{did_path}"
    logging.info("Uploading DID document to %s", document_url)
    success = await upload_did_document(document_url, did_document)
    if not success:
        logging.error("Failed to upload DID document")
        return
    logging.info("DID document uploaded successfully")

    # 6. 创建 DIDWbaAuthHeader 实例
    logging.info("Creating DIDWbaAuthHeader instance...")
    auth_client = DIDWbaAuthHeader(
        did_document_path=did_document_path,
        private_key_path=private_key_path
    )

    # 7. Test DID authentication and get token
    test_url = f"https://{server_domain}/wba/test"
    logging.info("Testing DID authentication at %s", test_url)
    auth_success, token = await test_did_auth(test_url, auth_client)

    if not auth_success:
        logging.error("DID authentication test failed")
        return

    logging.info("DID authentication test successful")

    if token:
        logging.info(f"Received token: {token}")
    else:
        logging.info("No token received from server")

if __name__ == "__main__":
    set_log_color_level(logging.INFO)
    # Get unique_id and agent_description_url from command line arguments if provided
    unique_id = sys.argv[1] if len(sys.argv) > 1 else None
    agent_description_url = sys.argv[2] if len(sys.argv) > 2 else None
    asyncio.run(main(unique_id, agent_description_url))
