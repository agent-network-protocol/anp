# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.


import logging
from typing import Tuple

import aiohttp
import requests

from agent_connect.utils.crypto_tool import get_pem_from_private_key
from agent_connect.utils.did_generate import did_generate


class DIDAllClient:
    def __init__(self, did_service_url: str, api_key: str):
        self.api_key = api_key
        self.did_service_url = did_service_url

    def generate_did_document(self, communication_service_endpoint: str, router_did: str = "") -> Tuple[str, str, str]:
        """
        Generate DID document without registering to DID service

        Args:
            communication_service_endpoint (str): Communication service endpoint for DID document.
            router (str, optional): Router's DID, default is empty string.

        Returns:
            Tuple[str, str, str]: A tuple containing private key in PEM format, DID string, and DID document JSON string.
        """
        private_key, _, did, did_document_json = did_generate(communication_service_endpoint, router_did)

        # Convert private key to PEM format
        private_key_pem = get_pem_from_private_key(private_key)

        return private_key_pem, did, did_document_json

    async def generate_register_did_document(self, communication_service_endpoint: str, router_did: str = "") -> Tuple[str, str, str]:
        """
        Register DID document to DID service.

        This function asynchronously generates DID and corresponding DID document, and registers it to the configured DID service.
        It uses the aiohttp library to send asynchronous HTTP requests.

        Args:
            communication_service_endpoint (str): Communication service endpoint for DID document.
            router_did (str, optional): Router's DID, default is empty string.

        Returns:
            Tuple[str, str, str]: A tuple containing private key in PEM format, DID string, and DID document JSON string.
            If registration fails, it will return three None values.
        """

        # Generate private key, public key, DID and DID document
        private_key, _, did, did_document_json = did_generate(communication_service_endpoint, router_did)

        # Convert private key to PEM format
        private_key_pem = get_pem_from_private_key(private_key)

        # Prepare request headers
        headers = {
            "Content-Type": "application/text",
            "Authorization": f"Bearer {self.api_key}"
        }

        # Ensure correct request URL
        request_url = f"{self.did_service_url}/v1/did"  # Make sure the URL is correct

        # Use aiohttp to send asynchronous POST request
        async with aiohttp.ClientSession() as session:
            async with session.post(request_url, headers=headers, data=did_document_json) as response:
                if response.status == 200:
                    return private_key_pem, did, did_document_json
                else:
                    response_text = await response.text()
                    logging.error(f"Failed to create DID document: {response.status} {response_text}")
                    return None, None, None

    async def get_did_document(self, did: str):
        # Prepare request headers
        headers = {
            "Accept": "application/text",
            "Authorization": f"Bearer {self.api_key}"
        }

        # Construct complete request URL
        request_url = f"{self.did_service_url}/v1/did/{did}"

        # Use aiohttp to send asynchronous GET request
        async with aiohttp.ClientSession() as session:
            async with session.get(request_url, headers=headers) as response:
                if response.status == 200:
                    return await response.text()
                else:
                    response_text = await response.text()
                    logging.error(f"Failed to retrieve DID document: {response.status} {response_text}")
                    return None

    def register_did_document_sync(self, communication_service_endpoint: str, router: str = ""):
        # Generate private key, public key, DID and DID document
        private_key, _, did, did_document_json = did_generate(communication_service_endpoint, router)

        # Convert private key to PEM format
        private_key_pem = get_pem_from_private_key(private_key)

        # Prepare request headers
        headers = {
            "Content-Type": "application/text",
            "Authorization": f"Bearer {self.api_key}"
        }

        # Use requests to send synchronous POST request
        response = requests.post(f"{self.did_service_url}/v1/did", headers=headers, data=did_document_json)
        if response.status_code == 200:
            return private_key_pem, did, did_document_json
        else:
            logging.error(f"Failed to create DID document: {response.status_code} {response.text}")
            return None, None, None

    def get_did_document_sync(self, did: str):
        # Prepare request headers
        headers = {
            "Accept": "application/text",
            "Authorization": f"Bearer {self.api_key}"
        }

        # Send synchronous GET request
        response = requests.get(f"{self.did_service_url}/v1/did/{did}", headers=headers)
        if response.status_code == 200:
            return response.text
        else:
            logging.error(f"Failed to retrieve DID document: {response.status_code} {response.text}")
            return None