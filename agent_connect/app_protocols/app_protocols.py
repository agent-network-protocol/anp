# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.


# feature:
# 1. load app protocols from local path
# 2. load app protocols from remote url: download from url, unzip, load

# After the negotiation is completed, record the source, destination, and protocol hash
# Modify the handshake protocol to include the app protocol version (hash) during the handshake
# According to the hash value, find the directory of the app protocol. If it exists locally, load the local app protocol. If it doesn't exist locally, pull it from the network
# Associate the new connection with the protocol in the app protocols. Through code generation, the next time you get information, directly call the code instead of going through the negotiation process


import hashlib
import importlib.util
import json
import logging
import os
import traceback
from typing import Dict, Optional, Tuple

from agent_connect.app_protocols.protocol_base.provider_base import ProviderBase
from agent_connect.app_protocols.protocol_base.requester_base import RequesterBase
from agent_connect.app_protocols.protocol_container import (
    ProviderContainer,
    RequesterContainer,
)


class AppProtocols:
    """Application Protocol Management Class"""

    def __init__(self, protocol_paths: list[str]):
        '''
        Args:
            protocol_paths: Protocol code file paths, will traverse and load all protocols
        '''
        self.protocol_paths = protocol_paths
        # Use protocol hash as key instead of class name
        self.requester_protocols: Dict[str, RequesterContainer] = {}
        self.provider_protocols: Dict[str, ProviderContainer] = {}
        self.reload_all_protocols()

    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                sha256_hash.update(byte_block)
        return f"sha256:{sha256_hash.hexdigest()}"

    def verify_file_hash(self, file_path: str, expected_hash: str) -> bool:
        """Verify if file hash matches expected hash"""
        actual_hash = self.calculate_file_hash(file_path)
        return actual_hash == expected_hash

    def load_python_class(self, file_path: str, class_name: str):
        """Dynamically load a Python class

        Args:
            file_path: The path to the Python file containing the class
            class_name: The name of the class to be loaded

        Returns:
            Type[RequesterBase]: A subclass of RequesterBase
            None: If loading fails or type does not match
        """
        try:
            spec = importlib.util.spec_from_file_location(class_name, file_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return getattr(module, class_name)
        except Exception as e:
            logging.error(f"Failed to load class {class_name}: {str(e)}")
        return None

    def verify_protocol_files(self, protocol_dir: str, meta_data: Dict) -> bool:
        """Verify protocol file integrity"""
        files_info = meta_data['files']
        for file_type, file_info in files_info.items():
            file_path = os.path.join(protocol_dir, file_info['file'])
            if not os.path.exists(file_path):
                logging.error(f"File not found: {file_path}")
                return False

            if not self.verify_file_hash(file_path, file_info['hash']):
                logging.error(f"File hash mismatch: {file_path}")
                return False
        return True

    def load_protocol(self, protocol_dir: str) -> Optional[str]:
        """Load a single protocol directory

        Args:
            protocol_dir: Path to the protocol directory

        Returns:
            str: Hash value of the successfully loaded protocol
            None: If loading fails
        """
        try:
            meta_data_path = os.path.join(protocol_dir, 'meta_data.json')
            if not os.path.exists(meta_data_path):
                logging.error(f"meta_data.json not found: {protocol_dir}")
                return None

            with open(meta_data_path, 'r') as f:
                meta_data = json.load(f)

            if not self.verify_protocol_files(protocol_dir, meta_data):
                return None

            protocol_hash = None

            # Load requester
            requester_container = RequesterContainer(protocol_dir, meta_data)
            if requester_container.requester_class:
                self.requester_protocols[requester_container.protocol_hash] = requester_container
                protocol_hash = requester_container.protocol_hash

            # Load provider
            provider_container = ProviderContainer(protocol_dir, meta_data)
            if provider_container.provider_class:
                self.provider_protocols[provider_container.protocol_hash] = provider_container
                protocol_hash = provider_container.protocol_hash

            return protocol_hash
        except Exception as e:
            logging.error(f"Failed to load protocol from {protocol_dir}: {str(e)}")
            logging.error("Stack trace:\n" + traceback.format_exc())
            return None

    def reload_all_protocols(self) -> None:
        """Load all protocols under all protocol paths"""
        self.requester_protocols = {}
        self.provider_protocols = {}
        for path in self.protocol_paths:
            if os.path.isdir(path):
                for protocol_dir in os.listdir(path):
                    full_protocol_dir = os.path.join(path, protocol_dir)
                    if os.path.isdir(full_protocol_dir):
                        self.load_protocol(full_protocol_dir)

    def get_requester_by_hash(self, protocol_hash: str) -> Tuple[Optional[RequesterBase], Optional[dict]]:
        """Get requester class and send request description by protocol hash

        Args:
            protocol_hash: Hash value of the protocol document

        Returns:
            Tuple[RequesterBase class, send request description] if found, (None, None) otherwise
        """
        container: Optional[RequesterContainer] = self.requester_protocols.get(protocol_hash, None)
        if container:
            return container.requester_class, container.send_request_description
        return None, None

    def get_provider_by_hash(self, protocol_hash: str) -> Tuple[Optional[ProviderBase], Optional[dict]]:
        """Get provider class and protocol callback description by protocol hash

        Args:
            protocol_hash: Hash value of the protocol document

        Returns:
            Tuple[ProviderBase class, protocol callback description] if found, (None, None) otherwise
        """
        container: Optional[ProviderContainer] = self.provider_protocols.get(protocol_hash, None)
        if container:
            return container.provider_class, container.protocol_callback_description
        return None, None


    async def load_protocol_from_url(self, url: str) -> Optional[str]:
        """Load protocol from remote url"""
        pass










