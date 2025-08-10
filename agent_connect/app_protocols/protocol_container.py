# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import importlib.util
import json
import logging
import os
from typing import Dict, Optional, Type

from agent_connect.app_protocols.protocol_base.provider_base import ProviderBase
from agent_connect.app_protocols.protocol_base.requester_base import RequesterBase


class ProtocolContainer:
    """Protocol container base class"""

    def __init__(self, protocol_dir: str, meta_data: Dict):
        self.protocol_dir = protocol_dir
        self.meta_data = meta_data
        self.protocol_hash = meta_data['files']['protocol_document']['hash']
        self.protocol_content = self._load_protocol_document()

    def _load_protocol_document(self) -> str:
        """Load protocol document content"""
        doc_file = self.meta_data['files']['protocol_document']['file']
        with open(os.path.join(self.protocol_dir, doc_file), 'r') as f:
            return f.read()

    def _load_python_class(self, file_path: str, class_name: str) -> Optional[Type]:
        """Load Python class dynamically"""
        try:
            spec = importlib.util.spec_from_file_location(class_name, file_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return getattr(module, class_name)
        except Exception as e:
            logging.error(f"Failed to load class {class_name}: {str(e)}")
        return None

    def _extract_class_info(self, desc_file_path: str) -> Dict:
        """Extract class information from description file"""
        with open(desc_file_path, 'r') as f:
            desc_data = json.load(f)
        return desc_data['definitions'][0]['class']

class RequesterContainer(ProtocolContainer):
    """Requester protocol container"""

    def __init__(self, protocol_dir: str, meta_data: Dict):
        super().__init__(protocol_dir, meta_data)
        self.class_info = self._load_class_info()
        self.send_request_description = self._extract_send_request_description()
        self.requester_class = self._load_requester()

    def _load_class_info(self) -> Dict:
        """Load requester class info"""
        desc_path = os.path.join(
            self.protocol_dir,
            self.meta_data['files']['requester_description']['file']
        )
        return self._extract_class_info(desc_path)

    def _extract_send_request_description(self) -> Dict:
        """Extract send request description from class info"""
        return next((item for item in self.class_info['interfaces'] if item['function']['name'] == 'send_request'), None)

    def _load_requester(self) -> Optional[Type[RequesterBase]]:
        """Load requester class"""
        requester_path = os.path.join(
            self.protocol_dir,
            self.meta_data['files']['requester']['file']
        )
        requester_class = self._load_python_class(requester_path, self.class_info['name'])

        if requester_class and issubclass(requester_class, RequesterBase):
            return requester_class
        logging.error(f"Invalid requester class: {self.class_info['name']}")
        return None

class ProviderContainer(ProtocolContainer):
    """Provider protocol container"""

    def __init__(self, protocol_dir: str, meta_data: Dict):
        super().__init__(protocol_dir, meta_data)
        self.class_info = self._load_class_info()
        self.protocol_callback_description = self._extract_protocol_callback_description()
        self.provider_class = self._load_provider()

    def _load_class_info(self) -> Dict:
        """Load provider class info"""
        desc_path = os.path.join(
            self.protocol_dir,
            self.meta_data['files']['provider_description']['file']
        )
        return self._extract_class_info(desc_path)

    def _extract_protocol_callback_description(self) -> Dict:
        """Extract protocol callback description from class info"""
        set_protocol_callback_description = next((item for item in self.class_info['interfaces'] if item['function']['name'] == 'set_protocol_callback'), None)
        if set_protocol_callback_description:
            return set_protocol_callback_description['function']['parameters']['properties']['callback']
        return None

    def _load_provider(self) -> Optional[Type[ProviderBase]]:
        """Load provider class"""
        provider_path = os.path.join(
            self.protocol_dir,
            self.meta_data['files']['provider']['file']
        )
        provider_class = self._load_python_class(provider_path, self.class_info['name'])

        if provider_class and issubclass(provider_class, ProviderBase):
            return provider_class
        logging.error(f"Invalid provider class: {self.class_info['name']}")
        return None
