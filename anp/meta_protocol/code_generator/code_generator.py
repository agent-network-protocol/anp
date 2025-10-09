# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.


'''
1. Generate code for the requester or provider
2. interface is abstract, and the best mode is one query and one response, on request and response, a lot of use cases can be abstracted as this
  - For example, for joining a meeting process, previously there were many interfaces, now I only need one interface that provides sufficient information and handles complex process flows internally.
3. for the requester, there is a interface function which is async, prarmeter, send callback function and receive interface function.

'''

import hashlib
import json
import logging
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from anp.meta_protocol.code_generator.provider_generator import (
    generate_provider_code,
)
from anp.meta_protocol.code_generator.requester_generator import (
    generate_requester_code,
)
from anp.utils.llm.base_llm import BaseLLM


class ProtocolCodeGenerator:
    """Protocol code generator that generates code implementation based on protocol documentation

    Attributes:
        llm: LLM instance for code generation
        protocol_doc: Protocol documentation content
        output_path: Code output path
        language: Target programming language
    """

    def __init__(
        self,
        llm: BaseLLM,
        protocol_doc: str,
        output_path: str,
        language: str = "python"
    ):
        """Initialize the code generator

        Args:
            llm: LLM instance
            protocol_doc: Protocol documentation content
            output_path: Root path for code output
            language: Target programming language, defaults to python
        """
        self.llm = llm
        self.protocol_doc = protocol_doc
        self.output_path = Path(output_path)
        self.language = language
        self._module_name: Optional[str] = None

    def _create_module_structure(self, module_name: str) -> str:
        """Create the basic module structure

        Args:
            module_name: Name of the module to create

        Returns:
            str: The final module name (may include timestamp if original path existed)
        """
        module_path = self.output_path / module_name

        # If path exists, append timestamp to module_name
        if module_path.exists():
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')[:-3]  # Get milliseconds precision
            module_name = f"{module_name}_{timestamp}"
            module_path = self.output_path / module_name

        logging.info(f"Creating module structure for: {module_name}")
        module_path.mkdir(parents=True, exist_ok=True)
        self._module_name = module_name  # Update the internal module name
        self._generate_init_file(module_name)
        self._generate_meta_data(module_name)
        self._update_protocol_document(self.protocol_doc)

        return module_name

    def _update_protocol_document(self, protocol_doc: str) -> None:
        """Update protocol document and its hash in meta_data.json

        Args:
            protocol_doc: Protocol documentation content
        """
        try:
            # Write protocol document to module directory
            if not self._module_name:
                logging.error("Module name not set, cannot write protocol document")
                return

            doc_path = self.output_path / self._module_name / "protocol_document.md"
            doc_path.write_text(protocol_doc, encoding='utf-8')

            # Calculate file hash
            sha256_hash = hashlib.sha256(protocol_doc.encode('utf-8')).hexdigest()

            # Read and update meta_data.json in module directory
            meta_data_path = self.output_path / self._module_name / "meta_data.json"
            if meta_data_path.exists():
                with meta_data_path.open('r', encoding='utf-8') as f:
                    meta_data = json.load(f)

                # Update protocol_document section
                meta_data['files']['protocol_document'] = {
                    "file": "protocol_document.md",
                    "hash": f"sha256:{sha256_hash}"
                }

                # Write back to file
                with meta_data_path.open('w', encoding='utf-8') as f:
                    json.dump(meta_data, f, indent=2)

                logging.info(f"Updated protocol document and meta_data.json with hash: {sha256_hash}")
            else:
                logging.error(f"meta_data.json not found at {meta_data_path}")

        except Exception as e:
            logging.error(f"Failed to update protocol document: {str(e)}\nStack trace:\n{traceback.format_exc()}")

    def _generate_meta_data(self, module_name: str) -> None:
        """Generate meta_data.json file for the module

        Args:
            module_name: Name of the module
        """
        meta_data = {
            "meta_data_specification_version": "1.0", # TODO: add version
            "protocol_name": module_name,  # TODO: add name
            "protocol_version": "1.0", # TODO: add version
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "files": {}
        }

        meta_data_path = self.output_path / module_name / "meta_data.json"
        with open(meta_data_path, "w", encoding="utf-8") as f:
            json.dump(meta_data, f, indent=4, ensure_ascii=False)



    def _generate_init_file(self, module_name: str) -> None:
        """Generate __init__.py file for the specified module

        Args:
            module_name: Module name
        """
        init_content = f'''"""
{module_name.capitalize()} module for protocol implementation.

This module contains the {module_name} side implementation of the protocol.
"""

__version__ = '0.1.0'
'''
        self._write_txt_to_file(init_content, f'{module_name}/__init__.py')

    def _write_txt_to_file(self, code: str, file_path: str) -> None:
        """Write generated code to file

        Args:
            code: Generated code content
            file_path: Target file path
        """
        file_path = self.output_path / file_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(code, encoding='utf-8')

    def _update_meta_data_files(self, file_mappings: Dict[str, tuple[str, str]]) -> None:
        """Update file information in meta_data.json

        Args:
            file_mappings: Dictionary of file mappings in format:
                {
                    'key_in_meta': ('file_name', 'file_content')
                }
        """
        try:
            if not self._module_name:
                logging.error("Module name not set, cannot update meta_data.json")
                return

            meta_data_path = self.output_path / self._module_name / "meta_data.json"
            if not meta_data_path.exists():
                logging.error(f"meta_data.json not found at: {meta_data_path}")
                return

            with meta_data_path.open('r', encoding='utf-8') as f:
                meta_data = json.load(f)

            # Update hash for each file
            for key, (filename, content) in file_mappings.items():
                meta_data['files'][key] = {
                    "file": filename,
                    "hash": f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}"
                }

            with meta_data_path.open('w', encoding='utf-8') as f:
                json.dump(meta_data, f, indent=2)

            logging.info(f"Updated meta_data.json with files: {list(file_mappings.keys())}")

        except Exception as e:
            logging.error(f"Failed to update meta_data.json: {str(e)}\nStack trace:\n{traceback.format_exc()}")


    async def generate(self) -> tuple[bool, Optional[str]]:
        """Generate all protocol-related code, including requester and provider

        Returns:
            tuple[bool, Optional[str]]: A tuple containing:
                - bool: Whether generation was successful
                - Optional[str]: Absolute path of the generated module if successful, None otherwise
        """
        try:
            await self.generate_requester_code()
            await self.generate_provider_code()

            if self._module_name:
                module_path = str(self.output_path / self._module_name)
                return True, module_path
            return False, None

        except Exception as e:
            logging.error(f"Failed to generate code: {str(e)}\nStack trace:\n{traceback.format_exc()}")
            return False, None

    async def generate_requester_code(self) -> None:
        try:
            module_name, requester_code, description_json = await generate_requester_code(
                self.protocol_doc, self.llm
            )

            if not module_name:
                logging.error("Failed to generate requester code: empty module name")
                return

            if not self._module_name:
                self._module_name = self._create_module_structure(module_name)

            # Write files
            requester_path = f"{self._module_name}/requester.py"
            description_path = f"{self._module_name}/requester_description.json"
            self._write_txt_to_file(requester_code, requester_path)
            self._write_txt_to_file(description_json, description_path)

            # Update meta_data.json
            self._update_meta_data_files({
                'requester': ('requester.py', requester_code),
                'requester_description': ('requester_description.json', description_json)
            })

        except Exception as e:
            logging.error(f"Failed to generate requester code: {str(e)}\nStack trace:\n{traceback.format_exc()}")

    async def generate_provider_code(self) -> None:
        try:
            module_name, provider_code, description_json = await generate_provider_code(
                self.protocol_doc, self.llm
            )

            if not module_name:
                logging.error("Failed to generate provider code: empty module name")
                return

            if not self._module_name:
                self._module_name = module_name
                self._create_module_structure(module_name)

            # Write files
            provider_path = f"{self._module_name}/provider.py"
            description_path = f"{self._module_name}/provider_description.json"
            self._write_txt_to_file(provider_code, provider_path)
            self._write_txt_to_file(description_json, description_path)

            # Update meta_data.json
            self._update_meta_data_files({
                'provider': ('provider.py', provider_code),
                'provider_description': ('provider_description.json', description_json)
            })

        except Exception as e:
            logging.error(f"Failed to generate provider code: {str(e)}\nStack trace:\n{traceback.format_exc()}")
