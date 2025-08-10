# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import asyncio
import logging
import os
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent.parent))

from agent_connect.app_protocols.app_protocols import AppProtocols
from agent_connect.utils.log_base import set_log_color_level


async def test_app_protocols():
    """Test AppProtocols functionality"""
    try:
        # Get test protocol directory path
        current_dir = os.path.dirname(os.path.abspath(__file__))
        test_protocol_path = os.path.join(current_dir, 'generated_code_test')

        # Initialize AppProtocols instance
        app_protocols = AppProtocols([test_protocol_path])

        # Test protocol loading
        education_protocol_hash = "sha256:2664c06c8ff8f26a56a3a7d8da81c32ab1365d4c8cc1501b887dde82e0067f40"

        # Get Requester and Provider classes
        requester_class, send_request_description = app_protocols.get_requester_by_hash(education_protocol_hash)
        provider_class, set_protocol_callback_description = app_protocols.get_provider_by_hash(education_protocol_hash)

        if requester_class and provider_class:
            logging.info("Successfully loaded protocol classes")
            logging.info(f"Requester class: {requester_class.__name__}")
            logging.info(f"Provider class: {provider_class.__name__}")
        else:
            logging.error("Failed to load protocol classes")
            return

        # Test protocol file hash calculation
        protocol_doc_path = os.path.join(
            test_protocol_path,
            'education_history_protocol',
            'protocol_document.md'
        )
        calculated_hash = app_protocols.calculate_file_hash(protocol_doc_path)
        logging.info(f"Protocol file hash: {calculated_hash}")

        # Test protocol file integrity verification
        protocol_dir = os.path.join(
            test_protocol_path,
            'education_history_protocol'
        )

        verification_result = app_protocols.verify_protocol_files(
            protocol_dir,
            {
                "files": {
                    "protocol_document": {
                        "file": "protocol_document.md",
                        "hash": "sha256:2664c06c8ff8f26a56a3a7d8da81c32ab1365d4c8cc1501b887dde82e0067f40"
                    },
                    "requester": {
                        "file": "requester.py",
                        "hash": "sha256:af4bb9b0faaee53f2e86ceb448ed6ecc50a89c99177732858c6007e0aff1f87b"
                    },
                    "provider": {
                        "file": "provider.py",
                        "hash": "sha256:9701d46940bfa68972675ca25198321daf77ee685fe73861141602bfd2c42ad1"
                    }
                }
            }
        )

        if verification_result:
            logging.info("Protocol file integrity verification passed")
        else:
            logging.error("Protocol file integrity verification failed")

        # Test invalid protocol hash
        invalid_hash = "sha256:invalid_hash_value"
        invalid_requester, invalid_send_request_description = app_protocols.get_requester_by_hash(invalid_hash)
        invalid_provider, invalid_set_protocol_callback_description = app_protocols.get_provider_by_hash(invalid_hash)

        if invalid_requester is None and invalid_provider is None:
            logging.info("Invalid protocol hash handled correctly")
        else:
            logging.error("Invalid protocol hash handling error")

    except Exception as e:
        logging.error(f"Error occurred during testing: {str(e)}", exc_info=True)
        raise

async def main():
    """Main test function"""
    set_log_color_level(logging.INFO)
    await test_app_protocols()

if __name__ == "__main__":
    asyncio.run(main())