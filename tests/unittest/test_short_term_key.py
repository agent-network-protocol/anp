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
import unittest
from typing import Any, Dict

from cryptography.hazmat.primitives import serialization

current_script_path = os.path.abspath(__file__)
current_directory = os.path.dirname(current_script_path)
sys.path.append(current_directory)
sys.path.append(current_directory + "/../")
sys.path.append(current_directory + "/../../")

from agent_connect.short_term_key_generater import ShortTermKeyGenerater
from agent_connect.utils.did_generate import did_generate


class TestShortTermKeyGeneration(unittest.TestCase):
    def setUp(self):
        # Generate DID and private key for initiator and receiver using did_generate
        initiator_private_key, initiator_public_key, initiator_did, _ = did_generate("wss://initiator.com/endpoint")
        receiver_private_key, receiver_public_key, receiver_did, _ = did_generate("wss://receiver.com/endpoint")

        # Save private keys in PEM format
        initiator_private_key_pem = initiator_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        receiver_private_key_pem = receiver_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        initiator_private_key_pem = initiator_private_key_pem.decode('utf-8')
        receiver_private_key_pem = receiver_private_key_pem.decode('utf-8')

        # Initialize two instances, one as initiator and one as receiver
        self.initiator = ShortTermKeyGenerater(
            local_did=initiator_did,
            did_private_key_pem=initiator_private_key_pem,
            remote_did=receiver_did,
            json_send_func=self.receiver_receive_json,
            is_initiator=True
        )

        self.receiver = ShortTermKeyGenerater(
            local_did=receiver_did,
            did_private_key_pem=receiver_private_key_pem,
            remote_did=initiator_did,
            json_send_func=self.initiator_receive_json,
            is_initiator=False,
            session_id=self.initiator.session_id
        )

        self.initiator_did = initiator_did
        self.receiver_did = receiver_did

    async def initiator_receive_json(self, json_data: Dict[str, Any]):
        # Wait for 10ms
        self.initiator.receive_json_message(json_data)
        await asyncio.sleep(0.01)

    async def receiver_receive_json(self, json_data: Dict[str, Any]):
        self.receiver.receive_json_message(json_data)
        await asyncio.sleep(0.01)

    async def initiate_key_exchange(self):
        result = await self.initiator.generate_short_term_key_active()
        logging.info(f'generate_short_term_key_active {result}')
        self.assertTrue(result, "Key exchange failed")

    async def receive_key_exchange(self):
        """Start the key exchange process"""
        result = await self.receiver.generate_short_term_key_passive()
        logging.info(f'generate_short_term_key_passive {result}')
        self.assertTrue(result, "Key exchange failed")


    def test_key_exchange(self):
        # Test key exchange process
        async def run_test():
            return await asyncio.gather(
                self.initiate_key_exchange(),
                self.receive_key_exchange()
            )

        asyncio.run(run_test())

        # Verify if both parties have negotiated the same key
        initiator_remote_did, \
        initiator_send_encryption_key, \
        initiator_receive_decryption_key, \
        initiator_secret_key_id, \
        initiator_key_expires, \
        initiator_cipher_suite = self.initiator.get_final_short_term_key()

        receiver_remote_did, \
        receiver_send_encryption_key, \
        receiver_receive_decryption_key, \
        receiver_secret_key_id, \
        receiver_key_expires, \
        receiver_cipher_suite = self.receiver.get_final_short_term_key()

        self.assertEqual(initiator_remote_did, self.receiver_did, "Remote DID mismatch")
        self.assertEqual(receiver_remote_did, self.initiator_did, "Remote DID mismatch")
        self.assertEqual(initiator_send_encryption_key, receiver_receive_decryption_key, "Send encryption key mismatch")
        self.assertEqual(initiator_receive_decryption_key, receiver_send_encryption_key, "Receive decryption key mismatch")
        self.assertEqual(initiator_secret_key_id, receiver_secret_key_id, "Secret key ID mismatch")
        self.assertEqual(initiator_key_expires, receiver_key_expires, "Key expiration mismatch")
        self.assertEqual(initiator_cipher_suite, receiver_cipher_suite, "Cipher suite mismatch")

        # logging.info(f"initiator_remote_did: {initiator_remote_did}")
        # logging.info(f"receiver_remote_did: {receiver_remote_did}")
        # logging.info(f"initiator_send_encryption_key: {initiator_send_encryption_key}")
        # logging.info(f"initiator_receive_decryption_key: {initiator_receive_decryption_key}")
        # logging.info(f"initiator_secret_key_id: {initiator_secret_key_id}")
        # logging.info(f"receiver_send_encryption_key: {receiver_send_encryption_key}")
        # logging.info(f"receiver_receive_decryption_key: {receiver_receive_decryption_key}")
        # logging.info(f"receiver_secret_key_id: {receiver_secret_key_id}")
        # logging.info(f"initiator_key_expires: {initiator_key_expires}")
        # logging.info(f"receiver_key_expires: {receiver_key_expires}")
        # logging.info(f"initiator_cipher_suite: {initiator_cipher_suite}")
        # logging.info(f"receiver_cipher_suite: {receiver_cipher_suite}")

if __name__ == "__main__":
    unittest.main()

