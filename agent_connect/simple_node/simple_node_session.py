# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import asyncio
import datetime
import json
import logging
import traceback
from typing import Optional, Tuple, Union

from agent_connect.e2e_encryption.message_generation import generate_encrypted_message
from agent_connect.e2e_encryption.short_term_key_generater import ShortTermKeyGenerater
from agent_connect.simple_node.simple_wss_wraper import (
    SimpleClientWssWraper,
    SimpleWssWraper,
)
from agent_connect.utils.crypto_tool import decrypt_aes_gcm_sha256, generate_random_hex


class SimpleNodeSession:
    def __init__(self, local_did: str,
                 private_key_pem: str,
                 did_document_json: str,
                 wss_wraper: SimpleWssWraper,
                 protocol_hash: Optional[str] = None):
        """
        Initialize a SimpleNodeSession.

        Args:
            local_did (str): The local DID.
            private_key_pem (str): The private key in PEM format.
            did_document_json (str): The DID document in JSON format.
            wss_wraper (SimpleWssWraper): The WebSocket wrapper.
        """
        self.local_did = local_did
        self.remote_did = None
        self.private_key_pem = private_key_pem
        self.did_document_json = did_document_json
        self.wss_wraper: SimpleWssWraper = wss_wraper
        self.short_term_key_generater: ShortTermKeyGenerater = None
        self.short_term_key: dict = {}  # Store single short-term key information
        self.recv_task: asyncio.Task = None
        self.heartbeat_task: asyncio.Task = None
        self.protocol_hash: Optional[str] = protocol_hash
        if isinstance(self.wss_wraper, SimpleClientWssWraper):
            self._start_heartbeat()


    def set_remote_did(self, remote_did: str):
        """
        Set the remote DID.
        """
        self.remote_did = remote_did

    def set_recv_task(self, task: asyncio.Task):
        """
        Set the receive task.

        Args:
            task (asyncio.Task): The task to set.
        """
        self.recv_task = task

    async def close(self):
        """
        Close the session and cancel all running tasks.
        """
        if self.recv_task:
            self.recv_task.cancel()
            try:
                await self.recv_task
            except asyncio.CancelledError:
                pass

        if self.heartbeat_task:
            self.heartbeat_task.cancel()
            try:
                await self.heartbeat_task
            except asyncio.CancelledError:
                pass

        await self.wss_wraper.close()
        logging.info("SimpleNodeSession has been closed")

    def _start_heartbeat(self):
        """
        Start the heartbeat task.
        """
        self.heartbeat_task = asyncio.get_event_loop().create_task(self._heartbeat_loop())

    async def _heartbeat_loop(self):
        """
        The heartbeat loop that sends heartbeat requests periodically.
        """
        while True:
            try:
                await asyncio.sleep(5)  # Send heartbeat every 5 seconds
                await self._send_heartbeat_request()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error(f"Error sending heartbeat: {str(e)}")
                stack_trace = traceback.format_exc()
                logging.error(f"Heartbeat task exception: {e}, remote did: {self.remote_did}\nStack trace:\n{stack_trace}")
                return

    async def _send_heartbeat_request(self):
        """
        Send a heartbeat request.
        """
        heartbeat = {
            "version": "1.0",
            "type": "heartbeat",
            "timestamp": datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            "messageId": generate_random_hex(16),
            "message": "ping"
        }
        await self.wss_wraper.send_data(heartbeat)
        logging.debug(f"Heartbeat request sent: {heartbeat}")

    async def _process_short_term_key_negotiation_messages(self):
        """
        Internal method to handle "destinationHello" and "finished" messages.
        Uses new coroutines for asynchronous processing, exits when coroutine cancellation is detected.
        """
        try:
            while True:
                json_data = await self.wss_wraper.receive_data()
                msg_type = json_data.get('type')

                if msg_type in ["destinationHello", "finished"]:
                    if self.short_term_key_generater:
                        self.short_term_key_generater.receive_json_message(json_data)
                    else:
                        logging.warning("short_term_key_generater is not initialized, unable to process message")
        except asyncio.CancelledError:
            logging.info("Key negotiation message processing coroutine has been cancelled")
        except Exception as e:
            logging.error(f"Error occurred while processing key negotiation messages: {str(e)}")

    async def wait_generate_short_term_key_passive(self) -> Tuple[bool, str, str]:
        """
        As a server, wait and process short-term key negotiation requests in passive mode.

        Returns:
            Tuple[bool, str, str]:
                - Boolean indicating success
                - Remote DID
                - JSON string of key information (if successful). JSON contains the following fields:
                    send_encryption_key: Encryption key used by the sender, represented as a hexadecimal string
                    receive_decryption_key: Decryption key used by the receiver, represented as a hexadecimal string
                    secret_key_id: Unique identifier of the key
                    key_expires: Expiration time of the key, represented as a Unix timestamp
                    cipher_suite: Name of the encryption suite used
        """
        try:
            async with asyncio.timeout(15):  # Set 15 seconds timeout
                while True:
                    json_data = await self.wss_wraper.receive_data()
                    msg_type = json_data['type']

                    if msg_type == "sourceHello":
                        remote_did = json_data['sourceDid']
                        session_id = json_data['sessionId']

                        self.short_term_key_generater = ShortTermKeyGenerater(self.local_did, self.private_key_pem,
                                                        remote_did, self.wss_wraper.send_data,
                                                        is_initiator=False, session_id=session_id)
                        self.short_term_key_generater.receive_json_message(json_data)

                        recv_task = asyncio.create_task(self._process_short_term_key_negotiation_messages())

                        success = await self.short_term_key_generater.generate_short_term_key_passive()

                        recv_task.cancel()
                        try:
                            await recv_task
                        except asyncio.CancelledError:
                            pass

                        if success:
                            _, send_encryption_key, \
                            receive_decryption_key, secret_key_id, \
                                key_expires, cipher_suite = self.short_term_key_generater.get_final_short_term_key()
                            secret_info_json = json.dumps({
                                "send_encryption_key": send_encryption_key.hex(),
                                "receive_decryption_key": receive_decryption_key.hex(),
                                "secret_key_id": secret_key_id,
                                "key_expires": key_expires,
                                "cipher_suite": cipher_suite
                            })
                            # Save short-term key information
                            self.short_term_key = {
                                "remote_did": remote_did,
                                "send_encryption_key": send_encryption_key.hex(),
                                "receive_decryption_key": receive_decryption_key.hex(),
                                "secret_key_id": secret_key_id,
                                "key_expires": key_expires,
                                "cipher_suite": cipher_suite
                            }
                            return True, remote_did, secret_info_json
                        else:
                            logging.error(f"Key negotiation failed: {remote_did} -> {self.local_did}")
                            return False, remote_did, ""

                    elif msg_type in ["destinationHello", "finished"]:
                        self.short_term_key_generater.receive_json_message(json_data)

                    elif msg_type == 'response':
                        logging.info(f"Response message: {json_data}")

                    else:
                        logging.error(f"Unknown message type: {msg_type}")

        except asyncio.TimeoutError:
            logging.error("Key negotiation timeout")
            return False, "", ""

    async def generate_short_term_key_active(self, remote_did: str) -> Tuple[bool, str, str]:
        """
        Actively initiate short-term key negotiation.

        Args:
            remote_did (str): Remote DID.

        Returns:
            Tuple[bool, str, str]:
                - Boolean indicating success
                - Remote DID
                - If successful, returns a JSON string containing key information. JSON contains the following fields:
                    send_encryption_key: Encryption key used by the sender, represented as a hexadecimal string
                    receive_decryption_key: Decryption key used by the receiver, represented as a hexadecimal string
                    secret_key_id: Unique identifier of the key
                    key_expires: Expiration time of the key, represented as a Unix timestamp
                    cipher_suite: Name of the encryption suite used

        """
        try:
            self.short_term_key_generater = ShortTermKeyGenerater(
                self.local_did,
                self.private_key_pem,
                remote_did,
                self.wss_wraper.send_data,
                is_initiator=True,
                protocol_hash=self.protocol_hash
            )

            recv_task = asyncio.create_task(self._process_short_term_key_negotiation_messages())

            success = await self.short_term_key_generater.generate_short_term_key_active()

            recv_task.cancel()
            try:
                await recv_task
            except asyncio.CancelledError:
                pass

            if success:
                _, send_encryption_key, \
                receive_decryption_key, secret_key_id, \
                    key_expires, cipher_suite = self.short_term_key_generater.get_final_short_term_key()

                secret_info_json = json.dumps({
                    "send_encryption_key": send_encryption_key.hex(),
                    "receive_decryption_key": receive_decryption_key.hex(),
                    "secret_key_id": secret_key_id,
                    "key_expires": key_expires,
                    "cipher_suite": cipher_suite
                })

                # Save short-term key information
                self.short_term_key = {
                    "remote_did": remote_did,
                    "send_encryption_key": send_encryption_key.hex(),
                    "receive_decryption_key": receive_decryption_key.hex(),
                    "secret_key_id": secret_key_id,
                    "key_expires": key_expires,
                    "cipher_suite": cipher_suite
                }

                logging.info(f"Successfully negotiated short-term key with {remote_did}")
                return True, remote_did, secret_info_json
            else:
                logging.error(f"Key negotiation failed with {remote_did}")
                return False, remote_did, ""

        except Exception as e:
            logging.error(f"Error occurred during key negotiation: {str(e)}")
            return False, remote_did, ""

    async def _send_heartbeat_response(self, message_id: str):
        """
        Send heartbeat response.

        Args:
            message_id (str): Message ID of the received heartbeat request
        """
        response = {
            "version": "1.0",
            "type": "heartbeat",
            "timestamp": datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
            "messageId": message_id,
            "message": "pong"
        }
        await self.wss_wraper.send_data(response)
        logging.debug(f"Heartbeat response sent: {response}")

    async def receive_message(self) -> Optional[bytes]:
        """
        Asynchronously receive and decrypt messages.

        Returns:
            Optional[bytes]: Decrypted message content
        """
        while True:

            json_data = await self.wss_wraper.receive_data()

            if json_data['type'] == 'heartbeat':
                if json_data.get('message') == 'ping':
                    await self._send_heartbeat_response(json_data['messageId'])
                continue

            if json_data['type'] != 'message':
                logging.error(f"Received non-message type data: {json_data['type']}")
                continue

            decrypted_message = self._decrypt_message(json_data)
            if decrypted_message:
                return decrypted_message.encode('utf-8')
            else:
                return None

    def _decrypt_message(self, json_data: dict) -> Optional[str]:
        """
        Decrypt received message.

        Args:
            json_data (dict): Received JSON data

        Returns:
            Optional[str]: Decrypted message content
        """
        if not self.short_term_key:
            logging.error("No available short-term key")
            return ''

        if json_data['secretKeyId'] != self.short_term_key['secret_key_id']:
            logging.error("Key ID mismatch detected. Please check the short-term key.")
            return ''

        encrypted_data = json_data['encryptedData']
        secret_key = bytes.fromhex(self.short_term_key['receive_decryption_key'])

        try:
            plaintext = decrypt_aes_gcm_sha256(encrypted_data, secret_key)
            logging.info("Message decryption successful")
            return plaintext
        except Exception as e:
            logging.error(f"Message decryption failed: {e}")
            return ''

    async def send_message(self, message: Union[str, bytes]) -> bool:
        """
        Send message to the previously set destination DID.

        Args:
            message (Union[str, bytes]): Message content to be sent.

        Returns:
            bool: Returns True if sending is successful, False if failed.
        """
        try:
            destination_did = self.remote_did  # Use previously set remote DID
            # Convert message to bytes if it's a string
            message_bytes = message.encode('utf-8') if isinstance(message, str) else message

            # Generate encrypted message
            encrypted_message = generate_encrypted_message(
                version="1.0",
                message_id=generate_random_hex(16),
                source_did=self.local_did,
                destination_did=destination_did,
                secret_key_id=self.short_term_key['secret_key_id'],
                data=message_bytes,
                data_secret=bytes.fromhex(self.short_term_key['send_encryption_key'])
            )

            # Send encrypted message
            await self.wss_wraper.send_data(encrypted_message)
            logging.info(f"Successfully sent message to {destination_did}")
            return True

        except Exception as e:
            logging.error(f"Error occurred while sending message to {destination_did}: {str(e)}")
            return False