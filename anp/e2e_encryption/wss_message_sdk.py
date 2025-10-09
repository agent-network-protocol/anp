# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.


import asyncio
import json
import logging
from typing import Callable, Tuple, Union

from anp.e2e_encryption.message_generation import generate_encrypted_message
from anp.e2e_encryption.short_term_key_generater import ShortTermKeyGenerater
from anp.e2e_encryption.wss_message_client import WssMessageClient
from anp.utils.crypto_tool import decrypt_aes_gcm_sha256, generate_random_hex


# TODO:
# Key expiration management, check expiration when using
# Key error management
# Handling cases when key is not found or expired during sending
# Handling error responses
class WssMessageSDK:
    def __init__(self, wss_url: str, api_key: str, routers: list[tuple[str, str]],
                 short_term_key_callback: Callable[[tuple[str, str, str]], None]):
        '''
        Initialize WssMessageSDK class.

        Args:
            wss_url (str): URL of the WebSocket service.
            api_key (str): API key for the WebSocket service.
            routers (list[tuple[str, str]]): List of routers, each tuple contains the private key and did document of the router did
            short_term_key_callback (Callable[[tuple[str, str, str]], None]): Callback function for short-term keys,
                used to callback short-term key info. The tuple contains three strings: local did, remote did, and key info JSON string,
                JSON definition is the same as the input of set_short_term_keys
        '''
        self.client = WssMessageClient(wss_url, api_key)
        self.short_term_keys: dict[str, dict] = {}
        self.short_term_keys_combined: dict[str, dict] = {}
        self.local_did_to_private_key: dict[str, str] = {}  # Add a dictionary to store local DID and corresponding private key
        self.short_term_key_callback = short_term_key_callback
        self.short_term_key_generater_session_dict: dict[str, ShortTermKeyGenerater] = {}

    @classmethod
    async def create(cls, wss_url: str, api_key: str, routers: list[tuple[str, str]],
                     short_term_key_callback: Callable[[tuple[str, str, str]], None]):
        """Factory method to asynchronously create WssMessageSDK instance and register routers"""
        instance = cls(wss_url, api_key, routers, short_term_key_callback)
        await instance.client.register_routers(routers)
        return instance

    def key_combined(self, local_did: str, remote_did: str) -> str:
        return f"{local_did}_{remote_did}"

    def insert_did_private_key(self, local_did: str, private_key_pem: str):
        """Insert local DID and corresponding private key into the dictionary"""
        self.local_did_to_private_key[local_did] = private_key_pem

    # Change input to JSON, communicate with external through JSON, caller doesn't need to know JSON details
    def set_short_term_keys(self, local_did: str, remote_did: str, secret_info_json: str):
        """
        Set short-term key information based on JSON string. Short-term keys can be used before expiration,
        previously negotiated short-term keys can be set if server restarts.
        JSON string contains send encryption key, receive decryption key, key ID, key expiration time and cipher suite.

        Args:
            local_did (str): Local DID.
            remote_did (str): Remote DID.
            secret_info_json (str): JSON string containing key information. Same as negotiate_short_term_keys return value
        """
        secret_info = json.loads(secret_info_json)
        secret_key_id = secret_info['secret_key_id']
        key_combined = self.key_combined(local_did, remote_did)
        self.short_term_keys_combined[key_combined] = {
            "local_did": local_did,
            "remote_did": remote_did,
            "secret_key_id": secret_key_id,
            "send_encryption_key": secret_info['send_encryption_key'],
            "receive_decryption_key": secret_info['receive_decryption_key'],
            "key_expires": secret_info['key_expires'],
            "cipher_suite": secret_info['cipher_suite']
        }
        self.short_term_keys[secret_key_id] = {
            "local_did": local_did,
            "remote_did": remote_did,
            "send_encryption_key": secret_info['send_encryption_key'],
            "receive_decryption_key": secret_info['receive_decryption_key'],
            "key_expires": secret_info['key_expires'],
            "cipher_suite": secret_info['cipher_suite']
        }

    async def negotiate_short_term_keys(self, local_did: str,
                                        did_private_key_pem: str,
                                        remote_did: str) -> str:
        """
        Negotiate short-term keys and return JSON string containing key information.
        If negotiation is successful, return JSON string containing local DID, remote DID and key information;
        If negotiation fails, return JSON string containing error information.

        Args:
            local_did (str): Local DID.
            did_private_key_pem (str): Private key of local DID, in PEM format.
            remote_did (str): Remote DID.

        Returns:
            str: Key information JSON string. Generated JSON field description:
                send_encryption_key: Encryption key used by sender, represented as hexadecimal string.
                receive_decryption_key: Decryption key used by receiver, represented as hexadecimal string.
                secret_key_id: Unique identifier of the key.
                key_expires: Expiration time of the key, represented as Unix timestamp.
                cipher_suite: Name of the encryption suite used.

        Note: After function returns successfully, short_term_key_callback function is no longer called.
        """
        json_send_func = self.client.send_data  # Assume WssMessageClient has a method to send JSON messages
        key_gen = ShortTermKeyGenerater(local_did, did_private_key_pem, remote_did, json_send_func, is_initiator=True)

        self.short_term_key_generater_session_dict[key_gen.session_id] = key_gen
        success = await key_gen.generate_short_term_key_active()
        self.short_term_key_generater_session_dict.pop(key_gen.session_id)

        if success:
            remote_did, send_encryption_key, \
            receive_decryption_key, secret_key_id, \
                key_expires, cipher_suite = key_gen.get_final_short_term_key()
            secret_info_json = json.dumps({
                "send_encryption_key": send_encryption_key.hex(),
                "receive_decryption_key": receive_decryption_key.hex(),
                "secret_key_id": secret_key_id,
                "key_expires": key_expires,
                "cipher_suite": cipher_suite
                })
            self.set_short_term_keys(local_did, remote_did, secret_info_json)
            self.short_term_key_callback(local_did, remote_did, secret_info_json)
            return secret_info_json

        else:
            logging.error(f"Key negotiation failed: {local_did} -> {remote_did}")
            return None

    async def source_hello_process(self, json_data: dict):
        local_did = json_data['destinationDid'] # When receiving hello message from peer, destinationDID is local did
        did_private_key_pem = self.local_did_to_private_key.get(local_did, None)
        if did_private_key_pem is None:
            logging.error(f"Private key for local DID not found: {local_did}")
            return

        remote_did = json_data['sourceDid']
        session_id = json_data['sessionId']
        json_send_func = self.client.send_data

        key_gen = ShortTermKeyGenerater(local_did, did_private_key_pem,
                                        remote_did, json_send_func,
                                        is_initiator=False, session_id=session_id)
        self.short_term_key_generater_session_dict[session_id] = key_gen
        key_gen.receive_json_message(json_data)

        success = await key_gen.generate_short_term_key_passive()
        self.short_term_key_generater_session_dict.pop(key_gen.session_id)

        if success:
            remote_did, send_encryption_key, \
            receive_decryption_key, secret_key_id, \
                key_expires, cipher_suite = key_gen.get_final_short_term_key()
            secret_info_json = json.dumps({
                    "send_encryption_key": send_encryption_key.hex(),
                    "receive_decryption_key": receive_decryption_key.hex(),
                    "secret_key_id": secret_key_id,
                    "key_expires": key_expires,
                    "cipher_suite": cipher_suite
                })
            self.set_short_term_keys(local_did, remote_did, secret_info_json)
            self.short_term_key_callback(local_did, remote_did, secret_info_json)
        else:
            logging.error(f"Key negotiation failed: {remote_did} -> {local_did}")


    def ecrypted_message_process(self, json_data: dict):

        secret_key_id = json_data['secretKeyId']
        key_info = self.short_term_keys.get(secret_key_id, None)

        if key_info is None:
            logging.error("Cannot find secret key info. Key ID not found or invalid.")
            # TODO: Send error message later
            return

        encrypted_data = json_data['encryptedData']
        secret_key = bytes.fromhex(key_info['receive_decryption_key'])
        try:
            plaintext = decrypt_aes_gcm_sha256(encrypted_data, secret_key)
            logging.info(f"Message decryption successful: {plaintext}")
            return plaintext
        except Exception as e:
            logging.error(f"Message decryption failed: {e}")
            return None

    async def recv_data(self) -> Tuple[str, str, str]:
        """Asynchronously receive data"""
        while True:
            json_data = await self.client.receive_data()
            msg_type = json_data['type']
            if msg_type == "sourceHello":
                asyncio.create_task(self.source_hello_process(json_data))
                # TODO: Record the task here. May need to cancel later
            elif msg_type in ["destinationHello", "finished"]:
                session_id = json_data['sessionId']
                if session_id in self.short_term_key_generater_session_dict:
                    self.short_term_key_generater_session_dict[session_id].receive_json_message(json_data)
                else:
                    logging.error(f"Cannot find session_id: {session_id}")
            elif msg_type == 'message':
                msg = self.ecrypted_message_process(json_data)
                if msg is not None:
                    return json_data['sourceDid'], json_data['destinationDid'], msg
            elif msg_type == 'response':
                logging.info(f"Response message: {json_data}")
            else:
                logging.error(f"Unknown message type: {msg_type}")

    async def send_data(self, content: Union[str, bytes], source_did: str, destination_did: str):
        """
        Send encrypted message. Input data can be str or bytes, if it's str, convert to bytes.
        Get key information from short_term_keys_combined, use generate_encrypted_message to create message,
        and call client method to send data.

        Args:
            content (Union[str, bytes]): Message content to send.
            source_did (str): Source DID.
            destination_did (str): Destination DID.

        Returns:
            None
        """
        if isinstance(content, str):
            content = content.encode('utf-8')

        key_combined = self.key_combined(source_did, destination_did)
        key_info = self.short_term_keys_combined.get(key_combined, None)
        if key_info is None:
            # TODO: Handle exception here
            logging.error(f"Key information not found: {key_combined}")
            return
        secret_key_id = key_info['secret_key_id']
        data_secret = bytes.fromhex(key_info['send_encryption_key'])

        encrypted_message = generate_encrypted_message(
            version="1.0",
            message_id=generate_random_hex(16),
            source_did=source_did,
            destination_did=destination_did,
            secret_key_id=secret_key_id,
            data=content,
            data_secret=data_secret
        )

        await self.client.send_data(encrypted_message)
