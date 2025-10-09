# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.


import asyncio
import json
import logging
import os
import sys
import traceback
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric import ec

current_script_path = os.path.abspath(__file__)
current_directory = os.path.dirname(current_script_path)
sys.path.append(current_directory)
sys.path.append(current_directory + "/../")
sys.path.append(current_directory + "/../../")

from anp.e2e_encryption.message_generation import (
    generate_destination_hello,
    generate_finished_message,
    generate_source_hello,
)
from anp.utils.crypto_tool import (
    decrypt_aes_gcm_sha256,
    derive_tls13_data_keys,
    generate_16_char_from_random_num,
    generate_ec_key_pair,
    generate_random_hex,
    generate_shared_secret,
    get_key_length_from_cipher_suite,
    get_public_key_from_hex,
    load_private_key_from_pem,
    verify_did_with_public_key,
    verify_signature_for_json,
)


class ECKeyPair:
    def __init__(self, curve: ec.EllipticCurve):
        self.curve = curve
        self.private_key: ec.EllipticCurvePrivateKey = None
        self.public_key: ec.EllipticCurvePublicKey = None
        self.public_key_hex: str = None

        self.private_key, self.public_key, self.public_key_hex = generate_ec_key_pair(curve)

class ShortTermKeyGenerater:
    def __init__(self, local_did: str,
                 did_private_key_pem: str,
                 remote_did: str,
                 json_send_func: Callable[[Dict[str, Any]], None],
                 is_initiator: bool,
                 session_id: str=None,
                 protocol_hash: Optional[str] = None):
        self.session_id: str = session_id if session_id else generate_random_hex(16)
        self.json_send_func: Callable[[Dict[str, Any]], None] = json_send_func
        self.is_initiator: bool = is_initiator
        self.event: asyncio.Event = asyncio.Event()

        self.source_hello_message: Dict[str, Any] = None
        self.destination_hello_message: Dict[str, Any] = None
        self.finished_message: Dict[str, Any] = None

        # Local information
        self.local_did: str = local_did
        self.local_did_private_key: ec.EllipticCurvePrivateKey = None
        self.local_did_public_key_hex: str = None

        self.local_ec_key_pair: ECKeyPair = ECKeyPair(ec.SECP256R1())
        self.local_short_key_expires: int = 864000
        self.local_key_share: Dict[str, Any] = {
            "group": self.local_ec_key_pair.curve.name,
            "expires": self.local_short_key_expires,  # Example: 10 days
            "keyExchange": self.local_ec_key_pair.public_key_hex
        }
        self.local_cipher_suites: List[str] = ["TLS_AES_128_GCM_SHA256"]  #  "TLS_AES_128_GCM_SHA256" "TLS_AES_256_GCM_SHA384" "TLS_CHACHA20_POLY1305_SHA256"
        self.set_local_key_from_pem(did_private_key_pem)

        # Remote information
        self.remote_did: str = remote_did
        self.remote_did_public_key: ec.EllipticCurvePublicKey = None
        self.remote_key_share: Dict[str, Any] = {}

        # Current state
        # As initiator, states include: init, wait_destination_hello, wait_finished, finished
        # As responder, states include: init, wait_finished, finished
        self.state: str = "init"

        # Encryption keys
        self.source_hello_random: str = generate_random_hex(32) if self.is_initiator else None
        self.destination_hello_random: str = None if self.is_initiator else generate_random_hex(32)
        self.send_encryption_key: bytes = None  # Encryption key for sending
        self.receive_decryption_key: bytes = None  # Decryption key for receiving
        self.secret_key_id: str = None
        self.key_expires: int = None
        self.cipher_suite: str = None

        self.protocol_hash: Optional[str] = protocol_hash

    def get_final_short_term_key(self):
        return  self.remote_did, \
                self.send_encryption_key, \
                self.receive_decryption_key, \
                self.secret_key_id, \
                self.key_expires, \
                self.cipher_suite

    def set_local_key_from_pem(self, pem_data):
        self.local_did_private_key = load_private_key_from_pem(pem_data)
        public_key = self.local_did_private_key.public_key()
        public_numbers = public_key.public_numbers()
        self.local_did_public_key_hex = '04' + format(public_numbers.x, '064x') + format(public_numbers.y, '064x')


    async def send_source_hello(self):
        # Generate SourceHello message
        source_hello = generate_source_hello(
            "1.0",
            self.session_id,
            self.local_did_private_key,
            self.local_did,
            self.remote_did,
            self.source_hello_random,
            self.local_did_public_key_hex,
            [self.local_key_share],
            self.local_cipher_suites
        )

        # Send message
        self.source_hello_message = source_hello
        await self.json_send_func(source_hello)

    async def send_destination_hello(self):
        destination_hello = generate_destination_hello(
            "1.0",
            self.session_id,
            self.local_did_private_key,
            self.local_did,
            self.remote_did,
            self.destination_hello_random,
            self.local_did_public_key_hex,
            self.local_key_share,
            self.cipher_suite
        )
        # Send message
        self.destination_hello_message = destination_hello
        await self.json_send_func(destination_hello)

    async def send_finished(self):
        finished_message = generate_finished_message(
            "1.0",
            self.session_id,
            self.local_did,
            self.remote_did,
            self.source_hello_random,
            self.destination_hello_random,
            self.send_encryption_key
        )
        await self.json_send_func(finished_message)

    def receive_json_message(self, message_json: Dict[str, Any]):
        if message_json.get('type') == "sourceHello":
            self.source_hello_message = message_json
        elif message_json.get('type') == "destinationHello":
            self.destination_hello_message = message_json
            self.event.set()
            self.event.clear()
        elif message_json.get('type') == "finished":
            self.finished_message = message_json
            logging.info(f"receive_json_message[{id(self)}], finished: {message_json}")
            self.event.set()
            self.event.clear()
        else:
            logging.error("Unknown message type")


    def check_message_valid(self, message: Dict[str, Any]):
        session_id = message['sessionId']
        source_did = message['sourceDid']
        destination_did = message['destinationDid']
        if source_did != self.remote_did:
            logging.error(f"sourceDid does not match local DID: {source_did}, remote_did: {self.remote_did}")
            return False
        if destination_did != self.local_did:
            logging.error(f"destinationDid does not match local DID: {destination_did}, local_did: {self.local_did}")
            return False
        if session_id != self.session_id:
            logging.error(f"sessionId does not match local sessionId: {session_id}, session_id: {self.session_id}")
            return False

        return True

    def check_message_did_public_key(self, source_hello: Dict[str, Any], source_public_key: ec.EllipticCurvePublicKey):
        # 2. Verify DID and public key correspondence
        source_did = source_hello['sourceDid']
        is_did_valid = verify_did_with_public_key(source_did, source_public_key)
        if not is_did_valid:
            logging.error("DID verification failed")
            return False
        return True

    def check_message_proof(self, source_hello: Dict[str, Any], source_public_key: ec.EllipticCurvePublicKey):
        # 3. Verify proof signature
        original_message = deepcopy(source_hello)
        del original_message['proof']['proofValue']

        proof = source_hello["proof"]
        proof_value = proof['proofValue']
        is_signature_valid = verify_signature_for_json(source_public_key, original_message, proof_value)
        if not is_signature_valid:
            logging.error("Signature verification failed")
            return False

        created_time_str = proof['created']
        created_time = datetime.strptime(created_time_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        current_time = datetime.now(timezone.utc)
        time_difference = (current_time - created_time).total_seconds()

        if abs(time_difference) > 30:
            logging.error("Replay attack detected, proof timestamp differs from current time by more than 30 seconds")
            return False

        return True

    def process_source_hello(self):
        if not self.source_hello_message:
            logging.error("source_hello_message is empty")
            return False

        try:
            source_hello = self.source_hello_message

            # 1. Verify DID and session id
            if not self.check_message_valid(source_hello):
                return False

            verification_method = source_hello['proof']['verificationMethod']
            source_public_key = self.extract_public_key(source_hello, verification_method)

            # 2. Verify DID and public key correspondence
            if not self.check_message_did_public_key(source_hello, source_public_key):
                logging.error("DID verification failed")
                return False

            # 3. Verify proof signature
            if not self.check_message_proof(source_hello, source_public_key):
                logging.error("Signature verification failed")
                return False

            # 4. Record remote information, including random number, key share, etc.
            self.source_hello_random = source_hello['random']
            self.remote_did_public_key = source_public_key

            cipher_suites = source_hello['cipherSuites']
            for cs in self.local_cipher_suites:
                if cs in cipher_suites:
                    self.cipher_suite = cs
                    break
            if not self.cipher_suite:
                logging.error(f"Unsupported cipher suite: {cipher_suites}, Local supported cipher suites: {self.local_cipher_suites}")
                return False

            for ks in source_hello['keyShares']:
                if ks['group'] == "secp256r1":
                    self.remote_key_share = ks
                    break
            if not self.remote_key_share:
                logging.error("secp256r1 not found")
                return False

            key_expires = int(self.remote_key_share['expires'])
            self.key_expires = min(key_expires, self.local_short_key_expires)

            logging.info("SourceHello message processed successfully")
            return True

        except Exception as e:
            logging.error(f"Error processing SourceHello message: {e}")
            logging.error("Exception stack trace:")
            traceback.print_exc()
            logging.error(f"Error processing SourceHello message: {e}")
            return False


    def process_destination_hello(self):
        if not self.destination_hello_message:
            logging.error("destination_hello_message is empty")
            return False

        try:
            destination_hello = self.destination_hello_message

            # 1. Verify DID and session id
            if not self.check_message_valid(destination_hello):
                return False

            verification_method = destination_hello['proof']['verificationMethod']
            source_public_key = self.extract_public_key(destination_hello, verification_method)

            # 2. Verify DID and public key correspondence
            if not self.check_message_did_public_key(destination_hello, source_public_key):
                logging.error("DID verification failed")
                return False

            # 3. Verify proof signature
            if not self.check_message_proof(destination_hello, source_public_key):
                logging.error("Signature verification failed")
                return False

            # 4. Record remote information, including random number, key share, etc.
            self.destination_hello_random = destination_hello['random']
            self.remote_did_public_key = source_public_key
            self.cipher_suite = destination_hello['cipherSuite']
            self.remote_key_share = destination_hello['keyShare']
            if self.remote_key_share['group'] != "secp256r1":
                logging.error("Unsupported elliptic curve group")
                return False

            key_expires = int(self.remote_key_share['expires'])
            self.key_expires = min(key_expires, self.local_short_key_expires)

            logging.info("DestinationHello message processed successfully")
            return True

        except Exception as e:
            logging.error(f"Error processing DestinationHello message: {e}")
            return False

    def generate_keys(self):
        remote_public_ec_key = get_public_key_from_hex(self.remote_key_share['keyExchange'])
        shared_secret = generate_shared_secret(self.local_ec_key_pair.private_key,
                                               remote_public_ec_key)

        key_length = get_key_length_from_cipher_suite(self.cipher_suite)

        self.send_encryption_key, \
        self.receive_decryption_key, _, _ = derive_tls13_data_keys(shared_secret,
                                                                    self.source_hello_random.encode('utf-8'),
                                                                    self.destination_hello_random.encode('utf-8'),
                                                                    key_length=key_length)
        if not self.is_initiator:
            self.send_encryption_key, self.receive_decryption_key = (self.receive_decryption_key, self.send_encryption_key)


    def process_finished(self):
        if not self.finished_message:
            logging.error("finished_message is empty")
            return False

        if not self.check_message_valid(self.finished_message):
            return False

        verify_data = self.finished_message['verifyData']
        if not verify_data:
            logging.error("verifyData is empty")
            return False

        content= decrypt_aes_gcm_sha256(verify_data, self.receive_decryption_key)
        content_dict = json.loads(content)
        if not content_dict:
            logging.error("ciphertext is empty")
            return False

        secret_key_id = content_dict['secretKeyId']
        if not secret_key_id:
            logging.error("secretKeyId is empty")
            return False

        expected_secret_key_id = generate_16_char_from_random_num(self.source_hello_random, self.destination_hello_random)

        if secret_key_id != expected_secret_key_id:
            logging.error("secretKeyId does not match")
            return False

        self.secret_key_id = secret_key_id

        logging.info("Finished message processed successfully")
        return True

    def extract_public_key(self, did_document: Dict[str, Any], key_id: str) -> ec.EllipticCurvePublicKey:
        """Extract public key from DID document"""
        vm = did_document['verificationMethod']
        if vm['id'] == key_id and vm['type'] == "EcdsaSecp256r1VerificationKey2019":
            public_key_hex = vm['publicKeyHex']
            # Ensure public key starts with '04'
            if not public_key_hex.startswith('04'):
                logging.error(f"Public key must start with '04': {public_key_hex}")
                raise ValueError("Public key must start with '04'")

            public_key_bytes = bytes.fromhex(public_key_hex)  # Ensure conversion starts from the correct position
            return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key_bytes)

        raise ValueError(f"Public key not found in DID document {key_id}")

    # TODO: Capture exceptions and send error messages
    async def generate_short_term_key_active(self):

        await self.send_source_hello()

        self.state = "wait_destination_hello"

        if not self.destination_hello_message:
            try:
                # Wait for destination_hello message to arrive
                await asyncio.wait_for(self.event.wait(), timeout=10)
            except asyncio.TimeoutError:
                if not self.destination_hello_message:
                    logging.error("wait destination hello timeout!")
                    return False

        # Process destination_hello message
        if not self.process_destination_hello():
            return False

        self.generate_keys()

        await self.send_finished()

        # Update state
        self.state = "wait_finished"

        if not self.finished_message:
            try:
                # Wait for finished message to arrive
                await asyncio.wait_for(self.event.wait(), timeout=10)
            except asyncio.TimeoutError:
                logging.error("wait finished timeout!")
                return False

        if not self.process_finished():
            return False

        self.state = "finished"
        logging.info("generate_short_term_key_active, success")
        return True

    async def generate_short_term_key_passive(self):
        # self.source_hello_message = source_hello_json

        self.state = "init"

        if not self.process_source_hello():
            return False

        await self.send_destination_hello()

        self.generate_keys()

        await self.send_finished()

        # Update state
        self.state = "wait_finished"

        if not self.finished_message:
            try:
                # Wait for finished message to arrive
                await asyncio.wait_for(self.event.wait(), timeout=10)
            except asyncio.TimeoutError:
                logging.error("generate_short_term_key_passive wait finished timeout!")
                return False

        if not self.process_finished():
            return False

        self.state = "finished"
        logging.info("generate_short_term_key_passive, success")
        return True

