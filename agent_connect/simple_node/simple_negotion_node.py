# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import asyncio
import logging
import traceback
from typing import Awaitable, Callable, List, Optional, Tuple, Union

from agent_connect.app_protocols import AppProtocols, ProviderBase, RequesterBase
from agent_connect.meta_protocol import MetaProtocol, ProtocolType
from agent_connect.simple_node import SimpleNode, SimpleNodeSession
from agent_connect.utils.llm.base_llm import BaseLLM


class MessageReceiverTask:
    def __init__(self, simple_session: SimpleNodeSession, meta_protocol: MetaProtocol):
        self.simple_session = simple_session
        self.meta_protocol = meta_protocol  # Store meta protocol instance
        self.app_protocol_handler: Optional[Union[RequesterBase, ProviderBase]] = None
        self.receive_message_coroutine: Optional[asyncio.Task] = None
        self.app_messages_queue: List[bytes] = []

        self._start_receiving()

    async def set_app_protocol_handler(self, app_protocol_handler: Union[RequesterBase, ProviderBase]):
        self.app_protocol_handler = app_protocol_handler
        if self.app_messages_queue:
            while self.app_messages_queue:
                message = self.app_messages_queue.pop(0)  # 取出一个消息
                await self.app_protocol_handler.handle_message(message)

    async def receive_message_task(self):
        """Receive messages from the session and handle them."""
        try:
            while True:
                message = await self.simple_session.receive_message()
                protocol_type = message[0] >> 6  # Extract protocol type from the first byte
                if protocol_type == ProtocolType.META.value:
                    self.meta_protocol.handle_meta_data(message)
                elif protocol_type == ProtocolType.APPLICATION.value:
                    if self.app_protocol_handler:
                        await self.app_protocol_handler.handle_message(message)
                    else: # if app protocol handler is not set, save the message to app messages queue
                        self.app_messages_queue.append(message)
                else:
                    logging.error(f"Invalid protocol type: {protocol_type}")
        except asyncio.CancelledError:
            logging.info(f"Receive message task cancelled. remote did: {self.simple_session.remote_did}")
        except Exception as e:
            stack_trace = traceback.format_exc()
            logging.error(f"Receive message task exception: {e}, remote did: {self.simple_session.remote_did}\nStack trace:\n{stack_trace}")

    def _start_receiving(self):
        """Start the message receiving coroutine."""
        if self.receive_message_coroutine is None:
            self.receive_message_coroutine = asyncio.create_task(self.receive_message_task())
            logging.info(f"Started message receiving task. remote did: {self.simple_session.remote_did}")

    def cancel(self):
        """Cancel the message receiving coroutine."""
        if self.receive_message_coroutine:
            self.receive_message_coroutine.cancel()
            logging.info(f"Cancelled message receiving task. remote did: {self.simple_session.remote_did}")
            self.receive_message_coroutine = None

class RequesterSession():
    def __init__(self,
                 meta_protocol: MetaProtocol,
                 protocol_hash: str,
                 requester_instance: RequesterBase,
                 send_request_description: Optional[dict],
                 simple_session: SimpleNodeSession,
                 message_receiver_task: Optional[MessageReceiverTask]):
        self.meta_protocol = meta_protocol
        self.protocol_hash = protocol_hash
        self.requester_instance = requester_instance
        self.send_request_description = send_request_description
        self.simple_session = simple_session
        self.message_receiver_task = message_receiver_task
        self.remote_did = simple_session.remote_did

    def __del__(self):
        """Clean up resources when the instance is deleted."""
        if self.message_receiver_task:
            self.message_receiver_task.cancel()
            logging.info("Cancelled MessageReceiverTask.")

    async def code_generated(self) -> bool:
        '''
        Notify the remote side that code generation has been completed , and wait for the remote side to confirm.

        Returns:
            True if remote side confirms code generation succeeded, False otherwise
        '''
        await self.meta_protocol.notify_code_generation()
        return await self.meta_protocol.wait_for_code_generation()


class ProviderSession():
    def __init__(self,
                 meta_protocol: MetaProtocol,
                 protocol_hash: str,
                 provider_instance: ProviderBase,
                 protocol_callback_description: Optional[dict],
                 simple_session: SimpleNodeSession,
                 message_receiver_task: MessageReceiverTask):
        self.meta_protocol = meta_protocol
        self.protocol_hash = protocol_hash
        self.provider_instance = provider_instance
        self.protocol_callback_description = protocol_callback_description
        self.simple_session = simple_session
        self.message_receiver_task = message_receiver_task
        self.remote_did = simple_session.remote_did

    def __del__(self):
        """Clean up resources when the instance is deleted."""
        if self.message_receiver_task:
            self.message_receiver_task.cancel()
            logging.info("Cancelled MessageReceiverTask.")

    async def code_generated(self) -> bool:
        '''
        Notify the remote side that code generation has been completed , and wait for the remote side to confirm.

        Returns:
            True if remote side confirms code generation succeeded, False otherwise
        '''
        await self.meta_protocol.notify_code_generation()
        return await self.meta_protocol.wait_for_code_generation()


class SimpleNegotiationNode():
    def __init__(self,
                 host_domain: str,
                 host_port: str = "",
                 host_ws_path: str = "/ws",  # Default WebSocket path is /ws
                 llm: Optional[BaseLLM] = None,
                 protocol_code_path: Optional[str] = None,
                 new_provider_session_callback: Optional[Callable[[ProviderSession], Awaitable[None]]] = None,
                 get_capability_info_callback: Optional[Callable[[str, str, str], Awaitable[str]]] = None,
                 private_key_pem: Optional[str] = None,
                 did: Optional[str] = None,
                 did_document_json: Optional[str] = None,
                 ssl_cert_path: Optional[str] = None,
                 ssl_key_path: Optional[str] = None):
        '''
        Initialize SimpleNegotiationNode
        '''
        self.simple_node = SimpleNode(host_domain=host_domain,
                                      new_session_callback=self._new_session_callback,
                                      host_port=host_port,
                                      host_ws_path=host_ws_path,
                                      private_key_pem=private_key_pem,
                                      did=did,
                                      did_document_json=did_document_json,
                                      ssl_cert_path=ssl_cert_path,
                                      ssl_key_path=ssl_key_path)
        self.did = did
        self.app_protocols = AppProtocols(protocol_paths=[protocol_code_path])
        self.protocol_code_path: Optional[str] = protocol_code_path  # Store protocol code path
        self.llm: Optional[BaseLLM] = llm  # Store LLM instance
        self.get_capability_info_callback: Optional[Callable[[str, str, str], Awaitable[str]]] = get_capability_info_callback  # Store capability info callback
        self.new_provider_session_callback: Optional[Callable[[ProviderSession], Awaitable[None]]] = new_provider_session_callback  # Store new provider session callback

    async def _new_session_callback(self, simple_session: SimpleNodeSession) -> None:
        meta_protocol = MetaProtocol(
            send_callback=simple_session.send_message,
            get_capability_info_callback=self.get_capability_info_callback,
            llm=self.llm,
            protocol_code_path=self.protocol_code_path
        )

        message_receiver_task = MessageReceiverTask(simple_session=simple_session, meta_protocol=meta_protocol)

        # wait for remote negotiation
        success, module_path = await meta_protocol.wait_remote_negotiation()

        # load app protocol code
        protocol_hash = self.app_protocols.load_protocol(module_path)
        provider_class, protocol_callback_description = self.app_protocols.get_provider_by_hash(protocol_hash)
        provider_instance: ProviderBase = provider_class()

        provider_instance.set_send_callback(simple_session.send_message)
        await message_receiver_task.set_app_protocol_handler(provider_instance)

        # provider_instance.set_protocol_callback(app_protocol_callback)

        provider_session = ProviderSession(meta_protocol=meta_protocol,
                                protocol_hash=protocol_hash,
                                provider_instance=provider_instance,
                                protocol_callback_description=protocol_callback_description,
                                simple_session=simple_session,
                                message_receiver_task=message_receiver_task)

        if self.new_provider_session_callback:
            await self.new_provider_session_callback(provider_session)

    async def connect_to_did_with_negotiation(self,
                             destination_did: str,
                             requirement: str,
                             input_description: str,
                             output_description: str) -> Optional[RequesterSession]:

        simple_session: SimpleNodeSession = await self.simple_node.connect_to_did(destination_did)
        if not simple_session:
            logging.error(f"Failed to connect to {destination_did}")
            return None

        meta_protocol = MetaProtocol(
            send_callback=simple_session.send_message,
            get_capability_info_callback=self.get_capability_info_callback,
            llm=self.llm,
            protocol_code_path=self.protocol_code_path
        )

        message_receiver_task = MessageReceiverTask(simple_session=simple_session, meta_protocol=meta_protocol)

        success, module_path = await meta_protocol.negotiate_protocol(requirement=requirement,
                                                                  input_description=input_description,
                                                                  output_description=output_description)
        if not success:
            logging.error(f"Failed to negotiate protocol for {destination_did}")
            return None

        # load app protocol code
        protocol_hash = self.app_protocols.load_protocol(module_path)
        requester_class, send_request_description = self.app_protocols.get_requester_by_hash(protocol_hash)
        requester_instance: RequesterBase = requester_class()

        requester_instance.set_send_callback(simple_session.send_message)
        await message_receiver_task.set_app_protocol_handler(requester_instance)

        return RequesterSession(meta_protocol=meta_protocol,
                                protocol_hash=protocol_hash,
                                requester_instance=requester_instance,
                                send_request_description=send_request_description,
                                simple_session=simple_session,
                                message_receiver_task=message_receiver_task)

    # TODO: Not supported yet, to be implemented
    async def connect_to_did_with_protocol(self,
                             destination_did: str,
                             protocol_hash: str) -> Optional[RequesterSession]:

        simple_session: SimpleNodeSession = await self.simple_node.connect_to_did(destination_did, protocol_hash=protocol_hash)
        if not simple_session:
            logging.error(f"Failed to connect to {destination_did}")
            return None

        meta_protocol = MetaProtocol(
            send_callback=simple_session.send_message,
            get_capability_info_callback=self.get_capability_info_callback,
            llm=self.llm,
            protocol_code_path=self.protocol_code_path
        )

        message_receiver_task = MessageReceiverTask(simple_session=simple_session, meta_protocol=meta_protocol)

        # load app protocol code
        requester_class, send_request_description = self.app_protocols.get_requester_by_hash(protocol_hash)
        requester_instance: RequesterBase = requester_class()

        requester_instance.set_send_callback(simple_session.send_message)
        await message_receiver_task.set_app_protocol_handler(requester_instance)

        return RequesterSession(meta_protocol=meta_protocol,
                                protocol_hash=protocol_hash,
                                requester_instance=requester_instance,
                                send_request_description=send_request_description,
                                simple_session=simple_session,
                                message_receiver_task=message_receiver_task)

    def generate_did_document(self) -> Tuple[str, str, str]:
        '''
        Generate DID document
        Note: This method does not automatically call set_did_info.
        Note: private_key_pem is a very important value, please keep it safe.

        Returns:
            Tuple[str, str, str]: A tuple containing private key in PEM format, DID string, and DID document JSON string.
        '''
        return self.simple_node.generate_did_document()

    def set_did_info(self, private_key_pem: str, did: str, did_document_json: str) -> None:
        '''
        Set private key PEM, DID, and DID document JSON.

        Args:
            private_key_pem (str): Private key in PEM format.
            did (str): DID string.
            did_document_json (str): DID document in JSON format.
        '''
        self.did = did
        self.simple_node.set_did_info(private_key_pem, did, did_document_json)

    def run(self):
        self.simple_node.run()

    async def stop(self):
        await self.simple_node.stop()
