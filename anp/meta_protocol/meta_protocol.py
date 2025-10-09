# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import asyncio
import json
import logging
import random
import string
import traceback
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from anp.meta_protocol.code_generator.code_generator import (
    ProtocolCodeGenerator,
)
from anp.meta_protocol.protocol_negotiator import (
    NegotiationStatus,
    ProtocolNegotiator,
)
from anp.utils.llm.base_llm import BaseLLM


class ProtocolType(Enum):
    """Protocol type enum"""
    META = 0        # Meta protocol for negotiation
    APPLICATION = 1 # Application protocol for data transfer
    NATURAL = 2     # Natural language protocol
    VERIFICATION = 3 # Verification protocol


class MetaProtocol:
    """Meta protocol implementation for protocol negotiation"""

    def __init__(
        self,
        send_callback: Optional[Callable[[bytes], Awaitable[None]]] = None,
        get_capability_info_callback: Optional[Callable[[str, str, str], Awaitable[str]]] = None,
        llm: Optional[BaseLLM] = None,
        protocol_code_path: Optional[str] = None  # Path for generated code
    ):
        """Initialize MetaProtocol

        Args:
            send_callback: Optional async callback function for sending data.
                         The callback takes bytes data as parameter and returns None.
                         If not provided, sending functionality will be disabled.
            get_capability_info_callback: Optional async callback function that checks
                provider's capability to implement a protocol. The callback takes three
                string parameters:
                - requirement: Protocol requirements description
                - input_description: Expected input format description
                - output_description: Expected output format description

                The callback should return a string containing capability assessment,
                including:
                - Whether the provider can meet the requirements
                - Whether the input format is processable
                - Whether the output format can be generated
                - Any limitations or constraints
            llm: Optional LLM instance for protocol negotiation
        """
        self.max_negotiation_rounds = 10
        self.negotiation_timeout_seconds = 60
        self.code_generation_timeout_seconds = 60
        self.send_callback = send_callback
        self.get_capability_info_callback = get_capability_info_callback
        self.llm = llm
        self.protocol_code_path = protocol_code_path  # Store code generation path
        self.negotiator: Optional[ProtocolNegotiator] = None
        self.negotiation_messages = []
        self.negotiation_messages_event = asyncio.Event()
        self.code_generation_messages = []
        self.code_generation_messages_event = asyncio.Event()

    async def send_data(self, data: bytes) -> None:
        """Send data using the callback function

        Args:
            data: Bytes data to be sent

        Raises:
            RuntimeError: If send_callback is not set
        """
        if not self.send_callback:
            raise RuntimeError("Send callback not set")
        await self.send_callback(data)

    def handle_meta_data(self, data: bytes) -> None:
        """Handle received meta protocol data

        Args:
            data: Received bytes data. First byte contains protocol type in first 2 bits:
                - 00: Meta protocol for negotiation
                - 01: Application protocol for data transfer
                - 10: Natural language protocol
                - 11: Verification protocol
                Remaining 6 bits are reserved. Rest of data is protocol-specific content.

        This method decodes the received data and processes it based on the action type.
        Supported actions:
        - protocolNegotiation: Handle protocol negotiation messages
        - codeGeneration: Handle code generation status messages
        - testCasesNegotiation: Handle test cases negotiation messages
        - fixErrorNegotiation: Handle error fixing negotiation messages
        - naturalLanguageNegotiation: Handle natural language communication messages
        """
        try:
            # Extract protocol type from first byte
            protocol_type = data[0] >> 6  # Get first 2 bits

            # Verify this is meta protocol data (type 00)
            if protocol_type != ProtocolType.META.value:
                logging.error(f"Invalid protocol type for meta data: {protocol_type}")
                return

            # Parse remaining data as JSON, skipping first byte
            json_data = json.loads(data[1:].decode('utf-8'))
            logging.info(f"Meta Protocol Received message: {json_data}")
            action = json_data.get("action")

            if action == "protocolNegotiation":
                self._handle_protocol_negotiation(json_data)
            elif action == "codeGeneration":
                self._handle_code_generation(json_data)
            elif action == "testCasesNegotiation":
                self._handle_test_cases_negotiation(json_data)
            elif action == "fixErrorNegotiation":
                self._handle_fix_error_negotiation(json_data)
            elif action == "naturalLanguageNegotiation":
                self._handle_natural_language_negotiation(json_data)
            else:
                logging.error(f"Unknown action type: {action}")

        except json.JSONDecodeError as e:
            stack_trace = traceback.format_exc()
            logging.error(f"Failed to decode JSON data: {str(e)}\nStack trace:\n{stack_trace}")
        except Exception as e:
            stack_trace = traceback.format_exc()
            logging.error(f"Error handling meta data: {str(e)}\nStack trace:\n{stack_trace}")

    async def negotiate_protocol(self, requirement: str,
                               input_description: str,
                               output_description: str) -> Tuple[bool, str]:
        """Negotiate protocol and generate code implementation

        Args:
            requirement: Natural language description of protocol requirements
            input_description: Description of expected input format
            output_description: Description of expected output format

        Returns:
            Tuple containing:
            - is_success: Whether negotiation and code generation succeeded
            - module_path: Path to generated code (if successful)
        """
        logging.info("Starting protocol negotiation")
        logging.info(f"Requirement: {requirement}")
        logging.info(f"Input description: {input_description}")
        logging.info(f"Output description: {output_description}")

        # Initialize protocol negotiator
        self.negotiator = ProtocolNegotiator(
            llm=self.llm,
            get_capability_info_callback=self.get_capability_info_callback
        )

        # Clear message queue
        self.negotiation_messages.clear()
        self.negotiation_messages_event.clear()

        # Generate initial protocol proposal
        protocol, status, round_num = await self.negotiator.generate_initial_protocol(
            requirement=requirement,
            input_description=input_description,
            output_description=output_description
        )

        # Create and send initial message
        message = self._create_protocol_negotiation_message(
            sequence_id=round_num,
            candidate_protocols=protocol,
            status=status
        )

        await self._send_message(message)

        success, protocol = await self._process_negotiation_messages()
        if not success:
            return False, ""

        # Generate code implementation
        if self.protocol_code_path and self.llm:
            try:
                code_generator = ProtocolCodeGenerator(
                    llm=self.llm,
                    protocol_doc=protocol,
                    output_path=self.protocol_code_path
                )
                success, module_path = await code_generator.generate()
                if success:
                    return True, module_path
                else:
                    logging.error("Code generation failed")
                    return False, ""
            except Exception as e:
                logging.error(f"Failed to generate code: {str(e)}\n{traceback.format_exc()}")
                return False, ""

        return False, ""


    async def wait_remote_negotiation(self) -> Tuple[bool, str]:
        """Wait for remote negotiation and generate code implementation

        Returns:
            Tuple containing:
            - is_success: Whether negotiation and code generation succeeded
            - module_path: Path to generated code (if successful)
        """
        logging.info("Starting protocol negotiation")

        # Initialize protocol negotiator
        self.negotiator = ProtocolNegotiator(
            llm=self.llm,
            get_capability_info_callback=self.get_capability_info_callback
        )

        # Clear message queue
        self.negotiation_messages.clear()
        self.negotiation_messages_event.clear()

        success, protocol = await self._process_negotiation_messages()
        if not success:
            return False, ""

        # Generate code implementation
        if self.protocol_code_path and self.llm:
            try:
                code_generator = ProtocolCodeGenerator(
                    llm=self.llm,
                    protocol_doc=protocol,
                    output_path=self.protocol_code_path
                )
                success, module_path = await code_generator.generate()
                if success:
                    return True, module_path
                else:
                    logging.error("Code generation failed")
                    return False, ""
            except Exception as e:
                logging.error(f"Failed to generate code: {str(e)}\n{traceback.format_exc()}")
                return False, ""

        return False, ""

    async def notify_code_generation(self) -> None:
        """Notify that code generation has been completed."""
        message = self._create_code_generation_message(success=True)
        await self._send_message(message)

    async def wait_for_code_generation(self) -> bool:
        """Wait for the remote side to send code generation status.

        Returns:
            True if code generation succeeded, False otherwise
        """
        while True:
            try:
                if not self.code_generation_messages:
                    # Wait for negotiation messages with timeout
                    await asyncio.wait_for(self.code_generation_messages_event.wait(), timeout=self.code_generation_timeout_seconds)
                    # Clear event for next wait
                    self.code_generation_messages_event.clear()

                if self.code_generation_messages:
                    message = self.code_generation_messages.pop(0)
                    if message.get("action") == "codeGeneration":
                        logging.info("Received code generation status: %s", message.get("status"))
                        self.code_generation_messages_event.clear()
                        return True
            except asyncio.TimeoutError:
                logging.error("Timeout waiting for code generation messages")
                return False

    def _handle_protocol_negotiation(self, data: Dict[str, Any]) -> None:
        """Handle protocol negotiation messages by adding to queue

        Args:
            data: Protocol negotiation message data
        """
        self.negotiation_messages.append(data)
        # Set event to notify waiting coroutines
        self.negotiation_messages_event.set()

    def _handle_code_generation(self, data: Dict[str, Any]) -> None:
        """Handle code generation status messages

        Args:
            data: Code generation message data containing:
                - status: Generation status (generated/error)
        """
        self.code_generation_messages.append(data)
        self.code_generation_messages_event.set()

    def _handle_test_cases_negotiation(self, data: Dict[str, Any]) -> None:
        """Handle test cases negotiation messages

        Args:
            data: Test cases message data containing:
                - testCases: Test cases description
                - modificationSummary: Optional modification summary
                - status: Negotiation status
        """
        # TODO: Implement test cases negotiation handling
        pass

    def _handle_fix_error_negotiation(self, data: Dict[str, Any]) -> None:
        """Handle error fixing negotiation messages

        Args:
            data: Error fixing message data containing:
                - errorDescription: Error description
                - status: Negotiation status
        """
        # TODO: Implement error fixing negotiation handling
        pass

    def _handle_natural_language_negotiation(self, data: Dict[str, Any]) -> None:
        """Handle natural language communication messages

        Args:
            data: Natural language message data containing:
                - type: Message type (REQUEST/RESPONSE)
                - messageId: Unique message identifier
                - message: Natural language message content
        """
        # TODO: Implement natural language communication handling
        pass

    async def _process_negotiation_messages(self) -> Tuple[bool, str]:
        """Process protocol negotiation messages and handle the negotiation flow

        Returns:
            Tuple containing:
            - is_success: Whether the negotiation was successful
            - protocol: Agreed protocol content if successful, empty string if failed
        """
        while True:
            if not self.negotiation_messages:
                try:
                    # Wait for new message with timeout
                    await asyncio.wait_for(self.negotiation_messages_event.wait(), timeout=self.negotiation_timeout_seconds)
                    # Clear event for next wait
                    self.negotiation_messages_event.clear()
                except asyncio.TimeoutError:
                    stack_trace = traceback.format_exc()
                    logging.error(f"Protocol negotiation timeout\nStack trace:\n{stack_trace}")
                    return False, ""

            logging.info("Start processing negotiation messages")
            while self.negotiation_messages:
                data = self.negotiation_messages.pop(0)
                logging.info(f"Processing negotiation message: {data}")

                if not self.negotiator:
                    logging.error("Protocol negotiator not initialized")
                    return False, ""

                # Extract message fields
                sequence_id = data.get("sequenceId")
                candidate_protocols = data.get("candidateProtocols", "")
                modification_summary = data.get("modificationSummary", "")
                status = NegotiationStatus(data.get("status", NegotiationStatus.NEGOTIATING.value))

                # Evaluate protocol proposal
                result, current_round = await self.negotiator.evaluate_protocol_proposal(
                    negotiation_status=status,
                    counterparty_round=sequence_id,
                    candidate_protocols=candidate_protocols,
                    modification_summary=modification_summary
                )

                if result.status == NegotiationStatus.NEGOTIATING:
                    response = self._create_protocol_negotiation_message(
                        sequence_id=current_round,
                        candidate_protocols=result.candidate_protocol,
                        modification_summary=result.modification_summary,
                        status=result.status
                    )
                    await self._send_message(response)
                elif result.status == NegotiationStatus.REJECTED:
                    # 发送拒绝消息
                    response = self._create_protocol_negotiation_message(
                        sequence_id=current_round,
                        candidate_protocols=result.candidate_protocol,
                        modification_summary=result.modification_summary,
                        status=result.status
                    )
                    await self._send_message(response)
                    return False, ""
                elif result.status == NegotiationStatus.ACCEPTED:
                    # 发送接受消息
                    response = self._create_protocol_negotiation_message(
                        sequence_id=current_round,
                        candidate_protocols=result.candidate_protocol,
                        modification_summary=result.modification_summary,
                        status=result.status
                    )
                    await self._send_message(response)
                    return True, result.candidate_protocol

        logging.error("Protocol negotiation failed")
        return False, ""

    async def _send_message(self, message: Dict[str, Any], protocol_type: ProtocolType = ProtocolType.META) -> None:
        """Send encoded message with protocol header

        Args:
            message: Message dictionary to send
            protocol_type: Protocol type, defaults to META

        Raises:
            RuntimeError: If send_callback is not set
        """

        logging.info(f"Meta Protocol Sending message[protocol_type={protocol_type}]: {message}")

        header = self._encode_protocol_header(protocol_type)
        message_bytes = json.dumps(message).encode('utf-8')
        await self.send_data(header + message_bytes)

    def _encode_protocol_header(self, protocol_type: ProtocolType) -> bytes:
        """Encode protocol header

        Args:
            protocol_type: Protocol type enum value

        Returns:
            Encoded header bytes
        """
        # Protocol type uses first 2 bits, remaining 6 bits are reserved
        header = protocol_type.value << 6
        return bytes([header])

    def _decode_protocol_header(self, header_byte: bytes) -> ProtocolType:
        """Decode protocol header

        Args:
            header_byte: Header byte to decode

        Returns:
            Decoded protocol type
        """
        protocol_type = header_byte[0] >> 6
        return ProtocolType(protocol_type)

    def _create_protocol_negotiation_message(
        self,
        sequence_id: int,
        candidate_protocols: str,
        modification_summary: Optional[str] = None,
        status: NegotiationStatus = NegotiationStatus.NEGOTIATING
    ) -> Dict[str, Any]:
        """Create protocol negotiation message

        Args:
            sequence_id: Negotiation sequence ID
            candidate_protocols: Candidate protocols description
            modification_summary: Optional modification summary
            status: Negotiation status

        Returns:
            Protocol negotiation message dict
        """
        message = {
            "action": "protocolNegotiation",
            "sequenceId": sequence_id,
            "candidateProtocols": candidate_protocols,
            "status": status.value
        }
        if modification_summary:
            message["modificationSummary"] = modification_summary
        return message

    def _create_code_generation_message(self, success: bool = True) -> Dict[str, str]:
        """Create code generation message

        Args:
            success: Whether code generation succeeded

        Returns:
            Code generation message dict
        """
        return {
            "action": "codeGeneration",
            "status": "generated" if success else "error"
        }

    def _create_test_cases_message(
        self,
        test_cases: str,
        modification_summary: Optional[str] = None,
        status: NegotiationStatus = NegotiationStatus.NEGOTIATING
    ) -> Dict[str, Any]:
        """Create test cases negotiation message

        Args:
            test_cases: Test cases description
            modification_summary: Optional modification summary
            status: Negotiation status

        Returns:
            Test cases message dict
        """
        message = {
            "action": "testCasesNegotiation",
            "testCases": test_cases,
            "status": status.value
        }
        if modification_summary:
            message["modificationSummary"] = modification_summary
        return message

    def _create_fix_error_message(
        self,
        error_description: str,
        status: NegotiationStatus = NegotiationStatus.NEGOTIATING
    ) -> Dict[str, str]:
        """Create fix error negotiation message

        Args:
            error_description: Error description
            status: Negotiation status

        Returns:
            Fix error message dict
        """
        return {
            "action": "fixErrorNegotiation",
            "errorDescription": error_description,
            "status": status.value
        }

    def _create_natural_language_message(
        self,
        message: str,
        is_request: bool = True
    ) -> Dict[str, str]:
        """Create natural language negotiation message

        Args:
            message: Natural language message content
            is_request: Whether this is a request message

        Returns:
            Natural language message dict
        """
        # Generate random 16 char message ID
        message_id = ''.join(random.choices(string.ascii_letters + string.digits, k=16))

        return {
            "action": "naturalLanguageNegotiation",
            "type": "REQUEST" if is_request else "RESPONSE",
            "messageId": message_id,
            "message": message
        }














