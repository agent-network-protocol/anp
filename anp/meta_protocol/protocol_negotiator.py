# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.


import json
import logging
import traceback
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

from pydantic import BaseModel, Field

from anp.utils.llm.base_llm import BaseLLM

NEGOTIATION_INITIAL_SYSTEM_PROMPT = """
You are a protocol design expert. Your task is to design a communication protocol document based on given requirements and input/output descriptions.
The protocol document should be clear, complete, and follow standard specifications and industry best practices.

1. Please follow these requirements when designing protocol documents:
- Request and response formats should use JSON whenever possible, strictly following RFC8259 specification
  - Use JSON Schema (draft-2020-12) to describe data formats, clearly specify required and optional fields
  - Field names should follow camelCase and be concise and clear
  - Character encoding should consistently use UTF-8
- For special scenarios like efficient data transmission, other formats like binary can be used
- Please use request/response pattern to design the protocol

2. Request/Response Design Specifications:
- When protocol has multiple requests/responses, use messageType and messageId for distinction, response message's messageType and messageId should match request message's messageType and messageId
- Response messages must carry code field to distinguish between success and failure, using HTTP standard status codes

3. Error Handling Requirements:
- Use standard HTTP status codes
- Use 200 series status codes for successful responses
- Use 400 series status codes for client errors
- Use 500 series status codes for server errors
- Custom error codes can be used for special errors
- Provide clear error description messages

4. Please reply in markdown format, including the following sections, where optional sections can be omitted:
# Requirements
xxx

# Protocol Flow
## Interaction Flow
xxx

## State Transitions [Optional]
xxx

## Timeout Handling [Optional]
xxx

# Data Format
## Request Message Format
xxx

## Response Message Format
xxx

# Error Handling
xxx

"""

NEGOTIATION_EVALUATION_SYSTEM_PROMPT_FOR_PROVIDER = '''
You are a senior communication protocol negotiation expert. Your goal is to negotiate a protocol that both parties can accept for data communication. As a service provider, you aim to meet the service requester's needs as much as possible.

# Input Information
Your decision inputs include:
- requirement: Requirements are included in the Protocol content
- counterparty_latest_protocol: The latest protocol proposal from the counterparty
- your_previous_protocol: Your previous protocol proposal (if any)
- counterparty_modification_summary: Summary of modifications to the counterparty's protocol proposal (if your_previous_protocol exists)
- capability_info_history: List of previous capability information obtained from get_capability_info tool

# Decision Process
1. Compare the counterparty's protocol with your capabilities:
   - Review capability_info_history to understand your system limitations
   - Verify if you can meet all functional requirements
   - Check if the protocol design is implementable with your system

2. Evaluate data formats:
   Input Data Validation:
   - Verify if all required fields are present and complete
   - Validate if data types and formats are processable
   - Ensure field definitions match your system constraints

   Output Data Validation:
   - Verify if you can provide all required output fields
   - Check if any critical data fields are missing from requester's requirements
   - Ensure you have access to all data needed for output generation
   - Validate if output data types match requester's expectations

   Format Compatibility:
   - Check for any incompatible field definitions or data types
   - Verify character encoding compatibility
   - Validate size limits and data constraints

3. Review protocol design:
   - Assess if the protocol flow is feasible for implementation
   - Verify if error handling aligns with your system capabilities
   - Check if all edge cases can be handled by your system

4. Make decision:
   - ACCEPTED: if you can fully implement the protocol
   - REJECTED: if there are major capability mismatches
   - NEGOTIATING: if minor adjustments are needed (provide detailed modification suggestions)

# Decision Tools
You can use the get_capability_info tool to obtain your capability information, including:
- Whether you can meet the counterparty's requirements
- Whether the protocol data input is correct
- Whether the protocol data output is correct

# Output
Output format is NegotiationResult:
{
    "status": "negotiating/accepted/rejected",
    "candidate_protocol": "complete protocol content when status is negotiating, empty string otherwise",
    "modification_summary": "summary of your modifications or reasons for rejection"
}

Note: When status is "negotiating", candidate_protocol should contain the complete protocol content, not just the modifications. The modification_summary field is used to explain what changes were made and why.
'''


NEGOTIATION_EVALUATION_SYSTEM_PROMPT_FOR_REQUESTER = '''
You are a senior communication protocol negotiation expert. Your goal is to negotiate a protocol that both parties can accept for data communication. As a service requester, your goal is to have the service provider meet your requirements as much as possible.

# Input Information
Your decision inputs include:
- requirement: Your original requirements for the protocol
- input_description: Your expected input format description
- output_description: Your expected output format description
- counterparty_latest_protocol: The latest protocol proposal from the counterparty
- your_previous_protocol: Your previous protocol proposal (if any)
- counterparty_modification_summary: Summary of modifications to the counterparty's protocol proposal (if your_previous_protocol exists)

# Decision Process
1. Compare the counterparty's protocol with your original requirements:
   - Verify if all functional requirements are met
   - Check if the protocol design aligns with your specifications

2. Evaluate data formats:
   - Verify if input format matches your input_description
   - Verify if output format matches your output_description
   - Check for any missing or unnecessary fields

3. Review protocol design:
   - Assess if the protocol flow is logical and efficient
   - Verify error handling mechanisms
   - Check if all edge cases are properly handled

4. Make decision:
   - ACCEPTED: if the protocol fully meets your requirements
   - REJECTED: if there are major incompatibilities
   - NEGOTIATING: if minor modifications are needed (provide detailed modification suggestions)

# Output
Output format is NegotiationResult:
{
    "status": "negotiating/accepted/rejected",
    "candidate_protocol": "complete protocol content when status is negotiating, empty string otherwise",
    "modification_summary": "summary of your modifications or reasons for rejection"
}

Note: When status is "negotiating", candidate_protocol should contain the complete protocol content, not just the modifications. The modification_summary field is used to explain what changes were made and why.
'''

class NegotiationStatus(str, Enum):
    """Negotiation status enum"""
    NEGOTIATING = "negotiating"
    REJECTED = "rejected"
    ACCEPTED = "accepted"

class NegotiationResult(BaseModel):
    """Protocol negotiation result model"""
    status: NegotiationStatus = Field(
        description="Current status of the protocol negotiation process, type: NegotiationStatus"
    )
    candidate_protocol: str = Field(
        default="",
        description="Complete content of the proposed protocol, included when status is negotiating, empty otherwise"
    )
    modification_summary: Optional[str] = Field(
        default="",
        description="Summary of modifications made to the counterparty's protocol in candidate_protocol, included when status is negotiating, empty otherwise"
    )

class NegotiatorRole(str, Enum):
    """Negotiator role enum"""
    PROVIDER = "provider"
    REQUESTER = "requester"

class NegotiationHistoryEntry:
    """Represents a single entry in the negotiation history.

    Attributes:
        round: The negotiation round number
        candidate_protocols: The protocol proposal for this round
        modification_summary: Summary of modifications made to previous proposal
    """
    def __init__(
        self,
        round: int,
        candidate_protocols: str,
        modification_summary: Optional[str] = None
    ):
        self.round = round
        self.candidate_protocols = candidate_protocols
        self.modification_summary = modification_summary

class ProtocolNegotiator:
    """Protocol negotiator that uses LLM to assist in protocol negotiation.

    This class handles the negotiation process between service providers and requesters
    to establish a mutually acceptable communication protocol.

    Attributes:
        llm: LLM instance used for protocol generation and evaluation
        requirement: Protocol requirements in natural language
        input_description: Expected input format description
        output_description: Expected output format description
        negotiation_round: Current round number in the negotiation process
        negotiation_history: List of previous protocol proposals and modifications
        role: Role in negotiation (PROVIDER or REQUESTER)
        capability_info_history: History of capability information responses
        get_capability_info_callback: Callback function for checking provider capabilities
    """
    def __init__(
        self,
        llm: BaseLLM,
        get_capability_info_callback: Optional[Callable[
            [str, str, str],  # requirement, input_description, output_description
            Awaitable[str]    # return type
        ]] = None
    ):
        """Initialize the protocol negotiator.

        Args:
            llm: Base LLM instance for generating and evaluating protocols
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

                This callback is only used when acting as a provider.
        """
        self.llm: BaseLLM = llm
        self.requirement: str = ""
        self.input_description: str = ""
        self.output_description: str = ""
        self.negotiation_round: int = 0
        self.negotiation_history: list[NegotiationHistoryEntry] = []
        self.role: NegotiatorRole = NegotiatorRole.PROVIDER
        self.capability_info_history: list[str] = []
        self.get_capability_info_callback = get_capability_info_callback


    async def get_capability_info(self, requirement: str,
                                 input_description: str,
                                 output_description: str) -> str:
        """Get capability information from external callback function

        Args:
            requirement: Natural language description of protocol requirements
            input_description: Natural language description of expected input format
            output_description: Natural language description of expected output format

        Returns:
            Capability information as string, including:
            - Whether requirements can be met
            - Whether input data is correct, including field completeness, comprehensiveness, and type correctness
            - Whether output data is correct, including having expected field data, field type correctness, and presence of important fields

        Note:
            The callback function should return a string containing the capability assessment.
            If no callback is registered, returns empty string.
        """
        if self.get_capability_info_callback:
            try:
                return await self.get_capability_info_callback(
                    requirement,
                    input_description,
                    output_description
                )
            except Exception as e:
                logging.error(f"Get capability info callback failed: {str(e)}\nStack trace:\n{traceback.format_exc()}")
                return f"Error getting capability info: {str(e)}"
        return ""

    async def generate_initial_protocol(
        self,
        requirement: str,
        input_description: str,
        output_description: str
    ) -> Tuple[str, NegotiationStatus, int]:
        """Generate initial protocol proposal

        Returns:
            Tuple containing:
            - protocol: The generated protocol string
            - status: Negotiation status
            - round: Current negotiation round number
        """

        logging.info("Starting to generate initial protocol...")

        # Set role to REQUESTER when generating initial protocol
        self.role = NegotiatorRole.REQUESTER

        # Store parameters to instance variables
        self.requirement = requirement
        self.input_description = input_description
        self.output_description = output_description

        # Initialize negotiation round
        self.negotiation_round = 1

        system_prompt = NEGOTIATION_INITIAL_SYSTEM_PROMPT

        user_prompt = f'''
Please design a protocol with:

--[ requirement ]--
{requirement}
--[END]--

--[ input_description ]--
{input_description}
--[END]--

--[ output_description ]--
{output_description}
--[END]--

The protocol should be practical and implementable.'''

        try:
            protocol = await self.llm.async_generate_response(
                system_prompt=system_prompt,
                user_prompt=user_prompt
            )

            logging.info(f"Successfully generated initial protocol, current round: {self.negotiation_round}, protocol: {protocol}")

            self.negotiation_history.append(NegotiationHistoryEntry(
                round=self.negotiation_round,
                candidate_protocols=protocol,
                modification_summary=None
            ))

            return protocol, NegotiationStatus.NEGOTIATING, self.negotiation_round

        except Exception as e:
            logging.error(f"Failed to generate initial protocol: {str(e)}\nStack trace:\n{traceback.format_exc()}")
            return "", NegotiationStatus.REJECTED, self.negotiation_round

    # TODO: Need to callback externally to check if it meets the other party's requirements
    async def evaluate_protocol_proposal(
        self,
        negotiation_status: NegotiationStatus,
        counterparty_round: int,
        candidate_protocols: Optional[str] = None,
        modification_summary: Optional[str] = None,
    ) -> Tuple[NegotiationResult, int]:
        """Evaluate protocol proposal

        Args:
            negotiation_status: Current negotiation status
            candidate_protocols: Protocol proposal to evaluate
            modification_summary: Optional summary of modifications
            counterparty_round: Round number from counterparty

        Returns:
            Tuple containing:
                - NegotiationResult: Updated status and details
                - int: Current negotiation round number
        """
        logging.info(f"Starting protocol proposal evaluation: status={negotiation_status.name}, round={counterparty_round}")
        # Validate round number
        if counterparty_round is not None:
            expected_round = self.negotiation_round + 1
            if counterparty_round != expected_round:
                logging.error(f"Invalid round number. Expected {expected_round}, got {counterparty_round}")
                # TODO: Handle invalid round number, JUST PRINT FOR NOW
                # return NegotiationResult(
                #     status=NegotiationStatus.REJECTED,
                #     candidate_protocol="",
                #     modification_summary=f"Invalid round number. Expected {expected_round}, got {counterparty_round}"
                # ), self.negotiation_round

        # Handle terminal states
        if negotiation_status == NegotiationStatus.ACCEPTED:
            # Check if candidate protocols match the latest negotiation history
            if self.negotiation_history and candidate_protocols != self.negotiation_history[-1].candidate_protocols:
                logging.error(f"Protocol mismatch in ACCEPTED state. Latest history: {self.negotiation_history[-1].candidate_protocols}, \nreceived: {candidate_protocols}")

            # Return the latest protocol from history if available
            return NegotiationResult(
                status=NegotiationStatus.ACCEPTED,
                candidate_protocol=self.negotiation_history[-1].candidate_protocols if self.negotiation_history else candidate_protocols,
                modification_summary=None
            ), self.negotiation_round

        if negotiation_status == NegotiationStatus.REJECTED:
            return NegotiationResult(
                status=NegotiationStatus.REJECTED,
                candidate_protocol="",
                modification_summary=None
            ), self.negotiation_round

        result : NegotiationResult = None
        if self.role == NegotiatorRole.PROVIDER:
            result = await self._evaluate_as_provider(
                candidate_protocols, modification_summary)
        else:
            result = await self._evaluate_as_requester(
                candidate_protocols, modification_summary)

        return result, self.negotiation_round

    async def _evaluate_as_provider(
        self,
        candidate_protocols: str,
        modification_summary: Optional[str] = None
    ) -> NegotiationResult:
        """Provider-specific protocol evaluation"""
        logging.info("Starting provider-side protocol evaluation...")

        tools = [
            {
                "type": "function",
                "function": {
                    "name": "get_capability_info",
                    "description": "Get capability information to check if requirements can be met",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "requirement": {
                                "type": "string",
                                "description": "Protocol requirements description"
                            },
                            "input_description": {
                                "type": "string",
                                "description": "Protocol document description of request or input data, including fields, field formats, field descriptions, and whether they are required"
                            },
                            "output_description": {
                                "type": "string",
                                "description": "Protocol document description of response or output data, including fields, field formats, field descriptions, and whether they are required"
                            }
                        },
                        "required": ["requirement", "input_description", "output_description"]
                    }
                }
            }
        ]

        user_prompt = f'''
Please evaluate this protocol proposal:

--[ counterparty_latest_protocol ]--
{candidate_protocols}
--[END]--

--[ your_previous_protocol ]--
{self.negotiation_history[-1].candidate_protocols if self.negotiation_history else ""}
--[END]--

--[ counterparty_modification_summary ]--
{modification_summary if modification_summary else 'None'}
--[END]--

--[ capability_info_history ]--
{json.dumps(self.capability_info_history, indent=2)}
--[END]--'''

        try:
            # Initialize base messages
            messages = [
                {"role": "system", "content": NEGOTIATION_EVALUATION_SYSTEM_PROMPT_FOR_PROVIDER},
                {"role": "user", "content": user_prompt}
            ]

            while True:
                completion = await self.llm.client.chat.completions.create(
                    model=self.llm.model_name,
                    messages=messages,
                    tools=tools,
                    tool_choice="auto",
                    response_format={"type": "json_object"}
                )

                assistant_message = completion.choices[0].message

                # Add assistant message to conversation history
                messages.append({
                    "role": "assistant",
                    "content": assistant_message.content,
                    "tool_calls": assistant_message.tool_calls
                })

                # If no tool calls, process the final response
                if not assistant_message.tool_calls:
                    logging.info("LLM evaluation completed, no tool calls needed")
                    break

                # Handle tool calls
                for tool_call in assistant_message.tool_calls:
                    if tool_call.function.name == "get_capability_info":
                        logging.info("Calling capability info check tool...")
                        args = json.loads(tool_call.function.arguments)
                        capability_info = await self.get_capability_info(
                            args["requirement"],
                            args["input_description"],
                            args["output_description"]
                        )
                        self.capability_info_history.append(capability_info)
                        # Add tool response to messages
                        messages.append({
                            "role": "tool",
                            "content": str(capability_info),
                            "tool_call_id": tool_call.id
                        })

            self.negotiation_round += 2

            # Parse JSON response from assistant message
            if not assistant_message.content:
                raise ValueError("Received empty response from LLM")

            logging.info(f"Provider evaluation result: {assistant_message.content}")

            result_json = json.loads(assistant_message.content)

            result = self._parse_negotiation_result(result_json)
            if result.status == NegotiationStatus.ACCEPTED:
                result.candidate_protocol = candidate_protocols

            logging.info(f"Provider evaluation result: status={result.status.name}, round={self.negotiation_round}")

            if result.status == NegotiationStatus.NEGOTIATING:
                self.negotiation_history.append(NegotiationHistoryEntry(
                    round=self.negotiation_round,
                    candidate_protocols=result.candidate_protocol,
                    modification_summary=result.modification_summary
                ))

            return result

        except Exception as e:
            logging.error(f"Failed to evaluate protocol: {str(e)}\nStack trace:\n{traceback.format_exc()}")
            return NegotiationResult(
                status=NegotiationStatus.REJECTED,
                candidate_protocol="",
                modification_summary=f"Error during evaluation: {str(e)}"
            )

    async def _evaluate_as_requester(
        self,
        candidate_protocols: str,
        modification_summary: Optional[str] = None
    ) -> NegotiationResult:
        """Requester-specific protocol evaluation"""
        logging.info("Starting requester-side protocol evaluation...")

        user_prompt = f'''
Please evaluate this protocol proposal:

--[ requirement ]--
{self.requirement}
--[END]--

--[ input_description ]--
{self.input_description}
--[END]--

--[ output_description ]--
{self.output_description}
--[END]--

--[ counterparty_latest_protocol ]--
{candidate_protocols}
--[END]--

--[ your_previous_protocol ]--
{self.negotiation_history[-1].candidate_protocols if self.negotiation_history else ""}
--[END]--

--[ counterparty_modification_summary ]--
{modification_summary if modification_summary else 'None'}
--[END]--'''

        try:
            # Call LLM client directly
            response = await self.llm.client.chat.completions.create(
                model=self.llm.model_name,
                messages=[
                    {"role": "system", "content": NEGOTIATION_EVALUATION_SYSTEM_PROMPT_FOR_REQUESTER},
                    {"role": "user", "content": user_prompt}
                ],
                response_format={"type": "json_object"}
            )

            result_json = json.loads(response.choices[0].message.content)
            self.negotiation_round += 2

            result = self._parse_negotiation_result(result_json)
            if result.status == NegotiationStatus.ACCEPTED:
                result.candidate_protocol = candidate_protocols

            logging.info(f"Requester evaluation result: status={result.status.name}, round={self.negotiation_round}")

            if result.status == NegotiationStatus.NEGOTIATING:
                self.negotiation_history.append(NegotiationHistoryEntry(
                    round=self.negotiation_round,
                    candidate_protocols=result.candidate_protocol,
                    modification_summary=result.modification_summary
                ))

            return result

        except Exception as e:
            logging.error(f"Failed to evaluate protocol as requester: {str(e)}\nStack trace:\n{traceback.format_exc()}")
            return NegotiationResult(
                status=NegotiationStatus.REJECTED,
                candidate_protocol="",
                modification_summary=f"Error during evaluation: {str(e)}"
            )

    def _parse_negotiation_result(self, result_json: Dict[str, Any]) -> NegotiationResult:
        """Parse and validate negotiation result from JSON response

        Args:
            result_json: Raw JSON response from LLM

        Returns:
            NegotiationResult: Validated negotiation result

        Raises:
            ValueError: If required fields are missing or invalid
        """
        try:
            status_str = result_json.get("status")
            if not status_str:
                logging.warning("Status field missing in response, using REJECTED")
                status = NegotiationStatus.REJECTED
            else:
                status = NegotiationStatus(status_str.lower())

            return NegotiationResult(
                status=status,
                candidate_protocol=result_json.get("candidate_protocol", ""),
                modification_summary=result_json.get("modification_summary", "")
            )
        except ValueError as e:
            logging.error(f"Invalid negotiation result: {e}")
            return NegotiationResult(
                status=NegotiationStatus.REJECTED,
                candidate_protocol="",
                modification_summary=f"Error parsing result: {str(e)}"
            )


