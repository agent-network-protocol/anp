import json
import logging
import traceback
from typing import Any, Optional
from uuid import UUID

from agent_connect.app_protocols.protocol_base.provider_base import ProviderBase


class EducationProtocolProvider(ProviderBase):
    """Provider class for retrieving educational background information for a user."""

    async def handle_message(self, message: bytes) -> None:
        """Handle received message, then call protocol callback function.

        Args:
            message: Received binary message data.
        """
        try:
            # Parse received message and convert to callback function dictionary parameters
            callback_input_dict, message_id = self._parse_message(message)

            # Call protocol callback function to handle business logic
            if self._protocol_callback:
                result = await self._protocol_callback(callback_input_dict)

                # Parse and construct response message based on callback return dictionary
                response_message = self._construct_response_message(result, message_id)

                # Send response
                if self._send_callback:
                    await self._send_callback(response_message)
                else:
                    logging.error("Send callback not set")
            else:
                logging.error("Protocol callback not set")
                error_message = self._construct_error_message(500, "Internal server error", message_id)
                if self._send_callback:
                    await self._send_callback(error_message)
        except (json.JSONDecodeError, TypeError, ValueError) as e:
            logging.error(f"Message format or parameter validation failure: {str(e)}")
            error_message = self._construct_error_message(400, "Invalid message format or parameters", None)
            if self._send_callback:
                await self._send_callback(error_message)
        except Exception as e:
            logging.error(f"Failed to handle message: {str(e)}\nStack trace:\n{traceback.format_exc()}")
            error_message = self._construct_error_message(500, "Internal server error", None)
            if self._send_callback:
                await self._send_callback(error_message)

    def _parse_message(self, message: bytes) -> tuple[dict[str, Any], Optional[str]]:
        """Parse the incoming message to expected format.

        Args:
            message: Received binary message data.

        Returns:
            A tuple containing the parsed message in dictionary form and a message ID.

        Raises:
            json.JSONDecodeError: When message is not valid JSON.
            ValueError: If message does not conform to the required structure.
        """
        try:
            request_data = json.loads(message.decode('utf-8'))
            assert request_data["messageType"] == "getUserEducation"
            message_id = request_data["messageId"]
            UUID(message_id)  # Validate UUID format
            # Prepare callback input dictionary
            callback_input_dict = {
                "user_id": request_data["userId"],
                "include_details": request_data.get("includeDetails", False),
                "page": request_data.get("page", 1),
                "page_size": request_data.get("pageSize", 10),
            }
            return callback_input_dict, message_id

        except (KeyError, AssertionError, ValueError) as e:
            raise ValueError(f"Invalid message structure: {str(e)}") from e

    def _construct_response_message(self, result: dict[str, Any], message_id: Optional[str]) -> bytes:
        """Construct the response message.

        Args:
            result: Result from the protocol callback, containing 'code', 'data', and optionally 'error_message'.
            message_id: Original message ID for pairing request and response.

        Returns:
            The constructed response message as bytes.
        """
        response = {
            "messageId": message_id,
            "code": result["code"],
        }
        if result["code"] == 200:
            response["data"] = result.get("data", {})
        else:
            response["error_message"] = result.get("error_message", "Unknown error occurred")

        return json.dumps(response).encode('utf-8')

    def _construct_error_message(self, code: int, error_message: str, message_id: Optional[str]) -> bytes:
        """Construct an error message.

        Args:
            code: The HTTP status code for the error.
            error_message: A descriptive error message.
            message_id: Original message ID for pairing request and response.

        Returns:
            The constructed error message as bytes.
        """
        error_response = {
            "messageId": message_id,
            "code": code,
            "error_message": error_message
        }
        return json.dumps(error_response).encode('utf-8')