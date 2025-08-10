import json
import logging
import traceback
from typing import Any, Dict, Optional

from agent_connect.app_protocols.protocol_base.provider_base import ProviderBase


class EducationHistoryProvider(ProviderBase):
    """A class managing the retrieval of user education history through protocol interactions."""

    def __init__(self) -> None:
        """Initializes the EducationHistoryProvider."""
        super().__init__()

    async def handle_message(self, message: bytes) -> None:
        """Handle received message, then call protocol callback function.

        Args:
            message: Received binary message data
        """
        try:
            # Parse received message and convert to callback function dictionary parameters
            callback_input_dict, message_id = self._parse_message(message)

            # Check if protocol callback function is set
            if self._protocol_callback:
                # Call protocol callback function to handle business logic
                result = await self._protocol_callback(callback_input_dict)

                # Parse and construct response message based on callback return dictionary
                response_message = self._construct_response_message(result, message_id)

                # Send response
                if self._send_callback:
                    await self._send_callback(response_message)
            else:
                logging.error("Protocol callback not set")
                error_message = self._construct_error_message(500, "Internal server error", message_id)
                await self._send_callback(error_message)

        except Exception as e:
            logging.error(f"Failed to handle message: {str(e)}\nStack trace:\n{traceback.format_exc()}")
            error_message = self._construct_error_message(400, str(e), None)
            if self._send_callback:
                await self._send_callback(error_message)

    def _parse_message(self, message: bytes) -> (Dict[str, Any], str):
        """Parse the incoming message and extract relevant fields.

        Args:
            message: Received binary message data

        Returns:
            A tuple containing a dictionary to pass to the callback and the extracted messageId.

        Raises:
            ValueError: If message parsing fails or the input is invalid.
        """
        try:
            message_dict = json.loads(message.decode('utf-8'))
            if not isinstance(message_dict, dict):
                raise ValueError("Message is not a valid dictionary")

            # Validate required fields
            if 'messageType' not in message_dict or message_dict['messageType'] != "EducationHistoryRequest":
                raise ValueError("Invalid or missing messageType")

            message_id = message_dict.get('messageId')
            if not message_id:
                raise ValueError("Missing messageId")

            user_id = message_dict.get('userId')
            if not user_id:
                raise ValueError("Missing userId")

            include_details = message_dict.get('includeDetails', False)

            return {
                "userId": user_id,
                "includeDetails": include_details
            }, message_id

        except (ValueError, json.JSONDecodeError) as e:
            logging.error(f"Error parsing message: {str(e)}")
            raise ValueError("Message format error")

    def _construct_response_message(
            self, result: Dict[str, Any], message_id: Optional[str]) -> bytes:
        """Construct a response message from the result dictionary.

        Args:
            result: Dictionary containing callback processing result.
            message_id: The request messageId to include in the response.

        Returns:
            A binary response message.
        """
        response = {
            "messageType": "EducationHistoryResponse",
            "messageId": message_id,
            "code": result.get("code", 500)
        }

        # Add education history or error to the response based on result code
        if response["code"] == 200:
            response["educationHistory"] = result.get("educationHistory", [])
        else:
            response["error"] = result.get("error", {
                "errorCode": "UNKNOWN_ERROR",
                "errorDescription": "Unknown error occurred"
            })

        return json.dumps(response).encode('utf-8')

    def _construct_error_message(self, code: int, error_description: str, message_id: Optional[str]) -> bytes:
        """Construct an error message response.

        Args:
            code: HTTP status code for the error.
            error_description: Description of the error.
            message_id: The request messageId to include in the response, if present.

        Returns:
            A binary error message.
        """
        error_response = {
            "messageType": "EducationHistoryResponse",
            "messageId": message_id,
            "code": code,
            "error": {
                "errorCode": "ERROR_CODE",
                "errorDescription": error_description
            }
        }
        return json.dumps(error_response).encode('utf-8')