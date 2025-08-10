import json
import logging
import traceback
from typing import Any, Dict, Tuple
from uuid import UUID

from agent_connect.app_protocols.protocol_base.provider_base import ProviderBase


class EducationalBackgroundProvider(ProviderBase):
    """Protocol provider class for retrieving educational background information."""

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
                logging.error("Protocol callback not set")
                error_message = self._construct_error_message(500, "Internal server error", message_id)
                await self._send_callback(error_message)

        except Exception as e:
            logging.error(f"Failed to handle message: {str(e)}\nStack trace:\n{traceback.format_exc()}")
            error_message = self._construct_error_message(400, str(e))
            await self._send_callback(error_message)

    def _parse_message(self, message: bytes) -> Tuple[Dict[str, Any], str]:
        """Parse the received message from bytes to dict and extract messageId.

        Args:
            message: Received bytes message data.

        Returns:
            A tuple containing the parsed dictionary and messageId.

        Raises:
            ValueError: If message format is invalid or required parameters are missing.
        """
        try:
            message_dict = json.loads(message.decode("utf-8"))
            assert message_dict["messageType"] == "getUserEducation", "Invalid messageType"

            message_id = message_dict["messageId"]

            # Validate messageId format
            UUID(message_id, version=4)

            user_id = message_dict["userId"]
            include_details = message_dict.get("includeDetails", False)
            page = message_dict.get("page", 1)
            page_size = message_dict.get("pageSize", 10)

            # Construct the input dictionary for the callback
            callback_input_dict = {
                "userId": user_id,
                "includeDetails": include_details,
                "page": page,
                "pageSize": page_size,
            }

            return callback_input_dict, message_id

        except (KeyError, AssertionError, ValueError) as e:
            logging.error(f"Message format error: {str(e)}")
            raise ValueError("Invalid message format or missing parameters") from e

    def _construct_response_message(self, result: Dict[str, Any], message_id: str) -> bytes:
        """Construct a JSON response message from the callback result.

        Args:
            result: Result dictionary from the protocol callback.
            message_id: The original messageId from the request.

        Returns:
            A bytes response message.
        """
        response_dict = {
            "messageType": "getUserEducation",
            "messageId": message_id,
            "code": result["code"],
        }

        if "data" in result:
            response_dict["data"] = result["data"]
        if "pagination" in result:
            response_dict["pagination"] = result["pagination"]
        if "error" in result:
            response_dict["error"] = result["error"]

        return json.dumps(response_dict).encode("utf-8")

    def _construct_error_message(self, code: int, message: str, message_id: str = "") -> bytes:
        """Construct a JSON error message with the specified code and message.

        Args:
            code: HTTP status code to use for the error.
            message: Error message description.
            message_id: The original messageId from the request, if available.

        Returns:
            A bytes error message.
        """
        error_response = {
            "messageType": "getUserEducation",
            "messageId": message_id,
            "code": code,
            "error": {
                "message": message
            }
        }
        return json.dumps(error_response).encode("utf-8")