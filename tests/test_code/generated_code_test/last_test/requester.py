import asyncio
import json
import logging
import traceback
import uuid
from typing import Any, Dict

from agent_connect.app_protocols.protocol_base.requester_base import RequesterBase


class EducationalBackgroundRequester(RequesterBase):
    """Requester class for fetching user educational background"""

    async def send_request(self, input: Dict[str, Any]) -> Dict[str, Any]:
        """Send request to retrieve educational background information for a specified user.

        Args:
            input: Request input data containing keys 'user_id', 'include_details', 'page', and 'page_size'.

        Returns:
            A dictionary containing the HTTP status code and data or error message.
        """
        try:
            # Validate input parameters
            user_id = input.get("user_id")
            if not user_id:
                raise ValueError("Missing required parameter 'user_id'")

            include_details = input.get("include_details", False)
            page = input.get("page", 1)
            page_size = input.get("page_size", 10)
            if page < 1 or page_size < 1:
                raise ValueError("Parameters 'page' and 'page_size' must be greater than 0")

            # Construct request protocol
            request_message = self._construct_request_message(
                user_id=user_id,
                include_details=include_details,
                page=page,
                page_size=page_size
            )

            # Send request protocol
            await self._send_callback(request_message)

            # Wait for response
            if not self.received_messages:
                try:
                    await asyncio.wait_for(self.messages_event.wait(), timeout=15)
                    self.messages_event.clear()
                except asyncio.TimeoutError:
                    logging.error(f"Protocol negotiation timeout\nStack trace:\n{traceback.format_exc()}")
                    return {"code": 504, "error_message": "Protocol negotiation timeout"}

            # Process response
            response_message = self.received_messages.pop(0)
            return self._process_response_message(response_message)

        except ValueError as e:
            logging.error(f"Validation error: {e}")
            return {"code": 400, "error_message": str(e)}
        except Exception as e:
            logging.error(f"Unexpected error: {e}\nStack trace:\n{traceback.format_exc()}")
            return {"code": 500, "error_message": "Internal server error"}

    def _construct_request_message(self, user_id: str, include_details: bool, page: int, page_size: int) -> bytes:
        """Constructs request message in JSON format.

        Args:
            user_id: Unique identifier of the user.
            include_details: Flag to indicate if detailed information is required.
            page: Page number for pagination.
            page_size: Number of items per page.

        Returns:
            A bytes object representing the JSON request message.
        """
        request_data = {
            "messageType": "getUserEducation",
            "messageId": str(uuid.uuid4()),
            "userId": user_id,
            "includeDetails": include_details,
            "page": page,
            "pageSize": page_size
        }
        return json.dumps(request_data).encode("utf-8")

    def _process_response_message(self, message: bytes) -> Dict[str, Any]:
        """Processes the response message.

        Args:
            message: Received binary message data.

        Returns:
            A dictionary containing the response data.
        """
        try:
            response_data = json.loads(message.decode("utf-8"))

            if "code" not in response_data:
                raise ValueError("Response message missing 'code' field")

            if response_data["code"] != 200:
                return {
                    "code": response_data["code"],
                    "error_message": response_data.get("error_message", "Unknown error")
                }

            return {
                "code": 200,
                "data": response_data["data"]
            }

        except json.JSONDecodeError:
            logging.error("Failed to decode response message as JSON")
            return {"code": 400, "error_message": "Invalid response format"}
        except ValueError as e:
            logging.error(f"Response processing error: {e}")
            return {"code": 500, "error_message": "Internal server error"}