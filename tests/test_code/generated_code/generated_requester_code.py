import asyncio
import json
import logging
from typing import Any
from uuid import uuid4

from agent_connect.app_protocols.protocol_base.requester_base import RequesterBase


class EducationBackgroundRequester(RequesterBase):
    """Requester class for retrieving user educational background information."""

    def __init__(self) -> None:
        """Initialize the EducationBackgroundRequester with default settings."""
        super().__init__()
        logging.basicConfig(level=logging.DEBUG)

    async def send_request(self, input: dict[str, Any]) -> dict[str, Any]:
        """Send a request to retrieve educational background information for a specified user.

        Args:
            input: Request input data including 'user_id', 'include_details', 'page', and 'page_size'.

        Returns:
            dict: Request output data from the response message.
        """
        request_message = self._construct_request_message(input)
        await self._send_callback(request_message)

        if not self.received_messages:
            try:
                await asyncio.wait_for(self.messages_event.wait(), timeout=15)
                self.messages_event.clear()
            except asyncio.TimeoutError:
                logging.error("Protocol negotiation timeout.")
                return {"code": 504, "error_message": "Protocol negotiation timeout"}

        response = self._process_response()
        return response

    def _construct_request_message(self, input: dict[str, Any]) -> bytes:
        """Construct the request message format as per protocol documentation.

        Args:
            input: A dictionary containing request parameters.

        Returns:
            bytes: JSON-encoded request message.
        """
        message = {
            "messageType": "getUserEducation",
            "messageId": str(uuid4()),
            "userId": input["user_id"],
            "includeDetails": input.get("include_details", False),
            "page": input.get("page", 1),
            "pageSize": input.get("page_size", 10),
        }
        request_message = json.dumps(message).encode()
        logging.debug(f"Constructed request message: {request_message}")
        return request_message

    def _process_response(self) -> dict[str, Any]:
        """Process the first received message as a response and return the result.

        Returns:
            dict: Parsed response data from the message.
        """
        message = self.received_messages.pop(0)
        logging.debug(f"Processing response message: {message}")

        try:
            response = json.loads(message.decode())
            if 'code' not in response:
                raise ValueError("Response is missing 'code' field.")
            return self._parse_response(response)
        except (json.JSONDecodeError, ValueError) as e:
            logging.error(f"Failed to decode or validate response: {e}")
            return {"code": 500, "error_message": "Internal response processing error"}

    def _parse_response(self, response: dict) -> dict:
        """Parse the response message to extract useful data or error messages.

        Args:
            response: The response message dictionary.

        Returns:
            dict: Parsed response including either data or error information.
        """
        if response.get("code") == 200:
            return {
                "code": 200,
                "data": response.get("data", []),
                "pagination": response.get("pagination", {}),
            }
        else:
            error_info = response.get("error", {})
            return {
                "code": response.get("code"),
                "error": {
                    "message": error_info.get("message", "Unknown error"),
                    "details": error_info.get("details", ""),
                }
            }