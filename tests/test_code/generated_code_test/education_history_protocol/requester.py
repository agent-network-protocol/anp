import asyncio
import json
import logging
from typing import Any, Dict
from uuid import uuid4

from agent_connect.app_protocols.protocol_base.requester_base import RequesterBase


class EducationHistoryRequester(RequesterBase):
    """Requester class for retrieving a user's education history."""

    async def send_request(self, input: Dict[str, Any]) -> Dict[str, Any]:
        """Send request to retrieve user education history.

        Constructs and sends a request message, waits for a response,
        and processes the response message.

        Args:
            input: Request input data containing 'user_id' and optionally
                   'include_details'.

        Returns:
            dict: A dictionary containing the response, including HTTP status
                  code and either education history records or error information.
        """
        # Validate input parameters
        user_id = input.get("user_id")
        include_details = input.get("include_details", False)

        if not isinstance(user_id, str) or len(user_id) < 1:
            logging.error("Validation failed: 'user_id' is required and must be a non-empty string.")
            return {"code": 400, "error": {"error_code": "INVALID_USER_ID", "error_description": "The provided user ID is invalid or not found."}}

        # Construct request message
        request_message = {
            "messageType": "EducationHistoryRequest",
            "messageId": str(uuid4()),
            "userId": user_id,
            "includeDetails": include_details
        }

        # Send request protocol
        try:
            await self._send_callback(json.dumps(request_message).encode('utf-8'))
        except Exception as e:
            logging.error(f"Failed to send the request: {str(e)}")
            return {"code": 500, "error": {"error_code": "REQUEST_SEND_ERROR", "error_description": "Failed to send the request."}}

        # Wait for response
        if not self.received_messages:
            try:
                await asyncio.wait_for(self.messages_event.wait(), timeout=15)
                self.messages_event.clear()
            except asyncio.TimeoutError:
                logging.error("Protocol negotiation timeout")
                return {"code": 504, "error": {"error_code": "TIMEOUT", "error_description": "Protocol negotiation timeout"}}

        # Process response
        response_message = self.received_messages.pop(0)
        try:
            response = json.loads(response_message.decode('utf-8'))
        except json.JSONDecodeError:
            logging.error("Received message format error")
            return {"code": 500, "error": {"error_code": "FORMAT_ERROR", "error_description": "Received message format error"}}

        # Handle response errors or return data
        if response.get("messageType") != "EducationHistoryResponse":
            logging.error("Unexpected message type received")
            return {"code": 500, "error": {"error_code": "UNEXPECTED_MESSAGE_TYPE", "error_description": "Unexpected message type received"}}

        response_code = response.get("code")
        if response_code != 200:
            error_info = response.get("error", {})
            return {
                "code": response_code,
                "error": {
                    "error_code": error_info.get("errorCode", "UNKNOWN_ERROR"),
                    "error_description": error_info.get("errorDescription", "An unknown error occurred.")
                }
            }

        # Extract education history
        education_history = response.get("educationHistory", [])
        return {
            "code": response_code,
            "education_history": [
                {
                    "institution": record["institution"],
                    "major": record["major"],
                    "degree": record["degree"],
                    "achievements": record.get("achievements", ""),
                    "start_date": record["startDate"],
                    "end_date": record["endDate"]
                } for record in education_history
            ]
        }