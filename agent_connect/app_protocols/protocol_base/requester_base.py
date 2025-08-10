# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

# requester base class
# Common interfaces for requester:
# 1. Send callback function
# 2. Receive data interface (non-async, using async event internally)
# 3. Method call interface, different methods and parameters based on protocol

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Optional, Awaitable
import asyncio

class RequesterBase(ABC):
    """Base class for protocol requesters"""
    
    def __init__(self):
        self._send_callback: Optional[Callable[[bytes], Awaitable[None]]] = None
        self.received_messages: list[bytes] = []
        self.messages_event = asyncio.Event()
        
    def set_send_callback(self, callback: Callable[[bytes], Awaitable[None]]) -> None:
        """Set async callback function for sending binary messages
        
        Args:
            callback: Async function that takes binary data (bytes) as input and sends 
                     it through the transport layer. The function should be a coroutine
                     and handle the actual sending mechanism and any potential errors.
                     Returns Awaitable.
        """
        self._send_callback = callback
    
    async def handle_message(self, message: bytes) -> None:
        """Handle received message, called by the class user
        
        Args:
            message: Received binary message data
        """
        self.received_messages.append(message)
        self.messages_event.set()

    @abstractmethod
    async def send_request(self, input: dict[str, Any]) -> dict[str, Any]:
        """Send request message 
        
        Args:
            input: Request input data
        Returns:
            dict: Request output data from response message
        """
        pass





