# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

# provider base class


from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, Optional, Awaitable

class ProviderBase(ABC):
    """Base class for protocol providers"""
    
    def __init__(self):
        self._send_callback: Optional[Callable[[bytes], Awaitable[None]]] = None
        self._protocol_callback: Optional[Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]] = None
        
    def set_send_callback(self, callback: Callable[[bytes], Awaitable[None]]) -> None:
        """Set async callback function for sending binary messages
        
        Args:
            callback: Async function that takes binary data (bytes) as input and sends 
                     it through the transport layer. The function should be a coroutine
                     and handle the actual sending mechanism and any potential errors.
                     Returns Awaitable.
        """
        self._send_callback = callback

    def set_protocol_callback(self, callback: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]]) -> None:
        """Set async callback function for handling protocol messages
        
        Args:
            callback: Async function that takes a dictionary (dict[str, Any]) as input and returns a dictionary (dict[str, Any]).
                      Input dictionary contains the received protocol message and other necessary data.
                      Output dictionary contains the processed result and other necessary data. It must include a code field
                      to identify the status code of the processing result, using HTTP status codes as values.
        """
        self._protocol_callback = callback
    
    @abstractmethod
    async def handle_message(self, message: bytes) -> None:
        """Handle received message, then call protocol callback function.
           if message is error, call send_callback to send error message.
        Args:
            message: Received binary message data
        """
        pass










