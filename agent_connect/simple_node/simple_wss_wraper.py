# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.

import json
import logging
from fastapi import WebSocket
import websockets
import asyncio
from abc import ABC, abstractmethod
from typing import Optional

class HeartbeatTimeoutError(Exception):
    pass

class ConnectionError(Exception):
    pass

class SimpleWssWraper(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def send_data(self, data: dict):
        pass

    @abstractmethod
    async def receive_data(self, timeout: float = 15.0) -> dict:
        pass

    @abstractmethod
    async def close(self):
        pass
    
class SimpleServerWssWraper(SimpleWssWraper):
    def __init__(self, websocket: WebSocket):
        super().__init__()
        self.websocket = websocket

    async def send_data(self, data: dict):
        """Send data to WebSocket."""
        if self.websocket:
            await self.websocket.send_text(json.dumps(data))
            logging.debug(f"Message content sent: {data}")
    
    async def receive_data(self, timeout: float = 15.0) -> dict:
        """Receive data from WebSocket with timeout."""
        if self.websocket:
            try:
                data = await asyncio.wait_for(self.websocket.receive_text(), timeout=timeout)
                json_data = json.loads(data)
                logging.debug(f"Message content received: {json_data}")
                return json_data
            except asyncio.TimeoutError:
                raise HeartbeatTimeoutError("Heartbeat timeout")
            except websockets.ConnectionClosed as e:
                logging.error(f"WebSocket connection closed: {e}")
                raise ConnectionError("WebSocket connection has been closed.")
            except json.JSONDecodeError as e:
                logging.error(f"Error parsing JSON data: {e}")
                return {}
        return {}

    async def close(self):
        """Close WebSocket connection."""
        if self.websocket:
            await self.websocket.close()
            logging.info("WebSocket connection closed")
            
class SimpleClientWssWraper(SimpleWssWraper):
    def __init__(self, websocket):
        super().__init__()
        self.websocket = websocket

    async def send_data(self, data: dict):
        """Send data to WebSocket."""
        if self.websocket:
            await self.websocket.send(json.dumps(data))
            logging.debug(f"Message content sent: {data}")

    async def receive_data(self, timeout: float = 15.0) -> dict:
        """Receive data from WebSocket with timeout."""
        try:
            if self.websocket:
                logging.debug(f"Receiving WSS data: {id(self.websocket)}")
                data = await asyncio.wait_for(self.websocket.recv(), timeout=timeout)
                json_data = json.loads(data)
                logging.debug(f"Message content received[{id(self.websocket)}]: {json_data}")
                return json_data
            else:
                logging.warning("WebSocket not connected")
                return {}
        except asyncio.TimeoutError:
            raise HeartbeatTimeoutError("Heartbeat timeout")
        except websockets.ConnectionClosed as e:
            logging.error(f"WebSocket connection closed: {e}")
            raise ConnectionError("WebSocket connection has been closed.")
        except json.JSONDecodeError:
            logging.error(f"Failed to parse received JSON data {data}.")
            return {}

    async def close(self):
        """Close WebSocket connection."""
        if self.websocket:
            await self.websocket.close()
            logging.info("WebSocket connection closed")
