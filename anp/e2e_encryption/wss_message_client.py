# AgentConnect: https://github.com/agent-network-protocol/AgentConnect
# Author: GaoWei Chang
# Email: chgaowei@gmail.com
# Website: https://agent-network-protocol.com/
#
# This project is open-sourced under the MIT License. For details, please see the LICENSE file.


import asyncio
import json
import logging
from datetime import datetime

import websockets
from cryptography.hazmat.primitives.asymmetric import ec

from anp.utils.crypto_tool import (
    generate_random_hex,
    generate_router_json,
    load_private_key_from_pem,
)


class WssMessageClient:
    def __init__(self, wss_url: str, api_key: str):
        self.wss_url = wss_url
        self.api_key = api_key
        self.websocket = None
        self.heartbeat_missed = 0
        self.heartbeat_task = None

    async def connect(self):
        """Connect to WebSocket server and authenticate using api_key"""
        try:
            # Prepare authentication header
            headers = {
                "Authorization": f"Bearer {self.api_key}"
            }
            self.websocket = await websockets.connect(self.wss_url, extra_headers=headers)
            self.heartbeat_missed = 0
            if self.heartbeat_task is not None:
                self.heartbeat_task.cancel()
            self.heartbeat_task = asyncio.create_task(self.send_heartbeat())
            logging.info(f"Connected to WebSocket at {self.wss_url} with authorization")
        except Exception as e:
            logging.error(f"Failed to connect to WebSocket: {e}")

    async def receive_data(self) -> dict:
        """Asynchronously receive data from WebSocket server and return parsed JSON dictionary"""
        while True:
            try:
                if self.websocket:
                    logging.info(f"Receiving WSS data: {id(self.websocket)}")
                    data = await self.websocket.recv()
                    json_data = json.loads(data)

                    msg_type = json_data.get("type")
                    if msg_type == "heartbeat" and json_data.get("message") == "pong":
                        self.heartbeat_missed = 0
                        continue

                    logging.info(f"Received[{id(self.websocket)}]: {json_data}")
                    return json_data
                else:
                    logging.warning("WebSocket not connected, attempting to reconnect...")
                    await self.connect()
            except websockets.exceptions.ConnectionClosed:
                logging.error("WebSocket connection closed.")
                self.websocket = None
                await self.connect()
            except json.JSONDecodeError:
                logging.error("Failed to decode JSON from received data.")
            except Exception as e:
                logging.error(f"Error receiving data: {e}")

    async def send_data(self, data: dict):
        """Asynchronously send data to WebSocket server"""
        if self.websocket:
            try:
                await self.websocket.send(json.dumps(data))
                logging.info(f"Data sent to {id(self.websocket)}: {data}")
            except Exception as e:
                logging.error(f"Failed to send data: {e}")
                self.websocket = None
                await self.connect()
        else:
            logging.warning("WebSocket not connected, attempting to reconnect...")
            await self.connect()

    async def send_heartbeat(self):
        """Send a heartbeat message to WebSocket server every 3 seconds"""
        while True:
            if self.websocket:
                message_id = generate_random_hex(16)
                heartbeat_message = {
                    "version": "1.0",
                    "type": "heartbeat",
                    "timestamp": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
                    "messageId": message_id,
                    "message": "ping"
                }
                await self.websocket.send(json.dumps(heartbeat_message))
                logging.info(f"Heartbeat sent: {heartbeat_message}")
                await asyncio.sleep(3)
                self.heartbeat_missed += 1
                if self.heartbeat_missed >= 3:
                    logging.warning("Heartbeat missed 3 times, attempting to reconnect...")
                    self.websocket = None
                    await self.connect()
            else:
                logging.warning("WebSocket not connected, attempting to reconnect...")
                await self.connect()

    async def register_routers(self, routers: list[tuple[str, str]]):
        if not self.websocket:
            await self.connect()

        routers_json: list[dict] = []
        for router in routers:
            private_key_pem, did_doc = router
            private_key: ec.EllipticCurvePrivateKey = load_private_key_from_pem(private_key_pem)
            router: dict = generate_router_json(private_key, json.loads(did_doc))
            routers_json.append(router)

            message_id = generate_random_hex(16)
            message_json = {
                "version": "1.0",
                "type": "register",
                "timestamp": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
                "messageId": message_id,
                "routers": routers_json
            }
            await self.websocket.send(json.dumps(message_json))

    async def close(self):
        """Close WebSocket connection"""
        if self.websocket:
            await self.websocket.close()
            logging.info("WebSocket connection closed")
