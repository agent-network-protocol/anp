# anpChat - LLM-Driven Chat Agent under ANP Protocol

A distributed chat system based on ANP (Agent Network Protocol) and LLM, featuring two communicating agents (ChatA and ChatB) with message generation and dialogue management driven by large language models.

## Project Overview

**anpChat** is a decentralized chat application example utilizing the ANP protocol, demonstrating how two AI agents can securely communicate through DID (Decentralized Identifier) authentication and integrate LLM models to achieve intelligent dialogue.

### Core Features

- **ANP Protocol Support**: Built on the ANP framework using DID authentication
- **LLM-Driven**: Integrated with OpenAI-compatible interfaces (defaults to DeepSeek model)
- **Distributed Architecture**: Two independent FastAPI services running on ports 8000 and 8001
- **Asynchronous Communication**: Efficient message handling based on async/await
- **Ed25519 Signature Support**: Fixed ANP library compatibility with Ed25519 keys

## Project Structure

```
anpChat/
├── ChatA.py          # Chat Agent A - Passively receives and responds to messages
├── ChatB.py          # Chat Agent B - Proactively initiates conversations
├── did_a.json        # Agent A's DID document
├── did_b.json        # Agent B's DID document
├── private_a.pem     # Agent A's private key file
├── private_b.pem     # Agent B's private key file
└── README.md         # This file
```

## Quick Start

### Requirements

- Python 3.8+
- pip or conda

### Install Dependencies

```bash
pip install fastapi uvicorn openai cryptography anp
```

### Environment Configuration

Set the LLM API key:

```bash
export OPENAI_KEY="your-api-key"
export OPENAI_API_BASE="https://api.deepseek.com"  # Optional, defaults to OpenAI
```

### Start Services

**Start Chat Agent A** (port 8000):
```bash
python ChatA.py
```

**Start Chat Agent B** (port 8001):
```bash
python ChatB.py
```

ChatB will automatically discover ChatA and initiate a 4-round conversation 2 seconds after startup.

## API Endpoints

### Chat Agent A (Port 8000) 
| Endpoint | Method | Description | |------|------|------|
| `/` | GET | View the status information of Agent A |
| `/health` | GET | Health check |
| `/a/ad.json` | GET | ANP advertisement (DID document) |
| `/a` | POST | ANP interface endpoint | 
**Status Example:** ```json
{
"name": "Chat Agent A",
"did": "did:wba:example.com:chata",
"endpoint": "/a",
"status": "running",
"messages_received": 5
}
```

### Chat Agent B (Port 8001) 
| Endpoint | Method | Description | |------|------|------|
| `/` | GET | View the status information of Agent B |
| `/health` | GET | Health check |
| `/b/ad.json` | GET | ANP advertisement (DID document) | 
**Status Example:** ```json
{
"name": "Chat Agent B",
"did": "did:wba:example.com:chatb",
"endpoint": "/b",
"status": "running",
"messages_sent": 4
}
```

## Workflow 
1. **Startup**: ChatA and ChatB respectively start FastAPI services on their own ports.
2. **Discovery**: After startup, ChatB attempts to discover ChatA (via the `/a/ad.json` endpoint).
3. **Initialization**: ChatB uses an LLM to generate an initial greeting message.
4. **Dialogue Loop**:
- ChatB generates a message and sends it to ChatA.
- ChatA responds using an LLM.
- ChatB receives the response and continues the dialogue.
- The loop continues until the specified number of rounds is reached or the connection fails. 
## Core Classes and Methods 
### ChatAgentA

```python
class ChatAgentA:
def _llm_reply(self, user_message: str) -> str
# Generate Responses Using LLM 
async def receive_message(self, message: str, remaining_turns: int) -> dict
# ANP Interface Method, Receives Messages and Returns Responses ```

### ChatAgentB

```python
class ChatAgentB:
def _llm_generate(self, prompt: str) -> str
# Generate New Messages Using LLM 
async def start_model_driven_chat(self, turns: int = 4)
# Initiate Model-Driven Dialogue Session 
async def ensure_chat_a_connection(self)
# Ensure the connection with ChatA ```

## Key Implementation Details 
### LLM Integration 
Both agents support integration with APIs compatible with OpenAI: 
- **ChatA**: Passive mode, generates responses after receiving messages
- **ChatB**: Active mode, generates messages and sends them to ChatA 
### DID Authentication 
Use `DIDWbaAuthHeader` for DID-based authentication: 
```python
auth = DIDWbaAuthHeader(
did_document_path="./did_a.json",
private_key_path="./private_a.pem"
)
```

### Ed25519 Compatibility Fix 
The project includes a compatibility patch for ANP library Ed25519 key signatures. 
```python
def _sign_callback_compat(self, content: bytes, method_fragment: str) -> bytes:
private_key = self._load_private_key()
if isinstance(private_key, Ed25519PrivateKey):
return private_key.sign(content)
return private_key.sign(content, ec.ECDSA(hashes.SHA256()))
```

## Configuration Instructions 
### Environment Variables 
| Variable | Description | Default Value | |------|------|--------|
| `OPENAI_KEY` | LLM API Key | None (Must be set) |
| `OPENAI_API_BASE` | LLM API Base URL | OpenAI Official API | 
### Model Configuration 
The current default model used is `deepseek-chat`, and it can be changed by modifying the `MODEL_NAME` variable in the code. 
## Frequently Asked Questions 
**Q: ChatB cannot detect ChatA**
- A: Make sure ChatA is running and listening on port 8000, and check the firewall settings. 
**Q: LLM call failed**
- A: Check if the `OPENAI_KEY` environment variable is set correctly and ensure that the API key is valid. 
**Q: DID authentication error**
- A: Ensure that the files `did_a.json`, `did_b.json`, `private_a.pem`, and `private_b.pem` exist and are in the correct format. 
## Expansion and Customization 
### Modify the number of dialogue rounds 
In the startup function of [ChatB.py](ChatB.py#L194), modify the `turns` parameter: 
```python
asyncio.create_task(chat_agent_b.start_model_driven_chat(turns=10))
```

### Custom System Prompt Words 
Modify the `system_prompt` in [ChatA.py](ChatA.py#L63) and [ChatB.py](ChatB.py#L70). 
```python
system_prompt = "Your custom prompt word" ```

Integrating Different LLMs 
Just modify the `_get_client()` method and the related API call parameters. 
## License 
MIT License

## Contribution 
Welcome to submit Issues and Pull Requests! 
---

**Last updated**: January 15, 2026