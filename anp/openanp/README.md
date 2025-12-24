# OpenANP SDK

Modern ANP (Agent Network Protocol) SDK for Python.

## Design Philosophy

- **SDK, Not Framework**: Provides capabilities, doesn't force implementation
- **P2P First**: Every agent is both client and server
- **Immutability**: Core data structures use frozen dataclass
- **Fail Fast**: Exceptions thrown immediately, no success/error wrappers
- **Type Safe**: Full type hints and Protocol definitions
- **OpenRPC 1.3.2 Compliant**: Strict adherence to OpenRPC specification

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      Your Agent                         │
├─────────────────────────────────────────────────────────┤
│  Server (expose methods)  │  Client (call remote)       │
│  - @anp_agent decorator   │  - RemoteAgent.discover()   │
│  - @interface decorator   │  - agent.call() / agent.x() │
│  - .router() → FastAPI    │  - fetch() + call_rpc()     │
└─────────────────────────────────────────────────────────┘
                            │
                      ANP Protocol
                            │
┌─────────────────────────────────────────────────────────┐
│                    Remote Agents                        │
├─────────────────────────────────────────────────────────┤
│  Server (expose methods)  │  Client (call remote)       │
│  - @anp_agent decorator   │  - RemoteAgent.discover()   │
│  - @interface decorator   │  - agent.call() / agent.x() │
│  - .router() → FastAPI    │  - fetch() + call_rpc()     │
└─────────────────────────────────────────────────────────┘
```

## Quick Start

### Client: Call Remote Agents

```python
from anp.openanp import RemoteAgent
from anp.authentication import DIDWbaAuthHeader

# Setup authentication (DID-WBA)
auth = DIDWbaAuthHeader(
    did_document_path="/path/to/did-doc.json",
    private_key_path="/path/to/private-key.pem",
)

# Discover agent from ad.json (fetches interface.json automatically)
agent = await RemoteAgent.discover("https://hotel.example.com/ad.json", auth)

# Inspect available methods
print(f"Agent: {agent.name}")
print(f"Methods: {agent.method_names}")  # ('search', 'book')

# Call methods - dynamic access
result = await agent.search(query="Tokyo")

# Or explicit call
result = await agent.call("search", query="Tokyo")

# Get OpenAI tools format
tools = agent.tools
```

### Server: Expose Methods

```python
from fastapi import FastAPI
from anp.openanp import anp_agent, interface, AgentConfig

@anp_agent(AgentConfig(
    name="Hotel Service",
    did="did:wba:example.com:hotel",
    prefix="/hotel",
))
class HotelAgent:
    @interface
    async def search(self, query: str) -> dict:
        """Search for hotels."""
        return {"results": [{"name": "Tokyo Hotel", "price": 100}]}

    @interface
    async def book(self, hotel_id: str, date: str) -> dict:
        """Book a hotel room."""
        return {"booking_id": "12345", "status": "confirmed"}

app = FastAPI()
app.include_router(HotelAgent.router())

# Automatically generates:
# - GET /hotel/ad.json (JSON-LD Agent Description)
# - GET /hotel/interface.json (OpenRPC 1.3.2)
# - POST /hotel/rpc (JSON-RPC 2.0)
```

### P2P: Both Client and Server

```python
from anp.openanp import anp_agent, interface, AgentConfig, RemoteAgent
from anp.authentication import DIDWbaAuthHeader

@anp_agent(AgentConfig(
    name="Travel Agent",
    did="did:wba:example.com:travel",
    prefix="/travel",
))
class TravelAgent:
    def __init__(self, auth: DIDWbaAuthHeader | None = None):
        self.auth = auth

    @interface
    async def plan_trip(self, destination: str) -> dict:
        """I'm a server - expose this method to others."""
        if not self.auth:
            raise ValueError("Auth required for client calls")

        # I'm also a client - discover and call other agents
        hotel = await RemoteAgent.discover(
            "http://localhost:8000/hotel/ad.json",
            self.auth
        )

        # Inspect discovered methods
        print(f"Hotel methods: {hotel.method_names}")

        # Call remote methods
        hotels = await hotel.search(query=destination)

        return {"destination": destination, "hotels": hotels}

# Setup for server mode
app = FastAPI()
app.include_router(TravelAgent().router())  # No auth needed for server

# Setup for client mode
auth = DIDWbaAuthHeader(
    did_document_path="/path/to/did-doc.json",
    private_key_path="/path/to/private-key.pem",
)
travel_with_auth = TravelAgent(auth)
```

## Discovery Flow

OpenANP follows the ANP protocol discovery flow:

```
1. Client requests ad.json (Agent Description)
   ↓
2. Parse ad.json (JSON-LD format with @context, @type)
   - Extract agent metadata (name, DID)
   - Find interface URLs
   ↓
3. Fetch interface.json from URL (OpenRPC 1.3.2)
   - Parse methods (ContentDescriptor format)
   - Extract RPC endpoint URLs
   ↓
4. Create RemoteAgent proxy
   - Dynamic method access: agent.method_name()
   - Validates parameters against schema
   ↓
5. Call methods via JSON-RPC 2.0
   - POST to RPC endpoint
   - DID-WBA authentication
```

**Key Points:**
- Discovery happens once, calls are direct
- Fail Fast: No fallbacks, clear errors
- Type-safe: Schema validation from OpenRPC
- Immutable: RemoteAgent is frozen after discovery

## Low-Level API

For more control, use pure functions directly:

```python
import json
from anp.openanp.client import fetch, call_rpc, parse_agent_document

# Fetch and parse agent document
text = await fetch("https://hotel.example.com/ad.json", auth)
ad = json.loads(text)
agent_data, methods = parse_agent_document(ad)

# If no embedded methods, fetch interface.json
if not methods:
    interface_url = ad["interfaces"][0]["url"]
    interface_text = await fetch(interface_url, auth)
    interface_data = json.loads(interface_text)
    # Parse OpenRPC methods...

# Call RPC directly
result = await call_rpc(
    "https://hotel.example.com/hotel/rpc",
    "search",
    {"query": "Tokyo"},
    auth,
)
```

## API Reference

### Client

| Export | Description |
|--------|-------------|
| `RemoteAgent` | High-level client for remote agents |
| `Method` | Method definition (name, params, rpc_url) |
| `fetch` | HTTP fetch with DID-WBA auth |
| `call_rpc` | JSON-RPC 2.0 call |
| `parse_agent_document` | Parse AD document |
| `parse_openrpc` | Parse OpenRPC document |
| `convert_to_openai_tool` | Convert method to OpenAI tool format |
| `HttpError` | HTTP request failed |
| `RpcError` | JSON-RPC error response |

### Server

| Export | Description |
|--------|-------------|
| `@anp_agent` | Decorator to define an ANP agent |
| `@interface` | Decorator to expose a method via JSON-RPC |
| `AgentConfig` | Agent configuration |
| `create_agent_router` | Create FastAPI router from config |
| `create_simple_agent_router` | Simplified router creation |

### Utilities

| Export | Description |
|--------|-------------|
| `generate_ad_document` | Generate Agent Description document |
| `generate_rpc_interface` | Generate OpenRPC interface |
| `type_to_json_schema` | Convert Python type to JSON Schema |

### AP2/ANP methods

Use the same `@interface` decorator and set `protocol="AP2/ANP"` to mark payment endpoints. The OpenRPC generator will emit `x-protocol` for these methods—no separate `generate_ap2_interface` step is needed.

```python
from anp.openanp import anp_agent, interface, AgentConfig

@anp_agent(AgentConfig(name="Tourism", did="did:wba:example.com:tourism"))
class TourismAgent:
    @interface(
        protocol="AP2/ANP",
        params_schema={"type": "object", "properties": {"cart_id": {"type": "string"}}},
        result_schema={"type": "object", "properties": {"status": {"type": "string"}}},
    )
    async def cart_mandate(self, cart_id: str):
        ...
```

## RemoteAgent

Immutable handle to a discovered remote agent.

```python
@dataclass(frozen=True)
class RemoteAgent:
    url: str                      # AD URL
    name: str                     # Agent name
    description: str              # Agent description
    methods: tuple[Method, ...]   # Available methods

    @classmethod
    async def discover(cls, ad_url: str, auth: DIDWbaAuthHeader) -> RemoteAgent:
        """Discover agent. Raises if no methods found."""

    @property
    def method_names(self) -> tuple[str, ...]:
        """Available method names."""

    @property
    def tools(self) -> list[dict]:
        """OpenAI Tools format."""

    async def call(self, method: str, **params) -> Any:
        """Call method by name."""

    # Dynamic access: agent.search(query="...")
    def __getattr__(self, name: str) -> Callable
```


## Error Handling

Fail Fast design - exceptions raised immediately:

```python
from anp.openanp.client import HttpError, RpcError

try:
    agent = await RemoteAgent.discover(url, auth)
    result = await agent.search(query="Tokyo")
except HttpError as e:
    print(f"HTTP {e.status}: {e} (url: {e.url})")
except RpcError as e:
    print(f"RPC {e.code}: {e} (data: {e.data})")
except ValueError as e:
    print(f"Discovery failed: {e}")
except KeyError as e:
    print(f"Invalid schema: missing {e}")  # Trust upstream failed
```

## Protocol Formats

### ad.json - Agent Description (JSON-LD)

```json
{
  "@context": {
    "@vocab": "https://schema.org/",
    "did": "https://w3id.org/did#",
    "ad": "https://agent-network-protocol.com/ad#"
  },
  "@type": "ad:AgentDescription",
  "@id": "https://hotel.example.com/hotel/ad.json",
  "protocolType": "ANP",
  "protocolVersion": "1.0.0",
  "name": "Hotel Service",
  "did": "did:wba:example.com:hotel",
  "description": "Hotel booking service",
  "securityDefinitions": {
    "didwba_sc": {
      "scheme": "didwba",
      "in": "header",
      "name": "Authorization"
    }
  },
  "security": "didwba_sc",
  "interfaces": [
    {
      "type": "StructuredInterface",
      "protocol": "openrpc",
      "url": "https://hotel.example.com/hotel/interface.json"
    }
  ]
}
```

### interface.json - OpenRPC 1.3.2

```json
{
  "openrpc": "1.3.2",
  "info": {
    "title": "Hotel Service API",
    "version": "1.0.0"
  },
  "methods": [
    {
      "name": "search",
      "description": "Search for hotels",
      "params": [
        {
          "name": "query",
          "schema": {"type": "string"},
          "required": true
        }
      ],
      "result": {
        "name": "result",
        "schema": {"type": "object"}
      }
    }
  ],
  "servers": [
    {
      "name": "Hotel Service Server",
      "url": "https://hotel.example.com/hotel/rpc"
    }
  ],
  "securityDefinitions": {
    "didwba_sc": {
      "scheme": "didwba",
      "in": "header",
      "name": "Authorization"
    }
  },
  "security": "didwba_sc"
}
```

**Key Features:**
- `params`: Array of ContentDescriptor objects (name, schema, required)
- `result`: Single ContentDescriptor object (name, schema)
- Automatic type extraction from Python type hints
- DID-WBA security scheme



## License

MIT License
