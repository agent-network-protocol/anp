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
│  - @information decorator │  - ANPClient (anp_crawler)  │
│  - .router() → FastAPI    │                             │
│  - Context injection      │                             │
└─────────────────────────────────────────────────────────┘
                            │
                      ANP Protocol
                            │
┌─────────────────────────────────────────────────────────┐
│                    Remote Agents                        │
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

# Get OpenAI tools format (for LLM integration)
tools = agent.tools
```

### Server: Expose Methods with Context

```python
from fastapi import FastAPI
from anp.openanp import anp_agent, interface, AgentConfig, Context, Information

@anp_agent(AgentConfig(
    name="Hotel Service",
    did="did:wba:example.com:hotel",
    prefix="/hotel",
    description="Hotel booking service",
))
class HotelAgent:
    # Static Information definitions
    informations = [
        Information(
            type="VideoObject",
            description="Hotel tour",
            url="https://cdn.example.com/tour.mp4",
        ),
        Information(
            type="Contact",
            description="Hotel contact info",
            mode="content",
            content={"phone": "+1-234-567"},
        ),
    ]

    @interface  # Default: content mode (embedded in interface.json)
    async def search(self, query: str) -> dict:
        """Search for hotels."""
        return {"results": [{"name": "Tokyo Hotel", "price": 100}]}

    @interface  # With Context injection
    async def search_with_session(self, query: str, ctx: Context) -> dict:
        """Search with session tracking."""
        # ctx.did - caller's DID
        # ctx.session - session for this DID
        # ctx.request - FastAPI Request
        ctx.session.set("last_query", query)
        return {"results": [...], "user": ctx.did}

    @interface(mode="link")  # Link mode: separate interface file
    async def book(self, hotel_id: str, date: str) -> dict:
        """Book a hotel room."""
        return {"booking_id": "12345", "status": "confirmed"}

app = FastAPI()
app.include_router(HotelAgent.router())

# Automatically generates:
# - GET /hotel/ad.json (with Informations)
# - GET /hotel/interface.json (content mode methods)
# - GET /hotel/interface/book.json (link mode methods)
# - POST /hotel/rpc (JSON-RPC 2.0)
```

### P2P: Both Client and Server

```python
from anp.openanp import anp_agent, interface, AgentConfig, Context, RemoteAgent
from anp.authentication import DIDWbaAuthHeader

@anp_agent(AgentConfig(
    name="Travel Agent",
    did="did:wba:example.com:travel",
    prefix="/travel",
))
class TravelAgent:
    def __init__(self, auth: DIDWbaAuthHeader):
        self.auth = auth

    @interface
    async def plan_trip(self, destination: str, ctx: Context) -> dict:
        """Plan a trip - I'm both server and client."""
        # Track in session
        ctx.session.set("destination", destination)

        # Discover and call hotel agent (client mode)
        hotel = await RemoteAgent.discover(
            "http://localhost:8000/hotel/ad.json",
            self.auth
        )

        hotels = await hotel.search(query=destination)
        return {
            "destination": destination,
            "hotels": hotels,
            "planner_did": ctx.did,
        }

# Create with auth for client calls
auth = DIDWbaAuthHeader(...)
travel_agent = TravelAgent(auth)
app.include_router(travel_agent.router())
```

## Features

### Interface Modes

Two modes for how methods appear in ad.json:

```python
# Content mode (default): embedded in single interface.json
@interface
async def search(self, query: str) -> dict:
    ...

# Link mode: separate interface file per method
@interface(mode="link")
async def book(self, hotel_id: str) -> dict:
    ...
```

### Context Injection

Automatic Context injection for session/DID access:

```python
from anp.openanp import Context

@interface
async def method(self, param: str, ctx: Context) -> dict:
    # Session management (based on caller's DID)
    ctx.session.set("key", "value")
    value = ctx.session.get("key")

    # Caller identification
    print(f"Called by: {ctx.did}")

    # Access raw request
    headers = ctx.request.headers

    return {"user": ctx.did}
```

### Information Definitions

Two ways to define Information (metadata for ad.json):

```python
from anp.openanp import Information, information

@anp_agent(config)
class MyAgent:
    # Static definitions
    informations = [
        Information(type="Product", description="...", path="/products.json", file="data/products.json"),
        Information(type="Contact", description="...", mode="content", content={"phone": "..."}),
    ]

    # Dynamic definitions via decorator
    @information(type="Product", description="Today's availability", path="/availability.json")
    def get_availability(self) -> dict:
        return {"available": self.db.get_available()}

    @information(type="Service", description="Specials", mode="content")
    def get_specials(self) -> dict:
        return {"specials": [...]}
```

### Custom ad.json

Use `generate_ad()` for complete customization:

```python
from anp.openanp import generate_ad
from anp.openanp.utils import resolve_base_url

router = HotelAgent.router()

@router.get("/hotel/ad.json")
async def custom_ad(request: Request):
    base_url = resolve_base_url(request)
    ad = generate_ad(config, HotelAgent, base_url, methods)
    ad["custom_field"] = "custom_value"
    return ad
```

## Discovery Flow

```
1. Client requests ad.json
   ↓
2. Parse ad.json (JSON-LD format)
   - Extract agent metadata
   - Find interface URLs (content or link mode)
   - Extract Informations
   ↓
3. Fetch interface documents
   - interface.json for content mode
   - interface/{method}.json for link mode
   ↓
4. Create RemoteAgent proxy
   - Dynamic method access
   - Schema validation
   ↓
5. Call methods via JSON-RPC 2.0
   - SSE streaming responses
   - DID-WBA authentication
```

## API Reference

### Client

| Export | Description |
|--------|-------------|
| `RemoteAgent` | High-level client for remote agents |
| `Method` | Method definition (name, params, rpc_url) |
| `HttpError` | HTTP request failed |
| `RpcError` | JSON-RPC error response |

### Server

| Export | Description |
|--------|-------------|
| `@anp_agent` | Decorator to define an ANP agent |
| `@interface` | Decorator to expose a method via JSON-RPC |
| `@information` | Decorator to define dynamic Information |
| `AgentConfig` | Agent configuration |
| `Information` | Information definition |
| `Context` | Request context with session/DID |
| `Session` | Session storage for a DID |
| `SessionManager` | Manages sessions across DIDs |
| `create_agent_router` | Create FastAPI router from config |
| `generate_ad` | Generate ad.json document |

### Utilities

| Export | Description |
|--------|-------------|
| `generate_ad_document` | Generate base Agent Description |
| `generate_rpc_interface` | Generate OpenRPC interface |
| `type_to_json_schema` | Convert Python type to JSON Schema |
| `resolve_base_url` | Get base URL from request |

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
```

## Protocol Formats

### ad.json - Agent Description (JSON-LD)

```json
{
  "@context": {...},
  "@type": "ad:AgentDescription",
  "name": "Hotel Service",
  "did": "did:wba:example.com:hotel",
  "description": "Hotel booking service",
  "interfaces": [
    {
      "type": "StructuredInterface",
      "protocol": "openrpc",
      "url": "https://hotel.example.com/hotel/interface.json"
    },
    {
      "type": "StructuredInterface",
      "protocol": "openrpc",
      "url": "https://hotel.example.com/hotel/interface/book.json"
    }
  ],
  "Infomations": [
    {
      "type": "VideoObject",
      "description": "Hotel tour",
      "url": "https://cdn.example.com/tour.mp4"
    },
    {
      "type": "Contact",
      "description": "Contact info",
      "content": {"phone": "+1-234-567"}
    }
  ]
}
```

### interface.json - OpenRPC 1.3.2

```json
{
  "openrpc": "1.3.2",
  "info": {"title": "Hotel Service API", "version": "1.0.0"},
  "methods": [
    {
      "name": "search",
      "description": "Search for hotels",
      "params": [
        {"name": "query", "schema": {"type": "string"}, "required": true}
      ],
      "result": {"name": "result", "schema": {"type": "object"}}
    }
  ],
  "servers": [{"name": "Hotel", "url": "https://hotel.example.com/hotel/rpc"}]
}
```

## Examples

See `anp/openanp/example/` for complete examples:

- `simple_server.py` - Full server with Context, Information, interface modes
- `simple_client.py` - Client discovery and method calling
- `hybrid_agent.py` - P2P agent (both server and client)

## License

MIT License
