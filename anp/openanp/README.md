<div align="center">

[English](README.md) | [中文](README.cn.md)

</div>

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

---

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

**Content Mode (default)**:
- All content mode methods are combined into a single `interface.json`
- Suitable for lightweight methods with simple schemas
- Reduces HTTP requests for clients

**Link Mode**:
- Each method gets its own interface file: `/interface/{method_name}.json`
- Suitable for complex methods or methods that change frequently
- Allows independent versioning of interfaces

**Generated ad.json structure**:

```json
{
  "interfaces": [
    {
      "type": "StructuredInterface",
      "protocol": "openrpc",
      "url": "https://example.com/hotel/interface.json",
      "description": "Hotel Service JSON-RPC interface"
    },
    {
      "type": "StructuredInterface",
      "protocol": "openrpc",
      "url": "https://example.com/hotel/interface/book.json",
      "description": "Book a hotel room"
    }
  ]
}
```

---

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

**Context Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `ctx.did` | `str` | Caller's DID (Decentralized Identifier) |
| `ctx.session` | `Session` | Session storage isolated by DID |
| `ctx.request` | `Request` | FastAPI Request object |
| `ctx.auth_result` | `dict` | Authentication result from middleware |

**Session Methods**:

```python
ctx.session.get("key", default_value)  # Read with default
ctx.session.set("key", value)          # Write
ctx.session.clear()                     # Clear all session data
```

**Important**: Context parameter (`ctx: Context`) is automatically injected and excluded from OpenRPC schemas. Clients do not pass this parameter.

---

### Information Definitions

Two ways to define Information (metadata for ad.json):

```python
from anp.openanp import Information, information

@anp_agent(config)
class MyAgent:
    # Static definitions (class attribute)
    informations = [
        # URL mode - hosted file
        Information(
            type="Product",
            description="Room catalog",
            path="/products/rooms.json",
            file="data/rooms.json"
        ),
        # URL mode - external link
        Information(
            type="VideoObject",
            description="Hotel tour",
            url="https://cdn.hotel.com/tour.mp4"
        ),
        # Content mode - embedded in ad.json
        Information(
            type="Contact",
            description="Contact info",
            mode="content",
            content={"phone": "+1-234-567"}
        ),
    ]

    # Dynamic definitions via decorator (URL mode)
    @information(type="Product", description="Today's availability", path="/availability.json")
    def get_availability(self) -> dict:
        return {"available": self.db.get_available()}

    # Dynamic definitions via decorator (Content mode)
    @information(type="Service", description="Specials", mode="content")
    def get_specials(self) -> dict:
        return {"specials": [...]}
```

**Information Class Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `type` | `str` | Type (Product, VideoObject, Organization, etc.) |
| `description` | `str` | Description |
| `mode` | `"url" \| "content"` | Output mode (default: "url") |
| `path` | `str \| None` | Relative path for hosted content |
| `url` | `str \| None` | External URL |
| `file` | `str \| None` | Static file path for hosting |
| `content` | `dict \| None` | Embedded content (Content mode) |

**Generated ad.json Infomations**:

```json
{
  "Infomations": [
    {
      "type": "Product",
      "description": "Room catalog",
      "url": "https://example.com/hotel/products/rooms.json"
    },
    {
      "type": "Contact",
      "description": "Contact info",
      "content": {"phone": "+1-234-567"}
    }
  ]
}
```

---

### Custom ad.json (customize_ad Hook)

Define a `customize_ad` method in your Agent class to customize ad.json. This method is automatically called by the framework when generating ad.json.

```python
from fastapi import FastAPI
from anp.openanp import anp_agent, interface, AgentConfig

@anp_agent(AgentConfig(name="Hotel", did="did:wba:example.com:hotel", prefix="/hotel"))
class HotelAgent:
    @interface
    async def search(self, query: str) -> dict:
        return {"results": [...]}

    def customize_ad(self, ad: dict, base_url: str) -> dict:
        """Customize ad.json - automatically called by OpenANP.

        Args:
            ad: The auto-generated ad.json dict
            base_url: The base URL of the server

        Returns:
            The modified ad.json dict
        """
        # Add custom metadata
        ad["custom_metadata"] = {"version": "2.0.0"}

        # Add additional Informations
        if "Infomations" not in ad:
            ad["Infomations"] = []
        ad["Infomations"].append({
            "type": "FAQ",
            "description": "FAQ",
            "url": f"{base_url}/hotel/faq.json",
        })

        # Add custom support info
        ad["support"] = {"email": "support@hotel.com"}

        return ad

app = FastAPI()
agent = HotelAgent()
app.include_router(agent.router())

# Add endpoints referenced in customize_ad
@app.get("/hotel/faq.json")
async def get_faq():
    return {"faqs": [...]}
```

**Note**: `customize_ad` can also be an async method:

```python
async def customize_ad(self, ad: dict, base_url: str) -> dict:
    # Async operations supported
    extra_info = await self.fetch_extra_info()
    ad["extra"] = extra_info
    return ad
```

**Extending Router with New Endpoints**:

You can also add new endpoints directly to the existing app:

```python
# Add custom endpoints to the existing app
@app.get("/hotel/stats.json")
async def get_stats() -> JSONResponse:
    return JSONResponse({"total_products": 100})

@app.get("/hotel/health")
async def health_check() -> JSONResponse:
    return JSONResponse({"status": "healthy"})
```

---

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
   - DID-WBA authentication
```

---

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
| `extract_rpc_methods` | Extract RPC methods from agent class |

---

## RemoteAgent

**RemoteAgent downloads all methods from a remote agent and transforms them into local method calls.** It creates a proxy object that makes calling remote agents feel like calling local methods.

> **RemoteAgent vs ANPCrawler**: RemoteAgent is a proxy-style client (methods feel like local calls), while ANPCrawler is a crawler-style client (fetch and parse documents). Use RemoteAgent for agent-to-agent communication in code; use ANPCrawler for LLM tool integration or data collection.

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

---

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

---

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

---

## Examples

See `examples/python/openanp_examples/` for complete examples:

- `minimal_server.py` - Minimal server (~30 lines)
- `minimal_client.py` - Minimal client (~25 lines)
- `advanced_server.py` - Full server with:
  - Context and Session management
  - Static and dynamic Information
  - Content and link interface modes
  - **Custom ad.json override example** (`create_app_with_custom_ad()`)
- `advanced_client.py` - Full client with discovery, LLM integration, error handling

**Running the custom ad.json example**:

```bash
# Standard app
uvicorn examples.python.openanp_examples.advanced_server:app --port 8000

# App with custom ad.json
uvicorn examples.python.openanp_examples.advanced_server:app_custom --port 8000
```

---

## Summary: Key Design Decisions

| Feature | Design | Rationale |
|---------|--------|-----------|
| Interface modes | content (default) / link | Flexibility for different use cases |
| Information modes | url / content | Support both hosted and embedded content |
| Context injection | Parameter-based (`ctx: Context`) | Explicit, type-safe, auto-excluded from schema |
| Session isolation | By DID | Multi-tenant support |
| Custom ad.json | Mixed mode (override before include) | Maximum flexibility |
| Error handling | Fail fast (exceptions) | Explicit error handling |

## License

MIT License
