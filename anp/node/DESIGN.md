# ANP Node Design Proposal

## Overview

This document proposes the design of a unified **ANP Node** that can operate as both a **server** (receiving requests) and a **client** (sending requests to other nodes). This dual-mode capability enables true peer-to-peer agent communication in the Agent Network Protocol (ANP) ecosystem.

## Motivation

### Current State

The ANP codebase currently has separate components:
- **FastANP**: Server-side framework for building agents that receive requests
- **ANPClient**: Client-side HTTP client for sending requests to other agents
- **ANPCrawler**: Discovery and interaction tool using ANPClient

### Problem

Developers must manually combine these components to create agents that both:
1. Expose services (server mode)
2. Consume services from other agents (client mode)

This leads to:
- Code duplication
- Complex setup
- Inconsistent identity management
- Difficult lifecycle management

### Solution

A unified **ANPNode** class that:
- Combines server and client capabilities
- Shares identity (DID) across both modes
- Provides a single, clean API
- Manages lifecycle automatically

## Architecture Design

### High-Level Architecture

```
┌─────────────────────────────────────────┐
│           ANPNode                       │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │      Identity & Configuration     │  │
│  │  - DID Document                   │  │
│  │  - Private Key                   │  │
│  │  - Agent Domain                  │  │
│  │  - Port/Address                  │  │
│  └───────────────────────────────────┘  │
│                                         │
│  ┌──────────────────┐  ┌──────────────┐ │
│  │  Server Component│  │Client Component│ │
│  │  (FastANP-based) │  │(ANPClient-based)│ │
│  │                  │  │                │ │
│  │  - FastAPI App   │  │  - HTTP Client │ │
│  │  - Interfaces    │  │  - DID Auth   │ │
│  │  - JSON-RPC      │  │  - Pooling    │ │
│  │  - Auth Middleware│ │  - Discovery   │ │
│  └──────────────────┘  └──────────────┘ │
│                                         │
│  ┌───────────────────────────────────┐  │
│  │      Shared Services              │  │
│  │  - Logging                        │  │
│  │  - Metrics                        │  │
│  │  - Error Handling                 │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

### Component Details

#### 1. Identity & Configuration

**Purpose**: Single source of truth for node identity

**Components**:
- DID document path
- Private key path
- Agent domain (e.g., `https://example.com`)
- Server port and host
- Feature flags (server_enabled, client_enabled)

**Design**:
```python
class NodeConfig:
    did_document_path: str
    private_key_path: str
    agent_domain: str
    host: str = "0.0.0.0"
    port: int = 8000
    server_enabled: bool = True
    client_enabled: bool = True
    auth_config: Optional[DidWbaVerifierConfig] = None
```

#### 2. Server Component

**Purpose**: Handle incoming requests from other nodes

**Based on**: FastANP framework

**Features**:
- FastAPI application
- Interface registration via decorator
- JSON-RPC endpoint (`/rpc`)
- DID WBA authentication middleware
- Context injection
- OpenRPC document generation
- Agent Description (`/ad.json`)

**API**:
```python
@node.interface("/info/search.json", description="Search items")
def search(query: str, limit: int = 10, ctx: Context = None) -> dict:
    """Search for items."""
    return {"results": [...]}
```

#### 3. Client Component

**Purpose**: Send requests to other nodes

**Based on**: ANPClient with enhancements

**Features**:
- HTTP client with DID authentication
- Connection pooling
- Interface discovery and caching
- Request/response handling
- Error handling and retries
- Timeout management

**API**:
```python
# Call remote interface
result = await node.call_interface(
    target_did="did:wba:other.com:node:2",
    method="get_data",
    params={"id": 123}
)

# Or use discovered interface
interface = await node.discover_interface(target_did, "get_data")
result = await interface.execute({"id": 123})
```

#### 4. Shared Services

**Purpose**: Common functionality used by both components

**Services**:
- **Logging**: Unified logging with node identity
- **Metrics**: Request/response metrics for both modes
- **Error Handling**: Consistent error formats
- **Configuration**: Shared configuration management

## API Design

### Core API

```python
class ANPNode:
    """Unified ANP node supporting both server and client modes."""
    
    def __init__(
        self,
        name: str,
        description: str,
        did_document_path: str,
        private_key_path: str,
        agent_domain: str,
        host: str = "0.0.0.0",
        port: int = 8000,
        server_enabled: bool = True,
        client_enabled: bool = True,
        enable_auth_middleware: bool = True,
        auth_config: Optional[DidWbaVerifierConfig] = None,
        **kwargs
    ):
        """Initialize ANP node."""
        pass
    
    # Server API
    def interface(
        self,
        path: str,
        description: Optional[str] = None,
        humanAuthorization: bool = False
    ) -> Callable:
        """Decorator to register server interface."""
        pass
    
    def get_common_header(
        self,
        agent_description_path: str = "/ad.json",
        ad_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get Agent Description common header."""
        pass
    
    # Client API
    async def call_interface(
        self,
        target_did: str,
        method: str,
        params: Dict[str, Any],
        timeout: Optional[float] = 30.0
    ) -> Dict[str, Any]:
        """Call remote interface by DID and method name."""
        pass
    
    async def discover_interface(
        self,
        target_did: str,
        method: Optional[str] = None
    ) -> Union[ANPInterface, Dict[str, ANPInterface]]:
        """Discover and cache remote interfaces."""
        pass
    
    # Lifecycle
    async def start(self) -> None:
        """
        Start the node server in non-blocking mode.
        
        This method starts the server in the background and returns immediately.
        Use this when you need to do other things while the server is running.
        
        Example:
            async def main():
                node = ANPNode(...)
                await node.start()  # Non-blocking
                # Can do other things here
                result = await node.call_interface(...)
                await node.stop()
        """
        pass
    
    async def stop(self) -> None:
        """
        Stop the node server gracefully.
        
        Stops the server and waits for ongoing requests to complete.
        """
        pass
    
    # Properties
    @property
    def did(self) -> str:
        """Get node DID."""
        pass
    
    @property
    def interfaces(self) -> Dict[Callable, InterfaceProxy]:
        """Get registered server interfaces."""
        pass
    
    @property
    def app(self) -> FastAPI:
        """Get FastAPI application (for advanced usage)."""
        pass
```

### Usage Example

#### Simple Server-Only Node

```python
from anp.node import ANPNode
import asyncio

# Initialize node
node = ANPNode(
    name="Simple Agent",
    description="A simple ANP agent",
    did_document_path="./did.json",
    private_key_path="./private_key.pem",
    agent_domain="https://myagent.com",
    port=8000
)

# Register server interface
@node.interface("/info/hello.json", description="Say hello")
def hello(name: str) -> dict:
    """Say hello to someone."""
    return {"message": f"Hello, {name}!"}

# Custom ad.json route
@node.app.get("/ad.json")
def get_agent_description():
    ad = node.get_common_header()
    ad["interfaces"] = [
        node.interfaces[hello].link_summary
    ]
    return ad

# Start node (minimal setup)
if __name__ == "__main__":
    async def main():
        await node.start()
        try:
            await asyncio.Event().wait()  # Keep running until Ctrl+C
        except KeyboardInterrupt:
            print("Stopping node...")
            await node.stop()
    
    asyncio.run(main())
```

#### Dual-Mode Node (Server + Client)

```python
from anp.node import ANPNode
from anp.fastanp import Context
import asyncio

# Initialize node
node = ANPNode(
    name="Orchestrator Agent",
    description="A dual-mode ANP agent",
    did_document_path="./did.json",
    private_key_path="./private_key.pem",
    agent_domain="https://myagent.com",
    port=8000
)

# Register server interface that calls other nodes
@node.interface("/info/aggregate.json", description="Aggregate data from multiple nodes")
async def aggregate(query: str, ctx: Context = None) -> dict:
    """Aggregate data from multiple nodes."""
    results = []
    
    # Call other nodes (client functionality)
    try:
        result1 = await node.call_interface(
            target_did="did:wba:node1.com:agent:1",
            method="get_data",
            params={"query": query}
        )
        results.append(result1)
        
        result2 = await node.call_interface(
            target_did="did:wba:node2.com:agent:1",
            method="get_data",
            params={"query": query}
        )
        results.append(result2)
    except Exception as e:
        return {"error": str(e)}
    
    return {"aggregated": results, "count": len(results)}

# Custom ad.json route
@node.app.get("/ad.json")
def get_agent_description():
    ad = node.get_common_header()
    ad["interfaces"] = [
        node.interfaces[aggregate].link_summary
    ]
    return ad

# Start node with initialization (non-blocking)
if __name__ == "__main__":
    async def main():
        # Start server (non-blocking)
        await node.start()
        print("Node server started!")
        
        # Can do initialization while server is running
        try:
            # Discover other nodes
            interface = await node.discover_interface(
                target_did="did:wba:node1.com:agent:1",
                method="get_data"
            )
            print(f"Discovered interface: {interface}")
        except Exception as e:
            print(f"Discovery failed: {e}")
        
        # Keep server running until stopped
        try:
            await asyncio.Event().wait()  # Wait forever
        except KeyboardInterrupt:
            print("Stopping node...")
            await node.stop()
    
    asyncio.run(main())
```

### Client Usage Example

```python
# In another script or async context
async def use_node_as_client():
    node = ANPNode(
        name="Client Agent",
        did_document_path="./client_did.json",
        private_key_path="./client_key.pem",
        agent_domain="https://client.com",
        server_enabled=False,  # Only client mode
        client_enabled=True
    )
    
    # Discover remote interface
    interface = await node.discover_interface(
        target_did="did:wba:myagent.com:agent:1",
        method="search"
    )
    
    # Call remote interface
    result = await interface.execute({
        "query": "test",
        "limit": 10
    })
    
    print(result)
```

## Implementation Phases

### Phase 1: Basic Node (MVP)

**Goal**: Working dual-mode node with basic functionality

**Components**:
- [ ] Node configuration and initialization
- [ ] Server component wrapper (FastANP integration)
- [ ] Client component wrapper (ANPClient integration)
- [ ] Shared identity management
- [ ] Basic lifecycle (start/stop)
- [ ] Simple interface registration
- [ ] Basic remote interface calling

**Timeline**: 2-3 weeks

### Phase 2: Enhanced Features

**Goal**: Production-ready features

**Components**:
- [ ] Interface discovery and caching
- [ ] Connection pooling for client
- [ ] Request routing (local vs remote)
- [ ] Context propagation
- [ ] Error handling improvements
- [ ] Timeout and retry logic
- [ ] Health checks

**Timeline**: 2-3 weeks

### Phase 3: Advanced Features

**Goal**: Enterprise-grade capabilities

**Components**:
- [ ] Metrics and monitoring
- [ ] Circuit breaker pattern
- [ ] Load balancing
- [ ] Service mesh integration
- [ ] Advanced caching strategies
- [ ] Request tracing
- [ ] Performance optimizations

**Timeline**: 3-4 weeks

## Design Decisions

### 1. Composition over Inheritance

**Decision**: Use composition to combine FastANP and ANPClient

**Rationale**:
- Clear separation of concerns
- Easier to test individual components
- More flexible configuration
- Avoids deep inheritance hierarchies

### 2. Shared Identity

**Decision**: Use same DID for both server and client modes

**Rationale**:
- Single source of truth
- Consistent authentication
- Simpler configuration
- Better security (one key pair)

### 3. Optional Components

**Decision**: Allow disabling server or client mode

**Rationale**:
- Flexibility for different use cases
- Resource optimization
- Easier testing
- Supports specialized nodes

### 4. Async-First Design

**Decision**: All I/O operations are async

**Rationale**:
- Better performance
- Non-blocking operations
- Supports high concurrency
- Aligns with FastAPI and aiohttp

### 5. FastAPI Integration

**Decision**: Expose FastAPI app for advanced usage

**Rationale**:
- Users can add custom routes
- Supports middleware customization
- Enables integration with other FastAPI features
- Maintains flexibility

## Best Practices

### 1. Error Handling

- **Server errors**: Return proper JSON-RPC error responses
- **Client errors**: Handle network failures gracefully
- **Use consistent error formats**: Standardize error codes and messages

### 2. Security

- **Always use authentication**: Enable DID WBA auth by default
- **Validate inputs**: Use Pydantic models for interface parameters
- **Rate limiting**: Implement rate limits for server endpoints
- **HTTPS**: Use HTTPS in production

### 3. Performance

- **Connection pooling**: Reuse HTTP connections
- **Interface caching**: Cache discovered interfaces
- **Async operations**: Use async/await throughout
- **Resource cleanup**: Properly close connections and cleanup

### 4. Observability

- **Structured logging**: Use structured logging with node identity
- **Metrics**: Track request/response metrics
- **Tracing**: Support distributed tracing
- **Health checks**: Implement health check endpoints

### 5. Testing

- **Unit tests**: Test components independently
- **Integration tests**: Test server and client together
- **Mock external nodes**: Use mocks for testing client calls
- **Test both modes**: Ensure both server and client work correctly

## Potential Challenges

### 1. Circular Dependencies

**Problem**: Node A calls Node B, which calls Node A

**Solutions**:
- Request ID tracking to detect cycles
- Maximum call depth limits
- Timeout mechanisms
- Circuit breaker pattern

### 2. Authentication Complexity

**Problem**: Managing authentication for both modes

**Solutions**:
- Reuse DID WBA authentication
- Shared authentication configuration
- Clear documentation
- Helper utilities

### 3. State Management

**Problem**: Server sessions vs client request state

**Solutions**:
- Separate state management
- Clear boundaries
- Context propagation
- Session isolation

### 4. Testing Complexity

**Problem**: Testing both server and client modes

**Solutions**:
- Mock components
- Integration test framework
- Test fixtures
- Example test cases

## Comparison with Existing Patterns

| Pattern | Example | ANP Node |
|---------|---------|----------|
| **Client-Server** | Traditional web apps | Unified in one class |
| **Peer-to-Peer** | BitTorrent, IPFS | Similar architecture |
| **Microservices** | Kubernetes services | Similar communication |
| **Agent Network** | ANP vision | Matches perfectly |

## Real-World Use Cases

### 1. Agent Orchestration

An agent that coordinates multiple other agents:
- Receives requests (server mode)
- Calls other agents to fulfill requests (client mode)
- Aggregates results

### 2. Service Mesh

Multiple nodes forming a network:
- Each node provides services
- Each node consumes services from others
- Automatic service discovery

### 3. Negotiation Protocols

Agents negotiating protocols:
- Act as server during negotiation
- Act as client to call negotiated interfaces
- Support bidirectional communication

### 4. Data Aggregation

An agent that aggregates data from multiple sources:
- Exposes aggregated data (server mode)
- Fetches data from multiple sources (client mode)
- Caches and processes data

## Migration Path

### For Existing FastANP Users

```python
# Before (blocking)
app = FastAPI()
anp = FastANP(app=app, ...)
uvicorn.run(app, host="0.0.0.0", port=8000)  # Blocking

# After (non-blocking)
node = ANPNode(...)
# node.app is the FastAPI app
# node.interface() works the same

async def main():
    await node.start()  # Non-blocking
    # Can do other things
    await asyncio.Event().wait()  # Keep running

asyncio.run(main())
```

### For Existing ANPClient Users

```python
# Before
client = ANPClient(did_doc_path, key_path)
result = await client.fetch_url(...)

# After (client-only mode)
node = ANPNode(..., server_enabled=False, client_enabled=True)
result = await node.call_interface(
    target_did="did:wba:target.com:agent:1",
    method="method_name",
    params={...}
)
```

## Conclusion

The unified ANP Node design provides:

✅ **Simplicity**: Single API for both server and client  
✅ **Consistency**: Shared identity and configuration  
✅ **Flexibility**: Optional components and advanced customization  
✅ **Real-world applicability**: Matches common distributed system patterns  
✅ **Future-proof**: Extensible architecture for advanced features  

This design enables true peer-to-peer agent communication while maintaining the simplicity and power of the existing ANP components.

## Next Steps

1. **Review and feedback**: Gather feedback on this design
2. **Prototype**: Build Phase 1 MVP
3. **Testing**: Create comprehensive test suite
4. **Documentation**: Write user guides and API docs
5. **Examples**: Create example implementations
6. **Iterate**: Refine based on usage

---

**Document Version**: 1.0  
**Last Updated**: 2025-01-XX  
**Authors**: ANP Development Team

