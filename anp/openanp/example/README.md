# OpenANP Examples

This directory contains examples of how to use OpenANP to build Agent Network Protocol (ANP) compliant agents. These examples demonstrate server-side implementation, client-side consumption, and hybrid agent patterns.

## Structure

- `simple_server.py`: A minimal agent server (Hotel Service) using `@interface` and `@anp_agent`.
- `hybrid_agent.py`: An agent (Travel Service) that acts as both a server and a client (calling other agents).
- `simple_client.py`: A client script discovering and calling a remote agent.

## Running the Examples

To see the full interaction (Client -> Travel Agent -> Hotel Agent), you should run all agents. Since they are standard FastAPI apps, we will run them on different ports.

### 1. Start the Hotel Agent (Port 8000)

The Hotel Agent provides the base capabilities (`search`, `book`).

```bash
# Terminal 1
uv run uvicorn anp.fastanp.example.simple_server:app --reload --port 8000
```

**Verify Hotel Agent:**

1.  **Agent Description (ad.json)**:
    ```bash
    curl http://localhost:8000/hotel/ad.json
    ```
    *Output:* Returns the agent identity and points to the interface.

2.  **Interface (interface.json)**:
    ```bash
    curl http://localhost:8000/hotel/interface.json
    ```
    *Output:* OpenRPC document listing `search` and `book` methods.

3.  **RPC Call**:
    ```bash
    curl -X POST http://localhost:8000/hotel/rpc \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc": "2.0", "id": 1, "method": "search", "params": {"query": "Tokyo"}}'
    ```

### 2. Start the Travel Agent (Port 8001)

The Travel Agent is a "Hybrid Agent". It exposes a `plan_trip` method, but internally it discovers and calls the Hotel Agent.

**Note**: The URLs in `hybrid_agent.py` are configured to use `http://localhost:8000/hotel/ad.json` for local testing. For production, update these URLs accordingly.

```bash
# Terminal 2
uv run uvicorn anp.fastanp.example.hybrid_agent:app --reload --port 8001
```

**Note**: The `hybrid_agent.py` example uses optional auth. The server endpoints (ad.json, interface.json, rpc) will work without auth, but actual RPC calls that make client-side requests to other agents will require proper authentication credentials.

**Verify Travel Agent:**

1.  **Agent Description**:
    ```bash
    curl http://localhost:8001/travel/ad.json
    ```

2.  **RPC Call (Chained)**:
    When you call this, the Travel Agent will effectively call the Hotel Agent.
    ```bash
    curl -X POST http://localhost:8001/travel/rpc \
      -H "Content-Type: application/json" \
      -d '{"jsonrpc": "2.0", "id": 1, "method": "plan_trip", "params": {"destination": "Tokyo"}}'
    ```

### 3. Run the Client

The client script demonstrates how to programmatically discover and call these agents using the `RemoteAgent` SDK.

**Note**: The `simple_client.py` is configured to use `http://localhost:8000/hotel/ad.json` by default. Make sure the Hotel Agent is running on port 8000 before running the client.

**Important**: You need to provide valid authentication credentials (DID document and private key paths) for the client to work. Update the paths in `simple_client.py` before running.

```bash
# Terminal 3
uv run python -m anp.fastanp.example.simple_client
```

*Output:*
It should print the results of the search and booking calls, demonstrating the full discovery and execution flow.

## Key Outputs Explained

### ad.json (Agent Definition)

This file tells the world **WHO** the agent is and **WHERE** to find its interface. OpenANP generates this automatically.

```json
{
  "protocolType": "ANP",
  "protocolVersion": "1.0.0",
  "type": "Agent",
  "url": ".../ad.json",
  "name": "Hotel Service",
  "did": "did:wba:example.com:hotel",
  "interfaces": [
    {
      "type": "StructuredInterface",
      "protocol": "openrpc",
      "url": ".../interface.json"
    }
  ]
}
```

### interface.json (OpenRPC)

This file tells the world **WHAT** the agent can do. OpenANP extracts schemas from your Python type hints.

```json
{
  "openrpc": "1.3.2",
  "methods": [
    {
      "name": "search",
      "params": {
        "type": "object",
        "properties": {
          "query": {"type": "string"}
        },
        "required": ["query"]
      },
      "result": {"type": "object"}
    }
  ]
}
```

## Key Concepts

- **@anp_agent**: Class decorator that transforms a Python class into an ANP Agent.
- **@interface**: Method decorator that marks a function as an exposed capability.
- **RemoteAgent**: The client-side SDK that reads `ad.json` and `interface.json` to dynamically build a proxy object for remote calls.
