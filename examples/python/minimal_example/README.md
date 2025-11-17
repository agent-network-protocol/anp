# Minimal ANP Example

This directory contains a minimal example demonstrating how to create an ANP server and client.

## Files

- `minimal_anp_server.py` - A minimal ANP server with:
  1. A basic one-line calculator function
  2. A JSON endpoint that returns "hello"
  3. A basic OpenAI API call

- `minimal_anp_client.py` - A minimal ANP client that interacts with the server

## Prerequisites

1. Ensure you have the DID documents in `docs/did_public/`:
   - `public-did-doc.json` (should exist)
   - `public-private-key.pem` (optional if server has auth disabled)

2. For OpenAI API calls, set the `OPENAI_API_KEY` environment variable:
   ```bash
   export OPENAI_API_KEY="your-api-key-here"
   ```

## Running the Example

### Step 1: Start the Server

```bash
cd /Users/moshiwei/Documents/GitHub/anp
uv run python examples/python/minimal_example/minimal_anp_server.py
```

The server will start on `http://localhost:8000`

### Step 2: Run the Client

In another terminal:

```bash
cd /Users/moshiwei/Documents/GitHub/anp
uv run python examples/python/minimal_example/minimal_anp_client.py
```

## What the Server Provides

1. **Calculator Function** (`calculate`)
   - Evaluates simple mathematical expressions
   - Example: `"2 + 3"` → `{"result": 5}`

2. **Hello JSON Endpoint** (`/info/hello.json`)
   - Returns: `{"message": "hello"}`

3. **OpenAI API Call** (`call_openai`)
   - Makes a basic OpenAI API call
   - Requires `OPENAI_API_KEY` environment variable on the server

## API Endpoints

- `GET /ad.json` - Agent Description
- `GET /info/hello.json` - Hello message JSON
- `GET /info/calculate.json` - Calculator OpenRPC document
- `GET /info/openai_call.json` - OpenAI OpenRPC document
- `POST /rpc` - JSON-RPC endpoint for method calls

## Example JSON-RPC Calls

### Calculator

```bash
curl -X POST http://localhost:8000/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "calculate", "params": {"expression": "2 + 3"}}'
```

### OpenAI

```bash
curl -X POST http://localhost:8000/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 2, "method": "call_openai", "params": {"prompt": "Say hello"}}'
```

### Hello JSON

```bash
curl http://localhost:8000/info/hello.json
```

## Notes

- The server runs with authentication disabled (`enable_auth_middleware=False`) for simplicity
- The client uses DID documents from `docs/did_public/`
- If the private key doesn't exist, the client will still work since auth is disabled
- OpenAI calls will fail gracefully if the API key is not set

