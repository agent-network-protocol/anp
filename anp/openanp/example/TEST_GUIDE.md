# Hybrid Agent Testing Guide

## Prerequisites

Both services must be running:

1. **Hotel Agent** (port 8000):
   ```bash
   uv run uvicorn anp.openanp.example.simple_server:app --reload --port 8000
   ```

2. **Travel Agent** (port 8001):
   ```bash
   uv run uvicorn anp.openanp.example.hybrid_agent:app --reload --port 8001
   ```

## Quick Manual Tests

### 1. Test Agent Description (ad.json)

```bash
curl http://localhost:8001/travel/ad.json | jq
```

**Expected:**
- `@context` with JSON-LD vocabularies
- `@type`: `"ad:AgentDescription"`
- `@id`: URL to the ad.json
- `name`: `"Travel Agent"`
- `interfaces`: Array with OpenRPC interface

### 2. Test Interface Document (interface.json)

```bash
curl http://localhost:8001/travel/interface.json | jq
```

**Expected:**
- `openrpc`: `"1.3.2"`
- `methods`: Array with 2 methods
  - `plan_trip`: 2 params (destination, budget)
  - `quick_search`: 1 param (query, NO auth)

### 3. Test RPC Call - plan_trip (Manual Schema)

```bash
curl -X POST http://localhost:8001/travel/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "1",
    "method": "plan_trip",
    "params": {
      "destination": "Tokyo",
      "budget": 1000
    }
  }' | jq
```

**Expected:**
```json
{
  "jsonrpc": "2.0",
  "id": "1",
  "result": {
    "destination": "Tokyo",
    "budget": 1000,
    "hotels": {...},
    "status": "planned"
  }
}
```

### 4. Test RPC Call - quick_search (Auto Schema)

```bash
curl -X POST http://localhost:8001/travel/rpc \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": "2",
    "method": "quick_search",
    "params": {
      "query": "Paris"
    }
  }' | jq
```

**Expected:**
```json
{
  "jsonrpc": "2.0",
  "id": "2",
  "result": {
    "query": "Paris",
    "results": {...}
  }
}
```

## Automated Test Script

Run the full test suite:

```bash
cd /Users/amdoi7/Desktop/work/anp/anp/openanp/example
./test_hybrid_agent.sh
```

**Features Tested:**
1. ✅ Service availability (Hotel + Travel)
2. ✅ JSON-LD compliance (@context, @type, @id)
3. ✅ OpenRPC 1.3.2 format
4. ✅ Method definitions (manual + auto)
5. ✅ Parameter filtering (auth removed)
6. ✅ RPC call execution
7. ✅ Error handling

## What This Demo Shows

### Feature 1: Manual Schema Definition
- **Method**: `plan_trip`
- **Approach**: Explicit `RPCMethodInfo` with complete schema
- **Benefits**: Full control, validation rules, detailed descriptions

### Feature 2: Auto Schema Extraction
- **Method**: `quick_search`
- **Approach**: `extract_method_schemas()` from type hints
- **Benefits**: Less boilerplate, DRY principle

### Feature 3: Parameter Filtering
- **Problem**: `auth` is internal, shouldn't be exposed
- **Solution**: Filter out from extracted schema
- **Result**: Only business parameters in interface.json

### Feature 4: Pure Functions
- **Approach**: No decorators, explicit dependencies
- **Benefits**: Testable, composable, clear data flow

### Feature 5: P2P Agent
- **Capability**: Acts as both server AND client
- **Server**: Exposes `plan_trip` and `quick_search`
- **Client**: Discovers and calls Hotel Agent

## Troubleshooting

### Error: "Connection refused"
- **Cause**: Services not running
- **Fix**: Start both Hotel Agent (8000) and Travel Agent (8001)

### Error: "Method not found"
- **Cause**: Invalid method name in RPC call
- **Fix**: Check interface.json for available methods

### Error: "Auth not configured"
- **Cause**: No auth provided to agent instance
- **Fix**: This is expected for demo mode (auth=None)
- **Note**: Real calls to Hotel Agent require valid DID credentials

## Architecture

```
┌─────────────────────────────────────────────────┐
│           Travel Agent (Port 8001)              │
│                                                 │
│  ┌──────────────┐      ┌──────────────┐        │
│  │  plan_trip   │      │ quick_search │        │
│  │  (Manual)    │      │  (Auto)      │        │
│  └──────┬───────┘      └──────┬───────┘        │
│         └────────┬─────────────┘                │
│                  │                              │
│                  ▼                              │
│         RemoteAgent.discover()                  │
│                  │                              │
└──────────────────┼──────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────┐
│           Hotel Agent (Port 8000)               │
│                                                 │
│  ┌──────────────┐      ┌──────────────┐        │
│  │   search     │      │    book      │        │
│  └──────────────┘      └──────────────┘        │
│                                                 │
└─────────────────────────────────────────────────┘
```

## Next Steps

1. **Production Auth**: Replace `auth=None` with real DID credentials
2. **Error Handling**: Add try-catch for network failures
3. **Caching**: Cache discovered agents
4. **Monitoring**: Add logging and metrics
5. **Testing**: Add unit tests for pure functions
