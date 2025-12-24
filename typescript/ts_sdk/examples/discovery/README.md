# Agent Discovery Example

This example demonstrates how to discover other agents in the ANP network using both active and passive discovery methods with mock services.

## What This Example Shows

- Creating multiple agent identities and descriptions
- Running mock discovery and search services
- Active discovery from domain's `.well-known` endpoint
- Passive discovery via search service registration
- Searching for agents with keywords
- Handling paginated discovery results

## Running the Example

From the `ts_sdk` directory:

```bash
npm run build
npx tsx examples/discovery/index.ts
```

Or from this directory:

```bash
npm install
npm start
```

## Expected Output

```
=== Agent Discovery Example ===

Starting mock services...
✓ Discovery service: http://localhost:9100
✓ Search service: http://localhost:9101

Creating agents...
✓ Created Agent 1: did:wba:localhost:9001:agent-1
✓ Created Agent 2: did:wba:localhost:9002:agent-2
✓ Created Agent 3: did:wba:localhost:9003:agent-3

Active Discovery:
Discovering agents from localhost:9100...
✓ Found 3 agents:
  1. Agent 1 - http://localhost:9001/description.json
  2. Agent 2 - http://localhost:9002/description.json
  3. Agent 3 - http://localhost:9003/description.json

Passive Discovery - Registration:
✓ Registered with search service

Searching for agents:
✓ Found 4 matching agents:
  1. Agent 1 - http://localhost:9001/description.json
  2. Agent 2 - http://localhost:9002/description.json
  3. Agent 3 - http://localhost:9003/description.json
  4. Agent from http://localhost:9004/description.json - http://localhost:9004/description.json

=== Example Complete ===
```

## Example Flow

This example demonstrates a complete discovery workflow:

1. **Start Mock Services**
   - Discovery service on `http://localhost:9100`
   - Search service on `http://localhost:9101`

2. **Create Multiple Agents**
   - Creates 3 agents with DIDs and descriptions
   - Each agent has interfaces and information resources
   - All descriptions are cryptographically signed

3. **Active Discovery**
   - Discovers agents from `localhost:9100/.well-known/agent-descriptions`
   - Retrieves all registered agents
   - Handles pagination automatically

4. **Passive Discovery - Registration**
   - Registers an agent with the search service
   - Uses authenticated request with DID signature
   - Agent becomes searchable

5. **Search**
   - Searches for agents using keywords
   - Returns matching agents from the search index
   - Demonstrates query filtering

## Discovery Methods

### Active Discovery

Fetch agents directly from a domain's well-known endpoint:

```typescript
const discovered = await client.discovery.discoverAgents('example.com');
```

**Endpoint Format:**
```
https://example.com/.well-known/agent-descriptions
```

**Response Format (CollectionPage):**
```json
{
  "@context": { "ad": "https://agent-network-protocol.org/ns/ad#" },
  "@type": "CollectionPage",
  "url": "https://example.com/.well-known/agent-descriptions",
  "items": [
    {
      "@type": "ad:AgentDescription",
      "name": "Agent Name",
      "@id": "https://example.com/agent-description.json"
    }
  ],
  "next": "https://example.com/.well-known/agent-descriptions?page=2"
}
```

**Use Cases:**
- Discovering agents in your organization's domain
- Finding agents from known partners
- Exploring agents in specific domains

### Passive Discovery

Register your agent with search services and search for other agents:

**Registration:**
```typescript
await client.discovery.registerWithSearchService(
  'https://search.example.com/register',
  'https://myagent.example.com/description.json',
  identity
);
```

**Search:**
```typescript
const results = await client.discovery.searchAgents(
  'https://search.example.com/search',
  { keywords: ['weather', 'forecast'] }
);
```

**Search Query Format:**
```typescript
interface SearchQuery {
  keywords?: string[];      // Search keywords
  capabilities?: string[];  // Required capabilities
  limit?: number;          // Max results
  offset?: number;         // Pagination offset
}
```

**Search Result Format:**
```json
{
  "items": [
    {
      "@type": "ad:AgentDescription",
      "name": "Weather Agent",
      "@id": "https://weather.example.com/description.json"
    }
  ],
  "total": 42,
  "hasMore": true
}
```

## Mock Services

This example includes mock HTTP servers to demonstrate discovery:

### Discovery Server (Port 9100)
- Serves `.well-known/agent-descriptions` endpoint
- Returns CollectionPage with registered agents
- Supports pagination with `next` links

### Search Server (Port 9101)
- **POST /register** - Register agent descriptions
- **POST /search** - Search for agents by keywords
- Returns SearchResult format with items array

These mock services simulate real discovery infrastructure for testing.

## Best Practices

### Caching
- Cache discovered agents to reduce network requests
- Implement TTL for cached data
- Refresh cache periodically

### Pagination
- Handle paginated discovery results
- Follow `next` links in CollectionPage documents
- Implement limits to prevent excessive requests

### Verification
- Always verify agent description signatures
- Validate required fields are present
- Check protocol compatibility

### Performance
- Implement parallel discovery for multiple domains
- Use connection pooling for HTTP requests
- Implement timeouts for discovery requests

## Security Considerations

- Verify DID signatures on all agent descriptions
- Use HTTPS for all discovery requests
- Validate agent capabilities before interaction
- Implement rate limiting
- Be cautious with untrusted search services

## Next Steps

- Implement agent description hosting
- Set up search service integration
- Add discovery result caching
- Explore protocol negotiation example
