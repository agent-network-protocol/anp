# Agent Discovery Example

This example demonstrates how to discover other agents in the ANP network.

## What This Example Shows

- Active discovery from domains
- Passive discovery via search services
- Fetching agent descriptions
- Search functionality
- Discovery best practices

## Running the Example

```bash
npm install
npm start
```

## Discovery Methods

### Active Discovery

Fetch agents directly from a domain's well-known endpoint:

```
https://example.com/.well-known/agent-descriptions
```

**Use Cases:**
- Discovering agents in your organization's domain
- Finding agents from known partners
- Exploring agents in specific domains

### Passive Discovery

Register your agent with search services and search for other agents:

**Registration:**
- Submit your agent description URL to search services
- Search services index your agent
- Other agents can find you through search

**Search:**
- Query search services with keywords and filters
- Receive matching agent descriptions
- Fetch full descriptions for interesting agents

## Discovery Flow

1. **Create Agent Identity**: Create DID for your agent
2. **Create Description**: Define your agent's capabilities
3. **Publish Description**: Host description at public URL
4. **Register**: Submit to search services (passive)
5. **Discover**: Find other agents (active or search)
6. **Fetch Details**: Get full agent descriptions
7. **Verify**: Validate signatures and capabilities

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
