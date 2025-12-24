# Protocol Negotiation Example

This example demonstrates meta-protocol negotiation between two agents using XState v5 state machines.

## What This Example Shows

- Creating XState v5 negotiation state machines
- Proposing candidate protocols
- Handling negotiation rounds with state transitions
- Reaching protocol agreement
- State machine event handling
- Protocol selection logic
- Complete negotiation lifecycle

## Running the Example

From the `ts_sdk` directory:

```bash
npm run build
npx tsx examples/protocol-negotiation/index.ts
```

Or from this directory:

```bash
npm install
npm start
```

## Expected Output

```
=== Protocol Negotiation Example ===

Creating agent identities...
✓ Agent A: did:wba:localhost:9000:agent-a
✓ Agent B: did:wba:localhost:9001:agent-b

Creating negotiation state machines...
✓ State machines created

Starting negotiation...

Agent A proposes: JSON-RPC 2.0, gRPC, GraphQL

Agent B receives and finds common protocol: GraphQL

Both agents accept GraphQL

Generating protocol implementation...
✓ Code generation complete

=== Example Complete ===

Negotiation Result:
- Agreed Protocol: GraphQL
- Both agents ready to communicate
- State machines ensure predictable flow
```

## Example Flow

This example demonstrates a simplified negotiation:

### 1. Initialization
- Agent A creates DID: `did:wba:agentA.example.com:agent1`
- Agent B creates DID: `did:wba:agentB.example.com:agent1`
- Both create XState v5 state machines
- Machines start in **idle** state

### 2. Agent A Initiates
- Proposes: `"JSON-RPC, gRPC, GraphQL"`
- Machine transitions to **negotiating** state
- Sends protocolNegotiation message to Agent B

### 3. Agent B Responds
- Receives proposal
- Evaluates candidate protocols
- Finds common protocol: `"GraphQL"`
- Sends acceptance message
- Machine transitions to **negotiating** state

### 4. Agreement Reached
- Agent A receives acceptance
- Both machines transition to **codeGeneration** state
- Protocol agreed: `"GraphQL"`

### 5. Code Generation
- Both agents generate protocol implementation
- Machines emit `code_ready` event
- Transition to **testCases** state

### 6. Test Cases (Optional)
- Agents can negotiate test cases
- Or skip directly to **ready** state
- Example skips tests for simplicity

### 7. Ready State
- Both machines in **ready** state
- Ready for production communication
- Can emit `start_communication` to begin

### 8. Communication
- Machines transition to **communicating** state
- Agents exchange messages using GraphQL
- State machine monitors for protocol errors

## State Machine States

- **idle**: Initial state, waiting to start
- **negotiating**: Exchanging protocol proposals
- **codeGeneration**: Generating protocol implementation
- **testCases**: Agreeing on test cases
- **testing**: Running test cases
- **fixError**: Handling test failures
- **ready**: Ready for communication
- **communicating**: Active communication
- **rejected**: Negotiation failed
- **failed**: Unrecoverable error

## State Machine Configuration

```typescript
interface MetaProtocolConfig {
  localIdentity: DIDIdentity;      // Your agent's DID identity
  remoteDID: string;               // Remote agent's DID
  candidateProtocols: string;      // Comma-separated protocols
  maxNegotiationRounds: number;    // Max rounds (default: 5)
}
```

## Creating a State Machine

```typescript
const machine = MetaProtocolMachine.create({
  localIdentity: myIdentity,
  remoteDID: 'did:wba:other.example.com:agent1',
  candidateProtocols: 'JSON-RPC, gRPC, GraphQL',
  maxNegotiationRounds: 5,
});

// Subscribe to state changes
machine.subscribe((state) => {
  console.log('Current state:', state.value);
  console.log('Context:', state.context);
});

// Send events
machine.send({ type: 'initiate', remoteDID: '...', candidateProtocols: '...' });
```

## Best Practices

### Protocol Selection
- Propose multiple protocols in order of preference
- Include widely-supported protocols
- Consider performance and complexity trade-offs

### Negotiation Strategy
- Start with preferred protocols
- Be willing to compromise
- Set reasonable max rounds (3-5)

### Code Generation
- Validate generated code before use
- Implement error handling
- Test thoroughly

### Test Cases
- Cover common use cases
- Include edge cases
- Keep tests focused and fast

### Error Handling
- Monitor for protocol errors during communication
- Implement error negotiation
- Have fallback protocols ready

## Common Patterns

### Quick Agreement
```
A: "GraphQL"
B: "GraphQL" (accepts)
→ Agreement in 1 round
```

### Negotiation
```
A: "JSON-RPC, gRPC, GraphQL"
B: "REST, GraphQL, WebSocket"
→ Common: GraphQL
→ Agreement in 2 rounds
```

### No Agreement
```
A: "JSON-RPC, gRPC"
B: "REST, WebSocket"
→ No common protocols
→ Rejected after max rounds
```

## Troubleshooting

### Negotiation Timeout
- Increase maxNegotiationRounds
- Simplify protocol proposals
- Check network connectivity

### Code Generation Fails
- Verify protocol specifications
- Check for syntax errors
- Ensure dependencies available

### Test Failures
- Review test case definitions
- Check protocol implementation
- Use error negotiation to fix

## Next Steps

- Implement custom protocol handlers
- Add protocol versioning
- Explore encrypted communication
- Build production agent applications
