# Protocol Negotiation Example

This example demonstrates meta-protocol negotiation between two agents.

## What This Example Shows

- Creating negotiation state machines
- Proposing candidate protocols
- Handling negotiation rounds
- Reaching protocol agreement
- Code generation phase
- Test case negotiation
- Communication with agreed protocol

## Running the Example

```bash
npm install
npm start
```

## Negotiation Flow

### 1. Initialization
- Both agents create DID identities
- Each agent creates a negotiation state machine
- Machines start in idle state

### 2. Proposal
- Agent A proposes candidate protocols
- Machine transitions to negotiating state
- Proposal sent to Agent B

### 3. Negotiation Rounds
- Agent B evaluates proposals
- Finds common protocols
- May counter-propose or accept
- Multiple rounds until agreement

### 4. Code Generation
- Both agents generate protocol implementation
- Machines transition to codeGeneration state
- Code verified and loaded

### 5. Test Cases
- Agents agree on test cases
- Test cases define expected behavior
- Both agents must pass tests

### 6. Testing
- Execute agreed test cases
- Verify protocol implementation
- Handle failures with error negotiation

### 7. Ready
- All tests passed
- Machines transition to ready state
- Ready for production communication

### 8. Communication
- Agents communicate using agreed protocol
- State machine monitors for errors
- Can trigger error negotiation if needed

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

## Configuration Options

```typescript
{
  localIdentity: DIDIdentity,      // Your agent's identity
  remoteDID: string,               // Remote agent's DID
  candidateProtocols: string,      // Comma-separated protocols
  maxNegotiationRounds: number,    // Max rounds before timeout
  onStateChange: (state) => void   // State change callback
}
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
