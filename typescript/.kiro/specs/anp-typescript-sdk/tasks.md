# Implementation Plan

**CRITICAL**: All implementation MUST be done in the `ts_sdk` directory at the project root. Create this directory first before starting any development work.

- [x] 1. Project Setup and Infrastructure
  - Create `ts_sdk` directory at project root
  - Initialize TypeScript project in `ts_sdk` with proper configuration for ESM and CommonJS
  - Set up Vitest testing framework with coverage reporting
  - Configure build tools (tsup or rollup) for bundling
  - Set up linting (ESLint) and formatting (Prettier)
  - Create project structure: `ts_sdk/src/`, `ts_sdk/tests/`, `ts_sdk/examples/`, `ts_sdk/docs/`
  - Create subdirectories: `src/core/`, `src/protocol/`, `src/crypto/`, `src/transport/`, `src/types/`, `src/errors/`
  - Configure GitHub Actions for CI/CD
  - _Requirements: 10.1, 11.1_

- [x] 2. Cryptography Module Implementation
  - All code in `ts_sdk/src/crypto/` directory
  - All tests in `ts_sdk/tests/unit/crypto/` directory
  - _Requirements: 1.1, 1.3, 7.1, 7.2, 7.3, 7.4_

- [x] 2.1 Write unit tests for key generation
  - Create test file `ts_sdk/tests/unit/crypto/key-generation.test.ts`
  - Test ECDSA secp256k1 key pair generation
  - Test Ed25519 key pair generation
  - Test X25519 key pair generation
  - Test key format validation (JWK and Multibase)
  - Test error handling for invalid key types
  - _Requirements: 11.2_

- [x] 2.2 Implement key generation functions
  - Create `ts_sdk/src/crypto/key-generation.ts`
  - Implement generateKeyPair for ECDSA secp256k1
  - Implement generateKeyPair for Ed25519
  - Implement generateKeyPair for X25519
  - Implement key format conversion utilities
  - _Requirements: 1.1_

- [x] 2.3 Write unit tests for signing and verification
  - Test signing with ECDSA secp256k1
  - Test signing with Ed25519
  - Test signature verification with valid signatures
  - Test signature verification with invalid signatures
  - Test error handling for mismatched keys
  - _Requirements: 11.2_

- [x] 2.4 Implement signing and verification functions
  - Implement sign function for ECDSA secp256k1
  - Implement sign function for Ed25519
  - Implement verify function for both key types
  - Implement signature encoding/decoding
  - _Requirements: 1.3, 1.5_

- [x] 2.5 Write unit tests for ECDHE key exchange
  - Test key exchange with X25519 keys
  - Test shared secret derivation
  - Test key derivation function
  - Test error handling for invalid keys
  - _Requirements: 11.2_

- [x] 2.6 Implement ECDHE key exchange
  - Implement performKeyExchange function
  - Implement deriveKey function using HKDF
  - Implement shared secret validation
  - _Requirements: 7.1, 7.2_

- [x] 2.7 Write unit tests for encryption and decryption
  - Test AES-GCM encryption
  - Test AES-GCM decryption
  - Test IV generation
  - Test authentication tag validation
  - Test error handling for corrupted data
  - _Requirements: 11.2_

- [x] 2.8 Implement encryption and decryption functions
  - Implement encrypt function using AES-GCM
  - Implement decrypt function
  - Implement IV generation
  - Implement error handling for decryption failures
  - _Requirements: 7.3, 7.4, 7.5_

- [x] 3. DID Manager Implementation
  - All code in `ts_sdk/src/core/did/` directory
  - All tests in `ts_sdk/tests/unit/core/did/` directory
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

- [x] 3.1 Write unit tests for DID creation
  - Create test file `ts_sdk/tests/unit/core/did/did-manager.test.ts`
  - Test DID identifier construction from domain
  - Test DID identifier construction with path
  - Test DID identifier with port encoding
  - Test DID document generation
  - Test verification method creation
  - Test error handling for invalid domains
  - _Requirements: 11.2_

- [x] 3.2 Implement DID creation
  - Create `ts_sdk/src/core/did/did-manager.ts`
  - Create `ts_sdk/src/types/did.ts` for type definitions
  - Implement createDID function
  - Implement DID identifier construction
  - Implement DID document generation
  - Implement verification method creation
  - Add authentication and keyAgreement sections
  - _Requirements: 1.1, 1.2_

- [x] 3.3 Write unit tests for DID resolution
  - Test resolution from .well-known path
  - Test resolution from custom path
  - Test resolution with port
  - Test caching mechanism
  - Test error handling for 404 responses
  - Test error handling for invalid documents
  - _Requirements: 11.2_

- [x] 3.4 Implement DID resolution
  - Implement resolveDID function
  - Implement URL construction from DID
  - Implement HTTP fetching with retry
  - Implement DID document validation
  - Implement caching with TTL
  - _Requirements: 1.4, 9.2_

- [x] 3.5 Write unit tests for DID operations
  - Test signing with DID identity
  - Test verification with resolved DID
  - Test export of DID document
  - Test error handling for missing keys
  - _Requirements: 11.2_

- [x] 3.6 Implement DID operations
  - Implement sign method using crypto module
  - Implement verify method using crypto module
  - Implement exportDocument method
  - Integrate with cryptography module
  - _Requirements: 1.3, 1.5_

- [x] 4. Authentication Manager Implementation
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

- [x] 4.1 Write unit tests for auth header generation
  - Test header format compliance
  - Test nonce generation uniqueness
  - Test timestamp format
  - Test signature generation
  - Test verification method selection
  - _Requirements: 11.2, 11.4_

- [x] 4.2 Implement auth header generation
  - Implement generateAuthHeader function
  - Implement nonce generation
  - Implement timestamp generation
  - Implement signature data construction
  - Implement header formatting
  - _Requirements: 2.1_

- [x] 4.3 Write unit tests for auth header verification
  - Test successful verification
  - Test DID resolution during verification
  - Test signature verification
  - Test nonce replay prevention
  - Test timestamp validation with clock skew
  - Test expired timestamp rejection
  - _Requirements: 11.2, 11.4_

- [x] 4.4 Implement auth header verification
  - Implement verifyAuthHeader function
  - Implement header parsing
  - Implement DID resolution
  - Implement signature verification
  - Implement nonce tracking
  - Implement timestamp validation
  - _Requirements: 2.2, 9.3_

- [x] 4.5 Write unit tests for token management
  - Test token generation
  - Test token validation
  - Test token expiration
  - Test token format
  - _Requirements: 11.2, 11.4_

- [x] 4.6 Implement token management
  - Implement generateAccessToken function
  - Implement verifyAccessToken function
  - Implement JWT or similar token format
  - Implement token expiration checking
  - _Requirements: 2.3, 2.4, 2.5_

- [x] 5. HTTP Client Implementation
  - _Requirements: 2.1, 2.4, 9.1_

- [x] 5.1 Write unit tests for HTTP client
  - Test GET requests
  - Test POST requests
  - Test authenticated requests
  - Test retry mechanism
  - Test timeout handling
  - Test error handling
  - _Requirements: 11.2_

- [x] 5.2 Implement HTTP client
  - Implement request method with authentication
  - Implement GET and POST convenience methods
  - Implement retry with exponential backoff
  - Implement timeout handling
  - Integrate with authentication manager
  - _Requirements: 2.1, 2.4, 9.1_

- [x] 6. Protocol Message Handler Implementation
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5_

- [x] 6.1 Write unit tests for message encoding
  - Test meta-protocol message encoding
  - Test application protocol message encoding
  - Test natural language message encoding
  - Test verification protocol message encoding
  - Test binary format correctness
  - _Requirements: 11.2_

- [x] 6.2 Implement message encoding
  - Implement encode function
  - Implement protocol type header construction
  - Implement message serialization
  - _Requirements: 6.1, 6.3_

- [x] 6.3 Write unit tests for message decoding
  - Test meta-protocol message decoding
  - Test application protocol message decoding
  - Test natural language message decoding
  - Test verification protocol message decoding
  - Test error handling for malformed messages
  - _Requirements: 11.2_

- [x] 6.4 Implement message decoding
  - Implement decode function
  - Implement protocol type extraction
  - Implement message deserialization
  - Implement error handling
  - _Requirements: 6.2, 6.4, 6.5_

- [x] 6.5 Write unit tests for meta-protocol message parsing
  - Test protocolNegotiation message parsing
  - Test codeGeneration message parsing
  - Test testCasesNegotiation message parsing
  - Test fixErrorNegotiation message parsing
  - Test naturalLanguageNegotiation message parsing
  - _Requirements: 11.2_

- [x] 6.6 Implement meta-protocol message parsing
  - Implement parseMetaProtocol function
  - Implement JSON parsing and validation
  - Implement message type discrimination
  - _Requirements: 5.1, 5.2_

- [x] 7. Meta-Protocol State Machine Implementation
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 8.1, 8.2, 8.3, 8.4, 8.5_

- [x] 7.1 Write unit tests for state machine initialization
  - Test machine creation with config
  - Test initial state
  - Test context initialization
  - _Requirements: 11.2, 11.3_

- [x] 7.2 Implement state machine setup
  - Define state machine schema with XState v5
  - Implement context type definitions
  - Implement event type definitions
  - Create machine factory function
  - _Requirements: 5.1_

- [x] 7.3 Write unit tests for negotiation flow
  - Test initiate event handling
  - Test receive_request event handling
  - Test negotiate event handling
  - Test accept transition
  - Test reject transition
  - Test timeout handling
  - Test max rounds enforcement
  - _Requirements: 11.2, 11.3_

- [x] 7.4 Implement negotiation states and transitions
  - Implement Idle state
  - Implement Negotiating state
  - Implement negotiation guards
  - Implement negotiation actions
  - Implement sequence ID increment
  - Implement max rounds checking
  - _Requirements: 5.1, 5.2, 5.5_

- [x] 7.5 Write unit tests for code generation flow
  - Test code_ready event handling
  - Test code_error event handling
  - Test transition to TestCases state
  - Test transition to Failed state
  - _Requirements: 11.2, 11.3_

- [x] 7.6 Implement code generation states
  - Implement CodeGeneration state
  - Implement code generation actions
  - Implement error handling
  - _Requirements: 5.3, 5.4_

- [x] 7.7 Write unit tests for test cases flow
  - Test tests_agreed event handling
  - Test skip_tests event handling
  - Test tests_passed event handling
  - Test tests_failed event handling
  - _Requirements: 11.2, 11.3_

- [x] 7.8 Implement test cases states
  - Implement TestCases state
  - Implement Testing state
  - Implement test execution actions
  - _Requirements: 8.1, 8.2, 8.3_

- [x] 7.9 Write unit tests for error fixing flow
  - Test fix_accepted event handling
  - Test fix_rejected event handling
  - Test transition back to CodeGeneration
  - Test transition to Failed state
  - _Requirements: 11.2, 11.3_

- [x] 7.10 Implement error fixing states
  - Implement FixError state
  - Implement error negotiation actions
  - Implement fix acceptance logic
  - _Requirements: 8.4, 8.5_

- [x] 7.11 Write unit tests for communication flow
  - Test start_communication event handling
  - Test protocol_error event handling
  - Test end event handling
  - _Requirements: 11.2, 11.3_

- [x] 7.12 Implement communication states
  - Implement Ready state
  - Implement Communicating state
  - Implement protocol error handling
  - Implement cleanup on end
  - _Requirements: 5.1, 9.4_

- [x] 7.13 Write unit tests for message sending
  - Test sendNegotiation function
  - Test message construction
  - Test message encryption
  - Test message transmission
  - _Requirements: 11.2, 11.3_

- [x] 7.14 Implement message sending
  - Implement sendNegotiation function
  - Integrate with protocol message handler
  - Integrate with HTTP client
  - Implement error handling
  - _Requirements: 5.1, 5.2_

- [x] 7.15 Write unit tests for message processing
  - Test processMessage function
  - Test message decoding
  - Test state machine event dispatch
  - Test error handling
  - _Requirements: 11.2, 11.3_

- [x] 7.16 Implement message processing
  - Implement processMessage function
  - Integrate with protocol message handler
  - Implement event mapping
  - Implement error handling
  - _Requirements: 5.2, 6.5_

- [x] 8. Agent Description Manager Implementation
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 8.1 Write unit tests for description creation
  - Test createDescription function
  - Test required fields validation
  - Test security definitions
  - Test JSON-LD context
  - _Requirements: 11.2_

- [x] 8.2 Implement description creation
  - Implement createDescription function
  - Implement metadata validation
  - Implement JSON-LD structure generation
  - Implement security definitions setup
  - _Requirements: 3.1_

- [x] 8.3 Write unit tests for adding resources
  - Test addInformation function
  - Test addInterface function
  - Test resource validation
  - Test duplicate prevention
  - _Requirements: 11.2_

- [x] 8.4 Implement adding resources
  - Implement addInformation function
  - Implement addInterface function
  - Implement resource validation
  - _Requirements: 3.2, 3.3_

- [x] 8.5 Write unit tests for description signing
  - Test signDescription function
  - Test proof generation
  - Test JCS canonicalization
  - Test signature verification
  - _Requirements: 11.2_

- [x] 8.6 Implement description signing
  - Implement signDescription function
  - Implement JCS canonicalization
  - Implement proof object generation
  - Integrate with crypto module
  - _Requirements: 3.4_

- [x] 8.7 Write unit tests for description fetching
  - Test fetchDescription function
  - Test HTTP fetching
  - Test JSON-LD parsing
  - Test error handling
  - _Requirements: 11.2_

- [x] 8.8 Implement description fetching
  - Implement fetchDescription function
  - Integrate with HTTP client
  - Implement JSON-LD parsing
  - Implement validation
  - _Requirements: 3.5_

- [x] 8.9 Write unit tests for description verification
  - Test verifyDescription function
  - Test proof verification
  - Test domain validation
  - Test challenge validation
  - _Requirements: 11.2_

- [x] 8.10 Implement description verification
  - Implement verifyDescription function
  - Implement proof verification
  - Implement domain and challenge validation
  - _Requirements: 3.5_

- [x] 9. Agent Discovery Manager Implementation
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

- [x] 9.1 Write unit tests for active discovery
  - Test discoverAgents function
  - Test .well-known URL construction
  - Test discovery document parsing
  - Test pagination handling
  - Test error handling
  - _Requirements: 11.2_

- [x] 9.2 Implement active discovery
  - Implement discoverAgents function
  - Implement URL construction
  - Implement discovery document fetching
  - Implement pagination recursion
  - _Requirements: 4.1, 4.2_

- [x] 9.3 Write unit tests for passive discovery
  - Test registerWithSearchService function
  - Test registration request construction
  - Test authentication
  - Test error handling
  - _Requirements: 11.2_

- [x] 9.4 Implement passive discovery
  - Implement registerWithSearchService function
  - Implement registration request
  - Integrate with authentication
  - _Requirements: 4.3_

- [x] 9.5 Write unit tests for agent search
  - Test searchAgents function
  - Test query construction
  - Test result parsing
  - Test error handling
  - _Requirements: 11.2_

- [x] 9.6 Implement agent search
  - Implement searchAgents function
  - Implement query construction
  - Implement result parsing
  - _Requirements: 4.4, 4.5_

- [x] 10. Public API Implementation
  - Main entry point at `ts_sdk/src/index.ts`
  - All tests in `ts_sdk/tests/unit/api/` directory
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_

- [x] 10.1 Write unit tests for ANPClient initialization
  - Create test file `ts_sdk/tests/unit/api/anp-client.test.ts`
  - Test constructor with default config
  - Test constructor with custom config
  - Test module initialization
  - _Requirements: 11.2_

- [x] 10.2 Implement ANPClient class
  - Create `ts_sdk/src/index.ts` as main entry point
  - Create `ts_sdk/src/anp-client.ts` for ANPClient class
  - Implement constructor
  - Implement config validation
  - Initialize all managers
  - Create public API namespaces
  - _Requirements: 10.1_

- [x] 10.3 Write unit tests for DID API
  - Test did.create
  - Test did.resolve
  - Test did.sign
  - Test did.verify
  - _Requirements: 11.2_

- [x] 10.4 Implement DID API
  - Implement did namespace methods
  - Delegate to DID manager
  - Add error handling
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

- [x] 10.5 Write unit tests for Agent API
  - Test agent.createDescription
  - Test agent.addInformation
  - Test agent.addInterface
  - Test agent.signDescription
  - Test agent.fetchDescription
  - _Requirements: 11.2_

- [x] 10.6 Implement Agent API
  - Implement agent namespace methods
  - Delegate to agent description manager
  - Add error handling
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 10.7 Write unit tests for Discovery API
  - Test discovery.discoverAgents
  - Test discovery.registerWithSearchService
  - Test discovery.searchAgents
  - _Requirements: 11.2_

- [x] 10.8 Implement Discovery API
  - Implement discovery namespace methods
  - Delegate to discovery manager
  - Add error handling
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_

- [x] 10.9 Write unit tests for Protocol API
  - Test protocol.createNegotiationMachine
  - Test protocol.sendMessage
  - Test protocol.receiveMessage
  - _Requirements: 11.2_

- [x] 10.10 Implement Protocol API
  - Implement protocol namespace methods
  - Delegate to meta-protocol machine
  - Add error handling
  - _Requirements: 5.1, 5.2, 6.1, 6.2_

- [x] 10.11 Write unit tests for HTTP API
  - Test http.request
  - Test http.get
  - Test http.post
  - _Requirements: 11.2_

- [x] 10.12 Implement HTTP API
  - Implement http namespace methods
  - Delegate to HTTP client
  - Add error handling
  - _Requirements: 2.1, 2.4_

- [x] 11. Integration Tests
  - All integration tests in `ts_sdk/tests/integration/` directory
  - _Requirements: 11.5_

- [x] 11.1 Write end-to-end authentication integration test
  - Create test file `ts_sdk/tests/integration/authentication.test.ts`
  - Create two DID identities
  - Perform initial authentication
  - Verify token exchange
  - Make authenticated requests
  - Verify access control
  - _Requirements: 11.5_

- [x] 11.2 Write agent discovery integration test
  - Create agent description
  - Publish to mock server
  - Discover agents from domain
  - Register with search service
  - Search for agents
  - _Requirements: 11.5_

- [x] 11.3 Write protocol negotiation integration test
  - Create two agents
  - Initiate negotiation
  - Exchange multiple rounds
  - Reach agreement
  - Generate code (mocked)
  - Execute tests
  - Communicate with agreed protocol
  - _Requirements: 11.5_

- [x] 11.4 Write encrypted communication integration test
  - Create two DID identities with keyAgreement
  - Establish encrypted channel
  - Send encrypted messages
  - Receive and decrypt messages
  - Verify end-to-end encryption
  - _Requirements: 11.5_

- [x] 12. Documentation and Examples
  - All documentation in `ts_sdk/docs/` directory
  - All examples in `ts_sdk/examples/` directory
  - Main README at `ts_sdk/README.md`
  - _Requirements: 10.1_

- [x] 12.1 Write API documentation
  - Create `ts_sdk/docs/` directory
  - Generate TypeDoc documentation
  - Write `ts_sdk/docs/getting-started.md`
  - Write `ts_sdk/docs/api-reference.md`
  - Document configuration options in `ts_sdk/docs/configuration.md`
  - Document error codes in `ts_sdk/docs/errors.md`

- [x] 12.2 Create example applications
  - Create `ts_sdk/examples/simple-agent/` directory with example
  - Create `ts_sdk/examples/authentication/` directory with example
  - Create `ts_sdk/examples/discovery/` directory with example
  - Create `ts_sdk/examples/protocol-negotiation/` directory with example
  - Create `ts_sdk/examples/encrypted-communication/` directory with example

- [x] 12.3 Write README and contributing guide
  - Write comprehensive `ts_sdk/README.md`
  - Document installation
  - Document basic usage
  - Write `ts_sdk/CONTRIBUTING.md`
  - Document development setup

- [x] 13. Build and Release
  - All build configuration in `ts_sdk/` directory
  - _Requirements: 10.1_

- [x] 13.1 Configure build process
  - Create `ts_sdk/tsup.config.ts` or `ts_sdk/rollup.config.js`
  - Configure ESM and CommonJS outputs
  - Configure type definitions generation
  - Test build outputs in `ts_sdk/dist/`

- [x] 13.2 Prepare for npm release
  - Configure `ts_sdk/package.json` with proper metadata
  - Add npm scripts for build, test, and publish
  - Test package installation from `ts_sdk/`
  - Create `ts_sdk/CHANGELOG.md`
  - Create release notes
