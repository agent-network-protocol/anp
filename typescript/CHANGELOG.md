# Changelog

All notable changes to the ANP TypeScript SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of ANP TypeScript SDK
- DID:WBA identity management
  - Create and manage DID:WBA identities
  - DID document generation and resolution
  - Signing and verification with DID identities
- HTTP authentication with DID:WBA
  - Initial authentication with signature
  - Access token generation and validation
  - Nonce replay prevention
  - Timestamp validation with clock skew tolerance
- Agent Description Protocol (ADP) support
  - Create and manage agent description documents
  - Add information resources and interfaces
  - Sign and verify agent descriptions
  - Fetch agent descriptions from URLs
- Agent Discovery Service Protocol (ADSP) support
  - Active discovery from domains
  - Passive discovery via search services
  - Agent search functionality
  - Pagination support
- Meta-protocol negotiation state machine
  - Protocol negotiation flow
  - Code generation coordination
  - Test case negotiation
  - Error fixing negotiation
  - XState v5 based state management
- End-to-end encryption
  - ECDHE key exchange
  - AES-GCM encryption/decryption
  - Key derivation with HKDF
- Cryptography module
  - Key generation (ECDSA secp256k1, Ed25519, X25519)
  - Digital signatures
  - Signature verification
  - Encryption and decryption
- HTTP client with authentication
  - Automatic authentication header injection
  - Retry with exponential backoff
  - Timeout handling
- Comprehensive test suite
  - Unit tests for all modules
  - Integration tests for end-to-end flows
  - 80%+ code coverage
- Documentation
  - Getting started guide
  - API reference
  - Configuration guide
  - Error handling guide
  - Example applications
- TypeScript support
  - Full type definitions
  - ESM and CommonJS support
  - Source maps for debugging

## [0.1.0] - 2024-01-XX

### Added
- Initial development release
- Core functionality for ANP protocol implementation
- Basic documentation and examples

[Unreleased]: https://github.com/chgaowei/AgentNetworkProtocol/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/chgaowei/AgentNetworkProtocol/releases/tag/v0.1.0
