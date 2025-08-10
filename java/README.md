# AgentConnect4Java

This is a Java implementation of the Python AgentConnect codebase. It provides functionality for DID (Decentralized Identifier) generation, authentication, and cryptographic operations.

## Project Structure

The project is organized into the following packages:

- `com.agentconnect.authentication`: Contains classes for DID authentication
- `com.agentconnect.utils`: Contains utility classes for cryptographic operations and other helper functions
- `test`: This directory primarily contains the unit test class DIDWBAUnitTest, which verifies the correctness of several key functional methods.
- `test/java/com.agentconnect.test.example`: This directory features the DidWbaFullExample class, which provides a comprehensive DID identity verification example. This includes DID document generation, key storage, AuthHeader creation, signature signing/verification processes, and token validation/generation. It serves as an excellent entry-level learning resource for ANP4Java.
## Building the Project

This project uses Maven for dependency management. To build the project:

```bash
mvn clean package
```

## Dependencies

- BouncyCastle for cryptographic operations
- AsyncHttpClient for asynchronous HTTP requests
- Jackson for JSON processing
- NovaCrypto Base58 for Base58 encoding/decoding
- SLF4J and Logback for logging
- JSON Canonicalization Scheme for JSON canonicalization

## License

This project is open-sourced under the MIT License.

## Author

Original Python implementation by GaoWei Chang (chgaowei@gmail.com).