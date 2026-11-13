# HTTP authentication security vectors

The verification-only corpus in security_vectors_v1.json uses a fixed reference
clock and a public Ed25519 test identity. It contains no production credentials.
Consumers must supply the corpus clock rather than mutate signed timestamps.

The thirteen cases cover legitimate minimum coverage without authority, optional
expires/nonce, age and skew boundaries, expired/future signatures, missing target
or method, an unsigned body digest, an invalid lifetime, and genuine signed extension parameters. The nonce-free case
is valid for stateless verification only; complete authentication must still
consume an equivalent replay key.

Run each supported language's unit tests independently against this corpus. Do
not start servers, spawn another language's client, or use production endpoints.
Java's existing Legacy-only surface consumes separate applicable tests; lack of
an RFC 9421 entry point is not a successful HTTP-signature verification result.

The separate authority_compatibility_v1.json freezes the release/1030 source
serialization differences for explicit default ports and IPv6 brackets. It is
verification-only, with public fixture signatures, not a live old-client run.
Every accepted representation still signs the identical exact target URI.
Nonce-free replay keys use one canonical authority so switching an accepted
serializer cannot obtain another replay identity. New signing APIs retain their
existing serialization; compatibility is bounded to these redundant authority
representations, never an alternate target, method, digest or signed parameter.

legacy_compatibility_v1.json uses the unchanged Python release/1030 Legacy
header generator with explicit test-only timestamp/nonce and Ed25519 identity.
Java verifies the identical frozen header with its Policy clock. This documents
actual pre-existing signed bytes, not a new wire format or a Java RFC 9421 API.

Expanded IPv6 spellings are also frozen: all verifiers use the same compressed,
lowercase origin/replay authority, while retaining the exact signed target URI.
Mapped IPv6 URL aliases are rejected. Non-canonical numeric/zero-port Python
origins are rejected before credentials or the connector, including connector
versions that might otherwise treat ambiguous numeric hosts as IP literals.
