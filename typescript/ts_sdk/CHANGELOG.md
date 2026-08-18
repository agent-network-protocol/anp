# Changelog

## 0.2.1 - 2026-08-18

- Export the vNext device-manifest profiles, data model, builder, and validator.
- Export RFC 9421 origin-proof generation and verification helpers.
- Verify the compiled package exposes the APIs required by AWiki Lite before packing.
- Document POSIX mode and Windows ACL requirements for plaintext identity state.

## 0.2.0 - 2026-08-16

- Add the high-level AWiki IM client for Legacy single-device registration, direct and existing-group messaging, history, and P7 attachments.
- Add durable, restart-safe idempotency state for text and attachment sends.
- Add strict JSON-RPC, message acknowledgement, history membership, attachment ticket, digest, and size validation.
- Add explicit User Service domain, public Message Service endpoint and DID, attachment origin allowlist, and attachment size limit configuration.
- Make client disposal abort network work and join every operation that already entered the client before settling.
- Export `createAwikiImClient`, `AwikiImError`, and all AWiki IM public types from the package root.

## 0.1.0

- Initial authentication, proof, and WNS TypeScript SDK.
