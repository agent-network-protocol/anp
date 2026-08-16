# Changelog

## 0.2.0

- Add the high-level AWiki IM client for Legacy single-device registration, direct and existing-group messaging, history, and P7 attachments.
- Add durable, restart-safe idempotency state for text and attachment sends.
- Add strict JSON-RPC, message acknowledgement, history membership, attachment ticket, digest, and size validation.
- Add explicit User Service domain, public Message Service endpoint and DID, attachment origin allowlist, and attachment size limit configuration.
- Add public WNS display-name reads and updates, persist refreshed direct-peer profiles, and expose sender display names for group history.
- Add conversation unread counts and newest-message previews, including bounded Legacy group-history refresh and read acknowledgement.
- Make client disposal abort network work and join every operation that already entered the client before settling.
- Export `createAwikiImClient`, `AwikiImError`, and all AWiki IM public types from the package root.

## 0.1.0

- Initial authentication, proof, and WNS TypeScript SDK.
