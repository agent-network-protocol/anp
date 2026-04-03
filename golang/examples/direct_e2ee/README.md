# Direct E2EE Alice/Bob Example

This example demonstrates a complete two-party direct E2EE flow using the Go SDK.

## What it covers

- create Alice and Bob DID documents with E2EE keys
- publish Bob's prekey bundle through an in-memory RPC boundary
- let Alice initiate a direct E2EE session
- send a follow-up encrypted message from Alice to Bob
- process Bob's inbox out of order to demonstrate pending-message handling
- send a reply from Bob back to Alice over the established session
- decrypt Alice's history page

## Run

```bash
go run ./examples/direct_e2ee
```

## Output

The example prints each major step in English, including:

- bundle publication
- init-message send
- follow-up send
- pending state for out-of-order delivery
- successful decryption results for Bob and Alice
