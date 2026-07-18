# Group E2EE fixtures

- `did_wba_binding_golden.json` is the retained P6 v1 Object Proof vector.
- `p6_v2_wire_vectors.json` is the Rust/Go vNext wire, canonical
  `authenticated_data`, membership-submission binding, and inner plaintext
  vector frozen against protocol commit
  `25bfbc59a5a925141b565c4bc6c24195736382b5b`.

The v2 fixture's KeyPackage bytes and proof strings are contract-vector
placeholders for DTO/canonicalization tests. They are not claimed to be a
cryptographically valid MLS KeyPackage. Binding-verifier tests generate real
Ed25519 DID/Object Proof material and feed an independently authenticated MLS
leaf projection. Production callers must do the same after real TLS/OpenMLS
parsing; they must never trust the outer convenience JSON alone.
