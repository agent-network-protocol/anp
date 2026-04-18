# Direct E2EE / X3DH Deferred

The Dart v1 package intentionally does not export direct E2EE, X3DH, ratchet, prekey bundle, encrypted-message client, or session-store APIs.

X25519 appears only as key material so DID documents can represent key-agreement material. X3DH/session behavior requires a separate ADR and implementation plan.
