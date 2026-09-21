# DID Web SDK support

The Python, Rust and Go SDKs resolve `did:web`, authenticate it using the existing
HTTP Message Signature flow, and build public multi-device documents without a
WBA binding root. Host publication, account admission and administrator approval
remain application responsibilities. A valid public document alone grants none
of those permissions.

## Public operations

| Operation | Python / Rust | Go |
|---|---|---|
| Resolve | `resolve_did_document` | `ResolveDidDocument` |
| Construct the resource URL | `build_did_web_resolution_url` | `BuildDIDWebResolutionURL` |
| Build a public device document | `build_web_did_document` | `BuildWebDIDDocument` |
| Add a fresh device | `add_device_to_web_did_document` | `AddDeviceToWebDIDDocument` |
| Remove a device | `remove_device_from_web_did_document` | `RemoveDeviceFromWebDIDDocument` |

The new device helpers take the same public device entry and public verification
methods as the existing vNext helpers, with no root arguments. Add requires the
caller's durable retired-device-ID set. They return an unsigned copy, preserve
ordinary fields and extensions, and remove a stale top-level proof after mutation.
They validate Ed25519 assertion keys for P5/P6, X25519 agreement keys, verification
purposes, controller/KID ownership and distinct public key material. They never
generate, export or store private keys. Web API and assertion-only Group documents
do not need a device Manifest; the device helpers apply only when managing devices.

Current P6 declarations can use `core.binding.v1`, `identity.discovery.v1`,
`group.base.v2` and `group.e2ee.v2`. Existing P4 v1/P6 documents and all-v2 legacy
draft documents remain readable. All-v2 legacy foundation profiles remain
read-only. Existing WBA builders and service profile defaults retain their output;
new callers explicitly provide the current profile set.

Proof readers also accept the frozen WBA E1 `eddsa-jcs-2022` multibase format,
including the document `@context` in the proof configuration. Existing base64url
proof generation and verification bytes remain unchanged. The shared E1 fixture
checks current-format reading, context tampering, and the existing WBA regression
suites check the legacy format. Typed raw 32-byte `X25519KeyAgreementKey2019`
material remains readable; an untyped `Multikey` still needs its codec prefix.

## Resolution boundary

The resource mapping accepts a DNS hostname, an optional percent-encoded port and
percent-encoded UTF-8 path segments. It rejects empty/dot segments, malformed
encoding, IP literals, embedded separators, query/fragment delimiters and controls.
It re-encodes each segment exactly once. For example:

```text
did:web:example.com%3A8443:users:alice
https://example.com:8443/users/alice/did.json
```

Production resolution verifies TLS, uses the checked DNS addresses for the actual
connection, rejects non-public destinations, disables ambient proxy discovery,
requires HTTP 200 and an exact document `id`, and caps the decoded response at
1 MiB. Redirects are rejected. The existing timeout option applies to resolution.
The explicit `base_url_override` / `BaseURLOverride` option is trusted host/test
configuration and permits a controlled local endpoint; it must never come from a
peer document. Disabling certificate verification is permitted only with that
override. Real deployment acceptance must use the actual HTTPS URL.

`validate_did_document_method` / `ValidateDIDDocumentMethod` checks method rules
on an already trusted resolution result. It does not prove HTTPS provenance or
replace `authentication`, `assertionMethod`, device eligibility or account checks.
WBA E1 binding/proof rules stay inside the WBA branch. A Web path that happens to
start with `e1_` or `k1_` is a Web path, not a WBA binding profile.
Rust's `verify_proof=true` validates an existing Web document proof in both
the resolver and the offline method validator; an absent proof is allowed.
This uses the existing W3C proof verifier and does not grant a key relationship.

The existing `DidWbaVerifier` name is retained for compatibility. Its HTTP Message
Signature path dispatches WBA/Web resolution and accepts Web subjects in its
Bearer exchange. Legacy DIDWba authorization behavior and WBA error semantics
remain unchanged. This does not add a new wire authentication scheme.

Web Handle verification uses the existing provider-domain contract: the active
forward record names the exact Web DID, and that DID document declares an
`ANPHandleService` HTTPS endpoint on the real Handle Provider domain. The Web
identity host may differ from that domain. Missing declarations, a different
provider, non-HTTPS declarations and mismatched document IDs fail without exposing
a verified generation. This evidence does not prove an exact Handle endpoint,
account admission, permission inheritance or continuity across a DID change.
The existing WBA domain rule is retained.

## Verification assets

[Shared public lifecycle fixtures](../fixtures/did-method-lifecycle-v1.json)
cover rootless one/two-device Web documents, current P5/P6 profiles, an API
document without a Manifest, an assertion-only Group document and a WBA E1
comparison document. No live identity or private key is included.

The owning suites are Python `test_did_web_{resolution,lifecycle,verifier}.py`,
Rust `did_web_{resolution,lifecycle,verifier}` integration targets and the Go
`authentication` package's Web tests. They cover URL/HTTP boundaries, public key
validation, build/join/revoke results, HTTP body/target tampering, replay and
assertion-versus-authentication purposes. Product registration and real service
interoperability require their separate owning tests.
