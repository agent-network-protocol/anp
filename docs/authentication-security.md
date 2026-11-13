# Authentication security boundaries

This document describes the security-hardening API contract for the six existing
language surfaces. Language-specific unit evidence belongs in the execution plan;
it does not imply registry publication, production deployment or live-network verification.

## Signature verification versus authentication

Python's verify_http_message_signature keeps its tuple return shape. Its default
HttpSignaturePolicy checks method/target coverage, signed body integrity and the
time window (300 seconds maximum age, 60 seconds future skew). Authority is not
mandatory. Expires and nonce retain their protocol optionality. Parameter
extensions remain part of the signed serialization, and ambiguous duplicates
are rejected. This does not establish the provenance of a supplied DID document.

The keyword arguments policy and now support explicit service windows and frozen
unit-test clocks. Historical cryptographic checks can explicitly use
HttpSignaturePolicy(check_time=False). That mode must never be used for incoming
authentication. High-level federation rejects that mode.

Complete authentication also needs trusted resolution, authentication-key
authorization, a trusted receiver target and atomic replay consumption. Callers
must derive the request URL from their actual receiver context, not from an
unauthenticated JSON body describing an alleged original request.

## Shared replay state

Python DidWbaVerifierConfig accepts replay_store, verifier_scope and clock.
Federation accepts replay_store, verifier_scope, signature_policy and now.
Inject a store with consume_once(ReplayContext), or a synchronous/asynchronous
callback receiving that context. Only a real boolean true admits the request;
errors are failures, never an invitation to fall back to memory.

ReplayContext includes the verified signer DID, trusted receiver scope, a
domain-separated digest and the absolute retention deadline including skew.
Store the digest atomically, with a uniqueness constraint or conditional write.
All replicas of one logical receiver use the same scope and store. Retain records
through the deadline; do not store request bodies, signature bytes or tokens.
Nonce-free permitted profiles use the digest of the verified signature base,
not raw signature bytes, as their equivalent replay identity.

MemoryReplayStore is bounded and thread-safe, but works only in one process and
does not survive a restart. It refuses capacity exhaustion instead of evicting
live keys. It is not a distributed-store guarantee. Existing nonce callbacks
remain supported; their host implementation must provide atomicity and sufficient
retention. Legacy nonce consumption occurs after signature validation.

## Public resolution and discovery

WBA resolution now shares a bounded public HTTPS transport. Public IP literals
are checked before connecting; connector DNS answers must all be public. TLS
verification is required, redirects are disabled and ambient proxies are ignored.
Generic resolution's host-configured base_url_override remains an explicit
trusted transport override, not a permission granted by a remote DID document.
WNS uses the same connection policy and retains moved/not-found/gone semantics.

Crawler discovery is unsigned by default and does not adopt response tokens.
ANPCrawler and ANPClient accept an explicit authenticated_origins list for
protected documents and approved API origins. Requests to other origins strip
authentication headers; a 401 cannot promote an unapproved origin. Responses
are bounded, cannot redirect credentials, and only approved same-origin
authenticated exchanges may update the client's token cache.

Token caches are isolated by normalized scheme, hostname and effective port.
Use a separate authentication helper per identity. Direct update_token callers
are responsible for passing the actual authenticated HTTPS response origin;
never call it for discovery or a redirected response. Authentication-Info is
preferred; the legacy Authorization response-header reader remains compatible
under those same constraints. The Legacy DIDWba audience remains the hostname,
not the cache's newly isolated origin key.

These changes do not authorize discovered tools or implement business approval.
An application still owns which tools and effects its agent may invoke.

## Rust and Go policy and replay APIs

Rust preserves the existing public configuration and metadata structs. The new
verify_http_message_signature_with_policy accepts a policy and explicit clock;
the original function applies the real-time default. DidWbaVerifier provides
with_clock and with_replay_store builders rather than requiring new config
fields. Both existing request-verification methods remain async and consume
replay state after successful cryptographic and identity checks. The existing
synchronous nonce callback remains an explicit compatibility adapter.

Rust federation also exposes verify_federated_http_request_with_security with
FederatedHttpSecurity, including a host-trusted receiver scope and shared async
HttpReplayStore. The old entry uses bounded process-local memory and real time.
Full authentication rejects crypto-only policy. Replay outages remain in the
existing public error representation; is_replay_store_unavailable lets hosts
distinguish them without relying on message parsing or adding enum variants.
WBA and Web resolution use the same bounded, DNS-pinned HTTPS transport; an
explicit HostNetwork address policy still delegates network trust to the host.

Go preserves the old functions and config type, with additional
VerifyHTTPMessageSignatureWithPolicy, WithClock/WithReplayStore builders and a
VerifyRequestWithDidDocumentContext method to propagate context cancellation to
shared storage. Federation's WithSecurity variant accepts the same conceptual
security dependencies. Neither optional nonce nor a missing expires parameter
bypasses replay/time validation at complete authentication entry points.

Cross-language verification uses the same frozen public corpus. These unit
results do not attest live DNS, proxies, databases, deployed services, or the
languages whose hardening is still in progress.

## TypeScript transport and authentication

TypeScript's verification options and full verifiers use the same time and
coverage policy. Optional replayStore/clock/verifierScope configuration supports
async callbacks, bounded single-process memory or host-supplied shared storage.
Nonce-free permitted profiles still consume an equivalent signature-base key;
the full federation entry rejects crypto-only policy. Native Web validation does
not apply WBA fingerprint rules to an e1-prefixed Web path.

The Node document transport validates actual connection DNS answers and returns
only checked IPs to the connector. TLS retains the original hostname; no fetch
redirects or ambient proxy are used. Both wire and decoded compressed bodies are
bounded to 1 MiB, with an overall timeout and process-level concurrency budget.
WBA, Web and WNS use this transport. This is a Node guarantee, not a browser DNS
inspection claim. Trusted endpoint overrides are restricted to their configured
origin/path scope. Tokens use full origins and valid Bearer response semantics,
and a challenge cannot remove method/target/body coverage.

## Dart verification and IO transport

Dart keeps its const verifier constructor and old signature function parameters;
optional policy, clock and replay store/consumer parameters supply full validation.
The verified DID is derived from the key and must match the expected DID, not
merely echoed from a caller argument. E1/K1 document checks now actually verify
the fingerprint, root assertion authorization and root proof, while retaining
existing Dart base64url proof encoding and protocol multibase proof reads.
Proof signatures are persistent document evidence, not short-lived HTTP requests.

Legacy request authentication applies realm/time/key checks before replay
consumption. Signature primitives remain distinct from full authentication.
The former sender-only federation call returns verified=false with no authenticated
DID; supplying complete verified request/service evidence enables full federation.
The optional serviceDid result exposes the actual verified service identity.

Dart now uses Random.secure for both nonce generators and UTF-8 signature bases.
The outgoing authenticator supports an opaque MessageSigner without a private-key
downcast. IO resolution pins checked InternetAddress objects to TCP connections,
retaining original TLS hostname checks, and disables proxies/redirects. All
document readers bound decoded bytes, time and concurrency, enforce exact DID IDs
and use the proper bare-domain well-known resource. A host-injected http.Client
explicitly owns its connection policy. Non-IO platforms must supply a trusted
client for resolution; pure crypto APIs remain available without dart:io.

## Java Legacy and Spring

Java has Legacy DIDWba rather than a native RFC 9421 verifier. Its existing
stateless verification overload now applies a bounded freshness policy; an
explicit Policy can select historical checks. Full authenticateAsync adds exact
DID/key authorization and shared atomic ReplayStore consumption after crypto.
The Spring filter only publishes verified identities, rejects missing/ambiguous
protected authentication and fails closed on store outages. Public exempt paths
remain anonymous. Inject shared storage for replicated deployments.

The previous Ed25519 verifier mistakenly supplied signature bytes as content;
this is corrected with positive and tamper unit tests. Root-bound E1/K1 documents
also require their fingerprint, assertion authorization and document proof.
The existing Apache HC5 dependency provides DNS-checked connections, original
TLS hostname checks, bounded body/time/concurrency and no redirects/proxies.
Async facades use bounded workers rather than unbounded blocked common-pool work.
AD fetching is unsigned and cannot adopt tokens unless its origin is explicitly
approved. Legacy token/header entry points retain hostname audiences while their
cache keys use the full origin. Test transports/DNS are injected, not listeners.

The Spring filter requires an explicit trusted receiver HTTPS authority in
anp.auth.allowed-domains (host[:port], or a full HTTPS origin). Empty configuration
cannot authenticate protected paths. This formerly unused setting is not a signer
DID allowlist. Host or Forwarded assertions cannot approve another receiver or
port. Auth-disabled/exempt routes remain unchanged. Replicated Spring hosts must
register their own filter using the shared-store constructor (and disable the
default process-local registration), rather than treating the default memory
store as distributed state.

## Python framework wrappers and resource budgets

OpenANP/FastANP middleware calls the full verifier with actual method/URI/body.
It now requires explicit receiver authorities in config.allowed_domains: a bare
host[:port] denotes HTTPS, while an explicit HTTP origin is a host-trusted test
override. Empty configuration does not approve arbitrary Host values. Repeated
Host/authentication/digest/framing headers are rejected before dictionary
conversion, and failed requests cannot retain a previously injected identity.
Middleware logs do not include the authentication result or response tokens.

RemoteAgent.discover accepts optional authenticated_origins and retains that
policy for later calls. Discovery remains unsigned by default; an AD server URL
cannot grant itself credential access. Approved protected AD/API flows remain
available through explicit configuration.

Python public document/crawler transports and native Web share a process-wide
32-request nonblocking budget across loops/threads. Rust DID/WNS transports use
an owned permit with automatic release on failure or cancellation. Go shares
checked connection pools and retains a process-wide permit through response body
EOF/close, rather than leaking one pool per request. Overload rejects work, with
no unbounded waiting queue. These are local resource bounds, not an application
rate limiter or a distributed admission guarantee.

The built-in server challenge currently requests signature components but does
not issue challenge nonces. A host adding a server-generated nonce must validate
issuance, receiver scope and expiry in its atomic callback; a generic consume-once
store alone is not proof of challenge issuance. Legacy signatures retain their
historical hostname audience and are not upgraded into method/body-bound HTTP
proofs. Applications still need correct business authorization and protected
transport; the SDK does not turn discovery into permission to execute tools.

| Language | Stateless HTTP signatures | Full replay integration | Existing public network / credential boundary |
|---|---|---|---|
| Python | Policy / explicit clock | async store or callback; verifier + federation + framework wrappers | WBA/Web/WNS/crawler/RemoteAgent; approved origins |
| Rust | existing API + with_policy | async HttpReplayStore; verifier + federation | WBA/Web/WNS; bounded pinned connections |
| Go | existing API + WithPolicy | context-aware atomic store; verifier + federation | WBA/Web/WNS; shared public pools |
| TypeScript | optional verification options | Promise store/callback | Node transport + WBA/Web/WNS; not browser DNS attestation |
| Dart | optional policy/clock | Future store/consumer; no sender-prefix authentication | native IO / injected host transport; non-IO default fails closed |
| Java | feature_not_implemented (Legacy only) | CompletionStage Legacy store; Spring filter | HC5 checked DNS/TLS, AD origin approval and token isolation |

Origin keys use compressed lowercase IPv6 literals, so expanded/shortened spellings
cannot create language-dependent replay or credential contexts. Bounded authority
compatibility includes the legacy spellings for that same exact signed URI; it
never tries a different target URI. Mapped IPv6 URL aliases, port zero, fragments
and ambiguous numeric Python literals fail before signing or connecting.

Existing Legacy header/JSON signature primitives in the five HTTP-capable SDKs
remain cryptographic proof helpers; their boolean/signature result alone is not
fresh, replay-protected authentication. Use the full verifier/federation entry
for inbound admission. The Java Legacy policy overload is explicitly documented
separately. Native platform DNS cancellation/worker behavior and deployment rate
limits still belong to the host; SDK in-flight request budgets do not attest
all operating-system work after cancellation or replace an ingress limiter.
