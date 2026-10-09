# ANP vNext Device Manifest SDK surface

This SDK implements the P2 `deviceManifest` contract and complete P5/P6
Profile dependencies in ANP Messaging 1.2. The current Profile baseline is ANP
protocol commit `de99d26f26a80a9c9a9a70b2f6f37c72c5d605ea`; see the
[Messaging 1.2 catalog](https://github.com/agent-network-protocol/AgentNetworkProtocol/blob/de99d26f26a80a9c9a9a70b2f6f37c72c5d605ea/message/README.md).
Earlier draft dependency bundles remain readable only for compatibility, as
specified below.

## Scope

Rust, Python, Go, Dart, and TypeScript expose equivalent typed operations to:

- parse the optional `deviceManifest` DID document extension;
- validate its closed Manifest and device-entry schema;
- validate current `device_id` and key-reference uniqueness;
- resolve device keys in the same DID document and check their required
  `authentication`, `assertionMethod`, and `keyAgreement` relationships;
- validate the complete P5 or P6 Profile dependency set; and
- find a validated device that declares a supported device-addressed E2EE
  Profile; Base Profile dependencies never make Base operations device-addressed.

They also expose additive, side-by-side document helpers to:

- build an unsigned vNext DID document from an existing base document, one
  explicit root public verification method, and one device's independent
  signing and X25519 public verification methods;
- add, update, or remove one typed Manifest device while synchronizing
  `verificationMethod`, `authentication`, `assertionMethod`, `keyAgreement`,
  and the embedded `deviceManifest`; and
- validate the complete result before returning it.

The helpers accept only already-constructed public verification methods. They
never generate, import, export, or serialize private keys. Validation fails
closed and supports these public forms:

- `JsonWebKey2020` OKP `Ed25519` or `X25519`, with a canonical unpadded
  base64url `x` that decodes to exactly 32 bytes;
- `JsonWebKey2020` EC `P-256` or `secp256k1`, with canonical 32-byte `x` and
  `y` coordinates that form a valid curve point;
- the matching `EcdsaSecp256r1VerificationKey2019` and
  `EcdsaSecp256k1VerificationKey2019` JWK forms; and
- `Multikey` Ed25519 (`ed 01`) or X25519 (`ec 01`), plus the X25519-only
  `X25519KeyAgreementKey2019` Multikey form, using canonical base58btc and a
  32-byte raw key.

Each method must have exactly one supported public-material member.
`publicKeyBase58`, unknown or contradictory method types/codecs, malformed EC
points, non-canonical encodings, and any private material are rejected. Root
methods must be signing-capable and device E2EE methods must be X25519. Because
P5/P6 Object Proof uses EdDSA-JCS-2022, a device declaring either v2 E2EE
Profile must use Ed25519 for its device-signing method. Other device entries
may use any of the supported signing algorithms.

The raw public key bytes of the root and every active device key must be
unique, including when the same bytes are presented in different JWK/Multikey
forms or in different key roles. For each Manifest device, its signing key
must be present in `authentication` and `assertionMethod` and absent from
`keyAgreement`; its E2EE key must be present in `keyAgreement` and absent from
the signing relationships. Root must be in `assertionMethod`. Extra
application-defined verification methods and relationships remain allowed,
but update/remove clears both old device key IDs from all three managed
relationships so it cannot leave dangling or cross-role references.

All mutation helpers clone their input and preserve unknown top-level DID
extensions. Since any mutation invalidates a previous root proof, they remove
`proof` from the returned copy. The caller must root-sign that unsigned result
before publication.

Inputs must be JSON-domain values: null, strings, booleans, finite numbers,
arrays, and string-keyed objects. Host-language objects, functions, dates, and
NaN/infinities are rejected rather than being serialized implicitly. The Go
implementation uses a recursive clone instead of a JSON round trip so unknown
extension integers, including values above 2^53, keep their exact value and
type.

`Add` also requires the caller's collection of previously retired
`device_id` values and rejects reuse of any value in that collection. The
caller (for example, an identity Registry) owns and durably persists this
history and passes it into the stateless helper; the SDK does not create a
second lifecycle state source. Updating an existing active device keeps the
same `device_id` and does not use the retired-ID check.

The containing DID document remains an open object. These helpers read only the
Manifest and the DID relationships needed to validate it, do not mutate the
input, and therefore preserve unknown top-level DID extensions. A missing
Manifest returns no value rather than creating a default device because
Base-only ANP DIDs may omit the extension.

For ANP Messaging 1.2, the canonical dependency bundles are mixed-version
(all identifiers below have the `anp.` prefix):

```text
P5 v2: core.binding.v1, identity.discovery.v1, direct.base.v1, direct.e2ee.v2
P6 v2: core.binding.v1, identity.discovery.v1, group.base.v2, group.e2ee.v2
```

P6 requires the current P4 v2 business contract. Group Base v2 does not require
Core, Identity, or Direct Base v2; it is not the former all-v2 draft bundle.
The shared canonical read and build/add/update/remove fixtures use this current
P6 dependency set in every language.

Validators also accept the complete historical P6 mixed bundle containing
`group.base.v1`, and the complete all-v2 draft bundles, so existing Manifests
remain readable. Partial bundles and hybrids without any complete supported
bundle remain invalid. A current P6 eligible-device lookup requires the complete
current dependency set and returns no eligible device for either historical P6
bundle, even though parsing and validation still succeed. Reading a historical
declaration does not establish current P4/P6 interoperability or replace service
capability negotiation.

All vNext build/add/update/remove helpers require the complete current bundle
for every P6 device they write. A P6 device with only the historical
`group.base.v1` mixed bundle is read-only, as are the former all-v2 foundation
profiles. The helpers reject these inputs instead of silently adding or
rewriting capability declarations. Mutation inputs use the historical read
validation rules; canonical write rules apply to the complete result. A caller
can explicitly replace a historical device with its confirmed current profiles,
or remove that device, when every remaining entry satisfies the write rules.
An unrelated change that leaves a historical entry in the result is rejected.
The helpers never infer another device's capabilities or silently migrate it.
If several historical entries require migration, callers must explicitly prepare
a complete canonical replacement before publication; single-device helpers do
not return intermediate documents containing historical write profiles.
Successful mutations strip the old proof for re-signing, and both successful
and rejected mutations preserve the input document. An extra explicit
`group.base.v1` declaration does not replace the required `group.base.v2`.

Ordinary P4 v2 declarations require `core.binding.v1` and
`identity.discovery.v1`. This support neither enables P6 nor makes ordinary
Base operations device-addressed. P5 dependencies and pure Base v1 declarations
are unchanged.

A caller that currently supplies the old P6 bundle must explicitly update its
device profiles and, where applicable, its `ANPMessageService.profiles` and
runtime capability declarations after confirming actual P4 v2 support. The SDK
does not rewrite service declarations, signed requests, or stored MLS state.
P6 remains a candidate subject to its separate release and discovery gates.

## Compatibility boundary

Existing v1 DID builders retain their current output and defaults. The vNext
surface is an explicit parser/validator/helper layer; it does not silently add a
Manifest to old documents or reinterpret v1 Direct or Group behavior.

The public model contains only the P2 wire fields:

```text
deviceManifest: type, devices
device entry: device_id, signing_key_id, e2ee_key_id, profiles
```

Product-local device roles, lifecycle state, recovery data, replica state, and
concurrency bookkeeping remain outside the ANP SDK and cross-domain document.

The document helper names are:

| Operation | Rust / Python | Go | Dart | TypeScript |
| --- | --- | --- | --- | --- |
| Build | `build_vnext_did_document` | `BuildVNextDIDDocument` | `buildVNextDidDocument` | `buildVnextDidDocument` |
| Add (requires retired device IDs) | `add_device_to_did_document` | `AddDeviceToDIDDocument` | `addDeviceToDidDocument` | `addDeviceToDidDocument` |
| Update | `update_device_in_did_document` | `UpdateDeviceInDIDDocument` | `updateDeviceInDidDocument` | `updateDeviceInDidDocument` |
| Remove | `remove_device_from_did_document` | `RemoveDeviceFromDIDDocument` | `removeDeviceFromDidDocument` | `removeDeviceFromDidDocument` |

Cross-language acceptance and rejection cases live in
[`../../testdata/device_manifest/vnext_device_manifest_fixtures.json`](../../testdata/device_manifest/vnext_device_manifest_fixtures.json).
Build/add/update/remove vectors live in
[`../../testdata/device_manifest/vnext_did_builder_fixtures.json`](../../testdata/device_manifest/vnext_did_builder_fixtures.json).
The latter also contains shared rejection vectors for malformed or
contradictory key methods, cross-format raw-key reuse, role-confused
relationships, and retired device-ID reuse.
