# ANP vNext Device Manifest SDK surface

This SDK implements the minimal P2 `deviceManifest` contract frozen at ANP
protocol commit `25bfbc59a5a925141b565c4bc6c24195736382b5b`.

## Scope

Rust, Python, Go, and Dart expose equivalent typed operations to:

- parse the optional `deviceManifest` DID document extension;
- validate its closed Manifest and device-entry schema;
- validate current `device_id` and key-reference uniqueness;
- resolve device keys in the same DID document and check their required
  `authentication`, `assertionMethod`, and `keyAgreement` relationships;
- validate the complete P5 or P6 Profile dependency set; and
- find a validated device that declares a supported device-addressed E2EE
  Profile; Base Profile dependencies never make Base operations device-addressed.

The containing DID document remains an open object. These helpers read only the
Manifest and the DID relationships needed to validate it, do not mutate the
input, and therefore preserve unknown top-level DID extensions. A missing
Manifest returns no value rather than creating a default device because Base-only
ANP DIDs may omit the extension.

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

Cross-language acceptance and rejection cases live in
[`../../testdata/device_manifest/vnext_device_manifest_fixtures.json`](../../testdata/device_manifest/vnext_device_manifest_fixtures.json).
