use std::fs;
use std::path::PathBuf;

use anp::authentication::{
    find_eligible_device, parse_device_manifest, validate_device_manifest, DeviceManifest,
};
use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Debug, Deserialize)]
struct SharedFixtures {
    base_did_document: Value,
    valid: Vec<ValidFixture>,
    invalid: Vec<InvalidFixture>,
}

#[derive(Debug, Deserialize)]
struct ValidFixture {
    name: String,
    device_manifest: Value,
    lookup: LookupFixture,
}

#[derive(Debug, Deserialize)]
struct InvalidFixture {
    name: String,
    device_manifest: Value,
    #[serde(default)]
    document_patch: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
struct LookupFixture {
    device_id: String,
    profile: String,
    found: bool,
}

#[test]
fn shared_valid_manifests_parse_validate_and_lookup() {
    let fixtures = load_fixtures();
    for fixture in fixtures.valid {
        let document = document_with_manifest(
            &fixtures.base_did_document,
            &fixture.device_manifest,
            &Map::new(),
        );
        let original = document.clone();

        let parsed = parse_device_manifest(&document)
            .unwrap_or_else(|error| panic!("{} parse failed: {error}", fixture.name))
            .unwrap_or_else(|| panic!("{} should contain a Manifest", fixture.name));
        assert_manifest_serializes_to_fixture(&fixture.name, &parsed, &fixture.device_manifest);

        validate_device_manifest(&document)
            .unwrap_or_else(|error| panic!("{} validation failed: {error}", fixture.name))
            .unwrap_or_else(|| panic!("{} should contain a validated Manifest", fixture.name));
        let found = find_eligible_device(
            &document,
            &fixture.lookup.device_id,
            &fixture.lookup.profile,
        )
        .unwrap_or_else(|error| panic!("{} lookup failed: {error}", fixture.name));
        assert_eq!(
            found.is_some(),
            fixture.lookup.found,
            "{} lookup result",
            fixture.name
        );
        assert_eq!(
            document, original,
            "{} validation must not mutate unknown top-level extensions",
            fixture.name
        );
        assert_eq!(
            document["x-fixture-extension"]["must_survive_validation"],
            Value::Bool(true),
            "{} unknown top-level extension",
            fixture.name
        );
    }
}

#[test]
fn shared_invalid_manifests_are_rejected() {
    let fixtures = load_fixtures();
    for fixture in fixtures.invalid {
        let document = document_with_manifest(
            &fixtures.base_did_document,
            &fixture.device_manifest,
            &fixture.document_patch,
        );
        assert!(
            validate_device_manifest(&document).is_err(),
            "{} should be rejected",
            fixture.name
        );
    }
}

#[test]
fn missing_manifest_returns_none() {
    let fixtures = load_fixtures();
    assert!(parse_device_manifest(&fixtures.base_did_document)
        .expect("Manifest absence is valid")
        .is_none());
    assert!(validate_device_manifest(&fixtures.base_did_document)
        .expect("Manifest absence is valid")
        .is_none());
    assert!(find_eligible_device(
        &fixtures.base_did_document,
        "dev-a-7N3KQ2",
        "anp.direct.e2ee.v2",
    )
    .expect("Manifest absence is valid")
    .is_none());
}

#[test]
fn duplicate_verification_method_resolution_is_rejected() {
    let fixtures = load_fixtures();
    let fixture = &fixtures.valid[0];
    let mut document = document_with_manifest(
        &fixtures.base_did_document,
        &fixture.device_manifest,
        &Map::new(),
    );
    let methods = document["verificationMethod"]
        .as_array_mut()
        .expect("verificationMethod fixture array");
    methods.push(methods[0].clone());
    assert!(validate_device_manifest(&document).is_err());
}

#[test]
fn p5_lookup_rejects_wrong_device_key_algorithms() {
    let fixtures = load_fixtures();
    let fixture = &fixtures.valid[0];
    for (key_id_suffix, wrong_curve, wrong_x) in [
        (
            "#dev-a-sign",
            "X25519",
            "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
        ),
        (
            "#dev-a-e2ee",
            "Ed25519",
            "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w",
        ),
    ] {
        let mut document = document_with_manifest(
            &fixtures.base_did_document,
            &fixture.device_manifest,
            &Map::new(),
        );
        let method = verification_method_mut(&mut document, key_id_suffix);
        method["publicKeyJwk"]["crv"] = Value::String(wrong_curve.to_owned());
        method["publicKeyJwk"]["x"] = Value::String(wrong_x.to_owned());

        assert!(
            find_eligible_device(
                &document,
                &fixture.lookup.device_id,
                &fixture.lookup.profile,
            )
            .is_err(),
            "{key_id_suffix} with {wrong_curve} must not be P5 eligible",
        );
    }
}

#[test]
fn p5_lookup_rejects_reused_raw_key_material_across_device_roles() {
    let fixtures = load_fixtures();
    let fixture = &fixtures.valid[0];
    let mut document = document_with_manifest(
        &fixtures.base_did_document,
        &fixture.device_manifest,
        &Map::new(),
    );
    let signing_x =
        verification_method_mut(&mut document, "#dev-a-sign")["publicKeyJwk"]["x"].clone();
    verification_method_mut(&mut document, "#dev-a-e2ee")["publicKeyJwk"]["x"] = signing_x;

    assert!(
        find_eligible_device(
            &document,
            &fixture.lookup.device_id,
            &fixture.lookup.profile,
        )
        .is_err(),
        "P5 signing and E2EE roles must not reuse the same raw public key",
    );
}

fn assert_manifest_serializes_to_fixture(name: &str, manifest: &DeviceManifest, expected: &Value) {
    assert_eq!(
        serde_json::to_value(manifest).expect("Manifest should serialize"),
        *expected,
        "{name} typed Manifest round trip",
    );
}

fn verification_method_mut<'a>(document: &'a mut Value, key_id_suffix: &str) -> &'a mut Value {
    document["verificationMethod"]
        .as_array_mut()
        .expect("verificationMethod fixture array")
        .iter_mut()
        .find(|method| {
            method
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|key_id| key_id.ends_with(key_id_suffix))
        })
        .expect("fixture verification method")
}

fn document_with_manifest(base: &Value, manifest: &Value, patch: &Map<String, Value>) -> Value {
    let mut document = base.clone();
    let object = document
        .as_object_mut()
        .expect("base DID document fixture must be an object");
    for (key, value) in patch {
        object.insert(key.clone(), value.clone());
    }
    object.insert("deviceManifest".to_string(), manifest.clone());
    document
}

fn load_fixtures() -> SharedFixtures {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("testdata")
        .join("device_manifest")
        .join("vnext_device_manifest_fixtures.json");
    serde_json::from_str(&fs::read_to_string(path).expect("shared fixtures should be readable"))
        .expect("shared fixtures must be valid JSON")
}
