use anp::authentication::{
    add_device_to_did_document, build_vnext_did_document, remove_device_from_did_document,
    update_device_in_did_document, validate_device_manifest, DeviceManifestEntry,
};
use serde_json::{json, Value};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../testdata/device_manifest/vnext_did_builder_fixtures.json"
    ))
    .expect("builder fixture must be valid JSON")
}

fn entry(device: &Value) -> DeviceManifestEntry {
    serde_json::from_value(device["entry"].clone()).expect("device entry must be valid")
}

fn retired(value: &Value) -> Vec<String> {
    serde_json::from_value(value["retired_device_ids"].clone())
        .expect("retired device ids must be valid")
}

fn build(value: &Value) -> Value {
    let device = &value["device_a"];
    build_vnext_did_document(
        &value["base_document"],
        value["root_key_id"].as_str().expect("root key id"),
        &value["root_verification_method"],
        &entry(device),
        &device["signing_verification_method"],
        &device["e2ee_verification_method"],
    )
    .expect("build must succeed")
}

#[test]
fn shared_vnext_did_build_add_update_remove_vectors() {
    let value = fixture();
    let base_before = value["base_document"].clone();
    let built = build(&value);
    assert_eq!(built, value["expected_build"]);
    assert_eq!(value["base_document"], base_before);
    assert_eq!(built["x-example"], value["base_document"]["x-example"]);

    let mut with_stale_proof = built.clone();
    with_stale_proof["proof"] = json!({"proofValue": "stale"});
    let device_b = &value["device_b"];
    let added = add_device_to_did_document(
        &with_stale_proof,
        value["root_key_id"].as_str().expect("root key id"),
        &entry(device_b),
        &device_b["signing_verification_method"],
        &device_b["e2ee_verification_method"],
        &retired(&value),
    )
    .expect("add must succeed");
    assert_eq!(added, value["expected_add"]);
    assert!(added.get("proof").is_none());
    assert!(with_stale_proof.get("proof").is_some());

    let rotated = &value["device_b_rotated"];
    let updated = update_device_in_did_document(
        &added,
        value["root_key_id"].as_str().expect("root key id"),
        &entry(rotated),
        &rotated["signing_verification_method"],
        &rotated["e2ee_verification_method"],
    )
    .expect("update must succeed");
    assert_eq!(updated, value["expected_update"]);

    let removed = remove_device_from_did_document(
        &updated,
        value["root_key_id"].as_str().expect("root key id"),
        rotated["entry"]["device_id"].as_str().expect("device id"),
    )
    .expect("remove must succeed");
    assert_eq!(removed, value["expected_remove"]);
    assert_eq!(
        removed["deviceManifest"]["devices"],
        built["deviceManifest"]["devices"]
    );
    assert!(validate_device_manifest(&removed)
        .expect("removed document must validate")
        .is_some());

    let multikey_built = build_vnext_did_document(
        &value["base_document"],
        value["root_key_id"].as_str().expect("root key id"),
        &value["root_verification_method"],
        &entry(&value["device_a"]),
        &value["device_a"]["signing_verification_method"],
        &value["x25519_multikey_verification_method"],
    )
    .expect("X25519 Multikey build must succeed");
    assert_eq!(
        multikey_built["verificationMethod"][2],
        value["x25519_multikey_verification_method"]
    );
}

#[test]
fn vnext_builder_rejects_root_as_device_key_and_private_material() {
    let value = fixture();
    let mut device = value["device_a"].clone();
    device["entry"]["signing_key_id"] = value["root_key_id"].clone();
    device["signing_verification_method"] = value["root_verification_method"].clone();
    assert!(build_vnext_did_document(
        &value["base_document"],
        value["root_key_id"].as_str().expect("root key id"),
        &value["root_verification_method"],
        &entry(&device),
        &device["signing_verification_method"],
        &device["e2ee_verification_method"],
    )
    .is_err());

    let mut private_root = value["root_verification_method"].clone();
    private_root["publicKeyJwk"]["d"] = Value::String("PRIVATE".to_string());
    assert!(build_vnext_did_document(
        &value["base_document"],
        value["root_key_id"].as_str().expect("root key id"),
        &private_root,
        &entry(&value["device_a"]),
        &value["device_a"]["signing_verification_method"],
        &value["device_a"]["e2ee_verification_method"],
    )
    .is_err());

    let mut private_base = value["base_document"].clone();
    private_base["root_private_key"] = Value::String("PRIVATE".to_string());
    assert!(build_vnext_did_document(
        &private_base,
        value["root_key_id"].as_str().expect("root key id"),
        &value["root_verification_method"],
        &entry(&value["device_a"]),
        &value["device_a"]["signing_verification_method"],
        &value["device_a"]["e2ee_verification_method"],
    )
    .is_err());
}

#[test]
fn vnext_mutation_rejects_duplicate_foreign_and_missing_relationship() {
    let value = fixture();
    let built = build(&value);
    let device_a = &value["device_a"];
    assert!(add_device_to_did_document(
        &built,
        value["root_key_id"].as_str().expect("root key id"),
        &entry(device_a),
        &device_a["signing_verification_method"],
        &device_a["e2ee_verification_method"],
        &retired(&value),
    )
    .is_err());

    let mut foreign = value["device_b"].clone();
    foreign["signing_verification_method"]["controller"] =
        Value::String("did:example:other".to_string());
    assert!(add_device_to_did_document(
        &built,
        value["root_key_id"].as_str().expect("root key id"),
        &entry(&foreign),
        &foreign["signing_verification_method"],
        &foreign["e2ee_verification_method"],
        &retired(&value),
    )
    .is_err());

    let mut missing_relationship = built;
    missing_relationship["keyAgreement"] = json!([]);
    let device_b = &value["device_b"];
    assert!(add_device_to_did_document(
        &missing_relationship,
        value["root_key_id"].as_str().expect("root key id"),
        &entry(device_b),
        &device_b["signing_verification_method"],
        &device_b["e2ee_verification_method"],
        &retired(&value),
    )
    .is_err());
}

#[test]
fn shared_invalid_public_key_cases_are_rejected() {
    let value = fixture();
    for case in value["invalid_public_key_cases"]
        .as_array()
        .expect("invalid public key cases")
    {
        let mut root = value["root_verification_method"].clone();
        let mut signing = value["device_a"]["signing_verification_method"].clone();
        let mut e2ee = value["device_a"]["e2ee_verification_method"].clone();
        match case["role"].as_str().expect("role") {
            "root" => root = case["verification_method"].clone(),
            "device_signing" => signing = case["verification_method"].clone(),
            "device_e2ee" => e2ee = case["verification_method"].clone(),
            other => panic!("unknown fixture role: {other}"),
        }
        assert!(
            build_vnext_did_document(
                &value["base_document"],
                value["root_key_id"].as_str().expect("root key id"),
                &root,
                &entry(&value["device_a"]),
                &signing,
                &e2ee,
            )
            .is_err(),
            "accepted invalid public key fixture {}",
            case["name"]
        );
    }
}

#[test]
fn shared_duplicate_key_material_cases_are_rejected() {
    let value = fixture();
    for case in value["duplicate_key_material_cases"]
        .as_array()
        .expect("duplicate key cases")
    {
        let result = if case["operation"] == "build" {
            build_vnext_did_document(
                &value["base_document"],
                value["root_key_id"].as_str().expect("root key id"),
                &case["root_verification_method"],
                &entry(&value["device_a"]),
                &value["device_a"]["signing_verification_method"],
                &value["device_a"]["e2ee_verification_method"],
            )
        } else {
            let device_b = &value["device_b"];
            let signing = case
                .get("signing_verification_method")
                .unwrap_or(&device_b["signing_verification_method"]);
            let e2ee = case
                .get("e2ee_verification_method")
                .unwrap_or(&device_b["e2ee_verification_method"]);
            add_device_to_did_document(
                &build(&value),
                value["root_key_id"].as_str().expect("root key id"),
                &entry(device_b),
                signing,
                e2ee,
                &retired(&value),
            )
        };
        assert!(
            result.is_err(),
            "accepted duplicate key fixture {}",
            case["name"]
        );
    }
}

#[test]
fn shared_invalid_relationship_cases_are_rejected() {
    let value = fixture();
    for case in value["invalid_relationship_cases"]
        .as_array()
        .expect("invalid relationship cases")
    {
        let mut document = build(&value);
        document[case["relationship"].as_str().expect("relationship")]
            .as_array_mut()
            .expect("relationship array")
            .push(case["key_id"].clone());
        let device_b = &value["device_b"];
        assert!(add_device_to_did_document(
            &document,
            value["root_key_id"].as_str().expect("root key id"),
            &entry(device_b),
            &device_b["signing_verification_method"],
            &device_b["e2ee_verification_method"],
            &retired(&value),
        )
        .is_err());
    }
}

#[test]
fn retired_device_id_and_removed_relationship_cleanup() {
    let value = fixture();
    let device_b = &value["device_b"];
    let mut added = add_device_to_did_document(
        &build(&value),
        value["root_key_id"].as_str().expect("root key id"),
        &entry(device_b),
        &device_b["signing_verification_method"],
        &device_b["e2ee_verification_method"],
        &retired(&value),
    )
    .expect("add must succeed");
    for (relationship, key_id) in [
        ("authentication", &device_b["entry"]["signing_key_id"]),
        ("assertionMethod", &device_b["entry"]["signing_key_id"]),
        ("keyAgreement", &device_b["entry"]["e2ee_key_id"]),
    ] {
        added[relationship]
            .as_array_mut()
            .expect("relationship array")
            .push(key_id.clone());
    }
    let rotated = &value["device_b_rotated"];
    let updated = update_device_in_did_document(
        &added,
        value["root_key_id"].as_str().expect("root key id"),
        &entry(rotated),
        &rotated["signing_verification_method"],
        &rotated["e2ee_verification_method"],
    )
    .expect("update must succeed");
    for relationship in ["authentication", "assertionMethod", "keyAgreement"] {
        let entries = updated[relationship]
            .as_array()
            .expect("relationship array");
        for old_key_id in [
            device_b["entry"]["signing_key_id"].as_str().unwrap(),
            device_b["entry"]["e2ee_key_id"].as_str().unwrap(),
        ] {
            assert!(!entries.iter().any(|entry| {
                entry.as_str() == Some(old_key_id)
                    || entry.get("id").and_then(Value::as_str) == Some(old_key_id)
            }));
        }
    }

    let removed = remove_device_from_did_document(
        &added,
        value["root_key_id"].as_str().expect("root key id"),
        device_b["entry"]["device_id"].as_str().expect("device id"),
    )
    .expect("remove must succeed");
    assert!(add_device_to_did_document(
        &removed,
        value["root_key_id"].as_str().expect("root key id"),
        &entry(device_b),
        &device_b["signing_verification_method"],
        &device_b["e2ee_verification_method"],
        &[device_b["entry"]["device_id"]
            .as_str()
            .expect("device id")
            .to_string()],
    )
    .is_err());
}
