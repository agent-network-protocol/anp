use anp::authentication::{
    add_device_to_web_did_document, build_web_did_document, remove_device_from_web_did_document,
    validate_device_manifest, validate_did_document_method, DeviceManifestEntry,
};
use serde_json::{json, Value};

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../fixtures/did-method-lifecycle-v1.json")).unwrap()
}

#[test]
fn rootless_web_build_join_revoke() {
    let f = fixture();
    let single = &f["documents"]["web_single_device"];
    let mut base = single.clone();
    for key in [
        "verificationMethod",
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "deviceManifest",
        "proof",
    ] {
        base.as_object_mut().unwrap().remove(key);
    }
    let first: DeviceManifestEntry =
        serde_json::from_value(single["deviceManifest"]["devices"][0].clone()).unwrap();
    let built = build_web_did_document(
        &base,
        &first,
        &single["verificationMethod"][0],
        &single["verificationMethod"][1],
    )
    .unwrap();
    assert_eq!(&built, single);
    let mut signed = built;
    signed["proof"] = json!({"stale":"must disappear"});
    let second: DeviceManifestEntry = serde_json::from_value(f["device_b"].clone()).unwrap();
    let joined = add_device_to_web_did_document(
        &signed,
        &second,
        &f["device_b_verification_methods"][0],
        &f["device_b_verification_methods"][1],
        &[],
    )
    .unwrap();
    assert_eq!(joined, f["documents"]["web_two_devices"]);
    assert!(signed.get("proof").is_some());
    assert_eq!(
        remove_device_from_web_did_document(&joined, "device-b").unwrap(),
        *single
    );
    assert!(add_device_to_web_did_document(
        single,
        &second,
        &f["device_b_verification_methods"][0],
        &f["device_b_verification_methods"][1],
        &["device-b".to_owned()]
    )
    .is_err());
}

#[test]
fn method_independent_manifest_profiles() {
    let f = fixture();
    for name in ["web_single_device", "web_two_devices", "wba_two_devices"] {
        assert!(validate_did_document_method(&f["documents"][name], true));
        assert!(validate_device_manifest(&f["documents"][name])
            .unwrap()
            .is_some());
    }
    for name in ["web_api", "web_group_assertion_only"] {
        assert!(validate_device_manifest(&f["documents"][name])
            .unwrap()
            .is_none());
    }
}

#[test]
fn current_wba_multibase_proof_protects_context() {
    let mut document = fixture()["documents"]["wba_two_devices"].clone();
    assert!(validate_did_document_method(&document, true));
    document["@context"]
        .as_array_mut()
        .unwrap()
        .push(json!("https://changed.example/context"));
    assert!(!validate_did_document_method(&document, true));
}

#[test]
fn web_method_validation_accepts_absent_proof_but_checks_present_proof() {
    use anp::proof::{generate_w3c_proof, ProofGenerationOptions};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let did = "did:web:identity.example:api";
    let key_id = format!("{did}#sign");
    let key = ed25519_dalek::SigningKey::from_bytes(&[71; 32]);
    let document = json!({
        "id": did,
        "verificationMethod": [{
            "id": key_id, "controller": did, "type": "JsonWebKey2020",
            "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes())},
        }],
        "assertionMethod": [key_id],
    });
    assert!(validate_did_document_method(&document, true));
    let signed = generate_w3c_proof(
        &document,
        &anp::PrivateKeyMaterial::Ed25519(key),
        &key_id,
        ProofGenerationOptions::default(),
    )
    .unwrap();
    assert!(validate_did_document_method(&signed, true));
    for mutation in ["content", "key", "malformed", "null"] {
        let mut invalid = signed.clone();
        match mutation {
            "content" => invalid["alsoKnownAs"] = json!(["https://changed.example"]),
            "key" => invalid["proof"]["verificationMethod"] = json!(format!("{did}#missing")),
            "malformed" => {
                invalid["proof"] = json!({"type": "DataIntegrityProof", "proofValue": "invalid"})
            }
            _ => invalid["proof"] = Value::Null,
        }
        assert!(!validate_did_document_method(&invalid, true), "{mutation}");
        assert!(validate_did_document_method(&invalid, false), "{mutation}");
    }
}

#[test]
fn web_mutation_keeps_validation() {
    let f = fixture();
    for failure in [
        "private",
        "purpose",
        "duplicate-material",
        "wrong-method",
        "dependency",
    ] {
        let mut document = f["documents"]["web_two_devices"].clone();
        match failure {
            "private" => {
                document["verificationMethod"][0]["privateKeyMultibase"] = json!("not-public")
            }
            "purpose" => document["authentication"] = json!([]),
            "duplicate-material" => {
                document["verificationMethod"][2]["publicKeyMultibase"] =
                    document["verificationMethod"][0]["publicKeyMultibase"].clone()
            }
            "wrong-method" => document = f["documents"]["wba_two_devices"].clone(),
            _ => document["deviceManifest"]["devices"][0]["profiles"]
                .as_array_mut()
                .unwrap()
                .retain(|p| p != "anp.core.binding.v1"),
        }
        assert!(
            remove_device_from_web_did_document(&document, "device-b").is_err(),
            "accepted {failure}"
        );
    }
}
