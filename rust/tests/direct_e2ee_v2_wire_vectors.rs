use anp::authentication::{create_did_wba_document, DidDocumentOptions, DidProfile};
use anp::direct_e2ee::{
    build_init_aad_v2, build_message_aad_v2, canonical_application_plaintext_v2,
    direct_e2ee_v2_error, direct_send_request_v2, get_prekey_bundle_request_v2,
    parse_direct_send_request_v2, parse_direct_send_result_v2, parse_get_prekey_bundle_request_v2,
    parse_get_prekey_bundle_result_v2, parse_publish_prekey_bundle_request_v2,
    parse_publish_prekey_bundle_result_v2, publish_prekey_bundle_request_v2,
    signed_bundle_object_jcs_v2, V2ApplicationPlaintext, V2DirectBody, V2GetPrekeyBundleBody,
    V2PrekeyBundle, V2PublishPrekeyBundleBody, DIRECT_E2EE_V2_ERRORS,
};
use anp::direct_e2ee::{build_prekey_bundle_v2, V2SignedPrekey, MTI_DIRECT_E2EE_SUITE_V2};
use anp::proof::{
    generate_w3c_proof, ProofGenerationOptions, CRYPTOSUITE_EDDSA_JCS_2022,
    PROOF_TYPE_DATA_INTEGRITY,
};
use anp::PrivateKeyMaterial;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, TimeZone, Utc};
use serde_json::json;
use serde_json::Value;
use x25519_dalek::StaticSecret as X25519StaticSecret;

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../testdata/direct_e2ee/p5_v2_wire_vectors.json"
    ))
    .expect("P5 v2 fixture")
}

#[test]
fn shared_v2_bundle_and_rpc_vectors_round_trip() {
    let fixture = vectors();
    let bundle: V2PrekeyBundle =
        serde_json::from_value(fixture["prekey_bundle"].clone()).expect("bundle model");
    assert_eq!(
        String::from_utf8(signed_bundle_object_jcs_v2(&bundle).expect("bundle JCS"))
            .expect("UTF-8"),
        fixture["expected_signed_bundle_object_jcs"]
            .as_str()
            .expect("expected JCS")
    );

    let (publish_meta, publish_body) =
        parse_publish_prekey_bundle_request_v2(&fixture["publish_request"])
            .expect("publish request");
    assert_eq!(
        publish_prekey_bundle_request_v2(publish_meta, publish_body).expect("publish build"),
        fixture["publish_request"]
    );

    let (get_meta, get_body) =
        parse_get_prekey_bundle_request_v2(&fixture["get_request"]).expect("get request");
    assert_eq!(
        get_prekey_bundle_request_v2(get_meta, get_body).expect("get build"),
        fixture["get_request"]
    );

    assert!(parse_publish_prekey_bundle_result_v2(&fixture["publish_result"]).is_ok());
    assert!(parse_get_prekey_bundle_result_v2(&fixture["get_result"]).is_ok());
    assert!(parse_direct_send_result_v2(&fixture["direct_send_result"]).is_ok());

    let mut invalid_get_result = fixture["get_result"].clone();
    invalid_get_result["target_device_id"] = Value::String("dev-sibling".into());
    assert!(parse_get_prekey_bundle_result_v2(&invalid_get_result).is_err());
    let mut invalid_direct_result = fixture["direct_send_result"].clone();
    invalid_direct_result["operation_id"] = Value::String("other-operation".into());
    assert!(parse_direct_send_result_v2(&invalid_direct_result).is_err());
    let mut invalid_publish_result = fixture["publish_result"].clone();
    invalid_publish_result["unexpected"] = Value::Bool(true);
    assert!(parse_publish_prekey_bundle_result_v2(&invalid_publish_result).is_err());
}

#[test]
fn shared_signed_bundle_golden_verifies() {
    let fixture = vectors();
    let golden = &fixture["signed_bundle_golden"];
    let bundle: V2PrekeyBundle =
        serde_json::from_value(golden["prekey_bundle"].clone()).expect("signed bundle");
    let now = DateTime::parse_from_rfc3339(golden["now"].as_str().expect("now"))
        .expect("RFC3339")
        .with_timezone(&Utc);
    anp::direct_e2ee::verify_prekey_bundle_v2(&bundle, &golden["did_document"], now)
        .expect("cross-language signed bundle");

    let mut tampered = bundle;
    tampered.signed_prekey.key_id = "spk-tampered".to_owned();
    assert!(
        anp::direct_e2ee::verify_prekey_bundle_v2(&tampered, &golden["did_document"], now,)
            .is_err()
    );
}

#[test]
fn shared_v2_direct_aad_and_plaintext_vectors_match() {
    let fixture = vectors();
    let (init_meta, init_body) =
        parse_direct_send_request_v2(&fixture["direct_init_request"]).expect("init request");
    let V2DirectBody::Init(init_body) = init_body else {
        panic!("expected init body")
    };
    assert_eq!(
        String::from_utf8(build_init_aad_v2(&init_meta, &init_body).expect("AD_init"))
            .expect("UTF-8"),
        fixture["expected_ad_init"]
            .as_str()
            .expect("AD_init vector")
    );
    assert_eq!(
        direct_send_request_v2(init_meta, V2DirectBody::Init(init_body)).expect("rebuild init"),
        fixture["direct_init_request"]
    );

    let (cipher_meta, cipher_body) =
        parse_direct_send_request_v2(&fixture["direct_cipher_request"]).expect("cipher request");
    let V2DirectBody::Cipher(cipher_body) = cipher_body else {
        panic!("expected cipher body")
    };
    assert_eq!(
        String::from_utf8(build_message_aad_v2(&cipher_meta, &cipher_body).expect("AD_msg"))
            .expect("UTF-8"),
        fixture["expected_ad_msg"].as_str().expect("AD_msg vector")
    );

    let plaintext: V2ApplicationPlaintext =
        serde_json::from_value(fixture["application_plaintext"].clone()).expect("plaintext");
    assert_eq!(
        String::from_utf8(canonical_application_plaintext_v2(&plaintext).expect("plaintext JCS"))
            .expect("UTF-8"),
        fixture["expected_application_plaintext_jcs"]
            .as_str()
            .expect("plaintext vector")
    );
    let numeric: V2ApplicationPlaintext =
        serde_json::from_value(fixture["application_plaintext_numeric"].clone())
            .expect("numeric plaintext");
    assert_eq!(
        String::from_utf8(
            canonical_application_plaintext_v2(&numeric).expect("numeric plaintext JCS")
        )
        .expect("UTF-8"),
        fixture["expected_application_plaintext_numeric_jcs"]
            .as_str()
            .expect("numeric plaintext vector")
    );
}

#[test]
fn v2_rejects_device_tamper_batches_auth_and_internal_fields() {
    let fixture = vectors();
    let mut request = fixture["direct_init_request"].clone();
    request["params"]["meta"]["recipient_device_id"] = Value::String("dev-sibling".into());
    let (tampered_meta, body) = parse_direct_send_request_v2(&request).expect("wire shape");
    let V2DirectBody::Init(body) = body else {
        panic!("init body")
    };
    let tampered = build_init_aad_v2(&tampered_meta, &body).expect("tampered AAD");
    assert_ne!(
        String::from_utf8(tampered).expect("UTF-8"),
        fixture["expected_ad_init"].as_str().expect("original AAD")
    );
    request["params"]["meta"]["recipient_device_id"] =
        fixture["direct_init_request"]["params"]["meta"]["recipient_device_id"].clone();
    request["params"]["meta"]["sender_device_id"] = Value::String("dev-sender-sibling".into());
    let (tampered_meta, body) = parse_direct_send_request_v2(&request).expect("wire shape");
    let V2DirectBody::Init(body) = body else {
        panic!("init body")
    };
    assert_ne!(
        String::from_utf8(build_init_aad_v2(&tampered_meta, &body).expect("AAD")).expect("UTF-8"),
        fixture["expected_ad_init"].as_str().expect("original AAD")
    );

    for forbidden in ["auth", "deliveries", "root_private_key", "document_version"] {
        let mut invalid = fixture["direct_init_request"].clone();
        invalid["params"][forbidden] = Value::Object(Default::default());
        assert!(
            parse_direct_send_request_v2(&invalid).is_err(),
            "accepted forbidden field {forbidden}"
        );
    }

    let mut mismatched = fixture["direct_init_request"].clone();
    mismatched["params"]["meta"]["operation_id"] = Value::String("other-id".into());
    assert!(parse_direct_send_request_v2(&mismatched).is_err());

    let mut logical_outer = fixture["direct_init_request"].clone();
    logical_outer["params"]["meta"]["logical_message_id"] = Value::String("logical".into());
    assert!(parse_direct_send_request_v2(&logical_outer).is_err());
}

#[test]
fn v2_error_allocations_match_shared_table() {
    let fixture = vectors();
    let expected = fixture["errors"].as_array().expect("error table");
    assert_eq!(expected.len(), DIRECT_E2EE_V2_ERRORS.len());
    for value in expected {
        let code = value["code"].as_i64().expect("code") as i32;
        let entry = direct_e2ee_v2_error(code).expect("known P5 v2 code");
        assert_eq!(
            entry.anp_code,
            value["anp_code"].as_str().expect("anp_code")
        );
    }
    assert!(direct_e2ee_v2_error(5000).is_none());
}

#[test]
fn optional_meta_fields_never_enter_v2_aad() {
    let fixture = vectors();
    let (mut metadata, body) =
        parse_direct_send_request_v2(&fixture["direct_init_request"]).expect("request");
    let V2DirectBody::Init(body) = body else {
        panic!("init body")
    };
    let original = build_init_aad_v2(&metadata, &body).expect("AAD");
    metadata.anp_version = Some("9.9".into());
    metadata.created_at = Some("2030-01-01T00:00:00Z".into());
    assert_eq!(original, build_init_aad_v2(&metadata, &body).expect("AAD"));
}

#[test]
fn get_body_requires_exact_device_selector() {
    let fixture = vectors();
    let (meta, _) =
        parse_get_prekey_bundle_request_v2(&fixture["get_request"]).expect("get request");
    let body = V2GetPrekeyBundleBody {
        target_did: fixture["get_result"]["target_did"]
            .as_str()
            .expect("target DID")
            .to_owned(),
        target_device_id: String::new(),
        preferred_suite: None,
        require_opk: None,
    };
    assert!(get_prekey_bundle_request_v2(meta, body).is_err());
}

#[test]
fn publish_opks_are_optional_but_not_encoded_as_empty_placeholder() {
    let fixture = vectors();
    let (meta, body) =
        parse_publish_prekey_bundle_request_v2(&fixture["publish_request"]).expect("publish");
    let request = publish_prekey_bundle_request_v2(
        meta,
        V2PublishPrekeyBundleBody {
            prekey_bundle: body.prekey_bundle,
            one_time_prekeys: Vec::new(),
        },
    )
    .expect("request without OPKs");
    assert!(request["params"]["body"].get("one_time_prekeys").is_none());

    let mut invalid = fixture["publish_request"].clone();
    invalid["params"]["body"]["one_time_prekeys"] = Value::Array(Vec::new());
    assert!(parse_publish_prekey_bundle_request_v2(&invalid).is_err());

    let mut invalid = fixture["publish_request"].clone();
    invalid["params"]["body"]["prekey_bundle"]["signed_prekey"]["public_key_b64u"] =
        Value::String("AA==".to_owned());
    assert!(parse_publish_prekey_bundle_request_v2(&invalid).is_err());
}

#[test]
fn v2_rejects_shared_invalid_wire_encodings() {
    let fixture = vectors();
    let invalid = &fixture["encoding_negative_values"];
    for (request_name, pointer, value_name) in [
        (
            "direct_init_request",
            "/params/body/session_id",
            "session_id",
        ),
        (
            "direct_init_request",
            "/params/body/sender_ephemeral_pub_b64u",
            "x25519_public_key",
        ),
        (
            "direct_init_request",
            "/params/body/ciphertext_b64u",
            "ciphertext_b64u",
        ),
        (
            "direct_cipher_request",
            "/params/body/ratchet_header/dh_pub_b64u",
            "x25519_public_key",
        ),
        (
            "direct_cipher_request",
            "/params/meta/created_at",
            "created_at",
        ),
    ] {
        let mut request = fixture[request_name].clone();
        *request.pointer_mut(pointer).expect("fixture path") = invalid[value_name].clone();
        assert!(
            parse_direct_send_request_v2(&request).is_err(),
            "accepted {value_name}"
        );
    }
    let mut plaintext = json!({
        "application_content_type": "application/octet-stream",
        "payload_b64u": invalid["payload_b64u"]
    });
    let plaintext: V2ApplicationPlaintext =
        serde_json::from_value(plaintext.take()).expect("wire shape");
    assert!(canonical_application_plaintext_v2(&plaintext).is_err());
}

#[test]
fn v2_rejects_explicit_nulls_and_content_bearer_mismatches() {
    let fixture = vectors();
    let mut request = fixture["direct_init_request"].clone();
    request["params"]["body"]["recipient_one_time_prekey_id"] = Value::Null;
    assert!(parse_direct_send_request_v2(&request).is_err());

    for field in ["preferred_suite", "require_opk"] {
        let mut request = fixture["get_request"].clone();
        request["params"]["body"][field] = Value::Null;
        assert!(parse_get_prekey_bundle_request_v2(&request).is_err());
    }

    for plaintext in [
        json!({"application_content_type": "text/plain", "payload": {}}),
        json!({"application_content_type": "application/json", "text": "wrong"}),
        json!({"application_content_type": "application/json", "annotations": [], "payload": {}}),
        json!({"application_content_type": "application/json", "annotations": null, "payload": {}}),
    ] {
        if let Ok(value) = serde_json::from_value::<V2ApplicationPlaintext>(plaintext) {
            assert!(canonical_application_plaintext_v2(&value).is_err());
        }
    }
}

#[test]
fn v2_bundle_proof_covers_owner_device_and_all_static_fields() {
    let generated = create_did_wba_document(
        "bundle-v2.example",
        DidDocumentOptions {
            path_segments: vec!["agents".to_owned(), "alice".to_owned()],
            did_profile: DidProfile::E1,
            ..Default::default()
        },
    )
    .expect("DID document");
    let did = generated.did().expect("DID").to_owned();
    let mut document = generated.did_document.clone();
    document
        .as_object_mut()
        .expect("document object")
        .remove("proof");
    document["deviceManifest"] = json!({
        "type": "ANPDeviceManifest",
        "devices": [{
            "device_id": "dev-a",
            "signing_key_id": format!("{did}#key-1"),
            "e2ee_key_id": format!("{did}#key-3"),
            "profiles": [
                "anp.core.binding.v2",
                "anp.identity.discovery.v2",
                "anp.direct.base.v2",
                "anp.direct.e2ee.v2"
            ]
        }]
    });
    let signing_key = PrivateKeyMaterial::from_pem(&generated.keys["key-1"].private_key_pem)
        .expect("signing key");
    document = generate_w3c_proof(
        &document,
        &signing_key,
        &format!("{did}#key-1"),
        ProofGenerationOptions {
            proof_purpose: Some("assertionMethod".to_owned()),
            proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_owned()),
            cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.to_owned()),
            created: Some("2026-07-19T00:00:00Z".to_owned()),
            ..Default::default()
        },
    )
    .expect("resigned DID document");
    let spk = X25519StaticSecret::from([17u8; 32]);
    let signed_prekey = V2SignedPrekey {
        key_id: "spk-v2".to_owned(),
        public_key_b64u: URL_SAFE_NO_PAD.encode(x25519_dalek::PublicKey::from(&spk).to_bytes()),
        expires_at: "2035-01-01T00:00:00Z".to_owned(),
    };
    let bundle = build_prekey_bundle_v2(
        "bundle-v2",
        &did,
        "dev-a",
        &format!("{did}#key-3"),
        signed_prekey,
        &signing_key,
        &format!("{did}#key-1"),
        Some("2026-07-19T00:00:00Z"),
    )
    .expect("signed bundle");
    let invalid_prekey = V2SignedPrekey {
        key_id: "spk-invalid".to_owned(),
        public_key_b64u: "AA==".to_owned(),
        expires_at: "not-rfc3339".to_owned(),
    };
    assert!(build_prekey_bundle_v2(
        "bundle-invalid",
        &did,
        "dev-a",
        &format!("{did}#key-3"),
        invalid_prekey,
        &signing_key,
        &format!("{did}#key-1"),
        Some("2026-07-19T00:00:00Z"),
    )
    .is_err());
    anp::direct_e2ee::verify_prekey_bundle_v2(
        &bundle,
        &document,
        Utc.with_ymd_and_hms(2026, 7, 19, 0, 0, 1).unwrap(),
    )
    .expect("valid bundle");

    let mut tampered = bundle.clone();
    tampered.owner_device_id = "dev-sibling".to_owned();
    assert!(anp::direct_e2ee::verify_prekey_bundle_v2(
        &tampered,
        &document,
        Utc.with_ymd_and_hms(2026, 7, 19, 0, 0, 1).unwrap(),
    )
    .is_err());
    let mut tampered = bundle;
    tampered.suite = format!("{MTI_DIRECT_E2EE_SUITE_V2}-tampered");
    assert!(anp::direct_e2ee::verify_prekey_bundle_v2(
        &tampered,
        &document,
        Utc.with_ymd_and_hms(2026, 7, 19, 0, 0, 1).unwrap(),
    )
    .is_err());
}
