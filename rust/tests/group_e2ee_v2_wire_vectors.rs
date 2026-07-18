use anp::authentication::{create_did_wba_document, DidDocumentOptions, DidProfile};
use anp::group_e2ee::*;
use anp::proof::{
    generate_w3c_proof, ProofGenerationOptions, CRYPTOSUITE_EDDSA_JCS_2022,
    PROOF_TYPE_DATA_INTEGRITY,
};
use anp::PrivateKeyMaterial;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{json, Value};

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../testdata/group_e2ee/p6_v2_wire_vectors.json"
    ))
    .expect("P6 v2 fixture")
}

#[test]
fn shared_p6_v2_wire_objects_round_trip() {
    let fixture = vectors();
    assert_eq!(PROFILE, "anp.group.e2ee.v1");
    assert_eq!(GROUP_E2EE_PROFILE_V2, "anp.group.e2ee.v2");

    let (meta, body) =
        parse_publish_key_package_request_v2(&fixture["publish_request"]).expect("publish request");
    assert_eq!(
        publish_key_package_request_v2(meta, body).expect("publish build"),
        fixture["publish_request"]
    );

    let (meta, body) =
        parse_get_key_package_request_v2(&fixture["get_request"]).expect("get request");
    assert_eq!(
        get_key_package_request_v2(meta, body).expect("get build"),
        fixture["get_request"]
    );

    let (meta, body, auth) =
        parse_group_create_request_v2(&fixture["create_request"]).expect("create request");
    assert_eq!(
        group_create_request_v2(meta, body, auth).expect("create build"),
        fixture["create_request"]
    );

    let (meta, body, auth) =
        parse_group_add_request_v2(&fixture["add_request"]).expect("add request");
    assert_eq!(
        group_add_request_v2(meta, body, auth).expect("add build"),
        fixture["add_request"]
    );

    let (meta, body, auth) =
        parse_group_remove_request_v2(&fixture["remove_request"]).expect("remove request");
    assert_eq!(
        group_remove_request_v2(meta, body, auth).expect("remove build"),
        fixture["remove_request"]
    );

    let (meta, body, auth) =
        parse_group_send_request_v2(&fixture["send_request"]).expect("send request");
    assert_eq!(
        group_send_request_v2(meta, body, auth).expect("send build"),
        fixture["send_request"]
    );

    let (meta, body) = parse_group_notice_notification_v2(&fixture["notice_notification"])
        .expect("notice notification");
    assert_eq!(
        group_notice_notification_v2(meta, body).expect("notice build"),
        fixture["notice_notification"]
    );

    let (meta, body, auth) =
        parse_group_incoming_notification_v2(&fixture["incoming_notification"])
            .expect("incoming notification");
    assert_eq!(
        group_incoming_notification_v2(meta, body, auth).expect("incoming build"),
        fixture["incoming_notification"]
    );

    assert!(parse_publish_key_package_result_v2(&fixture["publish_result"]).is_ok());
    assert!(parse_get_key_package_result_v2(&fixture["get_result"]).is_ok());
    assert!(parse_group_create_result_v2(&fixture["create_result"]).is_ok());
    assert!(parse_group_membership_result_v2(&fixture["add_result"]).is_ok());
    assert!(parse_group_send_result_v2(&fixture["send_result"]).is_ok());
}

#[test]
fn shared_p6_v2_canonical_vectors_match() {
    let fixture = vectors();
    let binding: V2DidWbaBinding =
        serde_json::from_value(fixture["member_key_package"]["did_wba_binding"].clone())
            .expect("binding");
    assert_eq!(
        String::from_utf8(serde_json_canonicalizer::to_vec(&binding).expect("binding JCS"))
            .expect("UTF-8"),
        fixture["expected_member_binding_jcs"]
            .as_str()
            .expect("binding vector")
    );
    let (send_meta, cipher, _) =
        parse_group_send_request_v2(&fixture["send_request"]).expect("send");
    assert_eq!(
        String::from_utf8(
            group_send_authenticated_data_v2(&send_meta, &cipher).expect("authenticated_data")
        )
        .expect("UTF-8"),
        fixture["expected_send_authenticated_data_jcs"]
            .as_str()
            .expect("send JCS")
    );

    let (add_meta, add_body, _) = parse_group_add_request_v2(&fixture["add_request"]).expect("add");
    assert_eq!(
        String::from_utf8(
            group_add_submission_binding_v2(&add_meta, &add_body).expect("add binding")
        )
        .expect("UTF-8"),
        fixture["expected_add_submission_binding_jcs"]
            .as_str()
            .expect("add JCS")
    );

    let (remove_meta, remove_body, _) =
        parse_group_remove_request_v2(&fixture["remove_request"]).expect("remove");
    assert_eq!(
        String::from_utf8(
            group_remove_submission_binding_v2(&remove_meta, &remove_body).expect("remove binding")
        )
        .expect("UTF-8"),
        fixture["expected_remove_submission_binding_jcs"]
            .as_str()
            .expect("remove JCS")
    );

    let plaintext =
        parse_group_application_plaintext_v2(&fixture["application_plaintext"]).expect("plaintext");
    assert_eq!(
        String::from_utf8(
            canonical_group_application_plaintext_v2(&plaintext).expect("plaintext JCS")
        )
        .expect("UTF-8"),
        fixture["expected_application_plaintext_jcs"]
            .as_str()
            .expect("plaintext vector")
    );
}

#[test]
fn p6_v2_wire_is_closed_and_device_bound() {
    let fixture = vectors();
    let wire = serde_json::to_string(&fixture).expect("fixture JSON");
    for internal in [
        "document_version",
        "document_hash",
        "registry_version",
        "auth_generation",
    ] {
        assert!(
            !wire.contains(internal),
            "internal field leaked: {internal}"
        );
    }
    let mut request = fixture["send_request"].clone();
    request["params"]["meta"]["unexpected"] = json!(true);
    assert!(parse_group_send_request_v2(&request).is_err());

    let mut request = fixture["send_request"].clone();
    request["params"]["meta"]["sender_device_id"] = json!("dev-sibling");
    let (meta, body, _) = parse_group_send_request_v2(&request).expect("structurally valid tamper");
    let tampered = group_send_authenticated_data_v2(&meta, &body).expect("tampered AAD");
    assert_ne!(
        tampered,
        fixture["expected_send_authenticated_data_jcs"]
            .as_str()
            .unwrap()
            .as_bytes()
    );

    let mut request = fixture["add_request"].clone();
    request["params"]["body"]["member_device_id"] = json!("dev-sibling");
    assert!(parse_group_add_request_v2(&request).is_err());

    let mut request = fixture["get_request"].clone();
    request["params"]["body"]["require_fresh"] = Value::Null;
    assert!(parse_get_key_package_request_v2(&request).is_err());

    let mut request = fixture["send_request"].clone();
    request["params"]["body"]["group_state_ref"]["group_state_version"] = json!("state:opaque-v42");
    assert!(parse_group_send_request_v2(&request).is_ok());

    assert_eq!(
        group_e2ee_v2_error(5002).unwrap().anp_code,
        "group.e2ee.did_binding_invalid"
    );
    assert_eq!(GROUP_E2EE_V2_ERRORS.len(), 13);
}

#[test]
fn p6_v2_binding_verifies_manifest_leaf_and_extension_chain() {
    let generated = create_did_wba_document(
        "p6-v2.example",
        DidDocumentOptions {
            path_segments: vec!["agents".to_owned(), "alice".to_owned()],
            did_profile: DidProfile::E1,
            ..Default::default()
        },
    )
    .expect("DID document");
    let did = generated.did().expect("DID").to_owned();
    let signing_key = PrivateKeyMaterial::from_pem(&generated.keys["key-1"].private_key_pem)
        .expect("signing key");
    let mut document = generated.did_document.clone();
    document.as_object_mut().unwrap().remove("proof");
    document["deviceManifest"] = json!({
        "type": "ANPDeviceManifest",
        "devices": [{
            "device_id": "dev-a",
            "signing_key_id": format!("{did}#key-1"),
            "e2ee_key_id": format!("{did}#key-3"),
            "profiles": [
                "anp.core.binding.v2",
                "anp.identity.discovery.v2",
                "anp.group.base.v2",
                "anp.group.e2ee.v2"
            ]
        }]
    });
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

    let leaf_key = URL_SAFE_NO_PAD.encode([7u8; 32]);
    let binding = generate_did_wba_binding_v2(
        V2DidWbaBindingUnsigned {
            agent_did: did.clone(),
            device_id: "dev-a".to_owned(),
            verification_method: format!("{did}#key-1"),
            leaf_signature_key_b64u: leaf_key.clone(),
            issued_at: "2026-07-19T00:00:00Z".to_owned(),
            expires_at: "2026-08-19T00:00:00Z".to_owned(),
        },
        &signing_key,
        Some("2026-07-19T00:00:00Z".to_owned()),
    )
    .expect("binding proof");
    let extension_data = serde_json_canonicalizer::to_vec(&binding).expect("binding JCS");
    let evidence = V2LeafBindingEvidence {
        credential_identity: did.as_bytes().to_vec(),
        leaf_signature_key_b64u: leaf_key.clone(),
        extensions: vec![V2LeafExtension {
            extension_type: DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2,
            extension_data,
        }],
        leaf_capability_extensions: vec![DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2],
    };
    verify_did_wba_binding_v2(
        &binding,
        &document,
        &evidence,
        &[DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2],
        "2026-07-20T00:00:00Z",
        true,
    )
    .expect("binding chain");

    let key_package_bytes = b"verified-mls-key-package".to_vec();
    let package = V2GroupKeyPackage {
        key_package_id: "kp-dev-a".to_owned(),
        owner_did: did.clone(),
        owner_device_id: "dev-a".to_owned(),
        suite: GROUP_E2EE_MTI_SUITE_V2.to_owned(),
        mls_key_package_b64u: URL_SAFE_NO_PAD.encode(&key_package_bytes),
        did_wba_binding: binding.clone(),
        expires_at: Some("2026-08-19T00:00:00Z".to_owned()),
    };
    let package_evidence = V2KeyPackageBindingEvidence {
        tls_serialized_key_package: key_package_bytes,
        leaf: evidence.clone(),
    };
    validate_group_key_package_binding_v2(
        &package,
        &document,
        &package_evidence,
        &[DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2],
        "2026-07-20T00:00:00Z",
        true,
    )
    .expect("verified TLS package projection");
    let mut wrong_package_evidence = package_evidence.clone();
    wrong_package_evidence.tls_serialized_key_package.push(0);
    assert!(validate_group_key_package_binding_v2(
        &package,
        &document,
        &wrong_package_evidence,
        &[DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2],
        "2026-07-20T00:00:00Z",
        true,
    )
    .is_err());

    let mut tampered = evidence.clone();
    tampered.credential_identity = b"did:wba:other.example:mallory".to_vec();
    assert!(verify_did_wba_binding_v2(
        &binding,
        &document,
        &tampered,
        &[DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2],
        "2026-07-20T00:00:00Z",
        true,
    )
    .is_err());
    let mut tampered = evidence.clone();
    tampered.leaf_signature_key_b64u = URL_SAFE_NO_PAD.encode([9u8; 32]);
    assert!(verify_did_wba_binding_v2(
        &binding,
        &document,
        &tampered,
        &[DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2],
        "2026-07-20T00:00:00Z",
        true,
    )
    .is_err());
    let mut replayed_binding = binding.clone();
    replayed_binding.device_id = "dev-sibling".to_owned();
    let mut replayed_evidence = evidence.clone();
    replayed_evidence.extensions[0].extension_data =
        serde_json_canonicalizer::to_vec(&replayed_binding).expect("replayed binding JCS");
    assert!(verify_did_wba_binding_v2(
        &replayed_binding,
        &document,
        &replayed_evidence,
        &[DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2],
        "2026-07-20T00:00:00Z",
        true,
    )
    .is_err());
    let mut tampered = evidence.clone();
    tampered.extensions[0].extension_data.push(0);
    assert!(verify_did_wba_binding_v2(
        &binding,
        &document,
        &tampered,
        &[DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2],
        "2026-07-20T00:00:00Z",
        true,
    )
    .is_err());
    assert!(verify_did_wba_binding_v2(
        &binding,
        &document,
        &evidence,
        &[DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2],
        "2026-07-20T00:00:00Z",
        false,
    )
    .is_err());
    assert!(ensure_p6_v2_public_release_ready().is_err());

    validate_leaf_identity_set_v2(&[
        V2LeafIdentity {
            agent_did: did.clone(),
            device_id: "dev-a".to_owned(),
            leaf_signature_key_b64u: leaf_key,
        },
        V2LeafIdentity {
            agent_did: did,
            device_id: "dev-b".to_owned(),
            leaf_signature_key_b64u: URL_SAFE_NO_PAD.encode([8u8; 32]),
        },
    ])
    .expect("same DID may own two distinct device leaves");
}
