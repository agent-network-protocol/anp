mod common;

use std::collections::BTreeMap;
use std::fs;

use anp::authentication::{
    build_agent_message_service, build_agent_message_service_with_options,
    build_anp_message_service, build_group_message_service, build_unsigned_e1_did_document,
    complete_http_signature_headers, complete_legacy_did_wba_auth_header, create_did_wba_document,
    create_did_wba_document_with_creation_options, extract_signature_metadata,
    generate_auth_header, generate_auth_header_with_kid, generate_http_signature_headers,
    generate_http_signature_headers_with_kid, prepare_http_signature_headers,
    prepare_legacy_did_wba_auth_header, validate_did_document_binding,
    verify_auth_header_signature, verify_federated_http_request, verify_http_message_signature,
    AnpMessageServiceOptions, AuthMode, DIDWbaAuthHeader, DidDocumentCreationOptions,
    DidDocumentOptions, DidKeyRole, DidProfile, DidVerificationRelationship, DidWbaVerifier,
    DidWbaVerifierConfig, FederatedVerificationOptions, HttpSignatureError, HttpSignatureOptions,
    SuppliedDidKey, SuppliedE1DidDocumentOptions,
};
#[cfg(feature = "network")]
use anp::authentication::{
    resolve_did_document_with_options, resolve_did_wba_document_with_options, DidResolutionOptions,
};
use anp::proof::{
    complete_w3c_proof, prepare_w3c_proof, verify_w3c_proof, ProofGenerationOptions,
    ProofVerificationOptions, CRYPTOSUITE_EDDSA_JCS_2022, PROOF_TYPE_DATA_INTEGRITY,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use common::tempdir;
#[cfg(feature = "network")]
use common::{JsonTestServer, RecordingJsonTestServer};
use ed25519_dalek::SigningKey;
use serde_json::json;

#[test]
fn test_create_did_document_profiles() {
    let e1 = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["user".to_string(), "alice".to_string()],
            ..DidDocumentOptions::default()
        },
    )
    .expect("e1 DID creation should succeed");
    assert!(e1.did_document["id"].as_str().unwrap().contains(":e1_"));
    assert_eq!(
        e1.did_document["proof"]["type"],
        json!("DataIntegrityProof")
    );

    let k1 = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["user".to_string(), "alice".to_string()],
            did_profile: DidProfile::K1,
            ..DidDocumentOptions::default()
        },
    )
    .expect("k1 DID creation should succeed");
    assert!(k1.did_document["id"].as_str().unwrap().contains(":k1_"));

    let legacy = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["user".to_string(), "alice".to_string()],
            did_profile: DidProfile::PlainLegacy,
            ..DidDocumentOptions::default()
        },
    )
    .expect("legacy DID creation should succeed");
    assert_eq!(
        legacy.did_document["proof"]["type"],
        json!("EcdsaSecp256k1Signature2019")
    );

    let bare = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("bare DID creation should succeed");
    assert_eq!(bare.did_document["id"], json!("did:wba:example.com"));
}

#[test]
fn test_supplied_public_keys_build_and_sign_a_root_bound_e1_document() {
    let root = anp::PrivateKeyMaterial::Ed25519(SigningKey::from_bytes(&[7_u8; 32]));
    let request = anp::PrivateKeyMaterial::Ed25519(SigningKey::generate(&mut rand::rngs::OsRng));
    let device = anp::PrivateKeyMaterial::Ed25519(SigningKey::generate(&mut rand::rngs::OsRng));
    let e2ee_signing =
        anp::PrivateKeyMaterial::Ed25519(SigningKey::generate(&mut rand::rngs::OsRng));
    let agreement = anp::PrivateKeyMaterial::X25519(x25519_dalek::StaticSecret::random_from_rng(
        rand::rngs::OsRng,
    ));
    let unsigned = build_unsigned_e1_did_document(
        "example.com",
        SuppliedE1DidDocumentOptions {
            port: None,
            path_segments: vec!["agents".to_string(), "alice".to_string()],
            agent_description_url: Some("https://example.com/agents/alice".to_string()),
            services: Vec::new(),
            root_key: supplied_key(
                "root",
                DidKeyRole::RootControl,
                root.public_key(),
                &[
                    DidVerificationRelationship::Authentication,
                    DidVerificationRelationship::AssertionMethod,
                ],
            ),
            additional_keys: vec![
                supplied_key(
                    "device",
                    DidKeyRole::DeviceSigning,
                    device.public_key(),
                    &[
                        DidVerificationRelationship::Authentication,
                        DidVerificationRelationship::AssertionMethod,
                    ],
                ),
                supplied_key(
                    "request",
                    DidKeyRole::RequestSigning,
                    request.public_key(),
                    &[DidVerificationRelationship::Authentication],
                ),
                supplied_key(
                    "e2ee-signing",
                    DidKeyRole::E2eeSigning,
                    e2ee_signing.public_key(),
                    &[DidVerificationRelationship::AssertionMethod],
                ),
                supplied_key(
                    "agreement",
                    DidKeyRole::E2eeAgreement,
                    agreement.public_key(),
                    &[DidVerificationRelationship::KeyAgreement],
                ),
            ],
        },
    )
    .expect("supplied-key E1 builder should succeed");
    let did = unsigned["id"].as_str().expect("DID id");
    assert_eq!(
        did,
        "did:wba:example.com:agents:alice:e1_--6IM5l0OosLj9yWskISYhUA3n_3CURQkmrYMSha_ck"
    );
    assert!(unsigned.get("proof").is_none());
    assert_eq!(unsigned["verificationMethod"].as_array().unwrap().len(), 5);
    assert_eq!(unsigned["authentication"].as_array().unwrap().len(), 3);
    assert_eq!(unsigned["assertionMethod"].as_array().unwrap().len(), 3);
    assert_eq!(unsigned["keyAgreement"].as_array().unwrap().len(), 1);

    let root_kid = format!("{did}#root");
    let prepared = prepare_w3c_proof(
        &unsigned,
        &root.public_key(),
        &root_kid,
        ProofGenerationOptions {
            proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_string()),
            cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.to_string()),
            proof_purpose: Some("assertionMethod".to_string()),
            created: Some("2026-08-18T10:00:00Z".to_string()),
            ..ProofGenerationOptions::default()
        },
    )
    .expect("proof preparation should succeed");
    let signature = root
        .sign_message(prepared.signing_input())
        .expect("root signer should sign");
    let signed = complete_w3c_proof(prepared, &signature).expect("proof should complete");

    assert!(validate_did_document_binding(&signed, true));
}

#[test]
fn test_supplied_e1_builder_rejects_empty_path() {
    let root = anp::PrivateKeyMaterial::Ed25519(SigningKey::generate(&mut rand::rngs::OsRng));
    let result = build_unsigned_e1_did_document(
        "example.com",
        SuppliedE1DidDocumentOptions {
            port: None,
            path_segments: Vec::new(),
            agent_description_url: None,
            services: Vec::new(),
            root_key: supplied_key(
                "root",
                DidKeyRole::RootControl,
                root.public_key(),
                &[
                    DidVerificationRelationship::Authentication,
                    DidVerificationRelationship::AssertionMethod,
                ],
            ),
            additional_keys: Vec::new(),
        },
    );

    assert!(result.is_err());
}

#[test]
fn test_default_did_document_has_no_additional_authentication_methods() {
    let bundle = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["user".to_string(), "alice".to_string()],
            ..DidDocumentOptions::default()
        },
    )
    .expect("e1 DID creation should succeed");

    let methods = bundle
        .did_document
        .get("verificationMethod")
        .and_then(serde_json::Value::as_array)
        .expect("verification methods");
    assert!(!methods.iter().any(|method| method
        .get("id")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|id| id.ends_with("#daemon-key-1"))));
    let authentication = bundle
        .did_document
        .get("authentication")
        .and_then(serde_json::Value::as_array)
        .expect("authentication");
    assert!(!authentication.iter().any(|entry| entry
        .as_str()
        .is_some_and(|id| id.ends_with("#daemon-key-1"))));
}

#[test]
fn test_additional_authentication_methods_are_signed_before_proof() {
    let delegated_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let delegated_public_multibase =
        ed25519_public_key_to_multibase(&delegated_key.verifying_key());
    let options = DidDocumentCreationOptions::new(DidDocumentOptions {
        path_segments: vec!["user".to_string(), "alice".to_string()],
        ..DidDocumentOptions::default()
    })
    .with_additional_verification_method(json!({
        "id": "#daemon-key-1",
        "type": "Multikey",
        "publicKeyMultibase": delegated_public_multibase,
    }))
    .with_additional_authentication("#daemon-key-1");

    let bundle = create_did_wba_document_with_creation_options("example.com", options)
        .expect("DID creation should succeed");
    let did = bundle.did().expect("DID should exist");
    let delegated_method_id = format!("{did}#daemon-key-1");
    let methods = bundle
        .did_document
        .get("verificationMethod")
        .and_then(serde_json::Value::as_array)
        .expect("verification methods");
    let delegated_method = methods
        .iter()
        .find(|method| {
            method.get("id").and_then(serde_json::Value::as_str)
                == Some(delegated_method_id.as_str())
        })
        .expect("delegated method should exist");
    assert_eq!(delegated_method["controller"], json!(did));
    assert_eq!(
        delegated_method["publicKeyMultibase"],
        json!(delegated_public_multibase)
    );
    assert!(bundle
        .did_document
        .get("authentication")
        .and_then(serde_json::Value::as_array)
        .expect("authentication")
        .iter()
        .any(|entry| entry.as_str() == Some(delegated_method_id.as_str())));

    let signing_public = anp::PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
        .expect("key-1 private should load")
        .public_key();
    assert!(verify_w3c_proof(
        &bundle.did_document,
        &signing_public,
        ProofVerificationOptions {
            expected_purpose: Some("assertionMethod".to_string()),
            ..ProofVerificationOptions::default()
        }
    ));

    let mut tampered = bundle.did_document.clone();
    tampered["authentication"] = json!([format!("{did}#key-1")]);
    assert!(!verify_w3c_proof(
        &tampered,
        &signing_public,
        ProofVerificationOptions {
            expected_purpose: Some("assertionMethod".to_string()),
            ..ProofVerificationOptions::default()
        }
    ));
}

#[test]
fn test_additional_verification_method_rejects_controller_mismatch() {
    let delegated_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let options = DidDocumentCreationOptions::new(DidDocumentOptions {
        path_segments: vec!["user".to_string(), "alice".to_string()],
        ..DidDocumentOptions::default()
    })
    .with_additional_verification_method(json!({
        "id": "#daemon-key-1",
        "type": "Multikey",
        "controller": "did:wba:evil.example",
        "publicKeyMultibase": ed25519_public_key_to_multibase(&delegated_key.verifying_key()),
    }))
    .with_additional_authentication("#daemon-key-1");

    assert!(create_did_wba_document_with_creation_options("example.com", options).is_err());
}

#[test]
fn test_additional_verification_method_rejects_private_jwk_material() {
    let delegated_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let options = DidDocumentCreationOptions::new(DidDocumentOptions {
        path_segments: vec!["user".to_string(), "alice".to_string()],
        ..DidDocumentOptions::default()
    })
    .with_additional_verification_method(json!({
        "id": "#daemon-key-1",
        "type": "JsonWebKey2020",
        "publicKeyJwk": {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(delegated_key.verifying_key().to_bytes()),
            "d": "must-not-be-accepted",
        },
    }));

    assert!(create_did_wba_document_with_creation_options("example.com", options).is_err());
}

#[test]
fn test_additional_authentication_rejects_unknown_reference() {
    let options = DidDocumentCreationOptions::new(DidDocumentOptions {
        path_segments: vec!["user".to_string(), "alice".to_string()],
        ..DidDocumentOptions::default()
    })
    .with_additional_authentication("#daemon-key-1");

    assert!(create_did_wba_document_with_creation_options("example.com", options).is_err());
}

#[test]
fn test_validate_did_document_binding_rejects_e1_without_assertion_method_authorization() {
    let bundle = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["user".to_string(), "alice".to_string()],
            ..DidDocumentOptions::default()
        },
    )
    .expect("e1 DID creation should succeed");

    let mut document = bundle.did_document.clone();
    let assertion_method = document
        .get_mut("assertionMethod")
        .and_then(serde_json::Value::as_array_mut)
        .expect("assertionMethod should exist");
    assertion_method.clear();

    assert!(
        !validate_did_document_binding(&document, false),
        "e1 DID binding should require proof.verificationMethod authorization in assertionMethod",
    );
}

fn ed25519_public_key_to_multibase(key: &ed25519_dalek::VerifyingKey) -> String {
    let mut bytes = vec![0xed, 0x01];
    bytes.extend_from_slice(&key.to_bytes());
    format!("z{}", bs58::encode(bytes).into_string())
}

fn supplied_key(
    fragment: &str,
    role: DidKeyRole,
    public_key: anp::PublicKeyMaterial,
    relationships: &[DidVerificationRelationship],
) -> SuppliedDidKey {
    SuppliedDidKey {
        fragment: fragment.to_string(),
        role,
        public_key,
        relationships: relationships.to_vec(),
    }
}

fn supplied_authentication_fixture() -> (
    serde_json::Value,
    anp::PrivateKeyMaterial,
    anp::PrivateKeyMaterial,
) {
    let root = anp::PrivateKeyMaterial::Ed25519(SigningKey::generate(&mut rand::rngs::OsRng));
    let request = anp::PrivateKeyMaterial::Ed25519(SigningKey::generate(&mut rand::rngs::OsRng));
    let e2ee = anp::PrivateKeyMaterial::Ed25519(SigningKey::generate(&mut rand::rngs::OsRng));
    let document = build_unsigned_e1_did_document(
        "example.com",
        SuppliedE1DidDocumentOptions {
            port: None,
            path_segments: vec!["agents".to_string(), "alice".to_string()],
            agent_description_url: None,
            services: Vec::new(),
            root_key: supplied_key(
                "root",
                DidKeyRole::RootControl,
                root.public_key(),
                &[
                    DidVerificationRelationship::Authentication,
                    DidVerificationRelationship::AssertionMethod,
                ],
            ),
            additional_keys: vec![
                supplied_key(
                    "request",
                    DidKeyRole::RequestSigning,
                    request.public_key(),
                    &[DidVerificationRelationship::Authentication],
                ),
                supplied_key(
                    "e2ee-signing",
                    DidKeyRole::E2eeSigning,
                    e2ee.public_key(),
                    &[DidVerificationRelationship::AssertionMethod],
                ),
            ],
        },
    )
    .expect("supplied authentication fixture should build");
    (document, request, e2ee)
}

#[test]
fn test_validate_did_document_binding_rejects_e1_with_tampered_thumbprint() {
    let bundle = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["user".to_string(), "alice".to_string()],
            ..DidDocumentOptions::default()
        },
    )
    .expect("e1 DID creation should succeed");

    let mut document = bundle.did_document.clone();
    let original_did = document["id"]
        .as_str()
        .expect("DID should be a string")
        .to_string();
    let tampered_did = format!("{original_did}x");
    document["id"] = json!(tampered_did);

    assert!(
        !validate_did_document_binding(&document, false),
        "e1 DID binding should fail when the path thumbprint no longer matches the proof key",
    );
}

#[test]
fn test_build_anp_message_service_helpers() {
    let agent =
        build_agent_message_service("did:wba:example.com:user:alice", "https://example.com/rpc");
    assert_eq!(agent["type"], json!("ANPMessageService"));
    assert_eq!(agent["id"], json!("did:wba:example.com:user:alice#message"));
    assert_eq!(agent["profiles"][1], json!("anp.direct.base.v1"));
    assert_eq!(agent["securityProfiles"][1], json!("direct-e2ee"));

    let group =
        build_group_message_service("did:wba:example.com:groups:test", "https://example.com/rpc");
    assert_eq!(group["type"], json!("ANPMessageService"));
    assert_eq!(group["profiles"][1], json!("anp.group.base.v1"));
    assert_eq!(group["securityProfiles"][1], json!("group-e2ee"));

    let service_ref = build_anp_message_service(
        "#message",
        "https://example.com/rpc",
        AnpMessageServiceOptions::default(),
    );
    assert_eq!(service_ref["id"], json!("#message"));
}

#[test]
fn test_legacy_auth_header_generation_and_verification() {
    let bundle = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["user".to_string(), "alice".to_string()],
            did_profile: DidProfile::K1,
            ..DidDocumentOptions::default()
        },
    )
    .expect("DID creation should succeed");
    let private_key = anp::PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
        .expect("private key should load");
    let header = generate_auth_header(&bundle.did_document, "api.example.com", &private_key, "1.1")
        .expect("auth header generation should succeed");
    verify_auth_header_signature(&header, &bundle.did_document, "api.example.com")
        .expect("verification should succeed");
}

#[test]
fn test_legacy_generators_keep_returning_headers_for_a_mismatched_private_key() {
    let bundle = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["user".to_string(), "alice".to_string()],
            ..DidDocumentOptions::default()
        },
    )
    .expect("DID creation should succeed");
    let wrong_key = anp::PrivateKeyMaterial::Ed25519(SigningKey::generate(&mut rand::rngs::OsRng));
    let legacy = generate_auth_header(&bundle.did_document, "api.example.com", &wrong_key, "1.1")
        .expect("the legacy generator historically returns an unverifiable header");
    assert!(
        verify_auth_header_signature(&legacy, &bundle.did_document, "api.example.com").is_err()
    );

    let http = generate_http_signature_headers(
        &bundle.did_document,
        "https://api.example.com/orders",
        "POST",
        &wrong_key,
        None,
        None,
        HttpSignatureOptions::default(),
    )
    .expect("the legacy HTTP generator historically returns unverifiable headers");
    assert!(verify_http_message_signature(
        &bundle.did_document,
        "POST",
        "https://api.example.com/orders",
        &http,
        None,
    )
    .is_err());

    assert!(generate_auth_header_with_kid(
        &bundle.did_document,
        "api.example.com",
        &wrong_key,
        "1.1",
        "#key-1",
    )
    .is_err());
    assert!(generate_http_signature_headers_with_kid(
        &bundle.did_document,
        "https://api.example.com/orders",
        "POST",
        &wrong_key,
        None,
        None,
        "#key-1",
        HttpSignatureOptions::default(),
    )
    .is_err());
}

#[test]
fn test_legacy_auth_explicit_kid_external_signer_and_relationship_authorization() {
    let (document, request_key, e2ee_key) = supplied_authentication_fixture();
    let did = document["id"].as_str().expect("DID id");
    let request_kid = format!("{did}#request");
    let prepared =
        prepare_legacy_did_wba_auth_header(&document, "api.example.com", "1.1", &request_kid)
            .expect("authorized request KID should prepare");
    let signature = request_key
        .sign_message(prepared.signing_input())
        .expect("request signer should sign");
    let header = complete_legacy_did_wba_auth_header(prepared, &signature)
        .expect("external signature should complete");
    verify_auth_header_signature(&header, &document, "api.example.com")
        .expect("authorized request KID should verify");

    let fragment_header = generate_auth_header_with_kid(
        &document,
        "api.example.com",
        &request_key,
        "1.1",
        "#request",
    )
    .expect("fragment KID should normalize");
    verify_auth_header_signature(&fragment_header, &document, "api.example.com")
        .expect("fragment and absolute KIDs should be equivalent");
    assert!(prepare_legacy_did_wba_auth_header(
        &document,
        "api.example.com",
        "1.1",
        "did:wba:evil.example#request",
    )
    .is_err());

    let e2ee_kid = format!("{did}#e2ee-signing");
    let mut attacker_document = document.clone();
    attacker_document["authentication"] = json!([e2ee_kid]);
    let unauthorized_header = generate_auth_header_with_kid(
        &attacker_document,
        "api.example.com",
        &e2ee_key,
        "1.1",
        "#e2ee-signing",
    )
    .expect("attacker fixture authorizes the key only to create the test signature");
    let error = verify_auth_header_signature(&unauthorized_header, &document, "api.example.com")
        .expect_err("assertionMethod-only key must not authenticate");
    assert!(matches!(
        error,
        anp::authentication::AuthenticationError::UnauthorizedVerificationMethod
    ));

    let mut no_relationship = document.clone();
    no_relationship["assertionMethod"] = json!([format!("{did}#root")]);
    assert!(verify_auth_header_signature(
        &unauthorized_header,
        &no_relationship,
        "api.example.com"
    )
    .is_err());

    let mut agreement_only = no_relationship;
    agreement_only["keyAgreement"] = json!([format!("{did}#e2ee-signing")]);
    assert!(
        verify_auth_header_signature(&unauthorized_header, &agreement_only, "api.example.com")
            .is_err()
    );
}

#[test]
fn test_http_signature_explicit_kid_and_relationship_authorization() {
    let (document, request_key, e2ee_key) = supplied_authentication_fixture();
    let did = document["id"].as_str().expect("DID id");
    let prepared = prepare_http_signature_headers(
        &document,
        "https://api.example.com/orders",
        "POST",
        None,
        Some(br#"{"item":"book"}"#),
        HttpSignatureOptions {
            keyid: Some("#request".to_string()),
            ..HttpSignatureOptions::default()
        },
    )
    .expect("authorized request key should prepare");
    let signature = request_key
        .sign_message(prepared.signing_input())
        .expect("request signer should sign");
    let headers = complete_http_signature_headers(prepared, &signature)
        .expect("external signature should complete");
    verify_http_message_signature(
        &document,
        "POST",
        "https://api.example.com/orders",
        &headers,
        Some(br#"{"item":"book"}"#),
    )
    .expect("authorized request key should verify");

    let mut attacker_document = document.clone();
    attacker_document["authentication"] = json!([format!("{did}#e2ee-signing")]);
    let unauthorized_headers = generate_http_signature_headers_with_kid(
        &attacker_document,
        "https://api.example.com/orders",
        "POST",
        &e2ee_key,
        None,
        None,
        "#e2ee-signing",
        HttpSignatureOptions::default(),
    )
    .expect("attacker fixture should produce a cryptographically valid signature");
    let error = verify_http_message_signature(
        &document,
        "POST",
        "https://api.example.com/orders",
        &unauthorized_headers,
        None,
    )
    .expect_err("assertionMethod-only key must not authenticate");
    assert!(matches!(
        error,
        HttpSignatureError::UnauthorizedVerificationMethod
    ));

    assert!(generate_http_signature_headers_with_kid(
        &document,
        "https://api.example.com/orders",
        "POST",
        &request_key,
        None,
        None,
        "did:wba:evil.example#request",
        HttpSignatureOptions::default(),
    )
    .is_err());
}

#[test]
fn test_legacy_auth_header_empty_version_defaults_to_1_1() {
    let bundle = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["user".to_string(), "alice".to_string()],
            did_profile: DidProfile::K1,
            ..DidDocumentOptions::default()
        },
    )
    .expect("DID creation should succeed");
    let private_key = anp::PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
        .expect("private key should load");

    let header = generate_auth_header(&bundle.did_document, "api.example.com", &private_key, "")
        .expect("auth header generation should succeed");

    assert!(header.starts_with("DIDWba v=\"1.1\""));
    verify_auth_header_signature(&header, &bundle.did_document, "api.example.com")
        .expect("verification should treat an empty requested version as 1.1");
}

#[test]
fn test_http_signature_verification_rejects_tampered_body() {
    let bundle = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("DID creation should succeed");
    let private_key = anp::PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
        .expect("private key should load");
    let headers = generate_http_signature_headers(
        &bundle.did_document,
        "https://api.example.com/orders",
        "POST",
        &private_key,
        None,
        Some(br#"{"item":"book"}"#),
        Default::default(),
    )
    .expect("HTTP signature generation should succeed");
    assert!(verify_http_message_signature(
        &bundle.did_document,
        "POST",
        "https://api.example.com/orders",
        &headers,
        Some(br#"{"item":"book"}"#),
    )
    .is_ok());
    assert!(verify_http_message_signature(
        &bundle.did_document,
        "POST",
        "https://api.example.com/orders",
        &headers,
        Some(br#"{"item":"music"}"#),
    )
    .is_err());
}

#[test]
fn test_http_signature_metadata_rejects_malformed_component_bounds_without_panic() {
    let mut headers = BTreeMap::new();
    headers.insert(
        "Signature-Input".to_string(),
        r#"sig1=)"@method" "content-digest"(;created=1712000000;keyid="did:wba:example.com#key-1""#
            .to_string(),
    );
    headers.insert("Signature".to_string(), "sig1=:YWJj:".to_string());

    let error =
        extract_signature_metadata(&headers).expect_err("malformed input should be rejected");
    assert!(matches!(error, HttpSignatureError::InvalidSignatureInput));
}

#[test]
fn test_http_signature_metadata_rejects_empty_keyid_like_go() {
    let mut headers = BTreeMap::new();
    headers.insert(
        "Signature-Input".to_string(),
        r#"sig1=("@method");created=1712000000;keyid="""#.to_string(),
    );
    headers.insert("Signature".to_string(), "sig1=:YWJj:".to_string());

    let error = extract_signature_metadata(&headers).expect_err("empty keyid should be rejected");
    assert!(matches!(error, HttpSignatureError::InvalidSignatureInput));
}

#[test]
fn test_http_signature_metadata_rejects_malformed_expires_like_go() {
    let mut headers = BTreeMap::new();
    headers.insert(
        "Signature-Input".to_string(),
        r#"sig1=("@method");created=1712000000;expires=not-a-number;keyid="did:wba:example.com#key-1""#
            .to_string(),
    );
    headers.insert("Signature".to_string(), "sig1=:YWJj:".to_string());

    let error =
        extract_signature_metadata(&headers).expect_err("malformed expires should be rejected");
    assert!(matches!(error, HttpSignatureError::InvalidSignatureInput));
}

#[test]
fn test_http_signature_metadata_treats_empty_expires_as_absent_like_go() {
    let mut headers = BTreeMap::new();
    headers.insert(
        "Signature-Input".to_string(),
        r#"sig1=("@method");created=1712000000;expires=;keyid="did:wba:example.com#key-1""#
            .to_string(),
    );
    headers.insert("Signature".to_string(), "sig1=:YWJj:".to_string());

    let metadata =
        extract_signature_metadata(&headers).expect("empty expires should be treated as absent");
    assert_eq!(metadata.expires, None);
}

#[test]
fn test_http_signature_verification_rejects_malformed_expires_like_go() {
    let bundle = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("DID creation should succeed");
    let private_key = anp::PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
        .expect("private key should load");
    let mut headers = generate_http_signature_headers(
        &bundle.did_document,
        "https://api.example.com/orders",
        "GET",
        &private_key,
        None,
        None,
        Default::default(),
    )
    .expect("HTTP signature generation should succeed");
    let original_input = headers
        .get("Signature-Input")
        .expect("Signature-Input should exist")
        .clone();
    headers.insert(
        "Signature-Input".to_string(),
        original_input.replacen(";expires=", ";expires=not-a-number-", 1),
    );

    let error = verify_http_message_signature(
        &bundle.did_document,
        "GET",
        "https://api.example.com/orders",
        &headers,
        None,
    )
    .expect_err("malformed expires should be rejected before signature verification");
    assert!(matches!(error, HttpSignatureError::InvalidSignatureInput));
}

#[test]
fn test_build_agent_message_service_with_service_did() {
    let service = build_agent_message_service_with_options(
        "did:wba:example.com:agents:alice:e1_demo",
        "https://example.com/anp",
        AnpMessageServiceOptions::default().with_service_did("did:wba:example.com"),
    );
    assert_eq!(service["serviceDid"], json!("did:wba:example.com"));
}

#[tokio::test]
async fn test_verify_federated_http_request_with_did_wba_service_did() {
    let sender = create_did_wba_document(
        "a.example.com",
        DidDocumentOptions {
            path_segments: vec!["agents".to_string(), "alice".to_string()],
            ..DidDocumentOptions::default()
        },
    )
    .expect("sender DID creation should succeed");
    let service_identity = create_did_wba_document("a.example.com", DidDocumentOptions::default())
        .expect("service DID creation should succeed");
    let private_key =
        anp::PrivateKeyMaterial::from_pem(&service_identity.keys["key-1"].private_key_pem)
            .expect("private key should load");
    let mut sender_document = sender.did_document.clone();
    sender_document
        .as_object_mut()
        .expect("sender document should be object")
        .insert(
            "service".to_string(),
            json!([build_agent_message_service_with_options(
                sender.did_document["id"].as_str().unwrap(),
                "https://a.example.com/anp",
                AnpMessageServiceOptions::default().with_service_did("did:wba:a.example.com"),
            )]),
        );
    let headers = generate_http_signature_headers(
        &service_identity.did_document,
        "https://b.example.com/anp",
        "POST",
        &private_key,
        None,
        Some(br#"{"message":"hello"}"#),
        Default::default(),
    )
    .expect("headers should generate");

    let result = verify_federated_http_request(
        sender.did_document["id"].as_str().unwrap(),
        "POST",
        "https://b.example.com/anp",
        &headers,
        Some(br#"{"message":"hello"}"#),
        FederatedVerificationOptions {
            sender_did_document: Some(sender_document),
            service_did_document: Some(service_identity.did_document.clone()),
            ..FederatedVerificationOptions::default()
        },
    )
    .await
    .expect("federated verification should succeed");

    assert_eq!(result.service_did, "did:wba:a.example.com");
    assert_eq!(
        result.signature_metadata.keyid,
        "did:wba:a.example.com#key-1"
    );
}

#[tokio::test]
async fn test_verify_federated_http_request_with_did_web_service_did() {
    let sender = create_did_wba_document(
        "a.example.com",
        DidDocumentOptions {
            path_segments: vec!["agents".to_string(), "alice".to_string()],
            ..DidDocumentOptions::default()
        },
    )
    .expect("sender DID creation should succeed");
    let mut sender_document = sender.did_document.clone();
    sender_document
        .as_object_mut()
        .expect("sender document should be object")
        .insert(
            "service".to_string(),
            json!([build_agent_message_service_with_options(
                sender.did_document["id"].as_str().unwrap(),
                "https://a.example.com/anp",
                AnpMessageServiceOptions::default().with_service_did("did:web:a.example.com"),
            )]),
        );

    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    let service_document = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:web:a.example.com",
        "verificationMethod": [{
            "id": "did:web:a.example.com#key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": "did:web:a.example.com",
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(verifying_key.as_bytes()),
            }
        }],
        "authentication": ["did:web:a.example.com#key-1"]
    });
    let private_key = anp::PrivateKeyMaterial::Ed25519(signing_key);
    let headers = generate_http_signature_headers(
        &service_document,
        "https://b.example.com/anp",
        "POST",
        &private_key,
        None,
        Some(br#"{"message":"hello"}"#),
        Default::default(),
    )
    .expect("headers should generate");

    let result = verify_federated_http_request(
        sender.did_document["id"].as_str().unwrap(),
        "POST",
        "https://b.example.com/anp",
        &headers,
        Some(br#"{"message":"hello"}"#),
        FederatedVerificationOptions {
            sender_did_document: Some(sender_document),
            service_did_document: Some(service_document),
            ..FederatedVerificationOptions::default()
        },
    )
    .await
    .expect("federated verification should succeed");

    assert_eq!(result.service_did, "did:web:a.example.com");
    assert_eq!(
        result.signature_metadata.keyid,
        "did:web:a.example.com#key-1"
    );
}

#[test]
fn test_did_wba_auth_header_reads_files_and_generates_headers() {
    let bundle = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("DID creation should succeed");
    let temp = tempdir("anp-auth").expect("temp dir should exist");
    let did_path = temp.path().join("did.json");
    let key_path = temp.path().join("key.pem");
    fs::write(&did_path, serde_json::to_vec(&bundle.did_document).unwrap()).unwrap();
    fs::write(&key_path, &bundle.keys["key-1"].private_key_pem).unwrap();

    let mut helper = DIDWbaAuthHeader::new(&did_path, &key_path, AuthMode::HttpSignatures);
    let headers = helper
        .get_auth_header("https://api.example.com/orders", false, "GET", None, None)
        .expect("header generation should succeed");
    assert!(headers.contains_key("Signature-Input"));
    assert!(headers.contains_key("Signature"));
}

#[test]
fn test_did_wba_auth_header_ignores_empty_auth_info_access_token() {
    let bundle = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("DID creation should succeed");
    let temp = tempdir("anp-auth").expect("temp dir should exist");
    let did_path = temp.path().join("did.json");
    let key_path = temp.path().join("key.pem");
    fs::write(&did_path, serde_json::to_vec(&bundle.did_document).unwrap()).unwrap();
    fs::write(&key_path, &bundle.keys["key-1"].private_key_pem).unwrap();

    let mut helper = DIDWbaAuthHeader::new(&did_path, &key_path, AuthMode::HttpSignatures);
    let mut response_headers = BTreeMap::new();
    response_headers.insert(
        "Authentication-Info".to_string(),
        r#"access_token="", token_type="Bearer""#.to_string(),
    );
    response_headers.insert(
        "Authorization".to_string(),
        "Bearer legacy-token".to_string(),
    );

    let token = helper
        .update_token("https://api.example.com/orders", &response_headers)
        .expect("legacy Authorization token should be captured");
    assert_eq!(token, "legacy-token");

    let headers = helper
        .get_auth_header("https://api.example.com/orders", false, "GET", None, None)
        .expect("cached token should be reused");
    assert_eq!(
        headers.get("Authorization").map(String::as_str),
        Some("Bearer legacy-token")
    );
}

#[test]
fn test_did_wba_auth_header_ignores_empty_auth_info_without_fallback() {
    let bundle = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("DID creation should succeed");
    let temp = tempdir("anp-auth").expect("temp dir should exist");
    let did_path = temp.path().join("did.json");
    let key_path = temp.path().join("key.pem");
    fs::write(&did_path, serde_json::to_vec(&bundle.did_document).unwrap()).unwrap();
    fs::write(&key_path, &bundle.keys["key-1"].private_key_pem).unwrap();

    let mut helper = DIDWbaAuthHeader::new(&did_path, &key_path, AuthMode::HttpSignatures);
    let mut response_headers = BTreeMap::new();
    response_headers.insert(
        "Authentication-Info".to_string(),
        r#"access_token="", token_type="Bearer""#.to_string(),
    );

    assert_eq!(
        helper.update_token("https://api.example.com/orders", &response_headers),
        None
    );

    let headers = helper
        .get_auth_header("https://api.example.com/orders", false, "GET", None, None)
        .expect("missing cached token should fall back to signature auth");
    assert!(!headers.contains_key("Authorization"));
    assert!(headers.contains_key("Signature-Input"));
    assert!(headers.contains_key("Signature"));
}

#[test]
fn test_did_wba_auth_header_reuses_server_nonce_for_challenge() {
    let bundle = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("DID creation should succeed");
    let temp = tempdir("anp-auth").expect("temp dir should exist");
    let did_path = temp.path().join("did.json");
    let key_path = temp.path().join("key.pem");
    fs::write(&did_path, serde_json::to_vec(&bundle.did_document).unwrap()).unwrap();
    fs::write(&key_path, &bundle.keys["key-1"].private_key_pem).unwrap();

    let mut helper = DIDWbaAuthHeader::new(&did_path, &key_path, AuthMode::HttpSignatures);
    let mut response_headers = BTreeMap::new();
    response_headers.insert(
        "WWW-Authenticate".to_string(),
        "DIDWba realm=\"api.example.com\", error=\"invalid_nonce\", error_description=\"Retry\", nonce=\"server-nonce-123\"".to_string(),
    );
    response_headers.insert(
        "Accept-Signature".to_string(),
        "sig1=(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \"content-type\");created;expires;nonce;keyid".to_string(),
    );
    let mut request_headers = BTreeMap::new();
    request_headers.insert("Content-Type".to_string(), "application/json".to_string());

    let headers = helper
        .get_challenge_auth_header(
            "https://api.example.com/orders",
            &response_headers,
            "POST",
            Some(&request_headers),
            Some(br#"{"item":"book"}"#),
        )
        .expect("challenge auth headers should be generated");
    let metadata = extract_signature_metadata(&headers).expect("metadata should parse");
    assert_eq!(metadata.nonce.as_deref(), Some("server-nonce-123"));
    assert!(metadata
        .components
        .iter()
        .any(|value| value == "content-type"));
    assert!(headers.contains_key("Content-Digest"));
}

#[test]
fn test_did_wba_auth_header_drops_empty_accepted_headers() {
    let bundle = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("DID creation should succeed");
    let temp = tempdir("anp-auth").expect("temp dir should exist");
    let did_path = temp.path().join("did.json");
    let key_path = temp.path().join("key.pem");
    fs::write(&did_path, serde_json::to_vec(&bundle.did_document).unwrap()).unwrap();
    fs::write(&key_path, &bundle.keys["key-1"].private_key_pem).unwrap();

    let mut helper = DIDWbaAuthHeader::new(&did_path, &key_path, AuthMode::HttpSignatures);
    let mut response_headers = BTreeMap::new();
    response_headers.insert(
        "WWW-Authenticate".to_string(),
        "DIDWba realm=\"api.example.com\", nonce=\"server-nonce-123\"".to_string(),
    );
    response_headers.insert(
        "Accept-Signature".to_string(),
        "sig1=(\"@method\" \"@target-uri\" \"@authority\" \"content-type\" \"x-optional\");created;expires;nonce;keyid".to_string(),
    );
    let mut request_headers = BTreeMap::new();
    request_headers.insert("Content-Type".to_string(), String::new());
    request_headers.insert("X-Optional".to_string(), String::new());

    let headers = helper
        .get_challenge_auth_header(
            "https://api.example.com/orders",
            &response_headers,
            "GET",
            Some(&request_headers),
            None,
        )
        .expect("challenge auth headers should be generated");
    let metadata = extract_signature_metadata(&headers).expect("metadata should parse");
    assert_eq!(metadata.nonce.as_deref(), Some("server-nonce-123"));
    assert!(!metadata
        .components
        .iter()
        .any(|value| value == "content-type"));
    assert!(!metadata
        .components
        .iter()
        .any(|value| value == "x-optional"));
    assert_eq!(
        metadata.components,
        vec![
            "@method".to_string(),
            "@target-uri".to_string(),
            "@authority".to_string()
        ]
    );
}

#[test]
fn test_did_wba_auth_header_falls_back_when_challenge_components_are_unusable() {
    let bundle = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("DID creation should succeed");
    let temp = tempdir("anp-auth").expect("temp dir should exist");
    let did_path = temp.path().join("did.json");
    let key_path = temp.path().join("key.pem");
    fs::write(&did_path, serde_json::to_vec(&bundle.did_document).unwrap()).unwrap();
    fs::write(&key_path, &bundle.keys["key-1"].private_key_pem).unwrap();

    let mut helper = DIDWbaAuthHeader::new(&did_path, &key_path, AuthMode::HttpSignatures);
    let mut response_headers = BTreeMap::new();
    response_headers.insert(
        "WWW-Authenticate".to_string(),
        "DIDWba realm=\"api.example.com\", nonce=\"server-nonce-123\"".to_string(),
    );
    response_headers.insert(
        "Accept-Signature".to_string(),
        "sig1=(\"content-type\" \"x-missing\");created;expires;nonce;keyid".to_string(),
    );

    let headers = helper
        .get_challenge_auth_header(
            "https://api.example.com/orders",
            &response_headers,
            "GET",
            None,
            None,
        )
        .expect("challenge auth headers should be generated");
    let metadata = extract_signature_metadata(&headers).expect("metadata should parse");

    assert_eq!(
        metadata.components,
        vec![
            "@method".to_string(),
            "@target-uri".to_string(),
            "@authority".to_string()
        ]
    );
    assert_eq!(metadata.nonce.as_deref(), Some("server-nonce-123"));
}

#[test]
fn test_did_wba_auth_header_should_not_retry_invalid_did() {
    let bundle = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("DID creation should succeed");
    let temp = tempdir("anp-auth").expect("temp dir should exist");
    let did_path = temp.path().join("did.json");
    let key_path = temp.path().join("key.pem");
    fs::write(&did_path, serde_json::to_vec(&bundle.did_document).unwrap()).unwrap();
    fs::write(&key_path, &bundle.keys["key-1"].private_key_pem).unwrap();

    let helper = DIDWbaAuthHeader::new(&did_path, &key_path, AuthMode::HttpSignatures);
    let mut response_headers = BTreeMap::new();
    response_headers.insert(
        "WWW-Authenticate".to_string(),
        "DIDWba realm=\"api.example.com\", error=\"invalid_did\", error_description=\"Unknown DID\"".to_string(),
    );
    assert!(!helper.should_retry_after_401(&response_headers));
}

#[tokio::test]
async fn test_did_wba_verifier_accepts_http_signatures() {
    let bundle = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("DID creation should succeed");

    let private_key = anp::PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
        .expect("private key should load");
    let request_url = "https://api.example.com/orders";
    let headers = generate_http_signature_headers(
        &bundle.did_document,
        request_url,
        "GET",
        &private_key,
        None,
        None,
        Default::default(),
    )
    .expect("HTTP signature generation should succeed");

    let mut verifier = DidWbaVerifier::new(DidWbaVerifierConfig {
        jwt_private_key: Some("test-secret".to_string()),
        jwt_public_key: Some("test-secret".to_string()),
        jwt_algorithm: "HS256".to_string(),
        ..DidWbaVerifierConfig::default()
    });

    let result = verifier
        .verify_request_with_did_document(
            "GET",
            request_url,
            &headers,
            None,
            Some("api.example.com"),
            &bundle.did_document,
        )
        .await
        .expect("verification should succeed");
    assert_eq!(result.auth_scheme, "http_signatures");
    assert!(result.access_token.is_some());
}

#[tokio::test]
async fn test_did_wba_verifier_rejects_http_signature_document_id_mismatch() {
    let bundle = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("DID creation should succeed");

    let private_key = anp::PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
        .expect("private key should load");
    let request_url = "https://api.example.com/orders";
    let headers = generate_http_signature_headers(
        &bundle.did_document,
        request_url,
        "GET",
        &private_key,
        None,
        None,
        Default::default(),
    )
    .expect("HTTP signature generation should succeed");
    let mut mismatched_document = bundle.did_document.clone();
    mismatched_document["id"] = json!("did:wba:attacker.example.com");

    let mut verifier = DidWbaVerifier::new(DidWbaVerifierConfig {
        jwt_private_key: Some("test-secret".to_string()),
        jwt_public_key: Some("test-secret".to_string()),
        jwt_algorithm: "HS256".to_string(),
        ..DidWbaVerifierConfig::default()
    });

    let error = verifier
        .verify_request_with_did_document(
            "GET",
            request_url,
            &headers,
            None,
            Some("api.example.com"),
            &mismatched_document,
        )
        .await
        .expect_err("document id must match the DID authenticated by keyid");

    assert_eq!(error.status_code, 401);
    assert_eq!(
        error.message,
        "DID document ID does not match authenticated DID"
    );
    assert_eq!(
        error.headers.get("WWW-Authenticate").map(String::as_str),
        Some(
            "DIDWba realm=\"api.example.com\", error=\"invalid_did\", error_description=\"DID document ID does not match authenticated DID\""
        )
    );
}

#[tokio::test]
async fn test_did_wba_verifier_rejects_legacy_document_id_mismatch_before_nonce_use() {
    let bundle = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            did_profile: DidProfile::K1,
            ..DidDocumentOptions::default()
        },
    )
    .expect("DID creation should succeed");
    let private_key = anp::PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
        .expect("private key should load");
    let auth_header =
        generate_auth_header(&bundle.did_document, "api.example.com", &private_key, "1.1")
            .expect("legacy DID-WBA auth header generation should succeed");
    let mut headers = BTreeMap::new();
    headers.insert("Authorization".to_string(), auth_header);
    let mut mismatched_document = bundle.did_document.clone();
    mismatched_document["id"] = json!("did:wba:attacker.example.com");

    let mut verifier = DidWbaVerifier::new(DidWbaVerifierConfig {
        jwt_private_key: Some("test-secret".to_string()),
        jwt_public_key: Some("test-secret".to_string()),
        jwt_algorithm: "HS256".to_string(),
        ..DidWbaVerifierConfig::default()
    });

    let error = verifier
        .verify_request_with_did_document(
            "GET",
            "https://api.example.com/orders",
            &headers,
            None,
            Some("api.example.com"),
            &mismatched_document,
        )
        .await
        .expect_err("document id must match the DID authenticated by Authorization");

    assert_eq!(error.status_code, 401);
    assert_eq!(
        error.message,
        "DID document ID does not match authenticated DID"
    );

    let result = verifier
        .verify_request_with_did_document(
            "GET",
            "https://api.example.com/orders",
            &headers,
            None,
            Some("api.example.com"),
            &bundle.did_document,
        )
        .await
        .expect("mismatch rejection should not consume the legacy nonce");
    assert_eq!(result.auth_scheme, "legacy_didwba");
}

#[tokio::test]
async fn test_did_wba_verifier_keeps_legacy_auth_when_only_signature_header_is_extra() {
    let bundle = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            did_profile: DidProfile::K1,
            ..DidDocumentOptions::default()
        },
    )
    .expect("DID creation should succeed");
    let private_key = anp::PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
        .expect("private key should load");
    let auth_header =
        generate_auth_header(&bundle.did_document, "api.example.com", &private_key, "1.1")
            .expect("legacy DID-WBA auth header generation should succeed");
    let mut headers = BTreeMap::new();
    headers.insert("Authorization".to_string(), auth_header);
    headers.insert(
        "Signature".to_string(),
        "sig1=:not-an-http-signature-discriminator:".to_string(),
    );

    let mut verifier = DidWbaVerifier::new(DidWbaVerifierConfig {
        jwt_private_key: Some("test-secret".to_string()),
        jwt_public_key: Some("test-secret".to_string()),
        jwt_algorithm: "HS256".to_string(),
        ..DidWbaVerifierConfig::default()
    });

    let result = verifier
        .verify_request_with_did_document(
            "GET",
            "https://api.example.com/orders",
            &headers,
            None,
            Some("api.example.com"),
            &bundle.did_document,
        )
        .await
        .expect("legacy verification should ignore a stray Signature header");

    assert_eq!(result.auth_scheme, "legacy_didwba");
    assert!(result.access_token.is_some());
}

#[cfg(feature = "network")]
#[tokio::test]
async fn test_did_wba_verifier_accepts_http_signatures_with_network_resolution() {
    let bundle = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("DID creation should succeed");
    let server = JsonTestServer::start([("/.well-known/did.json", bundle.did_document.clone())]);

    let private_key = anp::PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
        .expect("private key should load");
    let request_url = format!("{}/orders", server.uri());
    let headers = generate_http_signature_headers(
        &bundle.did_document,
        &request_url,
        "GET",
        &private_key,
        None,
        None,
        Default::default(),
    )
    .expect("HTTP signature generation should succeed");

    let mut verifier = DidWbaVerifier::new(DidWbaVerifierConfig {
        jwt_private_key: Some("test-secret".to_string()),
        jwt_public_key: Some("test-secret".to_string()),
        jwt_algorithm: "HS256".to_string(),
        did_resolution_options: anp::authentication::DidResolutionOptions {
            base_url_override: Some(server.uri()),
            verify_ssl: false,
            timeout_seconds: 5.0,
            ..anp::authentication::DidResolutionOptions::default()
        },
        ..DidWbaVerifierConfig::default()
    });

    let result = verifier
        .verify_request("GET", &request_url, &headers, None, Some("api.example.com"))
        .await
        .expect("verification should succeed");
    assert_eq!(result.auth_scheme, "http_signatures");
    assert!(result.access_token.is_some());
}

#[cfg(feature = "network")]
#[tokio::test]
async fn test_did_wba_resolution_sends_custom_headers_like_go() {
    let bundle = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("DID creation should succeed");
    let server =
        RecordingJsonTestServer::start([("/.well-known/did.json", bundle.did_document.clone())]);
    let mut headers = BTreeMap::new();
    headers.insert("X-ANP-Resolver".to_string(), "lane-d".to_string());

    let document = resolve_did_wba_document_with_options(
        "did:wba:example.com",
        false,
        &DidResolutionOptions {
            base_url_override: Some(server.uri()),
            verify_ssl: false,
            timeout_seconds: 5.0,
            headers,
        },
    )
    .await
    .expect("DID WBA resolution should succeed");

    assert_eq!(document["id"], json!("did:wba:example.com"));
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/.well-known/did.json");
    assert_eq!(
        header_value(&requests[0].headers, "X-ANP-Resolver").as_deref(),
        Some("lane-d")
    );
}

#[cfg(feature = "network")]
#[tokio::test]
async fn test_did_web_resolution_sends_custom_headers_like_go() {
    let server = RecordingJsonTestServer::start([(
        "/agents/alice/did.json",
        json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:web:example.com:agents:alice",
            "verificationMethod": [],
            "authentication": [],
        }),
    )]);
    let mut headers = BTreeMap::new();
    headers.insert("X-ANP-Resolver".to_string(), "did-web".to_string());

    let document = resolve_did_document_with_options(
        "did:web:example.com:agents:alice",
        false,
        &DidResolutionOptions {
            base_url_override: Some(server.uri()),
            verify_ssl: false,
            timeout_seconds: 5.0,
            headers,
        },
    )
    .await
    .expect("DID web resolution should succeed");

    assert_eq!(document["id"], json!("did:web:example.com:agents:alice"));
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/agents/alice/did.json");
    assert_eq!(
        header_value(&requests[0].headers, "X-ANP-Resolver").as_deref(),
        Some("did-web")
    );
}

#[cfg(feature = "network")]
fn header_value(headers: &BTreeMap<String, String>, name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
}
