use anp::authentication::{create_did_wba_document, DidDocumentOptions, DidProfile};
use anp::proof::{
    generate_did_wba_binding, generate_group_receipt_proof, generate_w3c_proof,
    verify_did_wba_binding, verify_group_receipt_proof, verify_w3c_proof,
    DidWbaBindingVerificationOptions, ProofGenerationOptions, ProofVerificationOptions,
    CRYPTOSUITE_EDDSA_JCS_2022, PROOF_TYPE_DATA_INTEGRITY,
};
use anp::PrivateKeyMaterial;
use serde_json::json;

#[test]
fn test_generate_and_verify_secp256k1_proof() {
    let private_key =
        PrivateKeyMaterial::Secp256k1(k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng));
    let public_key = private_key.public_key();
    let document = json!({
        "id": "did:wba:example.com:alice",
        "claim": "test-data",
    });
    let signed = generate_w3c_proof(
        &document,
        &private_key,
        "did:wba:example.com:alice#key-1",
        ProofGenerationOptions::default(),
    )
    .expect("proof generation should succeed");
    assert!(verify_w3c_proof(
        &signed,
        &public_key,
        ProofVerificationOptions::default(),
    ));
}

#[test]
fn test_generate_and_verify_ed25519_data_integrity_proof() {
    let private_key =
        PrivateKeyMaterial::Ed25519(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng));
    let public_key = private_key.public_key();
    let document = json!({
        "id": "did:wba:example.com:bob",
        "type": "VerifiableCredential",
    });
    let signed = generate_w3c_proof(
        &document,
        &private_key,
        "did:wba:example.com:bob#key-1",
        ProofGenerationOptions {
            proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_string()),
            cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.to_string()),
            ..ProofGenerationOptions::default()
        },
    )
    .expect("proof generation should succeed");
    assert!(verify_w3c_proof(
        &signed,
        &public_key,
        ProofVerificationOptions::default(),
    ));
}

#[test]
fn test_tampered_document_fails_proof_verification() {
    let private_key =
        PrivateKeyMaterial::Secp256k1(k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng));
    let public_key = private_key.public_key();
    let document = json!({
        "id": "did:wba:example.com:alice",
        "claim": "test-data",
    });
    let mut signed = generate_w3c_proof(
        &document,
        &private_key,
        "did:wba:example.com:alice#key-1",
        ProofGenerationOptions::default(),
    )
    .expect("proof generation should succeed");
    signed["claim"] = json!("tampered-data");
    assert!(!verify_w3c_proof(
        &signed,
        &public_key,
        ProofVerificationOptions::default(),
    ));
}

#[test]
fn test_generate_and_verify_group_receipt_proof() {
    let bundle = create_did_wba_document(
        "groups.example",
        DidDocumentOptions {
            path_segments: vec!["team".to_owned(), "dev".to_owned()],
            did_profile: DidProfile::E1,
            ..Default::default()
        },
    )
    .expect("group did document");
    let did = bundle.did().expect("group did").to_string();
    let private_key =
        PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem).expect("private key");
    let receipt = json!({
        "receipt_type": "anp.group_receipt.v1",
        "group_did": did,
        "group_state_version": "43",
        "group_event_seq": "128",
        "subject_method": "group.send",
        "operation_id": "op-group-send-001",
        "message_id": "msg-group-send-001",
        "actor_did": "did:wba:a.example:agents:alice:e1_alice",
        "accepted_at": "2026-03-29T15:10:01Z",
        "payload_digest": "sha-256=:stub:",
    });
    let signed = generate_group_receipt_proof(&receipt, &private_key, &format!("{did}#key-1"))
        .expect("group receipt proof generation should succeed");
    assert_eq!(signed["proof"]["cryptosuite"], json!("eddsa-jcs-2022"));
    assert!(signed["proof"]["proofValue"]
        .as_str()
        .expect("proof value")
        .starts_with('z'));
    assert!(verify_group_receipt_proof(&signed, &bundle.did_document).is_ok());
}

#[test]
fn test_tampered_group_receipt_fails_verification() {
    let bundle = create_did_wba_document(
        "groups.example",
        DidDocumentOptions {
            path_segments: vec!["team".to_owned(), "dev".to_owned()],
            did_profile: DidProfile::E1,
            ..Default::default()
        },
    )
    .expect("group did document");
    let did = bundle.did().expect("group did").to_string();
    let private_key =
        PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem).expect("private key");
    let receipt = json!({
        "receipt_type": "anp.group_receipt.v1",
        "group_did": did,
        "group_state_version": "43",
        "group_event_seq": "128",
        "subject_method": "group.send",
        "operation_id": "op-group-send-001",
        "message_id": "msg-group-send-001",
        "actor_did": "did:wba:a.example:agents:alice:e1_alice",
        "accepted_at": "2026-03-29T15:10:01Z",
        "payload_digest": "sha-256=:stub:",
    });
    let mut signed = generate_group_receipt_proof(
        &receipt,
        &private_key,
        &format!("{}#key-1", receipt["group_did"].as_str().unwrap()),
    )
    .expect("group receipt proof generation should succeed");
    signed["group_event_seq"] = json!("129");
    assert!(verify_group_receipt_proof(&signed, &bundle.did_document).is_err());
}

#[test]
fn test_generate_and_verify_did_wba_binding() {
    let bundle = create_did_wba_document(
        "a.example",
        DidDocumentOptions {
            path_segments: vec!["agents".to_owned(), "alice".to_owned()],
            did_profile: DidProfile::E1,
            ..Default::default()
        },
    )
    .expect("agent did document");
    let did = bundle.did().expect("agent did").to_string();
    let private_key =
        PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem).expect("private key");
    let binding = generate_did_wba_binding(
        &did,
        &format!("{did}#key-1"),
        "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
        &private_key,
        "2026-03-29T12:00:00Z",
        "2026-04-29T12:00:00Z",
        Some("2026-03-29T12:00:00Z".to_string()),
    )
    .expect("binding proof generation should succeed");
    assert!(binding["proof"]["proofValue"]
        .as_str()
        .expect("proof value")
        .starts_with('z'));
    assert!(verify_did_wba_binding(
        &binding,
        &bundle.did_document,
        DidWbaBindingVerificationOptions {
            now: Some("2026-03-30T12:00:00Z".to_string()),
            expected_credential_identity: Some(did.clone()),
            ..DidWbaBindingVerificationOptions::default()
        },
    )
    .is_ok());
}

#[test]
fn test_expired_did_wba_binding_fails() {
    let bundle = create_did_wba_document(
        "a.example",
        DidDocumentOptions {
            path_segments: vec!["agents".to_owned(), "alice".to_owned()],
            did_profile: DidProfile::E1,
            ..Default::default()
        },
    )
    .expect("agent did document");
    let did = bundle.did().expect("agent did").to_string();
    let private_key =
        PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem).expect("private key");
    let binding = generate_did_wba_binding(
        &did,
        &format!("{did}#key-1"),
        "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
        &private_key,
        "2026-03-29T12:00:00Z",
        "2026-04-29T12:00:00Z",
        Some("2026-03-29T12:00:00Z".to_string()),
    )
    .expect("binding proof generation should succeed");
    assert!(verify_did_wba_binding(
        &binding,
        &bundle.did_document,
        DidWbaBindingVerificationOptions {
            now: Some("2026-05-01T00:00:00Z".to_string()),
            ..DidWbaBindingVerificationOptions::default()
        },
    )
    .is_err());
}
