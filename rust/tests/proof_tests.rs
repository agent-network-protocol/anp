use anp::proof::{
    generate_group_receipt_proof, generate_w3c_proof, verify_group_receipt_proof, verify_w3c_proof,
    ProofGenerationOptions, ProofVerificationOptions, CRYPTOSUITE_EDDSA_JCS_2022,
    PROOF_TYPE_DATA_INTEGRITY,
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
    let private_key =
        PrivateKeyMaterial::Secp256k1(k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng));
    let public_key = private_key.public_key();
    let receipt = json!({
        "receipt_type": "anp.group_receipt.v1",
        "group_did": "did:wba:groups.example:team:dev:e1_group_dev",
        "group_state_version": "43",
        "group_event_seq": "128",
        "subject_method": "group.send",
        "operation_id": "op-group-send-001",
        "message_id": "msg-group-send-001",
        "actor_did": "did:wba:a.example:agents:alice:e1_alice",
        "accepted_at": "2026-03-29T15:10:01Z",
        "payload_digest": "sha-256=:stub:",
    });
    let signed = generate_group_receipt_proof(
        &receipt,
        &private_key,
        "did:wba:groups.example:team:dev:e1_group_dev#key-1",
    )
    .expect("group receipt proof generation should succeed");
    assert!(verify_group_receipt_proof(&signed, &public_key).is_ok());
}

#[test]
fn test_tampered_group_receipt_fails_verification() {
    let private_key =
        PrivateKeyMaterial::Secp256k1(k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng));
    let public_key = private_key.public_key();
    let receipt = json!({
        "receipt_type": "anp.group_receipt.v1",
        "group_did": "did:wba:groups.example:team:dev:e1_group_dev",
        "group_state_version": "43",
        "group_event_seq": "128",
        "subject_method": "group.send",
        "operation_id": "op-group-send-001",
        "actor_did": "did:wba:a.example:agents:alice:e1_alice",
        "accepted_at": "2026-03-29T15:10:01Z",
        "payload_digest": "sha-256=:stub:",
    });
    let mut signed = generate_group_receipt_proof(
        &receipt,
        &private_key,
        "did:wba:groups.example:team:dev:e1_group_dev#key-1",
    )
    .expect("group receipt proof generation should succeed");
    signed["group_event_seq"] = json!("129");
    assert!(verify_group_receipt_proof(&signed, &public_key).is_err());
}

#[test]
fn test_generate_and_verify_group_receipt_proof_ed25519() {
    let private_key =
        PrivateKeyMaterial::Ed25519(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng));
    let public_key = private_key.public_key();
    let receipt = json!({
        "receipt_type": "anp.group_receipt.v1",
        "group_did": "did:wba:groups.example:team:dev:e1_group_dev",
        "group_state_version": "43",
        "group_event_seq": "128",
        "subject_method": "group.send",
        "operation_id": "op-group-send-001",
        "actor_did": "did:wba:a.example:agents:alice:e1_alice",
        "accepted_at": "2026-03-29T15:10:01Z",
        "payload_digest": "sha-256=:stub:",
    });
    let signed = generate_group_receipt_proof(
        &receipt,
        &private_key,
        "did:wba:groups.example:team:dev:e1_group_dev#key-1",
    )
    .expect("group receipt proof generation should succeed");
    assert_eq!(signed["proof"]["cryptosuite"], json!("eddsa-jcs-2022"));
    assert!(verify_group_receipt_proof(&signed, &public_key).is_ok());
}
