use anp::proof::{
    generate_w3c_proof, verify_w3c_proof, ProofGenerationOptions, ProofVerificationOptions,
    PROOF_TYPE_DATA_INTEGRITY, CRYPTOSUITE_EDDSA_JCS_2022,
};
use anp::PrivateKeyMaterial;
use serde_json::json;

#[test]
fn test_generate_and_verify_secp256k1_proof() {
    let private_key = PrivateKeyMaterial::Secp256k1(k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng));
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
    let private_key = PrivateKeyMaterial::Ed25519(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng));
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
    let private_key = PrivateKeyMaterial::Secp256k1(k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng));
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
