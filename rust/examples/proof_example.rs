use anp::proof::{
    generate_w3c_proof, verify_w3c_proof, ProofGenerationOptions, ProofVerificationOptions,
    CRYPTOSUITE_EDDSA_JCS_2022, PROOF_TYPE_DATA_INTEGRITY,
};
use anp::PrivateKeyMaterial;
use serde_json::json;

fn main() {
    let secp256k1_private = PrivateKeyMaterial::Secp256k1(k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng));
    let secp256k1_public = secp256k1_private.public_key();
    let agent_claim = json!({
        "id": "did:wba:example.com:agents:alice",
        "type": "AgentIdentityClaim",
        "name": "Agent Alice",
        "capabilities": ["search", "booking", "payment"],
    });
    let signed_claim = generate_w3c_proof(
        &agent_claim,
        &secp256k1_private,
        "did:wba:example.com:agents:alice#key-1",
        ProofGenerationOptions::default(),
    )
    .expect("secp256k1 proof generation should succeed");
    println!("secp256k1 verification: {}", verify_w3c_proof(&signed_claim, &secp256k1_public, ProofVerificationOptions::default()));

    let ed25519_private = PrivateKeyMaterial::Ed25519(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng));
    let ed25519_public = ed25519_private.public_key();
    let credential = json!({
        "id": "did:wba:example.com:credential:bob",
        "type": ["VerifiableCredential", "AgentCapabilityCredential"],
        "issuer": "did:wba:issuer.example.com",
        "credentialSubject": {
            "id": "did:wba:example.com:agents:bob",
            "capability": "hotel-booking",
        }
    });
    let signed_credential = generate_w3c_proof(
        &credential,
        &ed25519_private,
        "did:wba:issuer.example.com#key-1",
        ProofGenerationOptions {
            proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_string()),
            cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.to_string()),
            domain: Some("example.com".to_string()),
            ..ProofGenerationOptions::default()
        },
    )
    .expect("Ed25519 proof generation should succeed");
    println!(
        "ed25519 verification: {}",
        verify_w3c_proof(
            &signed_credential,
            &ed25519_public,
            ProofVerificationOptions {
                expected_domain: Some("example.com".to_string()),
                ..ProofVerificationOptions::default()
            },
        )
    );
}
