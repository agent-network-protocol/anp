use anp::authentication::{
    build_unsigned_e1_did_document, DidKeyRole, DidVerificationRelationship, SuppliedDidKey,
    SuppliedE1DidDocumentOptions,
};
use anp::proof::{
    complete_w3c_proof, prepare_w3c_proof, ProofGenerationOptions, CRYPTOSUITE_EDDSA_JCS_2022,
    PROOF_TYPE_DATA_INTEGRITY,
};
use anp::PrivateKeyMaterial;

fn main() {
    let root =
        PrivateKeyMaterial::Ed25519(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng));
    let request =
        PrivateKeyMaterial::Ed25519(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng));
    let unsigned = build_unsigned_e1_did_document(
        "example.com",
        SuppliedE1DidDocumentOptions {
            port: None,
            path_segments: vec!["agents".to_string(), "external-signer".to_string()],
            agent_description_url: None,
            services: Vec::new(),
            root_key: SuppliedDidKey {
                fragment: "root".to_string(),
                role: DidKeyRole::RootControl,
                public_key: root.public_key(),
                relationships: vec![
                    DidVerificationRelationship::Authentication,
                    DidVerificationRelationship::AssertionMethod,
                ],
            },
            additional_keys: vec![SuppliedDidKey {
                fragment: "request".to_string(),
                role: DidKeyRole::RequestSigning,
                public_key: request.public_key(),
                relationships: vec![DidVerificationRelationship::Authentication],
            }],
        },
    )
    .expect("unsigned E1 document should build");
    let did = unsigned["id"].as_str().expect("DID id");
    let prepared = prepare_w3c_proof(
        &unsigned,
        &root.public_key(),
        &format!("{did}#root"),
        ProofGenerationOptions {
            proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_string()),
            cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.to_string()),
            proof_purpose: Some("assertionMethod".to_string()),
            ..ProofGenerationOptions::default()
        },
    )
    .expect("proof should prepare");
    let signature = root
        .sign_message(prepared.signing_input())
        .expect("external signer should sign");
    let signed = complete_w3c_proof(prepared, &signature).expect("proof should complete");

    println!(
        "{}",
        serde_json::to_string_pretty(&signed).expect("document should serialize")
    );
}
