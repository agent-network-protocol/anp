use serde_json::Value;

use crate::proof::{
    generate_w3c_proof, verify_w3c_proof_detailed, ProofError, ProofGenerationOptions,
    ProofVerificationOptions, CRYPTOSUITE_DIDWBA_SECP256K1_2025, CRYPTOSUITE_EDDSA_JCS_2022,
    PROOF_TYPE_DATA_INTEGRITY,
};
use crate::{PrivateKeyMaterial, PublicKeyMaterial};

pub const GROUP_RECEIPT_PROOF_PURPOSE: &str = "assertionMethod";
pub const GROUP_RECEIPT_REQUIRED_FIELDS: [&str; 8] = [
    "receipt_type",
    "group_did",
    "group_state_version",
    "subject_method",
    "operation_id",
    "actor_did",
    "accepted_at",
    "payload_digest",
];

pub fn generate_group_receipt_proof(
    receipt: &Value,
    private_key: &PrivateKeyMaterial,
    verification_method: &str,
) -> Result<Value, ProofError> {
    validate_group_receipt(receipt)?;
    generate_w3c_proof(
        receipt,
        private_key,
        verification_method,
        ProofGenerationOptions {
            proof_purpose: Some(GROUP_RECEIPT_PROOF_PURPOSE.to_string()),
            proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_string()),
            cryptosuite: Some(select_group_receipt_cryptosuite(private_key).to_string()),
            ..ProofGenerationOptions::default()
        },
    )
}

pub fn verify_group_receipt_proof(
    receipt: &Value,
    public_key: &PublicKeyMaterial,
) -> Result<(), ProofError> {
    validate_group_receipt(receipt)?;
    verify_w3c_proof_detailed(
        receipt,
        public_key,
        ProofVerificationOptions {
            expected_purpose: Some(GROUP_RECEIPT_PROOF_PURPOSE.to_string()),
            ..ProofVerificationOptions::default()
        },
    )
}

fn validate_group_receipt(receipt: &Value) -> Result<(), ProofError> {
    let object = receipt.as_object().ok_or(ProofError::VerificationFailed)?;
    for field in GROUP_RECEIPT_REQUIRED_FIELDS {
        if !object.contains_key(field) {
            return Err(ProofError::MissingProofField(field.to_string()));
        }
    }
    Ok(())
}

fn select_group_receipt_cryptosuite(private_key: &PrivateKeyMaterial) -> &'static str {
    match private_key {
        PrivateKeyMaterial::Ed25519(_) => CRYPTOSUITE_EDDSA_JCS_2022,
        PrivateKeyMaterial::Secp256k1(_) => CRYPTOSUITE_DIDWBA_SECP256K1_2025,
        _ => CRYPTOSUITE_DIDWBA_SECP256K1_2025,
    }
}
