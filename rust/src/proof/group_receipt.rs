use serde_json::Value;

use crate::proof::{generate_object_proof, verify_object_proof, ProofError};
use crate::PrivateKeyMaterial;

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
    let issuer_did = receipt
        .get("group_did")
        .and_then(Value::as_str)
        .ok_or_else(|| ProofError::MissingProofField("group_did".to_string()))?;
    generate_object_proof(receipt, private_key, verification_method, issuer_did, None)
}

pub fn verify_group_receipt_proof(
    receipt: &Value,
    issuer_document: &Value,
) -> Result<(), ProofError> {
    validate_group_receipt(receipt)?;
    let issuer_did = receipt
        .get("group_did")
        .and_then(Value::as_str)
        .ok_or_else(|| ProofError::MissingProofField("group_did".to_string()))?;
    verify_object_proof(receipt, issuer_did, issuer_document)
}

fn validate_group_receipt(receipt: &Value) -> Result<(), ProofError> {
    let object = receipt.as_object().ok_or_else(|| {
        ProofError::InvalidProofField("group receipt must be an object".to_string())
    })?;
    for field in GROUP_RECEIPT_REQUIRED_FIELDS {
        if !object.contains_key(field) {
            return Err(ProofError::MissingProofField(field.to_string()));
        }
    }
    Ok(())
}
