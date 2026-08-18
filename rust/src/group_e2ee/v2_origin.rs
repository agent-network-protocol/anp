//! P6 `group.incoming` origin-proof reconstruction and verification.

use crate::group_e2ee::{
    GroupE2eeV2Error, V2DeliveredOriginAuth, V2GroupIncomingBody, V2GroupIncomingMetadata,
    METHOD_GROUP_SEND_V2,
};
use crate::proof::{
    verify_rfc9421_origin_proof, ImProofVerificationResult, Rfc9421OriginProof,
    Rfc9421OriginProofVerificationOptions,
};
use serde_json::{json, Map, Value};

/// Reconstructs the exact Signed Request Object submitted as `group.e2ee.send`.
pub fn reconstruct_group_send_request_v2(
    meta: &V2GroupIncomingMetadata,
    body: &V2GroupIncomingBody,
    auth: &V2DeliveredOriginAuth,
) -> Result<Value, GroupE2eeV2Error> {
    meta.validate()?;
    body.validate()?;
    auth.validate()?;

    let mut reconstructed = Map::new();
    reconstructed.insert("profile".to_owned(), json!(meta.profile));
    reconstructed.insert("security_profile".to_owned(), json!(meta.security_profile));
    reconstructed.insert("sender_did".to_owned(), json!(meta.sender_did));
    reconstructed.insert("sender_device_id".to_owned(), json!(meta.sender_device_id));
    reconstructed.insert(
        "target".to_owned(),
        json!({"kind": "group", "did": body.group_did}),
    );
    reconstructed.insert("operation_id".to_owned(), json!(meta.operation_id));
    reconstructed.insert("message_id".to_owned(), json!(meta.message_id));
    reconstructed.insert("content_type".to_owned(), json!(meta.content_type));
    if let Some(created_at) = auth.origin_context.created_at.as_ref() {
        reconstructed.insert("created_at".to_owned(), json!(created_at));
    }
    for (field, value) in &auth.origin_context.extra_meta {
        if reconstructed.insert(field.clone(), value.clone()).is_some() {
            return Err(GroupE2eeV2Error::invalid(format!(
                "auth.origin_context.extra_meta conflicts with reconstructed field {field}"
            )));
        }
    }

    Ok(json!({
        "method": METHOD_GROUP_SEND_V2,
        "meta": reconstructed,
        "body": body.group_cipher_object,
    }))
}

/// Verifies the preserved sender proof against the reconstructed submission.
pub fn verify_group_incoming_origin_proof_v2(
    meta: &V2GroupIncomingMetadata,
    body: &V2GroupIncomingBody,
    auth: &V2DeliveredOriginAuth,
    options: Rfc9421OriginProofVerificationOptions,
) -> Result<ImProofVerificationResult, GroupE2eeV2Error> {
    let request = reconstruct_group_send_request_v2(meta, body, auth)?;
    let proof = Rfc9421OriginProof {
        content_digest: auth.origin_proof.content_digest.clone(),
        signature_input: auth.origin_proof.signature_input.clone(),
        signature: auth.origin_proof.signature.clone(),
    };
    Ok(verify_rfc9421_origin_proof(
        &proof,
        METHOD_GROUP_SEND_V2,
        &request["meta"],
        &request["body"],
        options,
    )?)
}
