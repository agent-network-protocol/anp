use serde_json::{json, Value};

use super::v2_errors::DirectE2eeV2Error;
use super::v2_models::{
    V2ApplicationPlaintext, V2DirectCipherBody, V2DirectInitBody, V2DirectMetadata,
    CONTENT_TYPE_DIRECT_CIPHER_V2, CONTENT_TYPE_DIRECT_INIT_V2,
};
use crate::canonical_json::canonicalize_json;

pub fn build_init_aad_v2(
    metadata: &V2DirectMetadata,
    body: &V2DirectInitBody,
) -> Result<Vec<u8>, DirectE2eeV2Error> {
    metadata.validate()?;
    body.validate()?;
    if metadata.content_type != CONTENT_TYPE_DIRECT_INIT_V2 {
        return Err(DirectE2eeV2Error::invalid(
            "init AAD requires application/anp-direct-init+json",
        ));
    }
    let mut payload = json!({
        "content_type": CONTENT_TYPE_DIRECT_INIT_V2,
        "message_id": metadata.message_id,
        "operation_id": metadata.operation_id,
        "profile": metadata.profile,
        "security_profile": metadata.security_profile,
        "sender_did": metadata.sender_did,
        "sender_device_id": metadata.sender_device_id,
        "recipient_did": metadata.target.did,
        "recipient_device_id": metadata.recipient_device_id,
        "suite": body.suite,
        "recipient_bundle_id": body.recipient_bundle_id,
        "sender_static_key_agreement_id": body.sender_static_key_agreement_id,
        "recipient_signed_prekey_id": body.recipient_signed_prekey_id,
        "session_id": body.session_id,
    });
    if let Some(opk) = body.recipient_one_time_prekey_id.as_deref() {
        payload["recipient_one_time_prekey_id"] = json!(opk);
    }
    Ok(canonicalize_json(&payload)?)
}

pub fn build_message_aad_v2(
    metadata: &V2DirectMetadata,
    body: &V2DirectCipherBody,
) -> Result<Vec<u8>, DirectE2eeV2Error> {
    metadata.validate()?;
    body.validate()?;
    if metadata.content_type != CONTENT_TYPE_DIRECT_CIPHER_V2 {
        return Err(DirectE2eeV2Error::invalid(
            "message AAD requires application/anp-direct-cipher+json",
        ));
    }
    let payload = json!({
        "content_type": CONTENT_TYPE_DIRECT_CIPHER_V2,
        "message_id": metadata.message_id,
        "operation_id": metadata.operation_id,
        "profile": metadata.profile,
        "security_profile": metadata.security_profile,
        "sender_did": metadata.sender_did,
        "sender_device_id": metadata.sender_device_id,
        "recipient_did": metadata.target.did,
        "recipient_device_id": metadata.recipient_device_id,
        "session_id": body.session_id,
        "ratchet_header": body.ratchet_header,
    });
    Ok(canonicalize_json(&payload)?)
}

pub fn canonical_application_plaintext_v2(
    plaintext: &V2ApplicationPlaintext,
) -> Result<Vec<u8>, DirectE2eeV2Error> {
    plaintext.validate()?;
    let value: Value = serde_json::to_value(plaintext)?;
    Ok(canonicalize_json(&value)?)
}
