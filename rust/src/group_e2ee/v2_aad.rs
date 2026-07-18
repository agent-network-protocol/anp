use serde_json::{json, Value};

use crate::canonical_json::canonicalize_json;

use super::v2_errors::GroupE2eeV2Error;
use super::v2_models::{
    V2GroupAddBody, V2GroupApplicationPlaintext, V2GroupRemoveBody, V2GroupSendMetadata,
    GROUP_CIPHER_CONTENT_TYPE_V2, GROUP_E2EE_SECURITY_PROFILE_V2, METHOD_GROUP_ADD_V2,
    METHOD_GROUP_REMOVE_V2,
};

/// Build the exact RFC 8785 bytes carried as MLS `authenticated_data` by P6 v2 send.
pub fn group_send_authenticated_data_v2(
    meta: &V2GroupSendMetadata,
    body: &super::v2_models::V2GroupCipherObject,
) -> Result<Vec<u8>, GroupE2eeV2Error> {
    meta.validate()?;
    body.validate()?;
    if body.group_state_ref.group_did != meta.target.did {
        return Err(GroupE2eeV2Error::invalid(
            "body.group_state_ref.group_did must equal meta.target.did",
        ));
    }
    canonicalize_json(&json!({
        "content_type": GROUP_CIPHER_CONTENT_TYPE_V2,
        "group_did": meta.target.did,
        "crypto_group_id_b64u": body.crypto_group_id_b64u,
        "group_state_ref": body.group_state_ref,
        "security_profile": GROUP_E2EE_SECURITY_PROFILE_V2,
        "sender_did": meta.sender_did,
        "sender_device_id": meta.sender_device_id,
        "message_id": meta.message_id,
        "operation_id": meta.operation_id,
    }))
    .map_err(GroupE2eeV2Error::from)
}

trait V2MembershipBody {
    fn member_did(&self) -> &str;
    fn member_device_id(&self) -> &str;
    fn group_state_ref(&self) -> &super::v2_models::V2GroupStateRef;
    fn crypto_group_id_b64u(&self) -> &str;
    fn epoch(&self) -> &str;
    fn validate_membership(&self) -> Result<(), GroupE2eeV2Error>;
}

impl V2MembershipBody for V2GroupAddBody {
    fn member_did(&self) -> &str {
        &self.member_did
    }
    fn member_device_id(&self) -> &str {
        &self.member_device_id
    }
    fn group_state_ref(&self) -> &super::v2_models::V2GroupStateRef {
        &self.group_state_ref
    }
    fn crypto_group_id_b64u(&self) -> &str {
        &self.crypto_group_id_b64u
    }
    fn epoch(&self) -> &str {
        &self.epoch
    }
    fn validate_membership(&self) -> Result<(), GroupE2eeV2Error> {
        self.validate()
    }
}

impl V2MembershipBody for V2GroupRemoveBody {
    fn member_did(&self) -> &str {
        &self.member_did
    }
    fn member_device_id(&self) -> &str {
        &self.member_device_id
    }
    fn group_state_ref(&self) -> &super::v2_models::V2GroupStateRef {
        &self.group_state_ref
    }
    fn crypto_group_id_b64u(&self) -> &str {
        &self.crypto_group_id_b64u
    }
    fn epoch(&self) -> &str {
        &self.epoch
    }
    fn validate_membership(&self) -> Result<(), GroupE2eeV2Error> {
        self.validate()
    }
}

fn membership_submission_binding<B: V2MembershipBody>(
    method: &str,
    meta: &super::v2_models::V2GroupControlMetadata,
    body: &B,
) -> Result<Vec<u8>, GroupE2eeV2Error> {
    if !matches!(method, METHOD_GROUP_ADD_V2 | METHOD_GROUP_REMOVE_V2) {
        return Err(GroupE2eeV2Error::invalid(
            "subject_method must be group.e2ee.add or group.e2ee.remove",
        ));
    }
    meta.validate()?;
    body.validate_membership()?;
    if body.group_state_ref().group_did != meta.target.did {
        return Err(GroupE2eeV2Error::invalid(
            "group_state_ref.group_did must equal meta.target.did",
        ));
    }
    canonicalize_json(&json!({
        "group_did": meta.target.did,
        "crypto_group_id_b64u": body.crypto_group_id_b64u(),
        "group_state_ref": body.group_state_ref(),
        "subject_method": method,
        "member_did": body.member_did(),
        "member_device_id": body.member_device_id(),
        "epoch": body.epoch(),
        "security_profile": GROUP_E2EE_SECURITY_PROFILE_V2,
        "sender_did": meta.sender_did,
        "sender_device_id": meta.sender_device_id,
        "operation_id": meta.operation_id,
    }))
    .map_err(GroupE2eeV2Error::from)
}

/// Build the exact P6 v2 Add submission binding without null/default placeholders.
pub fn group_add_submission_binding_v2(
    meta: &super::v2_models::V2GroupControlMetadata,
    body: &V2GroupAddBody,
) -> Result<Vec<u8>, GroupE2eeV2Error> {
    membership_submission_binding(METHOD_GROUP_ADD_V2, meta, body)
}

/// Build the exact P6 v2 Remove submission binding without null/default placeholders.
pub fn group_remove_submission_binding_v2(
    meta: &super::v2_models::V2GroupControlMetadata,
    body: &V2GroupRemoveBody,
) -> Result<Vec<u8>, GroupE2eeV2Error> {
    membership_submission_binding(METHOD_GROUP_REMOVE_V2, meta, body)
}

/// Canonicalize the inner group application object before MLS encryption.
pub fn canonical_group_application_plaintext_v2(
    plaintext: &V2GroupApplicationPlaintext,
) -> Result<Vec<u8>, GroupE2eeV2Error> {
    plaintext.validate()?;
    let value: Value = serde_json::to_value(plaintext)?;
    canonicalize_json(&value).map_err(GroupE2eeV2Error::from)
}

pub fn parse_group_application_plaintext_v2(
    value: &Value,
) -> Result<V2GroupApplicationPlaintext, GroupE2eeV2Error> {
    let plaintext: V2GroupApplicationPlaintext = serde_json::from_value(value.clone())?;
    plaintext.validate()?;
    Ok(plaintext)
}
