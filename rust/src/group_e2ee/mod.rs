//! P6 wire helpers for ANP group E2EE.
//!
//! This module owns P6 data models, canonical AAD helpers, and the explicit
//! non-cryptographic contract-test artifact generator. Real OpenMLS group
//! operations live in the `anp-mls` binary so SDK/product integrations can share
//! wire semantics without embedding local MLS private state in this helper module.

use crate::canonical_json::{canonicalize_json, CanonicalJsonError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PROFILE: &str = "anp.group.e2ee.v1";
pub const SECURITY_PROFILE: &str = "group-e2ee";
pub const TRANSPORT_SECURITY_PROFILE: &str = "transport-protected";
pub const CONTRACT_ARTIFACT_MODE: &str = "contract-test";
pub const MTI_SUITE: &str = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
pub const METHOD_LEAVE_REQUEST: &str = "group.e2ee.leave_request";
pub const METHOD_LEAVE_REQUEST_PROCESS: &str = "group.e2ee.process_leave_request";
pub const METHOD_RECOVER_MEMBER: &str = "group.e2ee.recover_member";
pub const METHOD_UPDATE: &str = "group.e2ee.update";

#[derive(Debug, Error)]
pub enum GroupE2eeError {
    #[error("P6 contract-test mode is disabled")]
    ContractModeDisabled,
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    #[error(transparent)]
    CanonicalJson(#[from] CanonicalJsonError),
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupStateRef {
    pub group_did: String,
    pub group_state_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupKeyPackage {
    pub key_package_id: String,
    pub owner_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_did: Option<String>,
    pub suite: String,
    pub mls_key_package_b64u: String,
    pub did_wba_binding: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub non_cryptographic: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoverMemberTarget {
    pub agent_did: String,
    pub device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoverMemberRequestObject {
    pub operation_id: String,
    pub group_did: String,
    pub actor_did: String,
    pub target: RecoverMemberTarget,
    pub group_state_ref: GroupStateRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_key_package_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_key_package: Option<GroupKeyPackage>,
    pub commit_b64u: String,
    pub welcome_b64u: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree_b64u: Option<String>,
    pub epoch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_authenticator: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub non_cryptographic: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateMemberTarget {
    pub agent_did: String,
    pub device_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateMemberRequestObject {
    pub operation_id: String,
    pub group_did: String,
    pub actor_did: String,
    pub target: UpdateMemberTarget,
    pub group_state_ref: GroupStateRef,
    pub update_key_package_id: String,
    pub group_key_package: GroupKeyPackage,
    pub commit_b64u: String,
    pub welcome_b64u: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree_b64u: Option<String>,
    pub crypto_group_id_b64u: String,
    pub epoch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_authenticator: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub non_cryptographic: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateMemberFinalizeRequestObject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    pub pending_commit_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateMemberAbortRequestObject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    pub pending_commit_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoverMemberFinalizeRequestObject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    pub pending_commit_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoverMemberAbortRequestObject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    pub pending_commit_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupCipherObject {
    pub crypto_group_id_b64u: String,
    pub epoch: String,
    pub private_message_b64u: String,
    pub group_state_ref: GroupStateRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_authenticator: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub non_cryptographic: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupLeaveRequestObject {
    pub leave_request_id: String,
    pub group_did: String,
    pub requester_did: String,
    pub group_state_ref: GroupStateRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_at: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub non_cryptographic: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupLeaveRequestProcessObject {
    pub leave_request_id: String,
    pub group_did: String,
    pub requester_did: String,
    pub processor_did: String,
    pub group_state_ref: GroupStateRef,
    pub crypto_group_id_b64u: String,
    pub epoch: String,
    pub commit_b64u: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_authenticator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_text: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub non_cryptographic: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct E2eeNoticeObject {
    pub notice_id: String,
    pub notice_type: String,
    pub group_did: String,
    pub group_state_ref: GroupStateRef,
    pub crypto_group_id_b64u: String,
    pub epoch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_b64u: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub welcome_b64u: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree_b64u: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_authenticator: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub non_cryptographic: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GroupApplicationPlaintext {
    pub application_content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_message_id: Option<String>,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub annotations: serde_json::Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_b64u: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractArtifact {
    pub value_b64u: String,
    pub digest_b64u: String,
    pub non_cryptographic: bool,
    pub artifact_mode: String,
}

pub fn build_leave_request_control_aad(value: &Value) -> Result<Vec<u8>, GroupE2eeError> {
    let method = value
        .get("method")
        .and_then(Value::as_str)
        .ok_or(GroupE2eeError::MissingField("method"))?;
    match method {
        METHOD_LEAVE_REQUEST => {
            for field in [
                "method",
                "security_profile",
                "group_did",
                "group_state_ref",
                "requester_did",
                "operation_id",
            ] {
                if value.get(field).is_none() {
                    return Err(GroupE2eeError::MissingField(field));
                }
            }
            if value.get("security_profile").and_then(Value::as_str)
                != Some(TRANSPORT_SECURITY_PROFILE)
            {
                return Err(GroupE2eeError::InvalidField("security_profile"));
            }
        }
        METHOD_LEAVE_REQUEST_PROCESS => {
            for field in [
                "method",
                "security_profile",
                "group_did",
                "group_state_ref",
                "leave_request_id",
                "requester_did",
                "processor_did",
                "crypto_group_id_b64u",
                "epoch",
                "commit_b64u",
                "operation_id",
            ] {
                if value.get(field).is_none() {
                    return Err(GroupE2eeError::MissingField(field));
                }
            }
            if value.get("security_profile").and_then(Value::as_str) != Some(SECURITY_PROFILE) {
                return Err(GroupE2eeError::InvalidField("security_profile"));
            }
        }
        _ => return Err(GroupE2eeError::InvalidField("method")),
    }
    Ok(canonicalize_json(value)?)
}

pub fn build_update_member_control_aad(value: &Value) -> Result<Vec<u8>, GroupE2eeError> {
    for field in [
        "method",
        "security_profile",
        "operation_id",
        "group_did",
        "group_state_ref",
        "actor_did",
        "target",
        "update_key_package_id",
        "commit_b64u",
        "welcome_b64u",
        "crypto_group_id_b64u",
        "epoch",
    ] {
        if value.get(field).is_none() {
            return Err(GroupE2eeError::MissingField(field));
        }
    }
    if value.get("method").and_then(Value::as_str) != Some(METHOD_UPDATE) {
        return Err(GroupE2eeError::InvalidField("method"));
    }
    if value.get("security_profile").and_then(Value::as_str) != Some(SECURITY_PROFILE) {
        return Err(GroupE2eeError::InvalidField("security_profile"));
    }
    let group_did = value
        .get("group_did")
        .and_then(Value::as_str)
        .ok_or(GroupE2eeError::MissingField("group_did"))?;
    if value
        .pointer("/group_state_ref/group_did")
        .and_then(Value::as_str)
        != Some(group_did)
    {
        return Err(GroupE2eeError::InvalidField("group_state_ref.group_did"));
    }
    if value
        .pointer("/target/agent_did")
        .and_then(Value::as_str)
        .is_none()
    {
        return Err(GroupE2eeError::MissingField("target.agent_did"));
    }
    if value
        .pointer("/target/device_id")
        .and_then(Value::as_str)
        .is_none()
    {
        return Err(GroupE2eeError::MissingField("target.device_id"));
    }
    if value
        .get("commit_b64u")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .is_empty()
    {
        return Err(GroupE2eeError::MissingField("commit_b64u"));
    }
    Ok(canonicalize_json(value)?)
}

pub fn build_send_aad(value: &Value) -> Result<Vec<u8>, GroupE2eeError> {
    for field in [
        "content_type",
        "group_did",
        "crypto_group_id_b64u",
        "group_state_ref",
        "security_profile",
        "sender_did",
        "message_id",
        "operation_id",
    ] {
        if value.get(field).is_none() {
            return Err(GroupE2eeError::MissingField(field));
        }
    }
    Ok(canonicalize_json(value)?)
}

pub fn deterministic_contract_artifact(
    purpose: &str,
    input: &Value,
    enabled: bool,
) -> Result<ContractArtifact, GroupE2eeError> {
    if !enabled {
        return Err(GroupE2eeError::ContractModeDisabled);
    }
    let canonical = canonicalize_json(input)?;
    let mut hasher = Sha256::new();
    hasher.update(b"ANP-P6-CONTRACT-TEST\0");
    hasher.update(purpose.as_bytes());
    hasher.update(b"\0");
    hasher.update(&canonical);
    let digest = hasher.finalize();
    let digest_b64u = URL_SAFE_NO_PAD.encode(digest);
    let value = json!({
        "purpose": purpose,
        "digest_b64u": digest_b64u,
        "non_cryptographic": true,
        "artifact_mode": CONTRACT_ARTIFACT_MODE,
    });
    Ok(ContractArtifact {
        value_b64u: URL_SAFE_NO_PAD.encode(canonicalize_json(&value)?),
        digest_b64u,
        non_cryptographic: true,
        artifact_mode: CONTRACT_ARTIFACT_MODE.to_owned(),
    })
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn leave_request_control_aad_has_stable_golden_vector() {
        let aad = build_leave_request_control_aad(&json!({
            "method": METHOD_LEAVE_REQUEST,
            "operation_id": "op-leave-request",
            "security_profile": TRANSPORT_SECURITY_PROFILE,
            "group_did": "did:wba:example.com:groups:golden:e1",
            "requester_did": "did:wba:example.com:users:bob:e1",
            "reason_text": "leaving this workspace",
            "group_state_ref": {
                "group_state_version": "7",
                "group_did": "did:wba:example.com:groups:golden:e1"
            }
        }))
        .expect("leave request aad");
        assert_eq!(
            String::from_utf8(aad).expect("utf8 aad"),
            r#"{"group_did":"did:wba:example.com:groups:golden:e1","group_state_ref":{"group_did":"did:wba:example.com:groups:golden:e1","group_state_version":"7"},"method":"group.e2ee.leave_request","operation_id":"op-leave-request","reason_text":"leaving this workspace","requester_did":"did:wba:example.com:users:bob:e1","security_profile":"transport-protected"}"#
        );
    }

    #[test]
    fn leave_request_process_requires_epoch_advancing_commit_fields() {
        let err = build_leave_request_control_aad(&json!({
            "method": METHOD_LEAVE_REQUEST_PROCESS,
            "operation_id": "op-process",
            "security_profile": SECURITY_PROFILE,
            "group_did": "did:wba:example.com:groups:golden:e1",
            "group_state_ref": {
                "group_state_version": "7",
                "group_did": "did:wba:example.com:groups:golden:e1"
            },
            "leave_request_id": "leave-req-1",
            "requester_did": "did:wba:example.com:users:bob:e1",
            "processor_did": "did:wba:example.com:users:alice:e1",
            "crypto_group_id_b64u": "Y3J5cHRv",
            "epoch": "8"
        }))
        .expect_err("missing commit");
        assert!(matches!(err, GroupE2eeError::MissingField("commit_b64u")));
    }

    #[test]
    fn recover_member_wire_model_carries_recovery_bound_package() {
        let request = RecoverMemberRequestObject {
            operation_id: "op-recover-bob".to_owned(),
            group_did: "did:wba:example.com:groups:golden:e1".to_owned(),
            actor_did: "did:wba:example.com:users:alice:e1".to_owned(),
            target: RecoverMemberTarget {
                agent_did: "did:wba:example.com:users:bob:e1".to_owned(),
                device_id: "phone".to_owned(),
            },
            group_state_ref: GroupStateRef {
                group_did: "did:wba:example.com:groups:golden:e1".to_owned(),
                group_state_version: "7".to_owned(),
                policy_hash: None,
            },
            recovery_key_package_id: Some("kp-recovery-bob".to_owned()),
            group_key_package: Some(GroupKeyPackage {
                key_package_id: "kp-recovery-bob".to_owned(),
                owner_did: "did:wba:example.com:users:bob:e1".to_owned(),
                device_id: Some("phone".to_owned()),
                purpose: Some("recovery".to_owned()),
                group_did: Some("did:wba:example.com:groups:golden:e1".to_owned()),
                suite: MTI_SUITE.to_owned(),
                mls_key_package_b64u: "bWxzLWtleS1wYWNrYWdl".to_owned(),
                did_wba_binding: json!({
                    "agent_did": "did:wba:example.com:users:bob:e1",
                    "device_id": "phone"
                }),
                expires_at: None,
                non_cryptographic: false,
                artifact_mode: None,
            }),
            commit_b64u: "Y29tbWl0".to_owned(),
            welcome_b64u: "d2VsY29tZQ".to_owned(),
            ratchet_tree_b64u: Some("cmF0Y2hldA".to_owned()),
            epoch: "8".to_owned(),
            epoch_authenticator: Some("YXV0aA".to_owned()),
            non_cryptographic: false,
            artifact_mode: None,
        };
        let encoded = serde_json::to_string(&request).expect("recover member json");
        assert!(encoded.contains(r#""purpose":"recovery""#));
        assert!(encoded.contains(r#""welcome_b64u":"d2VsY29tZQ""#));
        assert!(!encoded.contains("plaintext"));
        assert_eq!(METHOD_RECOVER_MEMBER, "group.e2ee.recover_member");
    }

    #[test]
    fn recover_member_finalize_abort_models_carry_pending_commit_id() {
        let finalize = RecoverMemberFinalizeRequestObject {
            operation_id: Some("op-finalize".to_owned()),
            pending_commit_id: "pc-recover".to_owned(),
        };
        let abort = RecoverMemberAbortRequestObject {
            operation_id: Some("op-abort".to_owned()),
            pending_commit_id: "pc-recover".to_owned(),
        };
        for encoded in [
            serde_json::to_string(&finalize).expect("finalize json"),
            serde_json::to_string(&abort).expect("abort json"),
        ] {
            assert!(encoded.contains(r#""pending_commit_id":"pc-recover""#));
            assert!(encoded.contains(r#""operation_id":"op-"#));
        }
    }

    #[test]
    fn update_member_wire_model_carries_update_bound_package() {
        let request = UpdateMemberRequestObject {
            operation_id: "op-update-bob".to_owned(),
            group_did: "did:wba:example.com:groups:golden:e1".to_owned(),
            actor_did: "did:wba:example.com:users:alice:e1".to_owned(),
            target: UpdateMemberTarget {
                agent_did: "did:wba:example.com:users:bob:e1".to_owned(),
                device_id: "phone".to_owned(),
            },
            group_state_ref: GroupStateRef {
                group_did: "did:wba:example.com:groups:golden:e1".to_owned(),
                group_state_version: "7".to_owned(),
                policy_hash: None,
            },
            update_key_package_id: "kp-update-bob".to_owned(),
            group_key_package: GroupKeyPackage {
                key_package_id: "kp-update-bob".to_owned(),
                owner_did: "did:wba:example.com:users:bob:e1".to_owned(),
                device_id: Some("phone".to_owned()),
                purpose: Some("update".to_owned()),
                group_did: Some("did:wba:example.com:groups:golden:e1".to_owned()),
                suite: MTI_SUITE.to_owned(),
                mls_key_package_b64u: "bWxzLWtleS1wYWNrYWdl".to_owned(),
                did_wba_binding: json!({
                    "agent_did": "did:wba:example.com:users:bob:e1",
                    "device_id": "phone"
                }),
                expires_at: None,
                non_cryptographic: false,
                artifact_mode: None,
            },
            commit_b64u: "Y29tbWl0".to_owned(),
            welcome_b64u: "d2VsY29tZQ".to_owned(),
            ratchet_tree_b64u: Some("cmF0Y2hldA".to_owned()),
            crypto_group_id_b64u: "Y3J5cHRv".to_owned(),
            epoch: "8".to_owned(),
            epoch_authenticator: Some("YXV0aA".to_owned()),
            non_cryptographic: false,
            artifact_mode: None,
        };
        let encoded = serde_json::to_string(&request).expect("update member json");
        assert!(encoded.contains(r#""purpose":"update""#));
        assert!(encoded.contains(r#""update_key_package_id":"kp-update-bob""#));
        assert!(encoded.contains(r#""welcome_b64u":"d2VsY29tZQ""#));
        assert!(!encoded.contains("plaintext"));
        assert_eq!(METHOD_UPDATE, "group.e2ee.update");
    }

    #[test]
    fn update_member_aad_requires_hidden_update_fields() {
        let aad = build_update_member_control_aad(&json!({
            "method": METHOD_UPDATE,
            "operation_id": "op-update-bob",
            "security_profile": SECURITY_PROFILE,
            "group_did": "did:wba:example.com:groups:golden:e1",
            "actor_did": "did:wba:example.com:users:alice:e1",
            "target": {
                "agent_did": "did:wba:example.com:users:bob:e1",
                "device_id": "phone"
            },
            "update_key_package_id": "kp-update-bob",
            "group_state_ref": {
                "group_state_version": "7",
                "group_did": "did:wba:example.com:groups:golden:e1"
            },
            "crypto_group_id_b64u": "Y3J5cHRv",
            "epoch": "8",
            "commit_b64u": "Y29tbWl0",
            "welcome_b64u": "d2VsY29tZQ"
        }))
        .expect("update member aad");
        assert!(String::from_utf8(aad)
            .expect("utf8 aad")
            .contains("group.e2ee.update"));

        let err = build_update_member_control_aad(&json!({
            "method": METHOD_UPDATE,
            "operation_id": "op-update-bob",
            "security_profile": SECURITY_PROFILE,
            "group_did": "did:wba:example.com:groups:golden:e1",
            "actor_did": "did:wba:example.com:users:alice:e1",
            "target": {"agent_did": "did:wba:example.com:users:bob:e1", "device_id": "phone"},
            "update_key_package_id": "kp-update-bob",
            "group_state_ref": {"group_state_version": "7", "group_did": "did:wba:example.com:groups:other:e1"},
            "crypto_group_id_b64u": "Y3J5cHRv",
            "epoch": "8",
            "welcome_b64u": "d2VsY29tZQ"
        }))
        .expect_err("missing commit and wrong group");
        assert!(matches!(err, GroupE2eeError::MissingField("commit_b64u")));
    }

    #[test]
    fn send_aad_canonicalizes_required_fields() {
        let aad = build_send_aad(&json!({
            "sender_did": "did:wba:example:alice",
            "operation_id": "op-1",
            "message_id": "msg-1",
            "security_profile": "group-e2ee",
            "content_type": "application/anp-group-cipher+json",
            "crypto_group_id_b64u": "Y3J5cHRv",
            "group_did": "did:wba:groups.example:team:e1_x",
            "group_state_ref": {"group_did":"did:wba:groups.example:team:e1_x","group_state_version":"1"}
        }))
        .expect("aad");
        assert!(String::from_utf8(aad).unwrap().starts_with("{"));
    }

    #[test]
    fn send_aad_has_stable_p6_golden_vector() {
        let aad = build_send_aad(&json!({
            "operation_id": "op-golden",
            "message_id": "msg-golden",
            "sender_did": "did:wba:example.com:users:alice:e1",
            "security_profile": "group-e2ee",
            "group_did": "did:wba:example.com:groups:golden:e1",
            "content_type": "application/anp-group-cipher+json",
            "crypto_group_id_b64u": "ZGlkOndiYTpleGFtcGxlLmNvbTpncm91cHM6Z29sZGVuOmUx",
            "group_state_ref": {
                "policy_hash": "sha256:policy",
                "group_state_version": "7",
                "group_did": "did:wba:example.com:groups:golden:e1"
            }
        }))
        .expect("aad");
        assert_eq!(
            String::from_utf8(aad).expect("utf8 aad"),
            r#"{"content_type":"application/anp-group-cipher+json","crypto_group_id_b64u":"ZGlkOndiYTpleGFtcGxlLmNvbTpncm91cHM6Z29sZGVuOmUx","group_did":"did:wba:example.com:groups:golden:e1","group_state_ref":{"group_did":"did:wba:example.com:groups:golden:e1","group_state_version":"7","policy_hash":"sha256:policy"},"message_id":"msg-golden","operation_id":"op-golden","security_profile":"group-e2ee","sender_did":"did:wba:example.com:users:alice:e1"}"#
        );
    }

    #[test]
    fn contract_artifact_requires_explicit_enablement() {
        let err = deterministic_contract_artifact("cipher", &json!({"x": 1}), false)
            .expect_err("disabled");
        assert!(matches!(err, GroupE2eeError::ContractModeDisabled));
        let artifact =
            deterministic_contract_artifact("cipher", &json!({"x": 1}), true).expect("artifact");
        assert!(artifact.non_cryptographic);
        assert_eq!(artifact.artifact_mode, CONTRACT_ARTIFACT_MODE);
    }
}
