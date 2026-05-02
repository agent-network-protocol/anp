//! Contract-first helpers for ANP P6 group E2EE.
//!
//! This module intentionally does not implement MLS cryptography yet. It owns
//! the P6 wire models and a deterministic contract-test artifact generator so
//! product integrations can stabilize API/storage boundaries before OpenMLS is
//! wired in.

use crate::canonical_json::{canonicalize_json, CanonicalJsonError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PROFILE: &str = "anp.group.e2ee.v1";
pub const SECURITY_PROFILE: &str = "group-e2ee";
pub const CONTRACT_ARTIFACT_MODE: &str = "contract-test";
pub const MTI_SUITE: &str = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";

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
