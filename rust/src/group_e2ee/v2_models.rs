use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::DateTime;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use super::v2_errors::GroupE2eeV2Error;

pub const GROUP_E2EE_PROFILE_V2: &str = "anp.group.e2ee.v2";
pub const GROUP_E2EE_SECURITY_PROFILE_V2: &str = "group-e2ee";
pub const GROUP_E2EE_TRANSPORT_PROFILE_V2: &str = "transport-protected";
pub const GROUP_CIPHER_CONTENT_TYPE_V2: &str = "application/anp-group-cipher+json";
pub const GROUP_E2EE_MTI_SUITE_V2: &str = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
pub const DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2: u16 = 0xF0A1;
pub const DID_WBA_DEVICE_BINDING_EXTENSION_REGISTERED_V2: bool = false;
pub const RFC9421_ORIGIN_PROOF_SCHEME_V2: &str = "anp-rfc9421-origin-proof-v1";

pub const METHOD_PUBLISH_KEY_PACKAGE_V2: &str = "group.e2ee.publish_key_package";
pub const METHOD_GET_KEY_PACKAGE_V2: &str = "group.e2ee.get_key_package";
pub const METHOD_GROUP_CREATE_V2: &str = "group.e2ee.create";
pub const METHOD_GROUP_ADD_V2: &str = "group.e2ee.add";
pub const METHOD_GROUP_REMOVE_V2: &str = "group.e2ee.remove";
pub const METHOD_GROUP_SEND_V2: &str = "group.e2ee.send";
pub const METHOD_GROUP_NOTICE_V2: &str = "group.e2ee.notice";
pub const METHOD_GROUP_INCOMING_V2: &str = "group.incoming";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2GroupStateRef {
    pub group_did: String,
    pub group_state_version: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub policy_hash: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub roster_hash: Option<String>,
}

impl V2GroupStateRef {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        require_non_empty("group_state_ref.group_did", &self.group_did)?;
        require_non_empty(
            "group_state_ref.group_state_version",
            &self.group_state_version,
        )?;
        validate_optional_non_empty("group_state_ref.policy_hash", self.policy_hash.as_deref())?;
        validate_optional_non_empty("group_state_ref.roster_hash", self.roster_hash.as_deref())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2Target {
    pub kind: String,
    pub did: String,
}

impl V2Target {
    pub fn validate(&self, kind: &str) -> Result<(), GroupE2eeV2Error> {
        require_eq("meta.target.kind", &self.kind, kind)?;
        require_non_empty("meta.target.did", &self.did)
    }
}

/// Metadata used by service-scoped P6 methods.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2ServiceMetadata {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub anp_version: Option<String>,
    pub profile: String,
    pub security_profile: String,
    pub sender_did: String,
    pub sender_device_id: String,
    pub target: V2Target,
    pub operation_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub created_at: Option<String>,
}

impl V2ServiceMetadata {
    pub fn validate(&self, security_profile: &str) -> Result<(), GroupE2eeV2Error> {
        validate_common_meta(
            self.anp_version.as_deref(),
            &self.profile,
            &self.security_profile,
            security_profile,
            &self.sender_did,
            Some(&self.sender_device_id),
            &self.target,
            "service",
            &self.operation_id,
            self.created_at.as_deref(),
        )
    }
}

/// Metadata used by group-addressed create/add/remove control methods.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2GroupControlMetadata {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub anp_version: Option<String>,
    pub profile: String,
    pub security_profile: String,
    pub sender_did: String,
    pub sender_device_id: String,
    pub target: V2Target,
    pub operation_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub created_at: Option<String>,
}

impl V2GroupControlMetadata {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        validate_common_meta(
            self.anp_version.as_deref(),
            &self.profile,
            &self.security_profile,
            GROUP_E2EE_SECURITY_PROFILE_V2,
            &self.sender_did,
            Some(&self.sender_device_id),
            &self.target,
            "group",
            &self.operation_id,
            self.created_at.as_deref(),
        )
    }
}

/// Metadata used by `group.e2ee.send` and preserved by P6 `group.incoming`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2GroupSendMetadata {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub anp_version: Option<String>,
    pub profile: String,
    pub security_profile: String,
    pub sender_did: String,
    pub sender_device_id: String,
    pub target: V2Target,
    pub operation_id: String,
    pub message_id: String,
    pub content_type: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub created_at: Option<String>,
}

impl V2GroupSendMetadata {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        validate_common_meta(
            self.anp_version.as_deref(),
            &self.profile,
            &self.security_profile,
            GROUP_E2EE_SECURITY_PROFILE_V2,
            &self.sender_did,
            Some(&self.sender_device_id),
            &self.target,
            "group",
            &self.operation_id,
            self.created_at.as_deref(),
        )?;
        require_non_empty("meta.message_id", &self.message_id)?;
        require_eq(
            "meta.content_type",
            &self.content_type,
            GROUP_CIPHER_CONTENT_TYPE_V2,
        )
    }
}

/// Host-originated, device-targeted MLS control notice metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2GroupNoticeMetadata {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub anp_version: Option<String>,
    pub profile: String,
    pub security_profile: String,
    pub sender_did: String,
    pub target: V2Target,
    pub recipient_device_id: String,
    pub operation_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub created_at: Option<String>,
}

impl V2GroupNoticeMetadata {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        validate_common_meta(
            self.anp_version.as_deref(),
            &self.profile,
            &self.security_profile,
            GROUP_E2EE_TRANSPORT_PROFILE_V2,
            &self.sender_did,
            None,
            &self.target,
            "agent",
            &self.operation_id,
            self.created_at.as_deref(),
        )?;
        require_non_empty("meta.recipient_device_id", &self.recipient_device_id)
    }
}

/// Device-targeted P6 application-ciphertext delivery metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2GroupIncomingMetadata {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub anp_version: Option<String>,
    pub profile: String,
    pub security_profile: String,
    pub sender_did: String,
    pub sender_device_id: String,
    pub target: V2Target,
    pub recipient_device_id: String,
    pub operation_id: String,
    pub message_id: String,
    pub content_type: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub created_at: Option<String>,
}

impl V2GroupIncomingMetadata {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        validate_common_meta(
            self.anp_version.as_deref(),
            &self.profile,
            &self.security_profile,
            GROUP_E2EE_SECURITY_PROFILE_V2,
            &self.sender_did,
            Some(&self.sender_device_id),
            &self.target,
            "agent",
            &self.operation_id,
            self.created_at.as_deref(),
        )?;
        require_non_empty("meta.recipient_device_id", &self.recipient_device_id)?;
        require_non_empty("meta.message_id", &self.message_id)?;
        require_eq(
            "meta.content_type",
            &self.content_type,
            GROUP_CIPHER_CONTENT_TYPE_V2,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2OriginProof {
    #[serde(rename = "contentDigest")]
    pub content_digest: String,
    #[serde(rename = "signatureInput")]
    pub signature_input: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2OriginAuth {
    pub scheme: String,
    pub origin_proof: V2OriginProof,
}

impl V2OriginAuth {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        require_eq("auth.scheme", &self.scheme, RFC9421_ORIGIN_PROOF_SCHEME_V2)?;
        for (field, value) in [
            (
                "auth.origin_proof.contentDigest",
                &self.origin_proof.content_digest,
            ),
            (
                "auth.origin_proof.signatureInput",
                &self.origin_proof.signature_input,
            ),
            ("auth.origin_proof.signature", &self.origin_proof.signature),
        ] {
            require_non_empty(field, value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2ObjectProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub cryptosuite: String,
    pub created: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

impl V2ObjectProof {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        require_eq("proof.type", &self.proof_type, "DataIntegrityProof")?;
        require_eq("proof.cryptosuite", &self.cryptosuite, "eddsa-jcs-2022")?;
        require_eq("proof.proofPurpose", &self.proof_purpose, "assertionMethod")?;
        validate_rfc3339("proof.created", &self.created)?;
        require_non_empty("proof.verificationMethod", &self.verification_method)?;
        require_non_empty("proof.proofValue", &self.proof_value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2DidWbaBinding {
    pub agent_did: String,
    pub device_id: String,
    pub verification_method: String,
    pub leaf_signature_key_b64u: String,
    pub issued_at: String,
    pub expires_at: String,
    pub proof: V2ObjectProof,
}

impl V2DidWbaBinding {
    pub fn validate_structure(&self) -> Result<(), GroupE2eeV2Error> {
        for (field, value) in [
            ("did_wba_binding.agent_did", self.agent_did.as_str()),
            ("did_wba_binding.device_id", self.device_id.as_str()),
            (
                "did_wba_binding.verification_method",
                self.verification_method.as_str(),
            ),
        ] {
            require_non_empty(field, value)?;
        }
        validate_ed25519_b64u(
            "did_wba_binding.leaf_signature_key_b64u",
            &self.leaf_signature_key_b64u,
        )?;
        validate_rfc3339("did_wba_binding.issued_at", &self.issued_at)?;
        validate_rfc3339("did_wba_binding.expires_at", &self.expires_at)?;
        self.proof.validate()?;
        if self.proof.verification_method != self.verification_method {
            return Err(GroupE2eeV2Error::invalid(
                "proof.verificationMethod must equal did_wba_binding.verification_method",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2GroupKeyPackage {
    pub key_package_id: String,
    pub owner_did: String,
    pub owner_device_id: String,
    pub suite: String,
    pub mls_key_package_b64u: String,
    pub did_wba_binding: V2DidWbaBinding,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub expires_at: Option<String>,
}

impl V2GroupKeyPackage {
    pub fn validate_structure(&self) -> Result<(), GroupE2eeV2Error> {
        for (field, value) in [
            (
                "group_key_package.key_package_id",
                self.key_package_id.as_str(),
            ),
            ("group_key_package.owner_did", self.owner_did.as_str()),
            (
                "group_key_package.owner_device_id",
                self.owner_device_id.as_str(),
            ),
        ] {
            require_non_empty(field, value)?;
        }
        require_eq(
            "group_key_package.suite",
            &self.suite,
            GROUP_E2EE_MTI_SUITE_V2,
        )?;
        validate_non_empty_b64u(
            "group_key_package.mls_key_package_b64u",
            &self.mls_key_package_b64u,
        )?;
        self.did_wba_binding.validate_structure()?;
        if self.owner_did != self.did_wba_binding.agent_did
            || self.owner_device_id != self.did_wba_binding.device_id
        {
            return Err(GroupE2eeV2Error::invalid(
                "group_key_package owner pair must equal did_wba_binding pair",
            ));
        }
        if let Some(expires_at) = self.expires_at.as_deref() {
            validate_rfc3339("group_key_package.expires_at", expires_at)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2GroupCipherObject {
    pub crypto_group_id_b64u: String,
    pub epoch: String,
    pub private_message_b64u: String,
    pub group_state_ref: V2GroupStateRef,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub epoch_authenticator: Option<String>,
}

impl V2GroupCipherObject {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        validate_non_empty_b64u("crypto_group_id_b64u", &self.crypto_group_id_b64u)?;
        validate_decimal("epoch", &self.epoch)?;
        validate_non_empty_b64u("private_message_b64u", &self.private_message_b64u)?;
        self.group_state_ref.validate()?;
        if let Some(value) = self.epoch_authenticator.as_deref() {
            validate_non_empty_b64u("epoch_authenticator", value)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct V2GroupApplicationPlaintext {
    pub application_content_type: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub thread_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub reply_to_message_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub annotations: Option<Value>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub text: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub payload: Option<Value>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub payload_b64u: Option<String>,
}

impl V2GroupApplicationPlaintext {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        require_non_empty("application_content_type", &self.application_content_type)?;
        validate_optional_non_empty("thread_id", self.thread_id.as_deref())?;
        validate_optional_non_empty("reply_to_message_id", self.reply_to_message_id.as_deref())?;
        if self
            .annotations
            .as_ref()
            .is_some_and(|value| !value.is_object())
        {
            return Err(GroupE2eeV2Error::invalid(
                "annotations must be a JSON object",
            ));
        }
        let present = usize::from(self.text.is_some())
            + usize::from(self.payload.is_some())
            + usize::from(self.payload_b64u.is_some());
        if present != 1 {
            return Err(GroupE2eeV2Error::invalid(
                "exactly one of text, payload, or payload_b64u must be present",
            ));
        }
        if let Some(text) = self.text.as_deref() {
            require_non_empty("text", text)?;
        }
        if let Some(payload) = self.payload.as_ref() {
            if !payload.is_object() {
                return Err(GroupE2eeV2Error::invalid("payload must be a JSON object"));
            }
        }
        if let Some(payload) = self.payload_b64u.as_deref() {
            validate_non_empty_b64u("payload_b64u", payload)?;
        }
        if self.application_content_type == "text/plain" && self.text.is_none() {
            return Err(GroupE2eeV2Error::invalid(
                "text/plain plaintext must use text",
            ));
        }
        if matches!(
            self.application_content_type.as_str(),
            "application/json" | "application/anp-attachment-manifest+json"
        ) && self.payload.is_none()
        {
            return Err(GroupE2eeV2Error::invalid(
                "JSON group plaintext must use payload",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct V2E2eeNotice {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub notice_id: Option<String>,
    pub notice_type: String,
    pub group_did: String,
    pub group_state_ref: V2GroupStateRef,
    pub crypto_group_id_b64u: String,
    pub epoch: String,
    pub subject_did: String,
    pub subject_device_id: String,
    pub subject_status: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub commit_b64u: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub welcome_b64u: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub ratchet_tree_b64u: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub epoch_authenticator: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub group_receipt: Option<Value>,
}

impl V2E2eeNotice {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        for (field, value) in [
            ("group_did", self.group_did.as_str()),
            ("subject_did", self.subject_did.as_str()),
            ("subject_device_id", self.subject_device_id.as_str()),
        ] {
            require_non_empty(field, value)?;
        }
        validate_optional_non_empty("notice_id", self.notice_id.as_deref())?;
        self.group_state_ref.validate()?;
        if self.group_state_ref.group_did != self.group_did {
            return Err(GroupE2eeV2Error::invalid(
                "notice group_state_ref.group_did must equal group_did",
            ));
        }
        validate_non_empty_b64u("crypto_group_id_b64u", &self.crypto_group_id_b64u)?;
        validate_decimal("epoch", &self.epoch)?;
        if !matches!(self.subject_status.as_str(), "active" | "removed") {
            return Err(GroupE2eeV2Error::invalid(
                "subject_status must be active or removed",
            ));
        }
        match self.notice_type.as_str() {
            "commit-delivery" => {
                validate_required_b64u("commit_b64u", self.commit_b64u.as_deref())?;
                if self.welcome_b64u.is_some() || self.ratchet_tree_b64u.is_some() {
                    return Err(GroupE2eeV2Error::invalid(
                        "commit-delivery must omit welcome_b64u and ratchet_tree_b64u",
                    ));
                }
            }
            "welcome-delivery" => {
                validate_required_b64u("welcome_b64u", self.welcome_b64u.as_deref())?;
                validate_required_b64u("ratchet_tree_b64u", self.ratchet_tree_b64u.as_deref())?;
                if self.commit_b64u.is_some() {
                    return Err(GroupE2eeV2Error::invalid(
                        "welcome-delivery must omit commit_b64u",
                    ));
                }
            }
            _ => {
                return Err(GroupE2eeV2Error::invalid(
                    "notice_type must be commit-delivery or welcome-delivery",
                ))
            }
        }
        if let Some(value) = self.epoch_authenticator.as_deref() {
            validate_non_empty_b64u("epoch_authenticator", value)?;
        }
        if self
            .group_receipt
            .as_ref()
            .is_some_and(|value| !value.is_object())
        {
            return Err(GroupE2eeV2Error::invalid(
                "group_receipt must be a JSON object",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2PublishKeyPackageBody {
    pub group_key_package: V2GroupKeyPackage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2GetKeyPackageBody {
    pub target_did: String,
    pub target_device_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub preferred_suite: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub require_fresh: Option<bool>,
}

impl V2GetKeyPackageBody {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        require_non_empty("target_did", &self.target_did)?;
        require_non_empty("target_device_id", &self.target_device_id)?;
        if let Some(suite) = self.preferred_suite.as_deref() {
            require_eq("preferred_suite", suite, GROUP_E2EE_MTI_SUITE_V2)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2GroupCreateBody {
    pub group_did: String,
    pub group_state_ref: V2GroupStateRef,
    pub suite: String,
    pub creator_key_package: V2GroupKeyPackage,
    pub crypto_group_id_b64u: String,
    pub epoch: String,
}

impl V2GroupCreateBody {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        require_non_empty("group_did", &self.group_did)?;
        self.group_state_ref.validate()?;
        if self.group_state_ref.group_did != self.group_did {
            return Err(GroupE2eeV2Error::invalid(
                "group_state_ref.group_did must equal group_did",
            ));
        }
        require_eq("suite", &self.suite, GROUP_E2EE_MTI_SUITE_V2)?;
        self.creator_key_package.validate_structure()?;
        validate_non_empty_b64u("crypto_group_id_b64u", &self.crypto_group_id_b64u)?;
        validate_decimal("epoch", &self.epoch)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2GroupAddBody {
    pub member_did: String,
    pub member_device_id: String,
    pub group_state_ref: V2GroupStateRef,
    pub group_key_package: V2GroupKeyPackage,
    pub crypto_group_id_b64u: String,
    pub epoch: String,
    pub commit_b64u: String,
    pub welcome_b64u: String,
    pub ratchet_tree_b64u: String,
}

impl V2GroupAddBody {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        require_non_empty("member_did", &self.member_did)?;
        require_non_empty("member_device_id", &self.member_device_id)?;
        self.group_state_ref.validate()?;
        self.group_key_package.validate_structure()?;
        if self.group_key_package.owner_did != self.member_did
            || self.group_key_package.owner_device_id != self.member_device_id
        {
            return Err(GroupE2eeV2Error::invalid(
                "group_key_package owner must equal add member pair",
            ));
        }
        validate_non_empty_b64u("crypto_group_id_b64u", &self.crypto_group_id_b64u)?;
        validate_decimal("epoch", &self.epoch)?;
        validate_non_empty_b64u("commit_b64u", &self.commit_b64u)?;
        validate_non_empty_b64u("welcome_b64u", &self.welcome_b64u)?;
        validate_non_empty_b64u("ratchet_tree_b64u", &self.ratchet_tree_b64u).map(|_| ())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2GroupRemoveBody {
    pub member_did: String,
    pub member_device_id: String,
    pub group_state_ref: V2GroupStateRef,
    pub crypto_group_id_b64u: String,
    pub epoch: String,
    pub commit_b64u: String,
}

impl V2GroupRemoveBody {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        require_non_empty("member_did", &self.member_did)?;
        require_non_empty("member_device_id", &self.member_device_id)?;
        self.group_state_ref.validate()?;
        validate_non_empty_b64u("crypto_group_id_b64u", &self.crypto_group_id_b64u)?;
        validate_decimal("epoch", &self.epoch)?;
        validate_non_empty_b64u("commit_b64u", &self.commit_b64u).map(|_| ())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct V2GroupIncomingBody {
    pub group_did: String,
    pub group_state_version: String,
    pub group_event_seq: String,
    pub accepted_at: String,
    pub group_receipt: Value,
    pub group_cipher_object: V2GroupCipherObject,
}

impl V2GroupIncomingBody {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        require_non_empty("group_did", &self.group_did)?;
        require_non_empty("group_state_version", &self.group_state_version)?;
        validate_decimal("group_event_seq", &self.group_event_seq)?;
        validate_rfc3339("accepted_at", &self.accepted_at)?;
        if !self.group_receipt.is_object() {
            return Err(GroupE2eeV2Error::invalid(
                "group_receipt must be a JSON object",
            ));
        }
        self.group_cipher_object.validate()?;
        if self.group_cipher_object.group_state_ref.group_did != self.group_did
            || self.group_cipher_object.group_state_ref.group_state_version
                != self.group_state_version
        {
            return Err(GroupE2eeV2Error::invalid(
                "incoming ordering fields must equal group_cipher_object.group_state_ref",
            ));
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn validate_common_meta(
    anp_version: Option<&str>,
    profile: &str,
    actual_security: &str,
    expected_security: &str,
    sender_did: &str,
    sender_device_id: Option<&str>,
    target: &V2Target,
    target_kind: &str,
    operation_id: &str,
    created_at: Option<&str>,
) -> Result<(), GroupE2eeV2Error> {
    require_eq("meta.profile", profile, GROUP_E2EE_PROFILE_V2)?;
    require_eq("meta.security_profile", actual_security, expected_security)?;
    require_non_empty("meta.sender_did", sender_did)?;
    if let Some(device_id) = sender_device_id {
        require_non_empty("meta.sender_device_id", device_id)?;
    }
    target.validate(target_kind)?;
    require_non_empty("meta.operation_id", operation_id)?;
    validate_optional_non_empty("meta.anp_version", anp_version)?;
    if let Some(value) = created_at {
        validate_rfc3339("meta.created_at", value)?;
    }
    Ok(())
}

pub(crate) fn require_non_empty(field: &str, value: &str) -> Result<(), GroupE2eeV2Error> {
    if value.is_empty() {
        Err(GroupE2eeV2Error::invalid(format!(
            "{field} must be a non-empty string"
        )))
    } else {
        Ok(())
    }
}

pub(crate) fn require_eq(
    field: &str,
    actual: &str,
    expected: &str,
) -> Result<(), GroupE2eeV2Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(GroupE2eeV2Error::invalid(format!(
            "{field} must equal {expected}"
        )))
    }
}

pub(crate) fn validate_decimal(field: &str, value: &str) -> Result<(), GroupE2eeV2Error> {
    if !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
    {
        Ok(())
    } else {
        Err(GroupE2eeV2Error::invalid(format!(
            "{field} must be a canonical unsigned decimal string"
        )))
    }
}

pub(crate) fn validate_non_empty_b64u(
    field: &str,
    value: &str,
) -> Result<Vec<u8>, GroupE2eeV2Error> {
    require_non_empty(field, value)?;
    if value.contains('=') {
        return Err(GroupE2eeV2Error::invalid(format!(
            "{field} must be unpadded base64url"
        )));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| GroupE2eeV2Error::invalid(format!("{field} must be base64url")))?;
    if decoded.is_empty() || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(GroupE2eeV2Error::invalid(format!(
            "{field} must be canonical non-empty base64url"
        )));
    }
    Ok(decoded)
}

pub(crate) fn validate_ed25519_b64u(field: &str, value: &str) -> Result<(), GroupE2eeV2Error> {
    if validate_non_empty_b64u(field, value)?.len() == 32 {
        Ok(())
    } else {
        Err(GroupE2eeV2Error::invalid(format!(
            "{field} must encode a 32-byte Ed25519 public key"
        )))
    }
}

pub(crate) fn validate_rfc3339(field: &str, value: &str) -> Result<(), GroupE2eeV2Error> {
    DateTime::parse_from_rfc3339(value)
        .map(|_| ())
        .map_err(|_| GroupE2eeV2Error::invalid(format!("{field} must be RFC3339")))
}

fn validate_optional_non_empty(field: &str, value: Option<&str>) -> Result<(), GroupE2eeV2Error> {
    if let Some(value) = value {
        require_non_empty(field, value)?;
    }
    Ok(())
}

fn validate_required_b64u(field: &str, value: Option<&str>) -> Result<(), GroupE2eeV2Error> {
    let value = value.ok_or_else(|| GroupE2eeV2Error::invalid(format!("{field} is required")))?;
    validate_non_empty_b64u(field, value).map(|_| ())
}

pub(crate) fn deserialize_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}
