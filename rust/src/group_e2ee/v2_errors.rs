use thiserror::Error;

/// One normative P6 v2 JSON-RPC error allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupE2eeV2ProtocolError {
    pub code: i32,
    pub anp_code: &'static str,
}

pub const GROUP_E2EE_V2_ERRORS: [GroupE2eeV2ProtocolError; 13] = [
    GroupE2eeV2ProtocolError {
        code: 5000,
        anp_code: "group.e2ee.key_package_not_found",
    },
    GroupE2eeV2ProtocolError {
        code: 5001,
        anp_code: "group.e2ee.invalid_key_package",
    },
    GroupE2eeV2ProtocolError {
        code: 5002,
        anp_code: "group.e2ee.did_binding_invalid",
    },
    GroupE2eeV2ProtocolError {
        code: 5003,
        anp_code: "group.e2ee.controller_required",
    },
    GroupE2eeV2ProtocolError {
        code: 5004,
        anp_code: "group.e2ee.state_not_ready",
    },
    GroupE2eeV2ProtocolError {
        code: 5005,
        anp_code: "group.e2ee.epoch_conflict",
    },
    GroupE2eeV2ProtocolError {
        code: 5006,
        anp_code: "group.e2ee.crypto_group_mismatch",
    },
    GroupE2eeV2ProtocolError {
        code: 5007,
        anp_code: "group.e2ee.private_message_invalid",
    },
    GroupE2eeV2ProtocolError {
        code: 5008,
        anp_code: "group.e2ee.commit_invalid",
    },
    GroupE2eeV2ProtocolError {
        code: 5009,
        anp_code: "group.e2ee.welcome_invalid",
    },
    GroupE2eeV2ProtocolError {
        code: 5010,
        anp_code: "group.e2ee.fork_suspected",
    },
    GroupE2eeV2ProtocolError {
        code: 5011,
        anp_code: "group.e2ee.notice_type_unsupported",
    },
    GroupE2eeV2ProtocolError {
        code: 5012,
        anp_code: "group.e2ee.key_package_consumed",
    },
];

pub fn group_e2ee_v2_error(code: i32) -> Option<GroupE2eeV2ProtocolError> {
    GROUP_E2EE_V2_ERRORS
        .iter()
        .copied()
        .find(|entry| entry.code == code)
}

#[derive(Debug, Error)]
pub enum GroupE2eeV2Error {
    #[error("invalid P6 v2 field: {0}")]
    InvalidField(String),
    #[error("invalid P6 v2 JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("invalid P6 v2 binding proof: {0}")]
    Proof(#[from] crate::proof::ProofError),
    #[error("invalid P6 v2 Device Manifest: {0}")]
    Manifest(#[from] crate::authentication::DeviceManifestError),
    #[error("invalid P6 v2 canonical JSON: {0}")]
    CanonicalJson(#[from] crate::canonical_json::CanonicalJsonError),
    #[error("P6 v2 public release is blocked until the draft MLS extension has a stable registered codepoint")]
    PublicReleaseBlocked,
}

impl GroupE2eeV2Error {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidField(message.into())
    }
}
