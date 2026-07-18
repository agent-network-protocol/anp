use thiserror::Error;

/// One normative P5 v2 JSON-RPC error allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectE2eeV2ProtocolError {
    pub code: i32,
    pub anp_code: &'static str,
}

pub const DIRECT_E2EE_V2_ERRORS: [DirectE2eeV2ProtocolError; 13] = [
    DirectE2eeV2ProtocolError {
        code: 4000,
        anp_code: "anp.direct.e2ee.bundle_not_found",
    },
    DirectE2eeV2ProtocolError {
        code: 4001,
        anp_code: "anp.direct.e2ee.bundle_invalid",
    },
    DirectE2eeV2ProtocolError {
        code: 4002,
        anp_code: "anp.direct.e2ee.bundle_expired",
    },
    DirectE2eeV2ProtocolError {
        code: 4003,
        anp_code: "anp.direct.e2ee.opk_unavailable",
    },
    DirectE2eeV2ProtocolError {
        code: 4004,
        anp_code: "anp.direct.e2ee.missing_key_agreement",
    },
    DirectE2eeV2ProtocolError {
        code: 4005,
        anp_code: "anp.direct.e2ee.session_not_found",
    },
    DirectE2eeV2ProtocolError {
        code: 4006,
        anp_code: "anp.direct.e2ee.session_conflict",
    },
    DirectE2eeV2ProtocolError {
        code: 4007,
        anp_code: "anp.direct.e2ee.bad_init_message",
    },
    DirectE2eeV2ProtocolError {
        code: 4008,
        anp_code: "anp.direct.e2ee.replay_detected",
    },
    DirectE2eeV2ProtocolError {
        code: 4009,
        anp_code: "anp.direct.e2ee.decrypt_failed",
    },
    DirectE2eeV2ProtocolError {
        code: 4010,
        anp_code: "anp.direct.e2ee.max_skip_exceeded",
    },
    DirectE2eeV2ProtocolError {
        code: 4011,
        anp_code: "anp.direct.e2ee.reset_required",
    },
    DirectE2eeV2ProtocolError {
        code: 4012,
        anp_code: "anp.direct.e2ee.invalid_security_binding",
    },
];

pub fn direct_e2ee_v2_error(code: i32) -> Option<DirectE2eeV2ProtocolError> {
    DIRECT_E2EE_V2_ERRORS
        .iter()
        .copied()
        .find(|entry| entry.code == code)
}

#[derive(Debug, Error)]
pub enum DirectE2eeV2Error {
    #[error("invalid P5 v2 field: {0}")]
    InvalidField(String),
    #[error("invalid P5 v2 JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("invalid P5 v2 bundle proof: {0}")]
    Proof(#[from] crate::proof::ProofError),
    #[error("invalid P5 v2 canonical JSON: {0}")]
    CanonicalJson(#[from] crate::canonical_json::CanonicalJsonError),
}

impl DirectE2eeV2Error {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidField(message.into())
    }
}
