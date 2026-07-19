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

/// Stable runtime failure categories mapped to the frozen P5 v2 error table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectE2eeV2RuntimeErrorKind {
    BadInitMessage,
    ReplayDetected,
    DecryptFailed,
    MaxSkipExceeded,
    InvalidSecurityBinding,
}

impl DirectE2eeV2RuntimeErrorKind {
    pub const fn code(self) -> i32 {
        match self {
            Self::BadInitMessage => 4007,
            Self::ReplayDetected => 4008,
            Self::DecryptFailed => 4009,
            Self::MaxSkipExceeded => 4010,
            Self::InvalidSecurityBinding => 4012,
        }
    }

    pub const fn anp_code(self) -> &'static str {
        match self {
            Self::BadInitMessage => "anp.direct.e2ee.bad_init_message",
            Self::ReplayDetected => "anp.direct.e2ee.replay_detected",
            Self::DecryptFailed => "anp.direct.e2ee.decrypt_failed",
            Self::MaxSkipExceeded => "anp.direct.e2ee.max_skip_exceeded",
            Self::InvalidSecurityBinding => "anp.direct.e2ee.invalid_security_binding",
        }
    }

    pub const fn protocol_error(self) -> DirectE2eeV2ProtocolError {
        DirectE2eeV2ProtocolError {
            code: self.code(),
            anp_code: self.anp_code(),
        }
    }
}

impl std::fmt::Display for DirectE2eeV2RuntimeErrorKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.anp_code())
    }
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
    #[error("P5 v2 runtime error: {0}")]
    Runtime(DirectE2eeV2RuntimeErrorKind),
}

impl DirectE2eeV2Error {
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidField(message.into())
    }

    pub const fn runtime(kind: DirectE2eeV2RuntimeErrorKind) -> Self {
        Self::Runtime(kind)
    }

    pub const fn runtime_kind(&self) -> Option<DirectE2eeV2RuntimeErrorKind> {
        match self {
            Self::Runtime(kind) => Some(*kind),
            _ => None,
        }
    }

    /// Returns the frozen P5 wire allocation for a categorized runtime error.
    pub const fn protocol_error(&self) -> Option<DirectE2eeV2ProtocolError> {
        match self {
            Self::Runtime(kind) => Some(kind.protocol_error()),
            _ => None,
        }
    }
}
