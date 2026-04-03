use crate::canonical_json::CanonicalJsonError;
use crate::proof::ProofError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DirectE2eeError {
    #[error("unsupported suite: {0}")]
    UnsupportedSuite(String),
    #[error("missing field: {0}")]
    MissingField(&'static str),
    #[error("invalid field: {0}")]
    InvalidField(String),
    #[error("proof error: {0}")]
    Proof(#[from] ProofError),
    #[error("canonical json error: {0}")]
    CanonicalJson(#[from] CanonicalJsonError),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("pending outbound not found: {0}")]
    PendingOutboundNotFound(String),
    #[error("replay detected: {0}")]
    ReplayDetected(String),
}

impl DirectE2eeError {
    pub fn invalid_field(field: impl Into<String>) -> Self {
        Self::InvalidField(field.into())
    }

    pub fn crypto(message: impl Into<String>) -> Self {
        Self::Crypto(message.into())
    }
}
