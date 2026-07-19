use std::collections::HashSet;
use std::fmt;

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

use super::ratchet::{
    decrypt_with_step, derive_chain_step, derive_root_step, encrypt_with_step, ChainStep, MAX_SKIP,
};
use super::v2_aad::{build_init_aad_v2, build_message_aad_v2, canonical_application_plaintext_v2};
use super::v2_errors::{DirectE2eeV2Error, DirectE2eeV2RuntimeErrorKind};
use super::v2_models::{
    V2ApplicationPlaintext, V2DirectCipherBody, V2DirectInitBody, V2DirectMetadata,
    V2OneTimePrekey, V2PrekeyBundle, V2RatchetHeader, CONTENT_TYPE_DIRECT_CIPHER_V2,
    CONTENT_TYPE_DIRECT_INIT_V2, MTI_DIRECT_E2EE_SUITE_V2,
};
use super::x3dh::{
    derive_initial_material_for_initiator_with_opk, derive_initial_material_for_responder_with_opk,
};

pub const DIRECT_E2EE_V2_SESSION_STATE_FORMAT: &str = "anp.direct.e2ee.v2.session-state.v1";
pub const DIRECT_E2EE_V2_PENDING_STATE_FORMAT: &str = "anp.direct.e2ee.v2.pending-state.v1";
pub const V2_SESSION_STATUS_PENDING_CONFIRMATION: &str = "pending-confirmation";
pub const V2_SESSION_STATUS_ESTABLISHED: &str = "established";

const SECRET_JSON_APPLICATION_PREFIX: &[u8] =
    br#"{"application_content_type":"application/json","payload":"#;
const SECRET_JSON_APPLICATION_SUFFIX: &[u8] = b"}";

/// Canonical JSON object bytes whose allocation is wiped on drop.
///
/// This is the application-plaintext boundary for unusually sensitive JSON
/// controls such as an encrypted root-key transfer. It does not change P5 v2
/// wire or AAD. `from_canonical_json_object` is a trusted-constructor boundary:
/// the caller must produce canonical JSON object bytes. The constructor checks
/// object syntax without materializing a `serde_json::Value`, because doing so
/// would create ordinary heap copies of every secret string; it deliberately
/// does not re-canonicalize or prove member order. This controls SDK-owned
/// plaintext allocations; the cryptographic backend may still use its own
/// temporary buffers.
pub struct V2SecretJsonPayload {
    bytes: Zeroizing<Vec<u8>>,
}

impl V2SecretJsonPayload {
    pub fn from_canonical_json_object(bytes: Vec<u8>) -> Result<Self, DirectE2eeV2Error> {
        let bytes = Zeroizing::new(bytes);
        validate_secret_json_object(&bytes)?;
        Ok(Self { bytes })
    }

    pub fn expose_secret(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    fn canonical_application_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            SECRET_JSON_APPLICATION_PREFIX.len()
                + self.bytes.len()
                + SECRET_JSON_APPLICATION_SUFFIX.len(),
        ));
        bytes.extend_from_slice(SECRET_JSON_APPLICATION_PREFIX);
        bytes.extend_from_slice(&self.bytes);
        bytes.extend_from_slice(SECRET_JSON_APPLICATION_SUFFIX);
        bytes
    }

    fn from_canonical_application_bytes(
        application: Zeroizing<Vec<u8>>,
    ) -> Result<Self, DirectE2eeV2Error> {
        if !application.starts_with(SECRET_JSON_APPLICATION_PREFIX)
            || !application.ends_with(SECRET_JSON_APPLICATION_SUFFIX)
            || application.len()
                <= SECRET_JSON_APPLICATION_PREFIX.len() + SECRET_JSON_APPLICATION_SUFFIX.len()
        {
            return Err(runtime_error(DirectE2eeV2RuntimeErrorKind::DecryptFailed));
        }
        let payload_end = application.len() - SECRET_JSON_APPLICATION_SUFFIX.len();
        let payload =
            Zeroizing::new(application[SECRET_JSON_APPLICATION_PREFIX.len()..payload_end].to_vec());
        validate_secret_json_object(&payload)
            .map_err(|_| runtime_error(DirectE2eeV2RuntimeErrorKind::DecryptFailed))?;
        Ok(Self { bytes: payload })
    }
}

impl fmt::Debug for V2SecretJsonPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V2SecretJsonPayload")
            .field("bytes", &"<redacted-zeroizing-json>")
            .finish()
    }
}

/// The exact local/peer device and key binding for one P5 v2 session.
///
/// The orientation is always local: the same wire session is represented by a
/// reversed binding on the peer device. Same-DID sessions are valid only when
/// their device IDs differ.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2SessionBinding {
    pub local_did: String,
    pub local_device_id: String,
    pub peer_did: String,
    pub peer_device_id: String,
    pub suite: String,
    pub local_e2ee_key_id: String,
    pub peer_e2ee_key_id: String,
}

impl V2SessionBinding {
    pub fn validate(&self) -> Result<(), DirectE2eeV2Error> {
        for value in [
            self.local_did.as_str(),
            self.local_device_id.as_str(),
            self.peer_did.as_str(),
            self.peer_device_id.as_str(),
            self.local_e2ee_key_id.as_str(),
            self.peer_e2ee_key_id.as_str(),
        ] {
            if value.is_empty() {
                return Err(runtime_error(
                    DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding,
                ));
            }
        }
        if self.suite != MTI_DIRECT_E2EE_SUITE_V2 {
            return Err(runtime_error(
                DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding,
            ));
        }
        if self.local_did == self.peer_did && self.local_device_id == self.peer_device_id {
            return Err(runtime_error(
                DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding,
            ));
        }
        validate_key_id_for_did(
            "binding.local_e2ee_key_id",
            &self.local_e2ee_key_id,
            &self.local_did,
        )
        .map_err(|_| runtime_error(DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding))?;
        validate_key_id_for_did(
            "binding.peer_e2ee_key_id",
            &self.peer_e2ee_key_id,
            &self.peer_did,
        )
        .map_err(|_| runtime_error(DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding))?;
        if self.local_e2ee_key_id == self.peer_e2ee_key_id {
            return Err(runtime_error(
                DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding,
            ));
        }
        Ok(())
    }

    fn validate_outbound_metadata(
        &self,
        metadata: &V2DirectMetadata,
        expected_content_type: &str,
    ) -> Result<(), DirectE2eeV2Error> {
        self.validate()?;
        metadata.validate()?;
        if metadata.sender_did != self.local_did
            || metadata.sender_device_id != self.local_device_id
            || metadata.target.did != self.peer_did
            || metadata.recipient_device_id != self.peer_device_id
            || metadata.content_type != expected_content_type
        {
            return Err(runtime_error(
                DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding,
            ));
        }
        Ok(())
    }

    fn validate_inbound_metadata(
        &self,
        metadata: &V2DirectMetadata,
        expected_content_type: &str,
    ) -> Result<(), DirectE2eeV2Error> {
        self.validate()?;
        metadata.validate()?;
        if metadata.sender_did != self.peer_did
            || metadata.sender_device_id != self.peer_device_id
            || metadata.target.did != self.local_did
            || metadata.recipient_device_id != self.local_device_id
            || metadata.content_type != expected_content_type
        {
            return Err(runtime_error(
                DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2SkippedMessageKey {
    pub dh_pub_b64u: String,
    pub n: u32,
    pub message_key_b64u: String,
    pub nonce_b64u: String,
}

impl fmt::Debug for V2SkippedMessageKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V2SkippedMessageKey")
            .field("dh_pub_b64u", &self.dh_pub_b64u)
            .field("n", &self.n)
            .field("message_key_b64u", &"<redacted>")
            .field("nonce_b64u", &"<redacted>")
            .finish()
    }
}

/// Persistable P5 v2 ratchet state for exactly one local/peer device pair.
///
/// Secret fields are serializable for an encrypted product-owned store, but
/// intentionally omitted from `Debug` output. This format is not compatible
/// with the legacy P5 v1 `DirectSessionState` JSON shape.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2DirectSessionState {
    pub state_format: String,
    pub binding: V2SessionBinding,
    pub session_id: String,
    pub root_key_b64u: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub send_chain_key_b64u: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recv_chain_key_b64u: Option<String>,
    pub ratchet_private_key_b64u: String,
    pub ratchet_public_key_b64u: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_ratchet_public_key_b64u: Option<String>,
    pub send_n: u32,
    pub recv_n: u32,
    pub previous_send_chain_length: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped_message_keys: Vec<V2SkippedMessageKey>,
    pub is_initiator: bool,
    pub status: String,
    #[serde(default)]
    pub disabled: bool,
}

impl fmt::Debug for V2DirectSessionState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("V2DirectSessionState")
            .field("state_format", &self.state_format)
            .field("binding", &self.binding)
            .field("session_id", &self.session_id)
            .field("root_key_b64u", &"<redacted>")
            .field("send_chain_key_b64u", &"<redacted>")
            .field("recv_chain_key_b64u", &"<redacted>")
            .field("ratchet_private_key_b64u", &"<redacted>")
            .field("ratchet_public_key_b64u", &self.ratchet_public_key_b64u)
            .field(
                "peer_ratchet_public_key_b64u",
                &self.peer_ratchet_public_key_b64u,
            )
            .field("send_n", &self.send_n)
            .field("recv_n", &self.recv_n)
            .field(
                "previous_send_chain_length",
                &self.previous_send_chain_length,
            )
            .field(
                "skipped_message_key_count",
                &self.skipped_message_keys.len(),
            )
            .field("is_initiator", &self.is_initiator)
            .field("status", &self.status)
            .field("disabled", &self.disabled)
            .finish()
    }
}

impl V2DirectSessionState {
    pub fn validate(&self) -> Result<(), DirectE2eeV2Error> {
        if self.state_format != DIRECT_E2EE_V2_SESSION_STATE_FORMAT {
            return Err(DirectE2eeV2Error::invalid(
                "state_format is not the P5 v2 session-state format",
            ));
        }
        self.binding.validate()?;
        decode_fixed::<16>("state.session_id", &self.session_id)?;
        decode_fixed::<32>("state.root_key_b64u", &self.root_key_b64u)?;
        let ratchet_private = decode_fixed::<32>(
            "state.ratchet_private_key_b64u",
            &self.ratchet_private_key_b64u,
        )?;
        let ratchet_public = decode_fixed::<32>(
            "state.ratchet_public_key_b64u",
            &self.ratchet_public_key_b64u,
        )?;
        if X25519PublicKey::from(&X25519StaticSecret::from(ratchet_private)).to_bytes()
            != ratchet_public
        {
            return Err(DirectE2eeV2Error::invalid(
                "state ratchet public key does not match its private key",
            ));
        }
        if let Some(value) = self.send_chain_key_b64u.as_deref() {
            decode_fixed::<32>("state.send_chain_key_b64u", value)?;
        }
        if let Some(value) = self.recv_chain_key_b64u.as_deref() {
            decode_fixed::<32>("state.recv_chain_key_b64u", value)?;
        }
        if let Some(value) = self.peer_ratchet_public_key_b64u.as_deref() {
            decode_fixed::<32>("state.peer_ratchet_public_key_b64u", value)?;
        }
        match self.status.as_str() {
            V2_SESSION_STATUS_PENDING_CONFIRMATION => {
                if !self.is_initiator
                    || self.send_chain_key_b64u.is_none()
                    || self.recv_chain_key_b64u.is_some()
                    || self.peer_ratchet_public_key_b64u.is_some()
                    || self.send_n != 1
                    || self.recv_n != 0
                    || self.previous_send_chain_length != 0
                {
                    return Err(DirectE2eeV2Error::invalid(
                        "pending-confirmation session has inconsistent bootstrap state",
                    ));
                }
            }
            V2_SESSION_STATUS_ESTABLISHED => {
                if self.send_chain_key_b64u.is_none()
                    || self.recv_chain_key_b64u.is_none()
                    || self.peer_ratchet_public_key_b64u.is_none()
                {
                    return Err(DirectE2eeV2Error::invalid(
                        "established session must contain both chains and a peer ratchet key",
                    ));
                }
            }
            _ => {
                return Err(DirectE2eeV2Error::invalid(
                    "state.status is not a P5 v2 session status",
                ));
            }
        }
        if self.skipped_message_keys.len() > MAX_SKIP as usize {
            return Err(DirectE2eeV2Error::invalid(
                "state contains more skipped message keys than MAX_SKIP",
            ));
        }
        let mut skipped_coordinates = HashSet::with_capacity(self.skipped_message_keys.len());
        for skipped in &self.skipped_message_keys {
            decode_fixed::<32>("state.skipped.dh_pub_b64u", &skipped.dh_pub_b64u)?;
            decode_fixed::<32>("state.skipped.message_key_b64u", &skipped.message_key_b64u)?;
            decode_fixed::<12>("state.skipped.nonce_b64u", &skipped.nonce_b64u)?;
            if !skipped_coordinates.insert((skipped.dh_pub_b64u.as_str(), skipped.n)) {
                return Err(DirectE2eeV2Error::invalid(
                    "state contains duplicate skipped message coordinates",
                ));
            }
        }
        Ok(())
    }

    fn validate_for(&self, expected_binding: &V2SessionBinding) -> Result<(), DirectE2eeV2Error> {
        self.validate()
            .map_err(|_| runtime_error(DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding))?;
        expected_binding.validate()?;
        if &self.binding != expected_binding {
            return Err(runtime_error(
                DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding,
            ));
        }
        if self.disabled {
            return Err(runtime_error(
                DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding,
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct V2PendingOutboundRecord {
    pub state_format: String,
    pub binding: V2SessionBinding,
    pub session_id: String,
    pub operation_id: String,
    pub message_id: String,
    pub wire_content_type: String,
    pub body: Value,
}

impl V2PendingOutboundRecord {
    pub fn validate(&self) -> Result<(), DirectE2eeV2Error> {
        if self.state_format != DIRECT_E2EE_V2_PENDING_STATE_FORMAT {
            return Err(DirectE2eeV2Error::invalid(
                "state_format is not the P5 v2 pending-state format",
            ));
        }
        self.binding.validate()?;
        decode_fixed::<16>("pending.session_id", &self.session_id)?;
        if self.operation_id.is_empty()
            || self.message_id.is_empty()
            || self.operation_id != self.message_id
        {
            return Err(DirectE2eeV2Error::invalid(
                "pending operation_id and message_id must be equal non-empty strings",
            ));
        }
        match self.wire_content_type.as_str() {
            CONTENT_TYPE_DIRECT_INIT_V2 => {
                let body: V2DirectInitBody = serde_json::from_value(self.body.clone())?;
                body.validate()?;
                if body.session_id != self.session_id {
                    return Err(DirectE2eeV2Error::invalid(
                        "pending init body uses a different session_id",
                    ));
                }
            }
            CONTENT_TYPE_DIRECT_CIPHER_V2 => {
                let body: V2DirectCipherBody = serde_json::from_value(self.body.clone())?;
                body.validate()?;
                if body.session_id != self.session_id {
                    return Err(DirectE2eeV2Error::invalid(
                        "pending cipher body uses a different session_id",
                    ));
                }
            }
            _ => {
                return Err(DirectE2eeV2Error::invalid(
                    "pending wire_content_type is not a P5 v2 MTI object",
                ));
            }
        }
        Ok(())
    }
}

pub fn serialize_session_state_v2(
    state: &V2DirectSessionState,
) -> Result<Vec<u8>, DirectE2eeV2Error> {
    state.validate()?;
    Ok(serde_json::to_vec(state)?)
}

pub fn deserialize_session_state_v2(
    bytes: &[u8],
) -> Result<V2DirectSessionState, DirectE2eeV2Error> {
    let state: V2DirectSessionState = serde_json::from_slice(bytes)?;
    state.validate()?;
    Ok(state)
}

pub fn serialize_pending_outbound_v2(
    pending: &V2PendingOutboundRecord,
) -> Result<Vec<u8>, DirectE2eeV2Error> {
    pending.validate()?;
    Ok(serde_json::to_vec(pending)?)
}

pub fn deserialize_pending_outbound_v2(
    bytes: &[u8],
) -> Result<V2PendingOutboundRecord, DirectE2eeV2Error> {
    let pending: V2PendingOutboundRecord = serde_json::from_slice(bytes)?;
    pending.validate()?;
    Ok(pending)
}

/// Select the first usable established session from a newest-first slice.
///
/// Selection never crosses an exact device or key binding. A caller that has
/// not yet established a matching session receives `None` and must initiate a
/// new v2 session rather than reuse v1 or sibling-device state.
pub fn select_default_outbound_session_v2<'a>(
    expected_binding: &V2SessionBinding,
    sessions_newest_first: &'a [V2DirectSessionState],
) -> Result<Option<&'a V2DirectSessionState>, DirectE2eeV2Error> {
    expected_binding.validate()?;
    for session in sessions_newest_first {
        if session.binding == *expected_binding {
            session.validate()?;
            if !session.disabled && session.status == V2_SESSION_STATUS_ESTABLISHED {
                return Ok(Some(session));
            }
        }
    }
    Ok(None)
}

/// Permanently disable local sessions for one exact peer device.
///
/// This is a local selection primitive, not a registry or revocation API. It
/// intentionally leaves sibling-device sessions untouched.
pub fn disable_peer_device_sessions_v2(
    sessions: &mut [V2DirectSessionState],
    local_did: &str,
    local_device_id: &str,
    peer_did: &str,
    peer_device_id: &str,
) -> Result<usize, DirectE2eeV2Error> {
    if [local_did, local_device_id, peer_did, peer_device_id]
        .iter()
        .any(|value| value.is_empty())
    {
        return Err(DirectE2eeV2Error::invalid(
            "peer-device disable selector fields must be non-empty",
        ));
    }
    let matching = sessions
        .iter()
        .enumerate()
        .filter(|(_, session)| {
            session.binding.local_did == local_did
                && session.binding.local_device_id == local_device_id
                && session.binding.peer_did == peer_did
                && session.binding.peer_device_id == peer_device_id
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    for index in &matching {
        sessions[*index].validate()?;
    }
    let mut disabled = 0;
    for index in matching {
        if !sessions[index].disabled {
            sessions[index].disabled = true;
            disabled += 1;
        }
    }
    Ok(disabled)
}

pub struct V2DirectE2eeSession;

impl V2DirectE2eeSession {
    /// Creates a v2 init and the exact pending record that must be retried.
    ///
    /// Before calling this method, the product must validate one complete
    /// `direct.e2ee.get_prekey_bundle` response with both
    /// `V2GetPrekeyBundleResult::validate` and `verify_prekey_bundle_v2`, after
    /// resolving and authenticity-validating the current DID document and
    /// confirming that the selected Manifest device is eligible for Direct
    /// E2EE. `recipient_static_public` must be extracted from that same verified
    /// document, and an optional OPK must be the sidecar returned for the same
    /// target device in that same response. The caller must also prove locally that
    /// `local_static_private` matches its current Manifest E2EE public key.
    ///
    /// Persist both returned state records before sending. An idempotent retry
    /// must resend the exact serialized pending body and outer identifiers; it
    /// must not generate a fresh ephemeral key or init.
    pub fn initiate_session(
        binding: &V2SessionBinding,
        metadata: &V2DirectMetadata,
        local_static_private: &X25519StaticSecret,
        recipient_bundle: &V2PrekeyBundle,
        recipient_static_public: &[u8; 32],
        recipient_one_time_prekey: Option<&V2OneTimePrekey>,
        plaintext: &V2ApplicationPlaintext,
    ) -> Result<
        (
            V2DirectSessionState,
            V2PendingOutboundRecord,
            V2DirectInitBody,
        ),
        DirectE2eeV2Error,
    > {
        let ephemeral = X25519StaticSecret::random_from_rng(OsRng);
        plaintext.validate()?;
        let plaintext_bytes = Zeroizing::new(canonical_application_plaintext_v2(plaintext)?);
        Self::initiate_session_with_ephemeral_bytes(
            binding,
            metadata,
            local_static_private,
            recipient_bundle,
            recipient_static_public,
            recipient_one_time_prekey,
            &plaintext_bytes,
            &ephemeral,
        )
    }

    /// Secret-payload equivalent of [`Self::initiate_session`]. All
    /// product-controlled plaintext buffers are zeroized after encryption.
    #[allow(clippy::too_many_arguments)]
    pub fn initiate_session_secret_json(
        binding: &V2SessionBinding,
        metadata: &V2DirectMetadata,
        local_static_private: &X25519StaticSecret,
        recipient_bundle: &V2PrekeyBundle,
        recipient_static_public: &[u8; 32],
        recipient_one_time_prekey: Option<&V2OneTimePrekey>,
        plaintext: &V2SecretJsonPayload,
    ) -> Result<
        (
            V2DirectSessionState,
            V2PendingOutboundRecord,
            V2DirectInitBody,
        ),
        DirectE2eeV2Error,
    > {
        let ephemeral = X25519StaticSecret::random_from_rng(OsRng);
        let plaintext_bytes = plaintext.canonical_application_bytes();
        Self::initiate_session_with_ephemeral_bytes(
            binding,
            metadata,
            local_static_private,
            recipient_bundle,
            recipient_static_public,
            recipient_one_time_prekey,
            &plaintext_bytes,
            &ephemeral,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn initiate_session_with_ephemeral_bytes(
        binding: &V2SessionBinding,
        metadata: &V2DirectMetadata,
        local_static_private: &X25519StaticSecret,
        recipient_bundle: &V2PrekeyBundle,
        recipient_static_public: &[u8; 32],
        recipient_one_time_prekey: Option<&V2OneTimePrekey>,
        plaintext_bytes: &[u8],
        ephemeral: &X25519StaticSecret,
    ) -> Result<
        (
            V2DirectSessionState,
            V2PendingOutboundRecord,
            V2DirectInitBody,
        ),
        DirectE2eeV2Error,
    > {
        Self::initiate_session_with_ephemeral_bytes_impl(
            binding,
            metadata,
            local_static_private,
            recipient_bundle,
            recipient_static_public,
            recipient_one_time_prekey,
            plaintext_bytes,
            ephemeral,
        )
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn initiate_session_with_ephemeral(
        binding: &V2SessionBinding,
        metadata: &V2DirectMetadata,
        local_static_private: &X25519StaticSecret,
        recipient_bundle: &V2PrekeyBundle,
        recipient_static_public: &[u8; 32],
        recipient_one_time_prekey: Option<&V2OneTimePrekey>,
        plaintext: &V2ApplicationPlaintext,
        sender_ephemeral_private: &X25519StaticSecret,
    ) -> Result<
        (
            V2DirectSessionState,
            V2PendingOutboundRecord,
            V2DirectInitBody,
        ),
        DirectE2eeV2Error,
    > {
        plaintext.validate()?;
        let plaintext_bytes = Zeroizing::new(canonical_application_plaintext_v2(plaintext)?);
        Self::initiate_session_with_ephemeral_bytes_impl(
            binding,
            metadata,
            local_static_private,
            recipient_bundle,
            recipient_static_public,
            recipient_one_time_prekey,
            &plaintext_bytes,
            sender_ephemeral_private,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn initiate_session_with_ephemeral_bytes_impl(
        binding: &V2SessionBinding,
        metadata: &V2DirectMetadata,
        local_static_private: &X25519StaticSecret,
        recipient_bundle: &V2PrekeyBundle,
        recipient_static_public: &[u8; 32],
        recipient_one_time_prekey: Option<&V2OneTimePrekey>,
        plaintext_bytes: &[u8],
        sender_ephemeral_private: &X25519StaticSecret,
    ) -> Result<
        (
            V2DirectSessionState,
            V2PendingOutboundRecord,
            V2DirectInitBody,
        ),
        DirectE2eeV2Error,
    > {
        binding.validate_outbound_metadata(metadata, CONTENT_TYPE_DIRECT_INIT_V2)?;
        validate_recipient_bundle(binding, recipient_bundle)?;

        let recipient_signed_prekey_public = decode_fixed::<32>(
            "prekey_bundle.signed_prekey.public_key_b64u",
            &recipient_bundle.signed_prekey.public_key_b64u,
        )?;
        let recipient_opk_public = recipient_one_time_prekey
            .map(|opk| {
                opk.validate()?;
                decode_fixed::<32>("one_time_prekey.public_key_b64u", &opk.public_key_b64u)
            })
            .transpose()?;
        let initial = derive_initial_material_for_initiator_with_opk(
            local_static_private,
            sender_ephemeral_private,
            recipient_static_public,
            &recipient_signed_prekey_public,
            recipient_opk_public.as_ref(),
        )
        .map_err(security_crypto_error)?;
        let sender_ephemeral_public = X25519PublicKey::from(sender_ephemeral_private).to_bytes();
        let mut body = V2DirectInitBody {
            session_id: initial.session_id.clone(),
            suite: MTI_DIRECT_E2EE_SUITE_V2.to_owned(),
            sender_static_key_agreement_id: binding.local_e2ee_key_id.clone(),
            recipient_bundle_id: recipient_bundle.bundle_id.clone(),
            recipient_signed_prekey_id: recipient_bundle.signed_prekey.key_id.clone(),
            recipient_one_time_prekey_id: recipient_one_time_prekey.map(|opk| opk.key_id.clone()),
            sender_ephemeral_pub_b64u: crate::keys::base64url_encode(&sender_ephemeral_public),
            ciphertext_b64u: String::new(),
        };
        let aad = build_init_aad_for_encryption(metadata, &body)?;
        let init_step = derive_chain_step(&initial.chain_key);
        body.ciphertext_b64u = crate::keys::base64url_encode(
            &encrypt_with_step(&init_step, plaintext_bytes, &aad).map_err(security_crypto_error)?,
        );
        body.validate()?;

        let state = V2DirectSessionState {
            state_format: DIRECT_E2EE_V2_SESSION_STATE_FORMAT.to_owned(),
            binding: binding.clone(),
            session_id: initial.session_id.clone(),
            root_key_b64u: crate::keys::base64url_encode(&initial.root_key),
            send_chain_key_b64u: Some(crate::keys::base64url_encode(&init_step.next_chain_key)),
            recv_chain_key_b64u: None,
            ratchet_private_key_b64u: crate::keys::base64url_encode(
                &sender_ephemeral_private.to_bytes(),
            ),
            ratchet_public_key_b64u: crate::keys::base64url_encode(&sender_ephemeral_public),
            peer_ratchet_public_key_b64u: None,
            send_n: 1,
            recv_n: 0,
            previous_send_chain_length: 0,
            skipped_message_keys: vec![],
            is_initiator: true,
            status: V2_SESSION_STATUS_PENDING_CONFIRMATION.to_owned(),
            disabled: false,
        };
        state.validate()?;
        let pending = pending_record(binding, metadata, &body)?;
        Ok((state, pending, body))
    }

    #[allow(clippy::too_many_arguments)]
    /// Accepts an init after product-level binding and replay checks.
    ///
    /// `local_bundle`, the optional OPK record/private key, and the local
    /// static private key must belong to the current local Manifest device.
    /// `sender_static_public` must be extracted from the current sender DID
    /// document for the exact peer binding used to route the init. The product
    /// storage transaction must atomically record init replay/idempotency
    /// state, persist the returned session, and consume/delete the returned
    /// OPK ID. This SDK method only returns the OPK ID to consume; it cannot
    /// make those product-owned stores atomic.
    pub fn accept_incoming_init(
        binding: &V2SessionBinding,
        metadata: &V2DirectMetadata,
        local_static_private: &X25519StaticSecret,
        local_bundle: &V2PrekeyBundle,
        local_signed_prekey_private: &X25519StaticSecret,
        local_one_time_prekey: Option<(&V2OneTimePrekey, &X25519StaticSecret)>,
        sender_static_public: &[u8; 32],
        body: &V2DirectInitBody,
    ) -> Result<(V2DirectSessionState, V2ApplicationPlaintext, Option<String>), DirectE2eeV2Error>
    {
        let (state, plaintext, consumed_opk_id) = Self::accept_incoming_init_bytes(
            binding,
            metadata,
            local_static_private,
            local_bundle,
            local_signed_prekey_private,
            local_one_time_prekey,
            sender_static_public,
            body,
        )?;
        Ok((
            state,
            parse_application_plaintext(&plaintext)?,
            consumed_opk_id,
        ))
    }

    /// Secret-payload equivalent of [`Self::accept_incoming_init`]. The full
    /// decrypted application object and returned JSON payload are both held in
    /// zeroizing allocations.
    #[allow(clippy::too_many_arguments)]
    pub fn accept_incoming_init_secret_json(
        binding: &V2SessionBinding,
        metadata: &V2DirectMetadata,
        local_static_private: &X25519StaticSecret,
        local_bundle: &V2PrekeyBundle,
        local_signed_prekey_private: &X25519StaticSecret,
        local_one_time_prekey: Option<(&V2OneTimePrekey, &X25519StaticSecret)>,
        sender_static_public: &[u8; 32],
        body: &V2DirectInitBody,
    ) -> Result<(V2DirectSessionState, V2SecretJsonPayload, Option<String>), DirectE2eeV2Error>
    {
        let (state, plaintext, consumed_opk_id) = Self::accept_incoming_init_bytes(
            binding,
            metadata,
            local_static_private,
            local_bundle,
            local_signed_prekey_private,
            local_one_time_prekey,
            sender_static_public,
            body,
        )?;
        Ok((
            state,
            V2SecretJsonPayload::from_canonical_application_bytes(plaintext)?,
            consumed_opk_id,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn accept_incoming_init_bytes(
        binding: &V2SessionBinding,
        metadata: &V2DirectMetadata,
        local_static_private: &X25519StaticSecret,
        local_bundle: &V2PrekeyBundle,
        local_signed_prekey_private: &X25519StaticSecret,
        local_one_time_prekey: Option<(&V2OneTimePrekey, &X25519StaticSecret)>,
        sender_static_public: &[u8; 32],
        body: &V2DirectInitBody,
    ) -> Result<(V2DirectSessionState, Zeroizing<Vec<u8>>, Option<String>), DirectE2eeV2Error> {
        binding.validate_inbound_metadata(metadata, CONTENT_TYPE_DIRECT_INIT_V2)?;
        validate_local_bundle(binding, local_bundle, local_signed_prekey_private)?;
        body.validate()
            .map_err(|_| runtime_error(DirectE2eeV2RuntimeErrorKind::BadInitMessage))?;
        if body.sender_static_key_agreement_id != binding.peer_e2ee_key_id
            || body.recipient_bundle_id != local_bundle.bundle_id
            || body.recipient_signed_prekey_id != local_bundle.signed_prekey.key_id
        {
            return Err(runtime_error(
                DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding,
            ));
        }

        let (local_opk_private, consumed_opk_id) = match (
            body.recipient_one_time_prekey_id.as_deref(),
            local_one_time_prekey,
        ) {
            (None, None) => (None, None),
            (Some(expected_id), Some((opk, private))) if expected_id == opk.key_id => {
                opk.validate().map_err(|_| {
                    runtime_error(DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding)
                })?;
                let expected_public =
                    decode_fixed::<32>("one_time_prekey.public_key_b64u", &opk.public_key_b64u)
                        .map_err(|_| {
                            runtime_error(DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding)
                        })?;
                if X25519PublicKey::from(private).to_bytes() != expected_public {
                    return Err(runtime_error(
                        DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding,
                    ));
                }
                (Some(private), Some(opk.key_id.clone()))
            }
            _ => {
                return Err(runtime_error(
                    DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding,
                ));
            }
        };

        let sender_ephemeral_public = decode_fixed::<32>(
            "body.sender_ephemeral_pub_b64u",
            &body.sender_ephemeral_pub_b64u,
        )?;
        let initial = derive_initial_material_for_responder_with_opk(
            local_static_private,
            local_signed_prekey_private,
            local_opk_private,
            sender_static_public,
            &sender_ephemeral_public,
        )
        .map_err(bad_init_crypto_error)?;
        if body.session_id != initial.session_id {
            return Err(runtime_error(DirectE2eeV2RuntimeErrorKind::BadInitMessage));
        }
        let aad = build_init_aad_v2(metadata, body)?;
        let init_step = derive_chain_step(&initial.chain_key);
        let plaintext = decrypt_plaintext_bytes(&init_step, &body.ciphertext_b64u, &aad)?;

        let ratchet_private = X25519StaticSecret::random_from_rng(OsRng);
        let ratchet_public = X25519PublicKey::from(&ratchet_private).to_bytes();
        let dh = ratchet_private.diffie_hellman(&X25519PublicKey::from(sender_ephemeral_public));
        let root_step =
            derive_root_step(&initial.root_key, &dh.to_bytes()).map_err(bad_init_crypto_error)?;
        let state = V2DirectSessionState {
            state_format: DIRECT_E2EE_V2_SESSION_STATE_FORMAT.to_owned(),
            binding: binding.clone(),
            session_id: body.session_id.clone(),
            root_key_b64u: crate::keys::base64url_encode(&root_step.root_key),
            send_chain_key_b64u: Some(crate::keys::base64url_encode(&root_step.chain_key)),
            recv_chain_key_b64u: Some(crate::keys::base64url_encode(&init_step.next_chain_key)),
            ratchet_private_key_b64u: crate::keys::base64url_encode(&ratchet_private.to_bytes()),
            ratchet_public_key_b64u: crate::keys::base64url_encode(&ratchet_public),
            peer_ratchet_public_key_b64u: Some(body.sender_ephemeral_pub_b64u.clone()),
            send_n: 0,
            recv_n: 1,
            previous_send_chain_length: 0,
            skipped_message_keys: vec![],
            is_initiator: false,
            status: V2_SESSION_STATUS_ESTABLISHED.to_owned(),
            disabled: false,
        };
        state.validate()?;
        Ok((state, plaintext, consumed_opk_id))
    }

    pub fn encrypt_follow_up(
        state: &mut V2DirectSessionState,
        expected_binding: &V2SessionBinding,
        metadata: &V2DirectMetadata,
        plaintext: &V2ApplicationPlaintext,
    ) -> Result<(V2PendingOutboundRecord, V2DirectCipherBody), DirectE2eeV2Error> {
        plaintext.validate()?;
        let plaintext_bytes = Zeroizing::new(canonical_application_plaintext_v2(plaintext)?);
        Self::encrypt_follow_up_bytes(state, expected_binding, metadata, &plaintext_bytes)
    }

    /// Secret-payload equivalent of [`Self::encrypt_follow_up`].
    pub fn encrypt_follow_up_secret_json(
        state: &mut V2DirectSessionState,
        expected_binding: &V2SessionBinding,
        metadata: &V2DirectMetadata,
        plaintext: &V2SecretJsonPayload,
    ) -> Result<(V2PendingOutboundRecord, V2DirectCipherBody), DirectE2eeV2Error> {
        let plaintext_bytes = plaintext.canonical_application_bytes();
        Self::encrypt_follow_up_bytes(state, expected_binding, metadata, &plaintext_bytes)
    }

    fn encrypt_follow_up_bytes(
        state: &mut V2DirectSessionState,
        expected_binding: &V2SessionBinding,
        metadata: &V2DirectMetadata,
        plaintext_bytes: &[u8],
    ) -> Result<(V2PendingOutboundRecord, V2DirectCipherBody), DirectE2eeV2Error> {
        state.validate_for(expected_binding)?;
        expected_binding.validate_outbound_metadata(metadata, CONTENT_TYPE_DIRECT_CIPHER_V2)?;
        if state.status != V2_SESSION_STATUS_ESTABLISHED {
            return Err(runtime_error(DirectE2eeV2RuntimeErrorKind::BadInitMessage));
        }
        let send_chain_key = decode_fixed::<32>(
            "state.send_chain_key_b64u",
            state.send_chain_key_b64u.as_deref().ok_or_else(|| {
                DirectE2eeV2Error::invalid("established session has no send chain")
            })?,
        )?;
        let next_send_n = state
            .send_n
            .checked_add(1)
            .ok_or_else(|| DirectE2eeV2Error::invalid("send counter overflow"))?;
        let step = derive_chain_step(&send_chain_key);
        let mut body = V2DirectCipherBody {
            session_id: state.session_id.clone(),
            suite: Some(MTI_DIRECT_E2EE_SUITE_V2.to_owned()),
            ratchet_header: V2RatchetHeader {
                dh_pub_b64u: state.ratchet_public_key_b64u.clone(),
                pn: state.previous_send_chain_length.to_string(),
                n: state.send_n.to_string(),
            },
            ciphertext_b64u: String::new(),
        };
        let aad = build_message_aad_for_encryption(metadata, &body)?;
        body.ciphertext_b64u = crate::keys::base64url_encode(
            &encrypt_with_step(&step, plaintext_bytes, &aad).map_err(security_crypto_error)?,
        );
        body.validate()?;
        let pending = pending_record(expected_binding, metadata, &body)?;
        let mut next_state = state.clone();
        next_state.send_chain_key_b64u = Some(crate::keys::base64url_encode(&step.next_chain_key));
        next_state.send_n = next_send_n;
        next_state.validate_for(expected_binding)?;
        *state = next_state;
        Ok((pending, body))
    }

    pub fn decrypt_follow_up(
        state: &mut V2DirectSessionState,
        expected_binding: &V2SessionBinding,
        metadata: &V2DirectMetadata,
        body: &V2DirectCipherBody,
    ) -> Result<V2ApplicationPlaintext, DirectE2eeV2Error> {
        let plaintext = Self::decrypt_follow_up_bytes(state, expected_binding, metadata, body)?;
        parse_application_plaintext(&plaintext)
    }

    /// Secret-payload equivalent of [`Self::decrypt_follow_up`].
    pub fn decrypt_follow_up_secret_json(
        state: &mut V2DirectSessionState,
        expected_binding: &V2SessionBinding,
        metadata: &V2DirectMetadata,
        body: &V2DirectCipherBody,
    ) -> Result<V2SecretJsonPayload, DirectE2eeV2Error> {
        let plaintext = Self::decrypt_follow_up_bytes(state, expected_binding, metadata, body)?;
        V2SecretJsonPayload::from_canonical_application_bytes(plaintext)
    }

    fn decrypt_follow_up_bytes(
        state: &mut V2DirectSessionState,
        expected_binding: &V2SessionBinding,
        metadata: &V2DirectMetadata,
        body: &V2DirectCipherBody,
    ) -> Result<Zeroizing<Vec<u8>>, DirectE2eeV2Error> {
        state.validate_for(expected_binding)?;
        expected_binding.validate_inbound_metadata(metadata, CONTENT_TYPE_DIRECT_CIPHER_V2)?;
        body.validate()
            .map_err(|_| runtime_error(DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding))?;
        if body.session_id != state.session_id {
            return Err(runtime_error(
                DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding,
            ));
        }
        if let Some(suite) = body.suite.as_deref() {
            if suite != state.binding.suite {
                return Err(runtime_error(
                    DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding,
                ));
            }
        }
        if state.status == V2_SESSION_STATUS_PENDING_CONFIRMATION {
            return decrypt_first_reply_bytes(state, metadata, body);
        }

        let mut skipped_state = state.clone();
        match try_skipped_message_key(&mut skipped_state, metadata, body) {
            Ok(Some(plaintext)) => {
                skipped_state.validate_for(expected_binding)?;
                *state = skipped_state;
                return Ok(plaintext);
            }
            Ok(None) => {}
            Err(error) => {
                if skipped_state.skipped_message_keys != state.skipped_message_keys {
                    skipped_state.validate_for(expected_binding)?;
                    *state = skipped_state;
                }
                return Err(error);
            }
        }

        let mut next_state = state.clone();
        if next_state.peer_ratchet_public_key_b64u.as_deref()
            != Some(body.ratchet_header.dh_pub_b64u.as_str())
        {
            let pn = parse_u32(&body.ratchet_header.pn, "ratchet_header.pn")?;
            skip_message_keys(&mut next_state, pn)?;
            ratchet_step(&mut next_state, &body.ratchet_header.dh_pub_b64u)?;
        }
        let n = parse_u32(&body.ratchet_header.n, "ratchet_header.n")?;
        if n < next_state.recv_n {
            return Err(runtime_error(DirectE2eeV2RuntimeErrorKind::DecryptFailed));
        }
        skip_message_keys(&mut next_state, n)?;
        let recv_chain_key = decode_fixed::<32>(
            "state.recv_chain_key_b64u",
            next_state.recv_chain_key_b64u.as_deref().ok_or_else(|| {
                DirectE2eeV2Error::invalid("established session has no receive chain")
            })?,
        )?;
        let step = derive_chain_step(&recv_chain_key);
        let plaintext = decrypt_cipher_plaintext_bytes(&step, metadata, body)?;
        next_state.recv_chain_key_b64u = Some(crate::keys::base64url_encode(&step.next_chain_key));
        next_state.recv_n = n
            .checked_add(1)
            .ok_or_else(|| DirectE2eeV2Error::invalid("receive counter overflow"))?;
        next_state.validate_for(expected_binding)?;
        *state = next_state;
        Ok(plaintext)
    }
}

fn validate_recipient_bundle(
    binding: &V2SessionBinding,
    bundle: &V2PrekeyBundle,
) -> Result<(), DirectE2eeV2Error> {
    bundle
        .validate_structure()
        .map_err(|_| runtime_error(DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding))?;
    if bundle.owner_did != binding.peer_did
        || bundle.owner_device_id != binding.peer_device_id
        || bundle.suite != binding.suite
        || bundle.static_key_agreement_id != binding.peer_e2ee_key_id
    {
        return Err(runtime_error(
            DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding,
        ));
    }
    Ok(())
}

fn validate_local_bundle(
    binding: &V2SessionBinding,
    bundle: &V2PrekeyBundle,
    signed_prekey_private: &X25519StaticSecret,
) -> Result<(), DirectE2eeV2Error> {
    bundle
        .validate_structure()
        .map_err(|_| runtime_error(DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding))?;
    if bundle.owner_did != binding.local_did
        || bundle.owner_device_id != binding.local_device_id
        || bundle.suite != binding.suite
        || bundle.static_key_agreement_id != binding.local_e2ee_key_id
    {
        return Err(runtime_error(
            DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding,
        ));
    }
    let expected_spk = decode_fixed::<32>(
        "prekey_bundle.signed_prekey.public_key_b64u",
        &bundle.signed_prekey.public_key_b64u,
    )
    .map_err(|_| runtime_error(DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding))?;
    if X25519PublicKey::from(signed_prekey_private).to_bytes() != expected_spk {
        return Err(runtime_error(
            DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding,
        ));
    }
    Ok(())
}

fn pending_record<T: Serialize>(
    binding: &V2SessionBinding,
    metadata: &V2DirectMetadata,
    body: &T,
) -> Result<V2PendingOutboundRecord, DirectE2eeV2Error> {
    let body_value = serde_json::to_value(body)?;
    let session_id = body_value
        .get("session_id")
        .and_then(Value::as_str)
        .ok_or_else(|| DirectE2eeV2Error::invalid("pending body has no session_id"))?;
    let pending = V2PendingOutboundRecord {
        state_format: DIRECT_E2EE_V2_PENDING_STATE_FORMAT.to_owned(),
        binding: binding.clone(),
        session_id: session_id.to_owned(),
        operation_id: metadata.operation_id.clone(),
        message_id: metadata.message_id.clone(),
        wire_content_type: metadata.content_type.clone(),
        body: body_value,
    };
    pending.validate()?;
    Ok(pending)
}

fn decrypt_first_reply_bytes(
    state: &mut V2DirectSessionState,
    metadata: &V2DirectMetadata,
    body: &V2DirectCipherBody,
) -> Result<Zeroizing<Vec<u8>>, DirectE2eeV2Error> {
    if body.ratchet_header.pn != "0" || body.ratchet_header.n != "0" {
        return Err(runtime_error(DirectE2eeV2RuntimeErrorKind::BadInitMessage));
    }
    let mut next_state = state.clone();
    let root_key = decode_fixed::<32>("state.root_key_b64u", &next_state.root_key_b64u)?;
    let local_private = X25519StaticSecret::from(decode_fixed::<32>(
        "state.ratchet_private_key_b64u",
        &next_state.ratchet_private_key_b64u,
    )?);
    let peer_public = X25519PublicKey::from(decode_fixed::<32>(
        "ratchet_header.dh_pub_b64u",
        &body.ratchet_header.dh_pub_b64u,
    )?);
    let recv_root = derive_root_step(
        &root_key,
        &local_private.diffie_hellman(&peer_public).to_bytes(),
    )
    .map_err(bad_init_crypto_error)?;
    let new_private = X25519StaticSecret::random_from_rng(OsRng);
    let send_root = derive_root_step(
        &recv_root.root_key,
        &new_private.diffie_hellman(&peer_public).to_bytes(),
    )
    .map_err(bad_init_crypto_error)?;
    let step = derive_chain_step(&recv_root.chain_key);
    let plaintext = decrypt_cipher_plaintext_bytes(&step, metadata, body)?;
    next_state.root_key_b64u = crate::keys::base64url_encode(&send_root.root_key);
    next_state.recv_chain_key_b64u = Some(crate::keys::base64url_encode(&step.next_chain_key));
    next_state.send_chain_key_b64u = Some(crate::keys::base64url_encode(&send_root.chain_key));
    next_state.peer_ratchet_public_key_b64u = Some(body.ratchet_header.dh_pub_b64u.clone());
    next_state.previous_send_chain_length = next_state.send_n;
    next_state.send_n = 0;
    next_state.recv_n = 1;
    next_state.ratchet_private_key_b64u = crate::keys::base64url_encode(&new_private.to_bytes());
    next_state.ratchet_public_key_b64u =
        crate::keys::base64url_encode(&X25519PublicKey::from(&new_private).to_bytes());
    next_state.status = V2_SESSION_STATUS_ESTABLISHED.to_owned();
    next_state.validate()?;
    *state = next_state;
    Ok(plaintext)
}

fn ratchet_step(
    state: &mut V2DirectSessionState,
    new_peer_pub_b64u: &str,
) -> Result<(), DirectE2eeV2Error> {
    let root_key = decode_fixed::<32>("state.root_key_b64u", &state.root_key_b64u)?;
    let local_private = X25519StaticSecret::from(decode_fixed::<32>(
        "state.ratchet_private_key_b64u",
        &state.ratchet_private_key_b64u,
    )?);
    let peer_public = X25519PublicKey::from(decode_fixed::<32>(
        "ratchet_header.dh_pub_b64u",
        new_peer_pub_b64u,
    )?);
    let recv_root = derive_root_step(
        &root_key,
        &local_private.diffie_hellman(&peer_public).to_bytes(),
    )
    .map_err(security_crypto_error)?;
    let new_private = X25519StaticSecret::random_from_rng(OsRng);
    let send_root = derive_root_step(
        &recv_root.root_key,
        &new_private.diffie_hellman(&peer_public).to_bytes(),
    )
    .map_err(security_crypto_error)?;
    state.root_key_b64u = crate::keys::base64url_encode(&send_root.root_key);
    state.recv_chain_key_b64u = Some(crate::keys::base64url_encode(&recv_root.chain_key));
    state.send_chain_key_b64u = Some(crate::keys::base64url_encode(&send_root.chain_key));
    state.peer_ratchet_public_key_b64u = Some(new_peer_pub_b64u.to_owned());
    state.previous_send_chain_length = state.send_n;
    state.send_n = 0;
    state.recv_n = 0;
    state.ratchet_private_key_b64u = crate::keys::base64url_encode(&new_private.to_bytes());
    state.ratchet_public_key_b64u =
        crate::keys::base64url_encode(&X25519PublicKey::from(&new_private).to_bytes());
    Ok(())
}

fn try_skipped_message_key(
    state: &mut V2DirectSessionState,
    metadata: &V2DirectMetadata,
    body: &V2DirectCipherBody,
) -> Result<Option<Zeroizing<Vec<u8>>>, DirectE2eeV2Error> {
    let n = parse_u32(&body.ratchet_header.n, "ratchet_header.n")?;
    let Some(index) = state
        .skipped_message_keys
        .iter()
        .position(|item| item.dh_pub_b64u == body.ratchet_header.dh_pub_b64u && item.n == n)
    else {
        return Ok(None);
    };
    // P5 vNext section 10.2.3.2 requires a matching skipped key to be
    // consumed even when authentication fails. This prevents repeated use of
    // the same one-time message key; unmatched/ordinary failure paths remain
    // tentative and do not advance state.
    let skipped = state.skipped_message_keys.remove(index);
    let step = ChainStep {
        message_key: decode_fixed::<32>(
            "state.skipped.message_key_b64u",
            &skipped.message_key_b64u,
        )?,
        nonce: decode_fixed::<12>("state.skipped.nonce_b64u", &skipped.nonce_b64u)?,
        next_chain_key: [0u8; 32],
    };
    decrypt_cipher_plaintext_bytes(&step, metadata, body).map(Some)
}

fn skip_message_keys(
    state: &mut V2DirectSessionState,
    until_n: u32,
) -> Result<(), DirectE2eeV2Error> {
    if until_n < state.recv_n {
        return Ok(());
    }
    if until_n.saturating_sub(state.recv_n) > MAX_SKIP {
        return Err(runtime_error(DirectE2eeV2RuntimeErrorKind::MaxSkipExceeded));
    }
    let mut recv_chain_key = decode_fixed::<32>(
        "state.recv_chain_key_b64u",
        state.recv_chain_key_b64u.as_deref().ok_or_else(|| {
            DirectE2eeV2Error::invalid("session has no receive chain for skipped messages")
        })?,
    )?;
    while state.recv_n < until_n {
        let step = derive_chain_step(&recv_chain_key);
        let skipped = V2SkippedMessageKey {
            dh_pub_b64u: state.peer_ratchet_public_key_b64u.clone().ok_or_else(|| {
                DirectE2eeV2Error::invalid("session has no peer ratchet public key")
            })?,
            n: state.recv_n,
            message_key_b64u: crate::keys::base64url_encode(&step.message_key),
            nonce_b64u: crate::keys::base64url_encode(&step.nonce),
        };
        push_skipped_message_key(state, skipped);
        recv_chain_key = step.next_chain_key;
        state.recv_n += 1;
    }
    state.recv_chain_key_b64u = Some(crate::keys::base64url_encode(&recv_chain_key));
    Ok(())
}

/// Insert one skipped key while enforcing the per-session P5 bound.
///
/// The vector is persisted in insertion order. Once full, the oldest entry is
/// evicted before the new entry is appended. This is deterministic across
/// restarts and DH chains and deliberately avoids wall-clock ordering.
fn push_skipped_message_key(state: &mut V2DirectSessionState, skipped: V2SkippedMessageKey) {
    let maximum = MAX_SKIP as usize;
    if state.skipped_message_keys.len() >= maximum {
        let remove_count = state.skipped_message_keys.len() + 1 - maximum;
        state.skipped_message_keys.drain(..remove_count);
    }
    state.skipped_message_keys.push(skipped);
}

fn build_init_aad_for_encryption(
    metadata: &V2DirectMetadata,
    body: &V2DirectInitBody,
) -> Result<Vec<u8>, DirectE2eeV2Error> {
    // The shared wire validator requires a complete ciphertext, while the
    // ciphertext itself is intentionally absent from AD_init. Validate the
    // exact AAD fields through the shared builder using a non-wire placeholder.
    let mut aad_body = body.clone();
    aad_body.ciphertext_b64u = crate::keys::base64url_encode(&[0u8]);
    build_init_aad_v2(metadata, &aad_body)
}

fn build_message_aad_for_encryption(
    metadata: &V2DirectMetadata,
    body: &V2DirectCipherBody,
) -> Result<Vec<u8>, DirectE2eeV2Error> {
    // As above, AD_msg excludes ciphertext and must be available before AEAD.
    let mut aad_body = body.clone();
    aad_body.ciphertext_b64u = crate::keys::base64url_encode(&[0u8]);
    build_message_aad_v2(metadata, &aad_body)
}

fn decrypt_cipher_plaintext_bytes(
    step: &ChainStep,
    metadata: &V2DirectMetadata,
    body: &V2DirectCipherBody,
) -> Result<Zeroizing<Vec<u8>>, DirectE2eeV2Error> {
    decrypt_plaintext_bytes(
        step,
        &body.ciphertext_b64u,
        &build_message_aad_v2(metadata, body)?,
    )
}

fn decrypt_plaintext_bytes(
    step: &ChainStep,
    ciphertext_b64u: &str,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, DirectE2eeV2Error> {
    let ciphertext = crate::keys::base64url_decode(ciphertext_b64u)
        .map_err(|_| runtime_error(DirectE2eeV2RuntimeErrorKind::DecryptFailed))?;
    let plaintext_bytes =
        Zeroizing::new(decrypt_with_step(step, &ciphertext, aad).map_err(decrypt_crypto_error)?);
    Ok(plaintext_bytes)
}

fn parse_application_plaintext(
    plaintext_bytes: &Zeroizing<Vec<u8>>,
) -> Result<V2ApplicationPlaintext, DirectE2eeV2Error> {
    let plaintext: V2ApplicationPlaintext = serde_json::from_slice(&plaintext_bytes)
        .map_err(|_| runtime_error(DirectE2eeV2RuntimeErrorKind::DecryptFailed))?;
    let canonical = canonical_application_plaintext_v2(&plaintext)
        .map_err(|_| runtime_error(DirectE2eeV2RuntimeErrorKind::DecryptFailed))?;
    if canonical.as_slice() != plaintext_bytes.as_slice() {
        return Err(runtime_error(DirectE2eeV2RuntimeErrorKind::DecryptFailed));
    }
    Ok(plaintext)
}

fn validate_secret_json_object(bytes: &[u8]) -> Result<(), DirectE2eeV2Error> {
    if bytes.len() < 2 || bytes.first() != Some(&b'{') || bytes.last() != Some(&b'}') {
        return Err(DirectE2eeV2Error::invalid(
            "secret JSON payload must be one canonical JSON object",
        ));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    serde::de::IgnoredAny::deserialize(&mut deserializer).map_err(|_| {
        DirectE2eeV2Error::invalid("secret JSON payload must be one canonical JSON object")
    })?;
    deserializer.end().map_err(|_| {
        DirectE2eeV2Error::invalid("secret JSON payload must be one canonical JSON object")
    })
}

fn parse_u32(value: &str, field: &str) -> Result<u32, DirectE2eeV2Error> {
    value
        .parse::<u32>()
        .map_err(|_| DirectE2eeV2Error::invalid(format!("{field} is not a u32")))
}

fn validate_key_id_for_did(field: &str, key_id: &str, did: &str) -> Result<(), DirectE2eeV2Error> {
    let fragment = key_id
        .strip_prefix(did)
        .and_then(|suffix| suffix.strip_prefix('#'));
    if fragment.is_none_or(str::is_empty) {
        return Err(DirectE2eeV2Error::invalid(format!(
            "{field} must be a fragment DID URL under its endpoint DID"
        )));
    }
    Ok(())
}

fn decode_fixed<const N: usize>(field: &str, value: &str) -> Result<[u8; N], DirectE2eeV2Error> {
    crate::keys::base64url_decode(value)
        .map_err(|_| DirectE2eeV2Error::invalid(format!("{field} is not base64url")))?
        .try_into()
        .map_err(|_| DirectE2eeV2Error::invalid(format!("{field} must encode {N} bytes")))
}

fn runtime_error(kind: DirectE2eeV2RuntimeErrorKind) -> DirectE2eeV2Error {
    DirectE2eeV2Error::runtime(kind)
}

fn decrypt_crypto_error(_error: super::errors::DirectE2eeError) -> DirectE2eeV2Error {
    runtime_error(DirectE2eeV2RuntimeErrorKind::DecryptFailed)
}

fn bad_init_crypto_error(_error: super::errors::DirectE2eeError) -> DirectE2eeV2Error {
    runtime_error(DirectE2eeV2RuntimeErrorKind::BadInitMessage)
}

fn security_crypto_error(_error: super::errors::DirectE2eeError) -> DirectE2eeV2Error {
    runtime_error(DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::{
        create_did_wba_document, DidDocumentBundle, DidDocumentOptions, DidProfile,
    };
    use crate::direct_e2ee::{
        build_prekey_bundle_v2, direct_e2ee_v2_error, extract_x25519_public_key,
        verify_prekey_bundle_v2, DirectSessionState, PendingOutboundRecord,
        V2GetPrekeyBundleResult, V2SignedPrekey, V2Target, DIRECT_E2EE_PROFILE_V2,
        DIRECT_E2EE_SECURITY_PROFILE,
    };
    use crate::proof::{
        generate_w3c_proof, ProofGenerationOptions, CRYPTOSUITE_EDDSA_JCS_2022,
        PROOF_TYPE_DATA_INTEGRITY,
    };
    use crate::PrivateKeyMaterial;
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    const ALICE_DID: &str = "did:wba:alice.example:agents:alice:e1_alice";
    const BOB_DID: &str = "did:wba:bob.example:agents:bob:e1_bob";
    const ALICE_DEVICE: &str = "dev-alice-a1";
    const BOB_DEVICE: &str = "dev-bob-b1";

    struct EstablishedPair {
        alice_binding: V2SessionBinding,
        bob_binding: V2SessionBinding,
        alice_state: V2DirectSessionState,
        bob_state: V2DirectSessionState,
    }

    fn assert_runtime_kind(error: DirectE2eeV2Error, expected: DirectE2eeV2RuntimeErrorKind) {
        assert_eq!(error.runtime_kind(), Some(expected));
        assert_eq!(error.protocol_error(), Some(expected.protocol_error()));
        assert_eq!(expected.protocol_error().code, expected.code());
        assert_eq!(expected.protocol_error().anp_code, expected.anp_code());
    }

    fn binding(
        local_did: &str,
        local_device: &str,
        peer_did: &str,
        peer_device: &str,
    ) -> V2SessionBinding {
        V2SessionBinding {
            local_did: local_did.to_owned(),
            local_device_id: local_device.to_owned(),
            peer_did: peer_did.to_owned(),
            peer_device_id: peer_device.to_owned(),
            suite: MTI_DIRECT_E2EE_SUITE_V2.to_owned(),
            local_e2ee_key_id: format!("{local_did}#ka-{local_device}"),
            peer_e2ee_key_id: format!("{peer_did}#ka-{peer_device}"),
        }
    }

    fn metadata(
        binding: &V2SessionBinding,
        message_id: &str,
        content_type: &str,
    ) -> V2DirectMetadata {
        V2DirectMetadata {
            anp_version: Some("1.0".to_owned()),
            profile: DIRECT_E2EE_PROFILE_V2.to_owned(),
            security_profile: DIRECT_E2EE_SECURITY_PROFILE.to_owned(),
            sender_did: binding.local_did.clone(),
            sender_device_id: binding.local_device_id.clone(),
            target: V2Target {
                kind: "agent".to_owned(),
                did: binding.peer_did.clone(),
            },
            recipient_device_id: binding.peer_device_id.clone(),
            operation_id: message_id.to_owned(),
            message_id: message_id.to_owned(),
            content_type: content_type.to_owned(),
            created_at: Some("2026-07-19T00:00:00Z".to_owned()),
        }
    }

    fn text_plaintext(text: &str) -> V2ApplicationPlaintext {
        V2ApplicationPlaintext {
            application_content_type: "text/plain".to_owned(),
            logical_message_id: None,
            conversation_id: None,
            reply_to_message_id: None,
            annotations: None,
            text: Some(text.to_owned()),
            payload: None,
            payload_b64u: None,
        }
    }

    fn initiate_pair_before_reply() -> (
        V2SessionBinding,
        V2SessionBinding,
        V2DirectSessionState,
        V2DirectSessionState,
    ) {
        let alice_binding = binding(ALICE_DID, ALICE_DEVICE, BOB_DID, BOB_DEVICE);
        let bob_binding = binding(BOB_DID, BOB_DEVICE, ALICE_DID, ALICE_DEVICE);
        let alice_static = X25519StaticSecret::from([71u8; 32]);
        let bob_static = X25519StaticSecret::from([73u8; 32]);
        let bob_spk = X25519StaticSecret::from([75u8; 32]);
        let bob_bundle = bundle(
            BOB_DID,
            BOB_DEVICE,
            &bob_binding.local_e2ee_key_id,
            &bob_spk,
        );
        let init_meta = metadata(
            &alice_binding,
            "msg-pending-init",
            CONTENT_TYPE_DIRECT_INIT_V2,
        );
        let (alice_state, _, init_body) = V2DirectE2eeSession::initiate_session(
            &alice_binding,
            &init_meta,
            &alice_static,
            &bob_bundle,
            &X25519PublicKey::from(&bob_static).to_bytes(),
            None,
            &text_plaintext("pending init"),
        )
        .expect("initiate pending pair");
        let (bob_state, _, _) = V2DirectE2eeSession::accept_incoming_init(
            &bob_binding,
            &init_meta,
            &bob_static,
            &bob_bundle,
            &bob_spk,
            None,
            &X25519PublicKey::from(&alice_static).to_bytes(),
            &init_body,
        )
        .expect("accept pending pair init");
        (alice_binding, bob_binding, alice_state, bob_state)
    }

    fn bundle(
        owner_did: &str,
        owner_device_id: &str,
        static_key_id: &str,
        signed_prekey: &X25519StaticSecret,
    ) -> V2PrekeyBundle {
        V2PrekeyBundle {
            bundle_id: format!("bundle-{owner_device_id}"),
            owner_did: owner_did.to_owned(),
            owner_device_id: owner_device_id.to_owned(),
            suite: MTI_DIRECT_E2EE_SUITE_V2.to_owned(),
            static_key_agreement_id: static_key_id.to_owned(),
            signed_prekey: V2SignedPrekey {
                key_id: format!("spk-{owner_device_id}"),
                public_key_b64u: crate::keys::base64url_encode(
                    &X25519PublicKey::from(signed_prekey).to_bytes(),
                ),
                expires_at: "2030-01-01T00:00:00Z".to_owned(),
            },
            proof: json!({
                "type": "DataIntegrityProof",
                "cryptosuite": "eddsa-jcs-2022",
                "verificationMethod": format!("{owner_did}#sign-{owner_device_id}"),
                "proofPurpose": "assertionMethod",
                "created": "2026-07-19T00:00:00Z",
                "proofValue": "zTestProof"
            }),
        }
    }

    fn manifest_device(hostname: &str, path: &str, device_id: &str) -> (DidDocumentBundle, Value) {
        let generated = create_did_wba_document(
            hostname,
            DidDocumentOptions {
                path_segments: vec!["agents".to_owned(), path.to_owned()],
                did_profile: DidProfile::E1,
                ..Default::default()
            },
        )
        .expect("create DID document");
        let did = generated.did().expect("generated DID").to_owned();
        let mut document = generated.did_document.clone();
        document
            .as_object_mut()
            .expect("DID document object")
            .remove("proof");
        document["deviceManifest"] = json!({
            "type": "ANPDeviceManifest",
            "devices": [{
                "device_id": device_id,
                "signing_key_id": format!("{did}#key-1"),
                "e2ee_key_id": format!("{did}#key-3"),
                "profiles": [
                    "anp.core.binding.v2",
                    "anp.identity.discovery.v2",
                    "anp.direct.base.v2",
                    "anp.direct.e2ee.v2"
                ]
            }]
        });
        let signing_key = PrivateKeyMaterial::from_pem(&generated.keys["key-1"].private_key_pem)
            .expect("load DID signing key");
        document = generate_w3c_proof(
            &document,
            &signing_key,
            &format!("{did}#key-1"),
            ProofGenerationOptions {
                proof_purpose: Some("assertionMethod".to_owned()),
                proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_owned()),
                cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.to_owned()),
                created: Some("2026-07-19T00:00:00Z".to_owned()),
                ..Default::default()
            },
        )
        .expect("sign DID document with Manifest");
        (generated, document)
    }

    fn generated_x25519_private(generated: &DidDocumentBundle) -> X25519StaticSecret {
        match PrivateKeyMaterial::from_pem(&generated.keys["key-3"].private_key_pem)
            .expect("load X25519 private key")
        {
            PrivateKeyMaterial::X25519(private) => private,
            _ => panic!("key-3 must be X25519"),
        }
    }

    fn establish_pair() -> EstablishedPair {
        let alice_binding = binding(ALICE_DID, ALICE_DEVICE, BOB_DID, BOB_DEVICE);
        let bob_binding = binding(BOB_DID, BOB_DEVICE, ALICE_DID, ALICE_DEVICE);
        let alice_static = X25519StaticSecret::from([7u8; 32]);
        let bob_static = X25519StaticSecret::from([9u8; 32]);
        let bob_spk = X25519StaticSecret::from([11u8; 32]);
        let bob_bundle = bundle(
            BOB_DID,
            BOB_DEVICE,
            &bob_binding.local_e2ee_key_id,
            &bob_spk,
        );
        let init_meta = metadata(&alice_binding, "msg-init", CONTENT_TYPE_DIRECT_INIT_V2);
        let init_plaintext = V2ApplicationPlaintext {
            application_content_type: "text/plain".to_owned(),
            logical_message_id: Some("logical-init".to_owned()),
            conversation_id: None,
            reply_to_message_id: None,
            annotations: None,
            text: Some("hello bob".to_owned()),
            payload: None,
            payload_b64u: None,
        };
        let (mut alice_state, _, init_body) = V2DirectE2eeSession::initiate_session(
            &alice_binding,
            &init_meta,
            &alice_static,
            &bob_bundle,
            &X25519PublicKey::from(&bob_static).to_bytes(),
            None,
            &init_plaintext,
        )
        .expect("initiate exact-device session");
        let (mut bob_state, received_init, consumed_opk) =
            V2DirectE2eeSession::accept_incoming_init(
                &bob_binding,
                &init_meta,
                &bob_static,
                &bob_bundle,
                &bob_spk,
                None,
                &X25519PublicKey::from(&alice_static).to_bytes(),
                &init_body,
            )
            .expect("accept exact-device init");
        assert_eq!(received_init, init_plaintext);
        assert_eq!(consumed_opk, None);

        let reply_meta = metadata(&bob_binding, "msg-reply", CONTENT_TYPE_DIRECT_CIPHER_V2);
        let reply_plaintext = V2ApplicationPlaintext {
            application_content_type: "application/json".to_owned(),
            logical_message_id: Some("logical-reply".to_owned()),
            conversation_id: Some("conv-1".to_owned()),
            reply_to_message_id: Some("logical-init".to_owned()),
            annotations: Some(json!({"kind": "receipt"})),
            text: None,
            payload: Some(json!({"type": "ack", "ok": true})),
            payload_b64u: None,
        };
        let (_, reply_body) = V2DirectE2eeSession::encrypt_follow_up(
            &mut bob_state,
            &bob_binding,
            &reply_meta,
            &reply_plaintext,
        )
        .expect("encrypt responder first reply");
        let received_reply = V2DirectE2eeSession::decrypt_follow_up(
            &mut alice_state,
            &alice_binding,
            &reply_meta,
            &reply_body,
        )
        .expect("decrypt responder first reply");
        assert_eq!(received_reply, reply_plaintext);
        assert_eq!(alice_state.status, V2_SESSION_STATUS_ESTABLISHED);

        EstablishedPair {
            alice_binding,
            bob_binding,
            alice_state,
            bob_state,
        }
    }

    #[test]
    fn init_reply_and_follow_up_ratchet_round_trip_structured_json() {
        let mut pair = establish_pair();
        let message_meta = metadata(
            &pair.alice_binding,
            "msg-json",
            CONTENT_TYPE_DIRECT_CIPHER_V2,
        );
        let plaintext = V2ApplicationPlaintext {
            application_content_type: "application/json".to_owned(),
            logical_message_id: Some("logical-json".to_owned()),
            conversation_id: Some("conv-1".to_owned()),
            reply_to_message_id: None,
            annotations: Some(json!({})),
            text: None,
            payload: Some(json!({
                "type": "awiki.device.sync.v1",
                "data": {"hello": "world", "sequence": 2}
            })),
            payload_b64u: None,
        };
        let (_, body) = V2DirectE2eeSession::encrypt_follow_up(
            &mut pair.alice_state,
            &pair.alice_binding,
            &message_meta,
            &plaintext,
        )
        .expect("encrypt structured JSON");
        let decrypted = V2DirectE2eeSession::decrypt_follow_up(
            &mut pair.bob_state,
            &pair.bob_binding,
            &message_meta,
            &body,
        )
        .expect("decrypt structured JSON");
        assert_eq!(decrypted, plaintext);
        assert_eq!(decrypted.payload, plaintext.payload);
    }

    #[test]
    fn secret_json_init_first_reply_and_follow_up_use_redacted_payload_boundary() {
        let alice_binding = binding(ALICE_DID, ALICE_DEVICE, BOB_DID, BOB_DEVICE);
        let bob_binding = binding(BOB_DID, BOB_DEVICE, ALICE_DID, ALICE_DEVICE);
        let alice_static = X25519StaticSecret::from([81u8; 32]);
        let bob_static = X25519StaticSecret::from([82u8; 32]);
        let bob_spk = X25519StaticSecret::from([83u8; 32]);
        let bob_bundle = bundle(
            BOB_DID,
            BOB_DEVICE,
            &bob_binding.local_e2ee_key_id,
            &bob_spk,
        );
        let envelope = V2SecretJsonPayload::from_canonical_json_object(
            br#"{"root_private_key":"TOP-SECRET-ROOT","system_type":"awiki.device.root-key.v1"}"#
                .to_vec(),
        )
        .expect("canonical secret envelope");
        assert!(!format!("{envelope:?}").contains("TOP-SECRET-ROOT"));

        let init_meta = metadata(
            &alice_binding,
            "msg-secret-init",
            CONTENT_TYPE_DIRECT_INIT_V2,
        );
        let (mut alice_state, _, init_body) = V2DirectE2eeSession::initiate_session_secret_json(
            &alice_binding,
            &init_meta,
            &alice_static,
            &bob_bundle,
            &X25519PublicKey::from(&bob_static).to_bytes(),
            None,
            &envelope,
        )
        .expect("encrypt secret init");
        let (mut bob_state, received, _) = V2DirectE2eeSession::accept_incoming_init_secret_json(
            &bob_binding,
            &init_meta,
            &bob_static,
            &bob_bundle,
            &bob_spk,
            None,
            &X25519PublicKey::from(&alice_static).to_bytes(),
            &init_body,
        )
        .expect("decrypt secret init");
        assert_eq!(received.expose_secret(), envelope.expose_secret());

        let ack = V2SecretJsonPayload::from_canonical_json_object(
            br#"{"result":"imported","system_type":"awiki.device.root-key-imported.v1"}"#.to_vec(),
        )
        .expect("canonical secret ack");
        let reply_meta = metadata(
            &bob_binding,
            "msg-secret-reply",
            CONTENT_TYPE_DIRECT_CIPHER_V2,
        );
        let (_, reply) = V2DirectE2eeSession::encrypt_follow_up_secret_json(
            &mut bob_state,
            &bob_binding,
            &reply_meta,
            &ack,
        )
        .expect("encrypt secret first reply");
        let received_ack = V2DirectE2eeSession::decrypt_follow_up_secret_json(
            &mut alice_state,
            &alice_binding,
            &reply_meta,
            &reply,
        )
        .expect("decrypt secret first reply");
        assert_eq!(received_ack.expose_secret(), ack.expose_secret());
        assert_eq!(alice_state.status, V2_SESSION_STATUS_ESTABLISHED);

        let follow_up = V2SecretJsonPayload::from_canonical_json_object(
            br#"{"sequence":2,"system_type":"awiki.device.control.v1"}"#.to_vec(),
        )
        .expect("canonical secret follow-up");
        let follow_meta = metadata(
            &alice_binding,
            "msg-secret-follow-up",
            CONTENT_TYPE_DIRECT_CIPHER_V2,
        );
        let (_, follow_body) = V2DirectE2eeSession::encrypt_follow_up_secret_json(
            &mut alice_state,
            &alice_binding,
            &follow_meta,
            &follow_up,
        )
        .expect("encrypt secret follow-up");
        let received_follow_up = V2DirectE2eeSession::decrypt_follow_up_secret_json(
            &mut bob_state,
            &bob_binding,
            &follow_meta,
            &follow_body,
        )
        .expect("decrypt secret follow-up");
        assert_eq!(
            received_follow_up.expose_secret(),
            follow_up.expose_secret()
        );
    }

    #[test]
    fn secret_json_trusted_constructor_rejects_invalid_objects() {
        for invalid in [
            b"not-json".to_vec(),
            br#"["not-an-object"]"#.to_vec(),
            br#"{"unterminated":"secret""#.to_vec(),
        ] {
            assert!(V2SecretJsonPayload::from_canonical_json_object(invalid).is_err());
        }
    }

    #[test]
    fn opk_is_bound_and_reported_for_consumption() {
        let alice_binding = binding(ALICE_DID, ALICE_DEVICE, BOB_DID, BOB_DEVICE);
        let bob_binding = binding(BOB_DID, BOB_DEVICE, ALICE_DID, ALICE_DEVICE);
        let alice_static = X25519StaticSecret::from([17u8; 32]);
        let bob_static = X25519StaticSecret::from([19u8; 32]);
        let bob_spk = X25519StaticSecret::from([21u8; 32]);
        let bob_opk = X25519StaticSecret::from([23u8; 32]);
        let bob_bundle = bundle(
            BOB_DID,
            BOB_DEVICE,
            &bob_binding.local_e2ee_key_id,
            &bob_spk,
        );
        let opk = V2OneTimePrekey {
            key_id: "opk-bob-1".to_owned(),
            public_key_b64u: crate::keys::base64url_encode(
                &X25519PublicKey::from(&bob_opk).to_bytes(),
            ),
        };
        let init_meta = metadata(&alice_binding, "msg-opk", CONTENT_TYPE_DIRECT_INIT_V2);
        let plaintext = V2ApplicationPlaintext {
            application_content_type: "text/plain".to_owned(),
            logical_message_id: None,
            conversation_id: None,
            reply_to_message_id: None,
            annotations: None,
            text: Some("uses opk".to_owned()),
            payload: None,
            payload_b64u: None,
        };
        let (_, _, body) = V2DirectE2eeSession::initiate_session(
            &alice_binding,
            &init_meta,
            &alice_static,
            &bob_bundle,
            &X25519PublicKey::from(&bob_static).to_bytes(),
            Some(&opk),
            &plaintext,
        )
        .expect("initiate with OPK");
        assert!(V2DirectE2eeSession::accept_incoming_init(
            &bob_binding,
            &init_meta,
            &bob_static,
            &bob_bundle,
            &bob_spk,
            None,
            &X25519PublicKey::from(&alice_static).to_bytes(),
            &body,
        )
        .is_err());
        let (_, decrypted, consumed) = V2DirectE2eeSession::accept_incoming_init(
            &bob_binding,
            &init_meta,
            &bob_static,
            &bob_bundle,
            &bob_spk,
            Some((&opk, &bob_opk)),
            &X25519PublicKey::from(&alice_static).to_bytes(),
            &body,
        )
        .expect("accept with exact OPK");
        assert_eq!(decrypted, plaintext);
        assert_eq!(consumed.as_deref(), Some("opk-bob-1"));
    }

    #[test]
    fn verified_manifest_bundle_response_drives_real_init() {
        let (alice_generated, alice_document) =
            manifest_device("alice-runtime.example", "alice", ALICE_DEVICE);
        let (bob_generated, bob_document) =
            manifest_device("bob-runtime.example", "bob", BOB_DEVICE);
        let alice_did = alice_generated.did().expect("Alice DID").to_owned();
        let bob_did = bob_generated.did().expect("Bob DID").to_owned();
        let alice_key_id = format!("{alice_did}#key-3");
        let bob_key_id = format!("{bob_did}#key-3");
        let alice_static = generated_x25519_private(&alice_generated);
        let bob_static = generated_x25519_private(&bob_generated);

        let alice_static_public =
            extract_x25519_public_key(&alice_document, &alice_key_id).expect("Alice static key");
        let bob_static_public =
            extract_x25519_public_key(&bob_document, &bob_key_id).expect("Bob static key");
        assert_eq!(
            X25519PublicKey::from(&alice_static).to_bytes(),
            alice_static_public,
            "the local private key must match the current Manifest public key",
        );
        assert_eq!(
            X25519PublicKey::from(&bob_static).to_bytes(),
            bob_static_public,
        );

        let bob_signing =
            PrivateKeyMaterial::from_pem(&bob_generated.keys["key-1"].private_key_pem)
                .expect("Bob signing key");
        let bob_spk = X25519StaticSecret::from([101u8; 32]);
        let signed_prekey = V2SignedPrekey {
            key_id: "spk-bob-real".to_owned(),
            public_key_b64u: crate::keys::base64url_encode(
                &X25519PublicKey::from(&bob_spk).to_bytes(),
            ),
            expires_at: "2035-01-01T00:00:00Z".to_owned(),
        };
        let signed_bundle = build_prekey_bundle_v2(
            "bundle-bob-real",
            &bob_did,
            BOB_DEVICE,
            &bob_key_id,
            signed_prekey,
            &bob_signing,
            &format!("{bob_did}#key-1"),
            Some("2026-07-19T00:00:00Z"),
        )
        .expect("build real Bundle proof");
        let bob_opk_private = X25519StaticSecret::from([103u8; 32]);
        let response = V2GetPrekeyBundleResult {
            target_did: bob_did.clone(),
            target_device_id: BOB_DEVICE.to_owned(),
            prekey_bundle: signed_bundle,
            one_time_prekey: Some(V2OneTimePrekey {
                key_id: "opk-bob-real".to_owned(),
                public_key_b64u: crate::keys::base64url_encode(
                    &X25519PublicKey::from(&bob_opk_private).to_bytes(),
                ),
            }),
        };
        response.validate().expect("complete get response");
        verify_prekey_bundle_v2(
            &response.prekey_bundle,
            &bob_document,
            Utc.with_ymd_and_hms(2026, 7, 19, 0, 0, 1).unwrap(),
        )
        .expect("real proof and current Manifest binding");

        let alice_binding = V2SessionBinding {
            local_did: alice_did.clone(),
            local_device_id: ALICE_DEVICE.to_owned(),
            peer_did: bob_did.clone(),
            peer_device_id: BOB_DEVICE.to_owned(),
            suite: MTI_DIRECT_E2EE_SUITE_V2.to_owned(),
            local_e2ee_key_id: alice_key_id,
            peer_e2ee_key_id: bob_key_id,
        };
        let bob_binding = V2SessionBinding {
            local_did: bob_did,
            local_device_id: BOB_DEVICE.to_owned(),
            peer_did: alice_did,
            peer_device_id: ALICE_DEVICE.to_owned(),
            suite: MTI_DIRECT_E2EE_SUITE_V2.to_owned(),
            local_e2ee_key_id: alice_binding.peer_e2ee_key_id.clone(),
            peer_e2ee_key_id: alice_binding.local_e2ee_key_id.clone(),
        };
        let init_meta = metadata(
            &alice_binding,
            "msg-real-binding-init",
            CONTENT_TYPE_DIRECT_INIT_V2,
        );
        let plaintext = text_plaintext("verified response only");
        let (_, pending, body) = V2DirectE2eeSession::initiate_session(
            &alice_binding,
            &init_meta,
            &alice_static,
            &response.prekey_bundle,
            &bob_static_public,
            response.one_time_prekey.as_ref(),
            &plaintext,
        )
        .expect("initiate from verified response");
        assert_eq!(pending.body, serde_json::to_value(&body).unwrap());
        let (_, decrypted, consumed_opk) = V2DirectE2eeSession::accept_incoming_init(
            &bob_binding,
            &init_meta,
            &bob_static,
            &response.prekey_bundle,
            &bob_spk,
            Some((
                response.one_time_prekey.as_ref().expect("response OPK"),
                &bob_opk_private,
            )),
            &alice_static_public,
            &body,
        )
        .expect("accept verified init");
        assert_eq!(decrypted, plaintext);
        assert_eq!(consumed_opk.as_deref(), Some("opk-bob-real"));
    }

    #[test]
    fn pending_init_retry_serialization_is_byte_exact() {
        let exact = binding(ALICE_DID, ALICE_DEVICE, BOB_DID, BOB_DEVICE);
        let alice_static = X25519StaticSecret::from([105u8; 32]);
        let bob_static = X25519StaticSecret::from([107u8; 32]);
        let bob_spk = X25519StaticSecret::from([109u8; 32]);
        let bob_bundle = bundle(BOB_DID, BOB_DEVICE, &exact.peer_e2ee_key_id, &bob_spk);
        let init_meta = metadata(&exact, "msg-byte-exact-retry", CONTENT_TYPE_DIRECT_INIT_V2);
        let (state, pending, body) = V2DirectE2eeSession::initiate_session(
            &exact,
            &init_meta,
            &alice_static,
            &bob_bundle,
            &X25519PublicKey::from(&bob_static).to_bytes(),
            None,
            &text_plaintext("persist once, retry exact bytes"),
        )
        .expect("create pending init");
        let first_bytes = serialize_pending_outbound_v2(&pending).expect("serialize pending");
        let restored = deserialize_pending_outbound_v2(&first_bytes).expect("restore pending");
        let retry_bytes = serialize_pending_outbound_v2(&restored).expect("serialize retry");
        assert_eq!(retry_bytes, first_bytes);
        assert_eq!(restored.operation_id, init_meta.operation_id);
        assert_eq!(restored.message_id, init_meta.message_id);
        assert_eq!(restored.session_id, state.session_id);
        assert_eq!(restored.body, serde_json::to_value(body).unwrap());
    }

    #[test]
    fn same_did_different_devices_are_valid_but_same_endpoint_is_rejected() {
        let did = ALICE_DID;
        let a1_binding = binding(did, "dev-a1", did, "dev-a2");
        let a2_binding = binding(did, "dev-a2", did, "dev-a1");
        a1_binding.validate().expect("same DID sibling devices");
        let same_endpoint = binding(did, "dev-a1", did, "dev-a1");
        assert!(same_endpoint.validate().is_err());

        let a1_static = X25519StaticSecret::from([31u8; 32]);
        let a2_static = X25519StaticSecret::from([33u8; 32]);
        let a2_spk = X25519StaticSecret::from([35u8; 32]);
        let a2_bundle = bundle(did, "dev-a2", &a2_binding.local_e2ee_key_id, &a2_spk);
        let init_meta = metadata(&a1_binding, "msg-self", CONTENT_TYPE_DIRECT_INIT_V2);
        let plaintext = V2ApplicationPlaintext {
            application_content_type: "application/json".to_owned(),
            logical_message_id: Some("logical-self".to_owned()),
            conversation_id: None,
            reply_to_message_id: None,
            annotations: None,
            text: None,
            payload: Some(json!({"type": "awiki.device.sync.v1"})),
            payload_b64u: None,
        };
        let (_, _, body) = V2DirectE2eeSession::initiate_session(
            &a1_binding,
            &init_meta,
            &a1_static,
            &a2_bundle,
            &X25519PublicKey::from(&a2_static).to_bytes(),
            None,
            &plaintext,
        )
        .expect("self-device init");
        let (_, decrypted, _) = V2DirectE2eeSession::accept_incoming_init(
            &a2_binding,
            &init_meta,
            &a2_static,
            &a2_bundle,
            &a2_spk,
            None,
            &X25519PublicKey::from(&a1_static).to_bytes(),
            &body,
        )
        .expect("self-device accept");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn one_to_many_sessions_do_not_collide_and_disable_is_device_local() {
        let alice_static = X25519StaticSecret::from([41u8; 32]);
        let mut states = Vec::new();
        for (index, device) in ["dev-bob-b1", "dev-bob-b2"].iter().enumerate() {
            let exact = binding(ALICE_DID, ALICE_DEVICE, BOB_DID, device);
            let peer_static = X25519StaticSecret::from([43u8 + index as u8; 32]);
            let peer_spk = X25519StaticSecret::from([47u8 + index as u8; 32]);
            let peer_bundle = bundle(BOB_DID, device, &exact.peer_e2ee_key_id, &peer_spk);
            let init_meta = metadata(
                &exact,
                &format!("msg-init-{index}"),
                CONTENT_TYPE_DIRECT_INIT_V2,
            );
            let plaintext = V2ApplicationPlaintext {
                application_content_type: "text/plain".to_owned(),
                logical_message_id: Some("one-logical-message".to_owned()),
                conversation_id: None,
                reply_to_message_id: None,
                annotations: None,
                text: Some("fan out independently".to_owned()),
                payload: None,
                payload_b64u: None,
            };
            let (mut state, pending, _) = V2DirectE2eeSession::initiate_session(
                &exact,
                &init_meta,
                &alice_static,
                &peer_bundle,
                &X25519PublicKey::from(&peer_static).to_bytes(),
                None,
                &plaintext,
            )
            .expect("initiate sibling-device session");
            assert_eq!(pending.binding, exact);
            state.status = V2_SESSION_STATUS_ESTABLISHED.to_owned();
            state.recv_chain_key_b64u = state.send_chain_key_b64u.clone();
            state.peer_ratchet_public_key_b64u = Some(state.ratchet_public_key_b64u.clone());
            states.push(state);
        }
        assert_ne!(states[0].session_id, states[1].session_id);
        assert_ne!(
            states[0].binding.peer_device_id,
            states[1].binding.peer_device_id
        );
        let b1_binding = binding(ALICE_DID, ALICE_DEVICE, BOB_DID, "dev-bob-b1");
        let b2_binding = binding(ALICE_DID, ALICE_DEVICE, BOB_DID, "dev-bob-b2");
        assert!(select_default_outbound_session_v2(&b1_binding, &states)
            .expect("select b1")
            .is_some());
        assert_eq!(
            disable_peer_device_sessions_v2(
                &mut states,
                ALICE_DID,
                ALICE_DEVICE,
                BOB_DID,
                "dev-bob-b1",
            )
            .expect("disable b1"),
            1
        );
        assert!(select_default_outbound_session_v2(&b1_binding, &states)
            .expect("b1 disabled")
            .is_none());
        assert!(select_default_outbound_session_v2(&b2_binding, &states)
            .expect("b2 remains")
            .is_some());
        assert!(!states[1].disabled);
    }

    #[test]
    fn device_and_key_tamper_fail_without_advancing_state() {
        let mut pair = establish_pair();
        let message_meta = metadata(
            &pair.alice_binding,
            "msg-tamper",
            CONTENT_TYPE_DIRECT_CIPHER_V2,
        );
        let plaintext = V2ApplicationPlaintext {
            application_content_type: "text/plain".to_owned(),
            logical_message_id: None,
            conversation_id: None,
            reply_to_message_id: None,
            annotations: None,
            text: Some("authenticated endpoints".to_owned()),
            payload: None,
            payload_b64u: None,
        };
        let (_, body) = V2DirectE2eeSession::encrypt_follow_up(
            &mut pair.alice_state,
            &pair.alice_binding,
            &message_meta,
            &plaintext,
        )
        .expect("encrypt message");
        let original = pair.bob_state.clone();

        let mut aad_tamper = message_meta.clone();
        aad_tamper.message_id = "msg-tamper-aad".to_owned();
        aad_tamper.operation_id = aad_tamper.message_id.clone();
        let error = V2DirectE2eeSession::decrypt_follow_up(
            &mut pair.bob_state,
            &pair.bob_binding,
            &aad_tamper,
            &body,
        )
        .expect_err("AAD tamper must fail");
        assert_runtime_kind(error, DirectE2eeV2RuntimeErrorKind::DecryptFailed);
        assert_eq!(pair.bob_state, original);

        let mut ciphertext_tamper = body.clone();
        let mut ciphertext = crate::keys::base64url_decode(&ciphertext_tamper.ciphertext_b64u)
            .expect("decode ciphertext");
        ciphertext[0] ^= 1;
        ciphertext_tamper.ciphertext_b64u = crate::keys::base64url_encode(&ciphertext);
        let error = V2DirectE2eeSession::decrypt_follow_up(
            &mut pair.bob_state,
            &pair.bob_binding,
            &message_meta,
            &ciphertext_tamper,
        )
        .expect_err("ciphertext tamper must fail");
        assert_runtime_kind(error, DirectE2eeV2RuntimeErrorKind::DecryptFailed);
        assert_eq!(pair.bob_state, original);

        let mut device_tamper = message_meta.clone();
        device_tamper.sender_device_id = "dev-alice-evil".to_owned();
        let error = V2DirectE2eeSession::decrypt_follow_up(
            &mut pair.bob_state,
            &pair.bob_binding,
            &device_tamper,
            &body,
        )
        .expect_err("device tamper must fail");
        assert_runtime_kind(error, DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding);
        assert_eq!(pair.bob_state, original);

        let mut key_tamper = pair.bob_binding.clone();
        key_tamper.peer_e2ee_key_id = format!("{ALICE_DID}#ka-attacker");
        let error = V2DirectE2eeSession::decrypt_follow_up(
            &mut pair.bob_state,
            &key_tamper,
            &message_meta,
            &body,
        )
        .expect_err("key tamper must fail");
        assert_runtime_kind(error, DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding);
        assert_eq!(pair.bob_state, original);
    }

    #[test]
    fn matched_skipped_key_is_consumed_after_ciphertext_or_aad_tamper() {
        for tamper_aad in [false, true] {
            let mut pair = establish_pair();
            let message_2_meta = metadata(
                &pair.alice_binding,
                "msg-skipped-2",
                CONTENT_TYPE_DIRECT_CIPHER_V2,
            );
            let message_3_meta = metadata(
                &pair.alice_binding,
                "msg-skipped-3",
                CONTENT_TYPE_DIRECT_CIPHER_V2,
            );
            let message_2 = V2ApplicationPlaintext {
                application_content_type: "text/plain".to_owned(),
                logical_message_id: None,
                conversation_id: None,
                reply_to_message_id: None,
                annotations: None,
                text: Some("second".to_owned()),
                payload: None,
                payload_b64u: None,
            };
            let message_3 = V2ApplicationPlaintext {
                text: Some("third".to_owned()),
                ..message_2.clone()
            };
            let (_, message_2_body) = V2DirectE2eeSession::encrypt_follow_up(
                &mut pair.alice_state,
                &pair.alice_binding,
                &message_2_meta,
                &message_2,
            )
            .expect("encrypt skipped message");
            let (_, message_3_body) = V2DirectE2eeSession::encrypt_follow_up(
                &mut pair.alice_state,
                &pair.alice_binding,
                &message_3_meta,
                &message_3,
            )
            .expect("encrypt later message");
            V2DirectE2eeSession::decrypt_follow_up(
                &mut pair.bob_state,
                &pair.bob_binding,
                &message_3_meta,
                &message_3_body,
            )
            .expect("decrypt later message out of order");
            assert_eq!(pair.bob_state.skipped_message_keys.len(), 1);

            let mut tampered_meta = message_2_meta.clone();
            let mut tampered_body = message_2_body.clone();
            if tamper_aad {
                tampered_meta.message_id = "msg-skipped-2-tampered".to_owned();
                tampered_meta.operation_id = tampered_meta.message_id.clone();
            } else {
                let mut ciphertext = crate::keys::base64url_decode(&tampered_body.ciphertext_b64u)
                    .expect("decode ciphertext");
                ciphertext[0] ^= 1;
                tampered_body.ciphertext_b64u = crate::keys::base64url_encode(&ciphertext);
            }
            let error = V2DirectE2eeSession::decrypt_follow_up(
                &mut pair.bob_state,
                &pair.bob_binding,
                &tampered_meta,
                &tampered_body,
            )
            .expect_err("matching skipped-key tamper must fail");
            assert_runtime_kind(error, DirectE2eeV2RuntimeErrorKind::DecryptFailed);
            assert!(
                pair.bob_state.skipped_message_keys.is_empty(),
                "P5 requires the matched skipped key to be consumed"
            );
            let error = V2DirectE2eeSession::decrypt_follow_up(
                &mut pair.bob_state,
                &pair.bob_binding,
                &message_2_meta,
                &message_2_body,
            )
            .expect_err("consumed skipped key cannot be retried");
            assert_runtime_kind(error, DirectE2eeV2RuntimeErrorKind::DecryptFailed);
        }
    }

    #[test]
    fn runtime_error_categories_match_the_frozen_p5_allocations() {
        for (kind, code, anp_code) in [
            (
                DirectE2eeV2RuntimeErrorKind::BadInitMessage,
                4007,
                "anp.direct.e2ee.bad_init_message",
            ),
            (
                DirectE2eeV2RuntimeErrorKind::ReplayDetected,
                4008,
                "anp.direct.e2ee.replay_detected",
            ),
            (
                DirectE2eeV2RuntimeErrorKind::DecryptFailed,
                4009,
                "anp.direct.e2ee.decrypt_failed",
            ),
            (
                DirectE2eeV2RuntimeErrorKind::MaxSkipExceeded,
                4010,
                "anp.direct.e2ee.max_skip_exceeded",
            ),
            (
                DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding,
                4012,
                "anp.direct.e2ee.invalid_security_binding",
            ),
        ] {
            let protocol = kind.protocol_error();
            assert_eq!(kind.code(), code);
            assert_eq!(kind.anp_code(), anp_code);
            assert_eq!(protocol.code, code);
            assert_eq!(protocol.anp_code, anp_code);
            assert_eq!(direct_e2ee_v2_error(code), Some(protocol));
            assert_runtime_kind(DirectE2eeV2Error::runtime(kind), kind);
        }
    }

    #[test]
    fn skipped_key_fifo_is_bounded_and_over_gap_failure_is_atomic() {
        let mut state = establish_pair().bob_state;
        let initial_recv_n = state.recv_n;
        skip_message_keys(&mut state, initial_recv_n + MAX_SKIP)
            .expect("exact MAX_SKIP gap is accepted");
        assert_eq!(state.skipped_message_keys.len(), MAX_SKIP as usize);
        let oldest = state.skipped_message_keys[0].clone();
        state.validate().expect("exact-bound state validates");

        let next_until = state.recv_n + 1;
        skip_message_keys(&mut state, next_until).expect("next insertion evicts oldest");
        assert_eq!(state.skipped_message_keys.len(), MAX_SKIP as usize);
        assert!(!state.skipped_message_keys.contains(&oldest));
        state.validate().expect("evicted state validates");

        let before_over_gap = state.clone();
        let error = skip_message_keys(&mut state, before_over_gap.recv_n + MAX_SKIP + 1)
            .expect_err("over-limit gap must fail");
        assert_runtime_kind(error, DirectE2eeV2RuntimeErrorKind::MaxSkipExceeded);
        assert_eq!(state, before_over_gap);
    }

    #[test]
    fn skipped_key_fifo_is_shared_across_dh_chains() {
        let mut state = establish_pair().bob_state;
        let old_dh = state
            .peer_ratchet_public_key_b64u
            .clone()
            .expect("old peer ratchet");
        let old_until = state.recv_n + 700;
        skip_message_keys(&mut state, old_until).expect("fill old chain");
        assert_eq!(state.skipped_message_keys.len(), 700);

        let new_peer = X25519PublicKey::from(&X25519StaticSecret::from([91u8; 32]));
        let new_dh = crate::keys::base64url_encode(&new_peer.to_bytes());
        ratchet_step(&mut state, &new_dh).expect("advance to new DH chain");
        skip_message_keys(&mut state, 700).expect("fill new chain and evict globally");

        assert_eq!(state.skipped_message_keys.len(), MAX_SKIP as usize);
        assert_eq!(
            state
                .skipped_message_keys
                .iter()
                .filter(|item| item.dh_pub_b64u == old_dh)
                .count(),
            300
        );
        assert_eq!(
            state
                .skipped_message_keys
                .iter()
                .filter(|item| item.dh_pub_b64u == new_dh)
                .count(),
            700
        );
        state.validate().expect("cross-DH bounded state validates");
    }

    #[test]
    fn multi_round_ratchet_decrypts_a_delayed_old_chain_message() {
        let mut pair = establish_pair();
        let delayed_meta = metadata(
            &pair.alice_binding,
            "msg-delayed-old-chain",
            CONTENT_TYPE_DIRECT_CIPHER_V2,
        );
        let (_, delayed_body) = V2DirectE2eeSession::encrypt_follow_up(
            &mut pair.alice_state,
            &pair.alice_binding,
            &delayed_meta,
            &text_plaintext("delayed across ratchets"),
        )
        .expect("encrypt delayed message");
        let later_meta = metadata(
            &pair.alice_binding,
            "msg-later-same-chain",
            CONTENT_TYPE_DIRECT_CIPHER_V2,
        );
        let (_, later_body) = V2DirectE2eeSession::encrypt_follow_up(
            &mut pair.alice_state,
            &pair.alice_binding,
            &later_meta,
            &text_plaintext("advance Alice chain"),
        )
        .expect("encrypt later message");
        V2DirectE2eeSession::decrypt_follow_up(
            &mut pair.bob_state,
            &pair.bob_binding,
            &later_meta,
            &later_body,
        )
        .expect("Bob skips delayed message");
        let delayed_dh = delayed_body.ratchet_header.dh_pub_b64u.clone();
        assert!(pair
            .bob_state
            .skipped_message_keys
            .iter()
            .any(|item| item.dh_pub_b64u == delayed_dh));

        let bob_meta = metadata(
            &pair.bob_binding,
            "msg-bob-next-ratchet",
            CONTENT_TYPE_DIRECT_CIPHER_V2,
        );
        let (_, bob_body) = V2DirectE2eeSession::encrypt_follow_up(
            &mut pair.bob_state,
            &pair.bob_binding,
            &bob_meta,
            &text_plaintext("advance Bob ratchet"),
        )
        .expect("Bob encrypts next ratchet message");
        V2DirectE2eeSession::decrypt_follow_up(
            &mut pair.alice_state,
            &pair.alice_binding,
            &bob_meta,
            &bob_body,
        )
        .expect("Alice advances and rotates send key");

        let alice_new_meta = metadata(
            &pair.alice_binding,
            "msg-alice-new-ratchet",
            CONTENT_TYPE_DIRECT_CIPHER_V2,
        );
        let (_, alice_new_body) = V2DirectE2eeSession::encrypt_follow_up(
            &mut pair.alice_state,
            &pair.alice_binding,
            &alice_new_meta,
            &text_plaintext("advance Alice ratchet again"),
        )
        .expect("Alice encrypts on new ratchet");
        assert_ne!(alice_new_body.ratchet_header.dh_pub_b64u, delayed_dh);
        V2DirectE2eeSession::decrypt_follow_up(
            &mut pair.bob_state,
            &pair.bob_binding,
            &alice_new_meta,
            &alice_new_body,
        )
        .expect("Bob advances to Alice's new DH chain");

        let delayed = V2DirectE2eeSession::decrypt_follow_up(
            &mut pair.bob_state,
            &pair.bob_binding,
            &delayed_meta,
            &delayed_body,
        )
        .expect("old-chain skipped key remains usable");
        assert_eq!(delayed.text.as_deref(), Some("delayed across ratchets"));
        assert!(!pair
            .bob_state
            .skipped_message_keys
            .iter()
            .any(|item| item.dh_pub_b64u == delayed_dh));
    }

    #[test]
    fn failed_decrypt_rolls_back_tentative_fifo_eviction_and_ratchet() {
        let mut pair = establish_pair();
        let old_dh = crate::keys::base64url_encode(&[97u8; 32]);
        pair.bob_state.skipped_message_keys = (0..MAX_SKIP)
            .map(|n| V2SkippedMessageKey {
                dh_pub_b64u: old_dh.clone(),
                n,
                message_key_b64u: crate::keys::base64url_encode(&[3u8; 32]),
                nonce_b64u: crate::keys::base64url_encode(&[4u8; 12]),
            })
            .collect();
        pair.bob_state
            .validate()
            .expect("full skipped-key state validates");
        let before = pair.bob_state.clone();

        let first_meta = metadata(
            &pair.alice_binding,
            "msg-eviction-first",
            CONTENT_TYPE_DIRECT_CIPHER_V2,
        );
        V2DirectE2eeSession::encrypt_follow_up(
            &mut pair.alice_state,
            &pair.alice_binding,
            &first_meta,
            &text_plaintext("intentionally skipped"),
        )
        .expect("encrypt skipped message");
        let second_meta = metadata(
            &pair.alice_binding,
            "msg-eviction-second",
            CONTENT_TYPE_DIRECT_CIPHER_V2,
        );
        let (_, mut second_body) = V2DirectE2eeSession::encrypt_follow_up(
            &mut pair.alice_state,
            &pair.alice_binding,
            &second_meta,
            &text_plaintext("tampered after tentative eviction"),
        )
        .expect("encrypt later message");
        let mut ciphertext =
            crate::keys::base64url_decode(&second_body.ciphertext_b64u).expect("decode ciphertext");
        ciphertext[0] ^= 1;
        second_body.ciphertext_b64u = crate::keys::base64url_encode(&ciphertext);

        let error = V2DirectE2eeSession::decrypt_follow_up(
            &mut pair.bob_state,
            &pair.bob_binding,
            &second_meta,
            &second_body,
        )
        .expect_err("tampered ciphertext must fail");
        assert_runtime_kind(error, DirectE2eeV2RuntimeErrorKind::DecryptFailed);
        assert_eq!(pair.bob_state, before);
    }

    #[test]
    fn first_reply_tamper_rolls_back_pending_confirmation_state() {
        let (alice_binding, bob_binding, mut alice_state, mut bob_state) =
            initiate_pair_before_reply();
        let reply_meta = metadata(
            &bob_binding,
            "msg-first-reply-tamper",
            CONTENT_TYPE_DIRECT_CIPHER_V2,
        );
        let (_, mut reply_body) = V2DirectE2eeSession::encrypt_follow_up(
            &mut bob_state,
            &bob_binding,
            &reply_meta,
            &text_plaintext("first reply"),
        )
        .expect("encrypt first reply");
        let original = alice_state.clone();
        let mut ciphertext =
            crate::keys::base64url_decode(&reply_body.ciphertext_b64u).expect("decode first reply");
        ciphertext[0] ^= 1;
        reply_body.ciphertext_b64u = crate::keys::base64url_encode(&ciphertext);

        let error = V2DirectE2eeSession::decrypt_follow_up(
            &mut alice_state,
            &alice_binding,
            &reply_meta,
            &reply_body,
        )
        .expect_err("tampered first reply must fail");
        assert_runtime_kind(error, DirectE2eeV2RuntimeErrorKind::DecryptFailed);
        assert_eq!(alice_state, original);

        let mut bad_header = reply_body;
        bad_header.ratchet_header.n = "1".to_owned();
        let error = V2DirectE2eeSession::decrypt_follow_up(
            &mut alice_state,
            &alice_binding,
            &reply_meta,
            &bad_header,
        )
        .expect_err("invalid first reply header must fail");
        assert_runtime_kind(error, DirectE2eeV2RuntimeErrorKind::BadInitMessage);
        assert_eq!(alice_state, original);
    }

    #[test]
    fn state_validation_and_mutations_fail_closed_and_atomically() {
        let mut pair = establish_pair();
        let mut bad_binding = pair.alice_binding.clone();
        bad_binding.local_e2ee_key_id = "ka-not-a-did-url".to_owned();
        assert!(bad_binding.validate().is_err());

        let mut mismatched_ratchet = pair.alice_state.clone();
        mismatched_ratchet.ratchet_public_key_b64u = crate::keys::base64url_encode(&[99u8; 32]);
        assert!(mismatched_ratchet.validate().is_err());

        let fixed32 = crate::keys::base64url_encode(&[3u8; 32]);
        let fixed12 = crate::keys::base64url_encode(&[4u8; 12]);
        let skipped = V2SkippedMessageKey {
            dh_pub_b64u: pair
                .alice_state
                .peer_ratchet_public_key_b64u
                .clone()
                .expect("peer ratchet"),
            n: 7,
            message_key_b64u: fixed32,
            nonce_b64u: fixed12,
        };
        let mut duplicate_skipped = pair.alice_state.clone();
        duplicate_skipped.skipped_message_keys = vec![skipped.clone(), skipped];
        assert!(duplicate_skipped.validate().is_err());

        let mut too_many_skipped = pair.alice_state.clone();
        too_many_skipped.skipped_message_keys = (0..=MAX_SKIP)
            .map(|n| V2SkippedMessageKey {
                dh_pub_b64u: pair
                    .alice_state
                    .peer_ratchet_public_key_b64u
                    .clone()
                    .expect("peer ratchet"),
                n,
                message_key_b64u: crate::keys::base64url_encode(&[3u8; 32]),
                nonce_b64u: crate::keys::base64url_encode(&[4u8; 12]),
            })
            .collect();
        assert!(too_many_skipped.validate().is_err());

        let before_overflow = pair.alice_state.clone();
        pair.alice_state.send_n = u32::MAX;
        let overflow_before_call = pair.alice_state.clone();
        let overflow_meta = metadata(
            &pair.alice_binding,
            "msg-overflow",
            CONTENT_TYPE_DIRECT_CIPHER_V2,
        );
        let overflow_plaintext = V2ApplicationPlaintext {
            application_content_type: "text/plain".to_owned(),
            logical_message_id: None,
            conversation_id: None,
            reply_to_message_id: None,
            annotations: None,
            text: Some("must not advance".to_owned()),
            payload: None,
            payload_b64u: None,
        };
        assert!(V2DirectE2eeSession::encrypt_follow_up(
            &mut pair.alice_state,
            &pair.alice_binding,
            &overflow_meta,
            &overflow_plaintext,
        )
        .is_err());
        assert_eq!(pair.alice_state, overflow_before_call);
        pair.alice_state = before_overflow;

        let mut sessions = vec![pair.alice_state.clone(), pair.alice_state.clone()];
        sessions[1].ratchet_public_key_b64u = crate::keys::base64url_encode(&[88u8; 32]);
        assert!(disable_peer_device_sessions_v2(
            &mut sessions,
            ALICE_DID,
            ALICE_DEVICE,
            BOB_DID,
            BOB_DEVICE,
        )
        .is_err());
        assert!(!sessions[0].disabled);
        assert!(!sessions[1].disabled);
    }

    #[test]
    fn bundle_device_and_key_mismatch_are_rejected_before_crypto() {
        let exact = binding(ALICE_DID, ALICE_DEVICE, BOB_DID, BOB_DEVICE);
        let local_static = X25519StaticSecret::from([51u8; 32]);
        let peer_static = X25519StaticSecret::from([53u8; 32]);
        let peer_spk = X25519StaticSecret::from([55u8; 32]);
        let init_meta = metadata(&exact, "msg-bundle", CONTENT_TYPE_DIRECT_INIT_V2);
        let plaintext = V2ApplicationPlaintext {
            application_content_type: "text/plain".to_owned(),
            logical_message_id: None,
            conversation_id: None,
            reply_to_message_id: None,
            annotations: None,
            text: Some("bundle binding".to_owned()),
            payload: None,
            payload_b64u: None,
        };
        let mut wrong_device = bundle(BOB_DID, "dev-bob-other", &exact.peer_e2ee_key_id, &peer_spk);
        let error = V2DirectE2eeSession::initiate_session(
            &exact,
            &init_meta,
            &local_static,
            &wrong_device,
            &X25519PublicKey::from(&peer_static).to_bytes(),
            None,
            &plaintext,
        )
        .expect_err("wrong Bundle device must fail");
        assert_runtime_kind(error, DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding);
        wrong_device.owner_device_id = BOB_DEVICE.to_owned();
        wrong_device.static_key_agreement_id = format!("{BOB_DID}#ka-wrong");
        let error = V2DirectE2eeSession::initiate_session(
            &exact,
            &init_meta,
            &local_static,
            &wrong_device,
            &X25519PublicKey::from(&peer_static).to_bytes(),
            None,
            &plaintext,
        )
        .expect_err("wrong Bundle key must fail");
        assert_runtime_kind(error, DirectE2eeV2RuntimeErrorKind::InvalidSecurityBinding);
    }

    #[test]
    fn v1_and_v2_session_and_pending_json_are_not_interchangeable() {
        let pair = establish_pair();
        let v2_json = serialize_session_state_v2(&pair.alice_state).expect("serialize v2 state");
        assert!(serde_json::from_slice::<DirectSessionState>(&v2_json).is_err());
        assert_eq!(
            deserialize_session_state_v2(&v2_json).expect("deserialize v2 state"),
            pair.alice_state
        );

        let fixed32 = crate::keys::base64url_encode(&[1u8; 32]);
        let v1 = DirectSessionState {
            session_id: crate::keys::base64url_encode(&[2u8; 16]),
            suite: crate::direct_e2ee::models::MTI_DIRECT_E2EE_SUITE.to_owned(),
            peer_did: BOB_DID.to_owned(),
            local_key_agreement_id: format!("{ALICE_DID}#ka-v1"),
            peer_key_agreement_id: format!("{BOB_DID}#ka-v1"),
            root_key_b64u: fixed32.clone(),
            send_chain_key_b64u: Some(fixed32.clone()),
            recv_chain_key_b64u: Some(fixed32.clone()),
            ratchet_private_key_b64u: fixed32.clone(),
            ratchet_public_key_b64u: fixed32.clone(),
            peer_ratchet_public_key_b64u: Some(fixed32),
            send_n: 0,
            recv_n: 0,
            previous_send_chain_length: 0,
            skipped_message_keys: vec![],
            is_initiator: true,
            status: crate::direct_e2ee::models::SESSION_STATUS_ESTABLISHED.to_owned(),
        };
        let v1_json = serde_json::to_vec(&v1).expect("serialize v1 state");
        assert!(deserialize_session_state_v2(&v1_json).is_err());

        let pending_meta = metadata(
            &pair.alice_binding,
            "msg-pending",
            CONTENT_TYPE_DIRECT_CIPHER_V2,
        );
        let body = V2DirectCipherBody {
            session_id: pair.alice_state.session_id.clone(),
            suite: Some(MTI_DIRECT_E2EE_SUITE_V2.to_owned()),
            ratchet_header: V2RatchetHeader {
                dh_pub_b64u: pair.alice_state.ratchet_public_key_b64u.clone(),
                pn: "0".to_owned(),
                n: "0".to_owned(),
            },
            ciphertext_b64u: crate::keys::base64url_encode(&[8u8; 16]),
        };
        let v2_pending =
            pending_record(&pair.alice_binding, &pending_meta, &body).expect("build v2 pending");
        let v2_pending_json =
            serialize_pending_outbound_v2(&v2_pending).expect("serialize v2 pending");
        assert!(serde_json::from_slice::<PendingOutboundRecord>(&v2_pending_json).is_err());
        assert_eq!(
            deserialize_pending_outbound_v2(&v2_pending_json).expect("deserialize v2 pending"),
            v2_pending
        );
    }

    #[test]
    fn deterministic_v2_init_vector_is_stable() {
        let exact = binding(ALICE_DID, ALICE_DEVICE, BOB_DID, BOB_DEVICE);
        let alice_static = X25519StaticSecret::from([61u8; 32]);
        let bob_static = X25519StaticSecret::from([63u8; 32]);
        let bob_spk = X25519StaticSecret::from([65u8; 32]);
        let ephemeral = X25519StaticSecret::from([67u8; 32]);
        let bob_bundle = bundle(BOB_DID, BOB_DEVICE, &exact.peer_e2ee_key_id, &bob_spk);
        let init_meta = metadata(&exact, "msg-fixed-vector", CONTENT_TYPE_DIRECT_INIT_V2);
        let plaintext = V2ApplicationPlaintext {
            application_content_type: "application/json".to_owned(),
            logical_message_id: Some("logical-fixed-vector".to_owned()),
            conversation_id: None,
            reply_to_message_id: None,
            annotations: Some(json!({})),
            text: None,
            payload: Some(json!({"fixed": true, "value": 7})),
            payload_b64u: None,
        };
        let (state, _, body) = V2DirectE2eeSession::initiate_session_with_ephemeral(
            &exact,
            &init_meta,
            &alice_static,
            &bob_bundle,
            &X25519PublicKey::from(&bob_static).to_bytes(),
            None,
            &plaintext,
            &ephemeral,
        )
        .expect("fixed vector init");
        assert_eq!(state.session_id, "l28SwKRtwFLRjf7iezWzNg");
        assert_eq!(body.session_id, "l28SwKRtwFLRjf7iezWzNg");
        assert_eq!(
            body.ciphertext_b64u,
            "P_JaHy9ckgbdukB7249JKsof7SrFbZqldyPxrw6Qvcu0M4DbdzNJ3DqyarBw1WKyjop0NHs2BlGBha1t2cXLpYGVXV5rNi3dm2a8ByKj4Kegh8q5pnCJIyjz7quI0taOxDZneprGqBu-0dcAiPh7h2RmWGGIK-EkAP9OmFYjAEAiGk7JUSHEBAHIKLJIfWidGPAdXcd89KCLQCHh-9kv"
        );
    }

    #[test]
    fn secret_session_material_is_redacted_from_debug() {
        let pair = establish_pair();
        let debug = format!("{:?}", pair.alice_state);
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&pair.alice_state.root_key_b64u));
        assert!(!debug.contains(&pair.alice_state.ratchet_private_key_b64u));
    }
}
