use std::collections::HashSet;
use std::fmt;

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use super::ratchet::{
    decrypt_with_step, derive_chain_step, derive_root_step, encrypt_with_step, ChainStep, MAX_SKIP,
};
use super::v2_aad::{build_init_aad_v2, build_message_aad_v2, canonical_application_plaintext_v2};
use super::v2_errors::DirectE2eeV2Error;
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
        for (field, value) in [
            ("binding.local_did", self.local_did.as_str()),
            ("binding.local_device_id", self.local_device_id.as_str()),
            ("binding.peer_did", self.peer_did.as_str()),
            ("binding.peer_device_id", self.peer_device_id.as_str()),
            ("binding.local_e2ee_key_id", self.local_e2ee_key_id.as_str()),
            ("binding.peer_e2ee_key_id", self.peer_e2ee_key_id.as_str()),
        ] {
            if value.is_empty() {
                return Err(DirectE2eeV2Error::invalid(format!(
                    "{field} must be a non-empty string"
                )));
            }
        }
        if self.suite != MTI_DIRECT_E2EE_SUITE_V2 {
            return Err(DirectE2eeV2Error::invalid(
                "binding.suite must equal the P5 v2 MTI suite",
            ));
        }
        if self.local_did == self.peer_did && self.local_device_id == self.peer_device_id {
            return Err(DirectE2eeV2Error::invalid(
                "a P5 v2 session cannot target the same DID and device as its local endpoint",
            ));
        }
        validate_key_id_for_did(
            "binding.local_e2ee_key_id",
            &self.local_e2ee_key_id,
            &self.local_did,
        )?;
        validate_key_id_for_did(
            "binding.peer_e2ee_key_id",
            &self.peer_e2ee_key_id,
            &self.peer_did,
        )?;
        if self.local_e2ee_key_id == self.peer_e2ee_key_id {
            return Err(DirectE2eeV2Error::invalid(
                "local and peer devices must use distinct E2EE key references",
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
            return Err(DirectE2eeV2Error::invalid(
                "outbound metadata does not match the exact session device pair",
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
            return Err(DirectE2eeV2Error::invalid(
                "inbound metadata does not match the exact session device pair",
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
        self.validate()?;
        expected_binding.validate()?;
        if &self.binding != expected_binding {
            return Err(DirectE2eeV2Error::invalid(
                "session state does not match the current exact device/key binding",
            ));
        }
        if self.disabled {
            return Err(DirectE2eeV2Error::invalid(
                "session state is disabled for this peer device",
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
        Self::initiate_session_with_ephemeral(
            binding,
            metadata,
            local_static_private,
            recipient_bundle,
            recipient_static_public,
            recipient_one_time_prekey,
            plaintext,
            &ephemeral,
        )
    }

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
        binding.validate_outbound_metadata(metadata, CONTENT_TYPE_DIRECT_INIT_V2)?;
        validate_recipient_bundle(binding, recipient_bundle)?;
        plaintext.validate()?;

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
        .map_err(runtime_crypto_error)?;
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
        let plaintext_bytes = canonical_application_plaintext_v2(plaintext)?;
        body.ciphertext_b64u = crate::keys::base64url_encode(
            &encrypt_with_step(&init_step, &plaintext_bytes, &aad).map_err(runtime_crypto_error)?,
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
        binding.validate_inbound_metadata(metadata, CONTENT_TYPE_DIRECT_INIT_V2)?;
        validate_local_bundle(binding, local_bundle, local_signed_prekey_private)?;
        body.validate()?;
        if body.sender_static_key_agreement_id != binding.peer_e2ee_key_id
            || body.recipient_bundle_id != local_bundle.bundle_id
            || body.recipient_signed_prekey_id != local_bundle.signed_prekey.key_id
        {
            return Err(DirectE2eeV2Error::invalid(
                "init key or Bundle references do not match the exact device pair",
            ));
        }

        let (local_opk_private, consumed_opk_id) = match (
            body.recipient_one_time_prekey_id.as_deref(),
            local_one_time_prekey,
        ) {
            (None, None) => (None, None),
            (Some(expected_id), Some((opk, private))) if expected_id == opk.key_id => {
                opk.validate()?;
                let expected_public =
                    decode_fixed::<32>("one_time_prekey.public_key_b64u", &opk.public_key_b64u)?;
                if X25519PublicKey::from(private).to_bytes() != expected_public {
                    return Err(DirectE2eeV2Error::invalid(
                        "one-time prekey private material does not match its public record",
                    ));
                }
                (Some(private), Some(opk.key_id.clone()))
            }
            _ => {
                return Err(DirectE2eeV2Error::invalid(
                    "init one-time prekey reference does not match local device material",
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
        .map_err(runtime_crypto_error)?;
        if body.session_id != initial.session_id {
            return Err(DirectE2eeV2Error::invalid(
                "body.session_id does not match the derived P5 v2 session",
            ));
        }
        let aad = build_init_aad_v2(metadata, body)?;
        let init_step = derive_chain_step(&initial.chain_key);
        let plaintext = decrypt_plaintext(
            &init_step,
            &body.ciphertext_b64u,
            &aad,
            "body.ciphertext_b64u",
        )?;

        let ratchet_private = X25519StaticSecret::random_from_rng(OsRng);
        let ratchet_public = X25519PublicKey::from(&ratchet_private).to_bytes();
        let dh = ratchet_private.diffie_hellman(&X25519PublicKey::from(sender_ephemeral_public));
        let root_step =
            derive_root_step(&initial.root_key, &dh.to_bytes()).map_err(runtime_crypto_error)?;
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
        state.validate_for(expected_binding)?;
        expected_binding.validate_outbound_metadata(metadata, CONTENT_TYPE_DIRECT_CIPHER_V2)?;
        if state.status != V2_SESSION_STATUS_ESTABLISHED {
            return Err(DirectE2eeV2Error::invalid(
                "pending-confirmation sessions cannot send follow-up ciphertext",
            ));
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
            &encrypt_with_step(&step, &canonical_application_plaintext_v2(plaintext)?, &aad)
                .map_err(runtime_crypto_error)?,
        );
        body.validate()?;
        let pending = pending_record(expected_binding, metadata, &body)?;
        state.send_chain_key_b64u = Some(crate::keys::base64url_encode(&step.next_chain_key));
        state.send_n = next_send_n;
        Ok((pending, body))
    }

    pub fn decrypt_follow_up(
        state: &mut V2DirectSessionState,
        expected_binding: &V2SessionBinding,
        metadata: &V2DirectMetadata,
        body: &V2DirectCipherBody,
    ) -> Result<V2ApplicationPlaintext, DirectE2eeV2Error> {
        state.validate_for(expected_binding)?;
        expected_binding.validate_inbound_metadata(metadata, CONTENT_TYPE_DIRECT_CIPHER_V2)?;
        body.validate()?;
        if body.session_id != state.session_id {
            return Err(DirectE2eeV2Error::invalid(
                "cipher body does not match the selected session_id",
            ));
        }
        if let Some(suite) = body.suite.as_deref() {
            if suite != state.binding.suite {
                return Err(DirectE2eeV2Error::invalid(
                    "cipher body suite does not match the selected session",
                ));
            }
        }
        if state.status == V2_SESSION_STATUS_PENDING_CONFIRMATION {
            return decrypt_first_reply(state, metadata, body);
        }

        let mut skipped_state = state.clone();
        match try_skipped_message_key(&mut skipped_state, metadata, body) {
            Ok(Some(plaintext)) => {
                *state = skipped_state;
                return Ok(plaintext);
            }
            Ok(None) => {}
            Err(error) => {
                if skipped_state.skipped_message_keys != state.skipped_message_keys {
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
            return Err(DirectE2eeV2Error::invalid("duplicate P5 v2 message number"));
        }
        skip_message_keys(&mut next_state, n)?;
        let recv_chain_key = decode_fixed::<32>(
            "state.recv_chain_key_b64u",
            next_state.recv_chain_key_b64u.as_deref().ok_or_else(|| {
                DirectE2eeV2Error::invalid("established session has no receive chain")
            })?,
        )?;
        let step = derive_chain_step(&recv_chain_key);
        let plaintext = decrypt_cipher_plaintext(&step, metadata, body)?;
        next_state.recv_chain_key_b64u = Some(crate::keys::base64url_encode(&step.next_chain_key));
        next_state.recv_n = n
            .checked_add(1)
            .ok_or_else(|| DirectE2eeV2Error::invalid("receive counter overflow"))?;
        *state = next_state;
        Ok(plaintext)
    }
}

fn validate_recipient_bundle(
    binding: &V2SessionBinding,
    bundle: &V2PrekeyBundle,
) -> Result<(), DirectE2eeV2Error> {
    bundle.validate_structure()?;
    if bundle.owner_did != binding.peer_did
        || bundle.owner_device_id != binding.peer_device_id
        || bundle.suite != binding.suite
        || bundle.static_key_agreement_id != binding.peer_e2ee_key_id
    {
        return Err(DirectE2eeV2Error::invalid(
            "recipient Bundle does not match the exact peer device/key binding",
        ));
    }
    Ok(())
}

fn validate_local_bundle(
    binding: &V2SessionBinding,
    bundle: &V2PrekeyBundle,
    signed_prekey_private: &X25519StaticSecret,
) -> Result<(), DirectE2eeV2Error> {
    bundle.validate_structure()?;
    if bundle.owner_did != binding.local_did
        || bundle.owner_device_id != binding.local_device_id
        || bundle.suite != binding.suite
        || bundle.static_key_agreement_id != binding.local_e2ee_key_id
    {
        return Err(DirectE2eeV2Error::invalid(
            "local Bundle does not match the exact local device/key binding",
        ));
    }
    let expected_spk = decode_fixed::<32>(
        "prekey_bundle.signed_prekey.public_key_b64u",
        &bundle.signed_prekey.public_key_b64u,
    )?;
    if X25519PublicKey::from(signed_prekey_private).to_bytes() != expected_spk {
        return Err(DirectE2eeV2Error::invalid(
            "signed prekey private material does not match the local Bundle",
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

fn decrypt_first_reply(
    state: &mut V2DirectSessionState,
    metadata: &V2DirectMetadata,
    body: &V2DirectCipherBody,
) -> Result<V2ApplicationPlaintext, DirectE2eeV2Error> {
    if body.ratchet_header.pn != "0" || body.ratchet_header.n != "0" {
        return Err(DirectE2eeV2Error::invalid(
            "first reply header must use pn=0 and n=0",
        ));
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
    .map_err(runtime_crypto_error)?;
    let new_private = X25519StaticSecret::random_from_rng(OsRng);
    let send_root = derive_root_step(
        &recv_root.root_key,
        &new_private.diffie_hellman(&peer_public).to_bytes(),
    )
    .map_err(runtime_crypto_error)?;
    let step = derive_chain_step(&recv_root.chain_key);
    let plaintext = decrypt_cipher_plaintext(&step, metadata, body)?;
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
    .map_err(runtime_crypto_error)?;
    let new_private = X25519StaticSecret::random_from_rng(OsRng);
    let send_root = derive_root_step(
        &recv_root.root_key,
        &new_private.diffie_hellman(&peer_public).to_bytes(),
    )
    .map_err(runtime_crypto_error)?;
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
) -> Result<Option<V2ApplicationPlaintext>, DirectE2eeV2Error> {
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
    decrypt_cipher_plaintext(&step, metadata, body).map(Some)
}

fn skip_message_keys(
    state: &mut V2DirectSessionState,
    until_n: u32,
) -> Result<(), DirectE2eeV2Error> {
    if until_n < state.recv_n {
        return Ok(());
    }
    if until_n.saturating_sub(state.recv_n) > MAX_SKIP {
        return Err(DirectE2eeV2Error::invalid(
            "P5 v2 message skip exceeded MAX_SKIP",
        ));
    }
    let mut recv_chain_key = decode_fixed::<32>(
        "state.recv_chain_key_b64u",
        state.recv_chain_key_b64u.as_deref().ok_or_else(|| {
            DirectE2eeV2Error::invalid("session has no receive chain for skipped messages")
        })?,
    )?;
    while state.recv_n < until_n {
        let step = derive_chain_step(&recv_chain_key);
        state.skipped_message_keys.push(V2SkippedMessageKey {
            dh_pub_b64u: state.peer_ratchet_public_key_b64u.clone().ok_or_else(|| {
                DirectE2eeV2Error::invalid("session has no peer ratchet public key")
            })?,
            n: state.recv_n,
            message_key_b64u: crate::keys::base64url_encode(&step.message_key),
            nonce_b64u: crate::keys::base64url_encode(&step.nonce),
        });
        recv_chain_key = step.next_chain_key;
        state.recv_n += 1;
    }
    state.recv_chain_key_b64u = Some(crate::keys::base64url_encode(&recv_chain_key));
    Ok(())
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

fn decrypt_cipher_plaintext(
    step: &ChainStep,
    metadata: &V2DirectMetadata,
    body: &V2DirectCipherBody,
) -> Result<V2ApplicationPlaintext, DirectE2eeV2Error> {
    decrypt_plaintext(
        step,
        &body.ciphertext_b64u,
        &build_message_aad_v2(metadata, body)?,
        "body.ciphertext_b64u",
    )
}

fn decrypt_plaintext(
    step: &ChainStep,
    ciphertext_b64u: &str,
    aad: &[u8],
    ciphertext_field: &str,
) -> Result<V2ApplicationPlaintext, DirectE2eeV2Error> {
    let ciphertext = crate::keys::base64url_decode(ciphertext_b64u)
        .map_err(|_| DirectE2eeV2Error::invalid(format!("{ciphertext_field} is not base64url")))?;
    let plaintext_bytes =
        decrypt_with_step(step, &ciphertext, aad).map_err(runtime_crypto_error)?;
    let plaintext: V2ApplicationPlaintext = serde_json::from_slice(&plaintext_bytes)?;
    let canonical = canonical_application_plaintext_v2(&plaintext)?;
    if canonical != plaintext_bytes {
        return Err(DirectE2eeV2Error::invalid(
            "decrypted Application Plaintext is not RFC 8785 canonical JSON",
        ));
    }
    Ok(plaintext)
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

fn runtime_crypto_error(_error: super::errors::DirectE2eeError) -> DirectE2eeV2Error {
    DirectE2eeV2Error::invalid("P5 v2 cryptographic operation failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct_e2ee::{
        DirectSessionState, PendingOutboundRecord, V2SignedPrekey, V2Target,
        DIRECT_E2EE_PROFILE_V2, DIRECT_E2EE_SECURITY_PROFILE,
    };
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
        assert!(V2DirectE2eeSession::decrypt_follow_up(
            &mut pair.bob_state,
            &pair.bob_binding,
            &aad_tamper,
            &body,
        )
        .is_err());
        assert_eq!(pair.bob_state, original);

        let mut ciphertext_tamper = body.clone();
        let mut ciphertext = crate::keys::base64url_decode(&ciphertext_tamper.ciphertext_b64u)
            .expect("decode ciphertext");
        ciphertext[0] ^= 1;
        ciphertext_tamper.ciphertext_b64u = crate::keys::base64url_encode(&ciphertext);
        assert!(V2DirectE2eeSession::decrypt_follow_up(
            &mut pair.bob_state,
            &pair.bob_binding,
            &message_meta,
            &ciphertext_tamper,
        )
        .is_err());
        assert_eq!(pair.bob_state, original);

        let mut device_tamper = message_meta.clone();
        device_tamper.sender_device_id = "dev-alice-evil".to_owned();
        assert!(V2DirectE2eeSession::decrypt_follow_up(
            &mut pair.bob_state,
            &pair.bob_binding,
            &device_tamper,
            &body,
        )
        .is_err());
        assert_eq!(pair.bob_state, original);

        let mut key_tamper = pair.bob_binding.clone();
        key_tamper.peer_e2ee_key_id = format!("{ALICE_DID}#ka-attacker");
        assert!(V2DirectE2eeSession::decrypt_follow_up(
            &mut pair.bob_state,
            &key_tamper,
            &message_meta,
            &body,
        )
        .is_err());
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
            assert!(V2DirectE2eeSession::decrypt_follow_up(
                &mut pair.bob_state,
                &pair.bob_binding,
                &tampered_meta,
                &tampered_body,
            )
            .is_err());
            assert!(
                pair.bob_state.skipped_message_keys.is_empty(),
                "P5 requires the matched skipped key to be consumed"
            );
            assert!(V2DirectE2eeSession::decrypt_follow_up(
                &mut pair.bob_state,
                &pair.bob_binding,
                &message_2_meta,
                &message_2_body,
            )
            .is_err());
        }
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
        assert!(V2DirectE2eeSession::initiate_session(
            &exact,
            &init_meta,
            &local_static,
            &wrong_device,
            &X25519PublicKey::from(&peer_static).to_bytes(),
            None,
            &plaintext,
        )
        .is_err());
        wrong_device.owner_device_id = BOB_DEVICE.to_owned();
        wrong_device.static_key_agreement_id = format!("{BOB_DID}#ka-wrong");
        assert!(V2DirectE2eeSession::initiate_session(
            &exact,
            &init_meta,
            &local_static,
            &wrong_device,
            &X25519PublicKey::from(&peer_static).to_bytes(),
            None,
            &plaintext,
        )
        .is_err());
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
