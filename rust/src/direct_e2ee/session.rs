use super::aad::{
    build_init_aad, build_message_aad, CONTENT_TYPE_DIRECT_CIPHER, CONTENT_TYPE_DIRECT_INIT,
};
use super::errors::DirectE2eeError;
use super::models::{
    ApplicationPlaintext, DirectCipherBody, DirectEnvelopeMetadata, DirectInitBody,
    DirectSessionState, PendingOutboundRecord, PrekeyBundle, RatchetHeader, MTI_DIRECT_E2EE_SUITE,
    SESSION_STATUS_ESTABLISHED, SESSION_STATUS_PENDING_CONFIRMATION,
};
use super::ratchet::{
    decrypt_with_step, derive_chain_step, derive_root_step, encrypt_with_step, MAX_SKIP,
};
use super::x3dh::{
    derive_initial_material_for_initiator, derive_initial_material_for_initiator_with_opk,
    derive_initial_material_for_responder, derive_initial_material_for_responder_with_opk,
};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

pub struct DirectE2eeSession;

impl DirectE2eeSession {
    #[allow(clippy::too_many_arguments)]
    pub fn initiate_session(
        metadata: &DirectEnvelopeMetadata,
        operation_id: &str,
        local_static_key_id: &str,
        local_static_private: &X25519StaticSecret,
        recipient_bundle: &PrekeyBundle,
        recipient_static_public: &[u8; 32],
        recipient_signed_prekey_public: &[u8; 32],
        plaintext: &ApplicationPlaintext,
    ) -> Result<(DirectSessionState, PendingOutboundRecord, DirectInitBody), DirectE2eeError> {
        Self::initiate_session_with_opk(
            metadata,
            operation_id,
            local_static_key_id,
            local_static_private,
            recipient_bundle,
            recipient_static_public,
            recipient_signed_prekey_public,
            None,
            None,
            plaintext,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn initiate_session_with_opk(
        metadata: &DirectEnvelopeMetadata,
        operation_id: &str,
        local_static_key_id: &str,
        local_static_private: &X25519StaticSecret,
        recipient_bundle: &PrekeyBundle,
        recipient_static_public: &[u8; 32],
        recipient_signed_prekey_public: &[u8; 32],
        recipient_one_time_prekey_public: Option<&[u8; 32]>,
        recipient_one_time_prekey_id: Option<String>,
        plaintext: &ApplicationPlaintext,
    ) -> Result<(DirectSessionState, PendingOutboundRecord, DirectInitBody), DirectE2eeError> {
        if recipient_bundle.suite != MTI_DIRECT_E2EE_SUITE {
            return Err(DirectE2eeError::UnsupportedSuite(
                recipient_bundle.suite.clone(),
            ));
        }
        let sender_ephemeral_private = X25519StaticSecret::random_from_rng(OsRng);
        let sender_ephemeral_public = X25519PublicKey::from(&sender_ephemeral_private).to_bytes();
        let initial = if recipient_one_time_prekey_public.is_some() {
            derive_initial_material_for_initiator_with_opk(
                local_static_private,
                &sender_ephemeral_private,
                recipient_static_public,
                recipient_signed_prekey_public,
                recipient_one_time_prekey_public,
            )?
        } else {
            derive_initial_material_for_initiator(
                local_static_private,
                &sender_ephemeral_private,
                recipient_static_public,
                recipient_signed_prekey_public,
            )?
        };
        let mut body = DirectInitBody {
            session_id: initial.session_id.clone(),
            suite: MTI_DIRECT_E2EE_SUITE.to_owned(),
            sender_static_key_agreement_id: local_static_key_id.to_owned(),
            recipient_bundle_id: recipient_bundle.bundle_id.clone(),
            recipient_signed_prekey_id: recipient_bundle.signed_prekey.key_id.clone(),
            recipient_one_time_prekey_id,
            sender_ephemeral_pub_b64u: crate::keys::base64url_encode(&sender_ephemeral_public),
            ciphertext_b64u: String::new(),
        };
        let aad = build_init_aad(metadata, &body)?;
        let init_step = derive_chain_step(&initial.chain_key);
        let plaintext_bytes = serialize_plaintext(plaintext)?;
        body.ciphertext_b64u =
            crate::keys::base64url_encode(&encrypt_with_step(&init_step, &plaintext_bytes, &aad)?);
        let session = DirectSessionState {
            session_id: initial.session_id.clone(),
            suite: MTI_DIRECT_E2EE_SUITE.to_owned(),
            peer_did: metadata.recipient_did.clone(),
            local_key_agreement_id: local_static_key_id.to_owned(),
            peer_key_agreement_id: recipient_bundle.static_key_agreement_id.clone(),
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
            status: SESSION_STATUS_PENDING_CONFIRMATION.to_owned(),
        };
        let pending = PendingOutboundRecord {
            operation_id: operation_id.to_owned(),
            message_id: metadata.message_id.clone(),
            wire_content_type: CONTENT_TYPE_DIRECT_INIT.to_owned(),
            body_json: serde_json::to_value(&body).map_err(|error| {
                DirectE2eeError::invalid_field(format!("invalid init body: {error}"))
            })?,
        };
        Ok((session, pending, body))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn accept_incoming_init(
        metadata: &DirectEnvelopeMetadata,
        local_static_key_id: &str,
        local_static_private: &X25519StaticSecret,
        local_signed_prekey_private: &X25519StaticSecret,
        sender_static_public: &[u8; 32],
        body: &DirectInitBody,
    ) -> Result<(DirectSessionState, ApplicationPlaintext), DirectE2eeError> {
        Self::accept_incoming_init_with_opk(
            metadata,
            local_static_key_id,
            local_static_private,
            local_signed_prekey_private,
            None,
            sender_static_public,
            body,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn accept_incoming_init_with_opk(
        metadata: &DirectEnvelopeMetadata,
        local_static_key_id: &str,
        local_static_private: &X25519StaticSecret,
        local_signed_prekey_private: &X25519StaticSecret,
        local_one_time_prekey_private: Option<&X25519StaticSecret>,
        sender_static_public: &[u8; 32],
        body: &DirectInitBody,
    ) -> Result<(DirectSessionState, ApplicationPlaintext), DirectE2eeError> {
        let sender_ephemeral_public = decode_fixed_32(&body.sender_ephemeral_pub_b64u)?;
        let initial = if local_one_time_prekey_private.is_some() {
            derive_initial_material_for_responder_with_opk(
                local_static_private,
                local_signed_prekey_private,
                local_one_time_prekey_private,
                sender_static_public,
                &sender_ephemeral_public,
            )?
        } else {
            derive_initial_material_for_responder(
                local_static_private,
                local_signed_prekey_private,
                sender_static_public,
                &sender_ephemeral_public,
            )?
        };
        if body.session_id != initial.session_id {
            return Err(DirectE2eeError::invalid_field(
                "session_id does not match derived session",
            ));
        }
        let aad = build_init_aad(metadata, body)?;
        let init_step = derive_chain_step(&initial.chain_key);
        let ciphertext = crate::keys::base64url_decode(&body.ciphertext_b64u)
            .map_err(|_| DirectE2eeError::invalid_field("ciphertext_b64u"))?;
        let plaintext_bytes = decrypt_with_step(&init_step, &ciphertext, &aad)?;
        let plaintext: ApplicationPlaintext =
            serde_json::from_slice(&plaintext_bytes).map_err(|error| {
                DirectE2eeError::invalid_field(format!("invalid plaintext json: {error}"))
            })?;
        let ratchet_private = X25519StaticSecret::random_from_rng(OsRng);
        let ratchet_public = X25519PublicKey::from(&ratchet_private).to_bytes();
        let dh = ratchet_private.diffie_hellman(&X25519PublicKey::from(sender_ephemeral_public));
        let root_step = derive_root_step(&initial.root_key, &dh.to_bytes())?;
        let session = DirectSessionState {
            session_id: body.session_id.clone(),
            suite: MTI_DIRECT_E2EE_SUITE.to_owned(),
            peer_did: metadata.sender_did.clone(),
            local_key_agreement_id: local_static_key_id.to_owned(),
            peer_key_agreement_id: body.sender_static_key_agreement_id.clone(),
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
            status: SESSION_STATUS_ESTABLISHED.to_owned(),
        };
        Ok((session, plaintext))
    }

    pub fn encrypt_follow_up(
        session: &mut DirectSessionState,
        metadata: &DirectEnvelopeMetadata,
        operation_id: &str,
        plaintext: &ApplicationPlaintext,
    ) -> Result<(PendingOutboundRecord, DirectCipherBody), DirectE2eeError> {
        if session.status == SESSION_STATUS_PENDING_CONFIRMATION {
            return Err(DirectE2eeError::invalid_field(
                "session pending confirmation",
            ));
        }
        let send_chain_key = decode_fixed_32(
            session
                .send_chain_key_b64u
                .as_deref()
                .ok_or(DirectE2eeError::MissingField("send_chain_key_b64u"))?,
        )?;
        let step = derive_chain_step(&send_chain_key);
        let mut body = DirectCipherBody {
            session_id: session.session_id.clone(),
            suite: Some(MTI_DIRECT_E2EE_SUITE.to_owned()),
            ratchet_header: RatchetHeader {
                dh_pub_b64u: session.ratchet_public_key_b64u.clone(),
                pn: session.previous_send_chain_length.to_string(),
                n: session.send_n.to_string(),
            },
            ciphertext_b64u: String::new(),
        };
        let aad = build_message_aad(metadata, &body)?;
        body.ciphertext_b64u = crate::keys::base64url_encode(&encrypt_with_step(
            &step,
            &serialize_plaintext(plaintext)?,
            &aad,
        )?);
        session.send_chain_key_b64u = Some(crate::keys::base64url_encode(&step.next_chain_key));
        session.send_n += 1;
        let pending = PendingOutboundRecord {
            operation_id: operation_id.to_owned(),
            message_id: metadata.message_id.clone(),
            wire_content_type: CONTENT_TYPE_DIRECT_CIPHER.to_owned(),
            body_json: serde_json::to_value(&body).map_err(|error| {
                DirectE2eeError::invalid_field(format!("invalid cipher body: {error}"))
            })?,
        };
        Ok((pending, body))
    }

    pub fn decrypt_follow_up(
        session: &mut DirectSessionState,
        metadata: &DirectEnvelopeMetadata,
        body: &DirectCipherBody,
        _application_content_type: &str,
    ) -> Result<ApplicationPlaintext, DirectE2eeError> {
        if session.status == SESSION_STATUS_PENDING_CONFIRMATION {
            return decrypt_first_reply(session, metadata, body);
        }
        let mut skipped_session = session.clone();
        match try_skipped_message_key(&mut skipped_session, metadata, body) {
            Ok(Some(plaintext)) => {
                *session = skipped_session;
                return Ok(plaintext);
            }
            Ok(None) => {}
            Err(error) => {
                if skipped_session.skipped_message_keys != session.skipped_message_keys {
                    *session = skipped_session;
                }
                return Err(error);
            }
        }
        let mut next_session = session.clone();
        if next_session.peer_ratchet_public_key_b64u.as_deref()
            != Some(body.ratchet_header.dh_pub_b64u.as_str())
        {
            let pn = parse_u32(&body.ratchet_header.pn, "ratchet_header.pn")?;
            skip_message_keys(&mut next_session, pn)?;
            ratchet_step(&mut next_session, &body.ratchet_header.dh_pub_b64u)?;
        }
        let n = parse_u32(&body.ratchet_header.n, "ratchet_header.n")?;
        if n < next_session.recv_n {
            return Err(DirectE2eeError::ReplayDetected(
                "duplicate direct-e2ee message number".to_owned(),
            ));
        }
        skip_message_keys(&mut next_session, n)?;
        let recv_chain_key = decode_fixed_32(
            next_session
                .recv_chain_key_b64u
                .as_deref()
                .ok_or(DirectE2eeError::MissingField("recv_chain_key_b64u"))?,
        )?;
        let step = derive_chain_step(&recv_chain_key);
        let plaintext = decrypt_plaintext_with_step(&step, metadata, body)?;
        next_session.recv_chain_key_b64u =
            Some(crate::keys::base64url_encode(&step.next_chain_key));
        next_session.recv_n = n + 1;
        *session = next_session;
        Ok(plaintext)
    }
}

fn decrypt_first_reply(
    session: &mut DirectSessionState,
    metadata: &DirectEnvelopeMetadata,
    body: &DirectCipherBody,
) -> Result<ApplicationPlaintext, DirectE2eeError> {
    if body.ratchet_header.pn != "0" || body.ratchet_header.n != "0" {
        return Err(DirectE2eeError::invalid_field("bad first reply header"));
    }
    let root_key = decode_fixed_32(&session.root_key_b64u)?;
    let local_private =
        X25519StaticSecret::from(decode_fixed_32(&session.ratchet_private_key_b64u)?);
    let peer_public = X25519PublicKey::from(decode_fixed_32(&body.ratchet_header.dh_pub_b64u)?);
    let recv_root = derive_root_step(
        &root_key,
        &local_private.diffie_hellman(&peer_public).to_bytes(),
    )?;
    let new_private = X25519StaticSecret::random_from_rng(OsRng);
    let send_root = derive_root_step(
        &recv_root.root_key,
        &new_private.diffie_hellman(&peer_public).to_bytes(),
    )?;
    let step = derive_chain_step(&recv_root.chain_key);
    let aad = build_message_aad(metadata, body)?;
    let ciphertext = crate::keys::base64url_decode(&body.ciphertext_b64u)
        .map_err(|_| DirectE2eeError::invalid_field("ciphertext_b64u"))?;
    let plaintext_bytes = decrypt_with_step(&step, &ciphertext, &aad)?;
    let plaintext: ApplicationPlaintext =
        serde_json::from_slice(&plaintext_bytes).map_err(|error| {
            DirectE2eeError::invalid_field(format!("invalid plaintext json: {error}"))
        })?;
    session.root_key_b64u = crate::keys::base64url_encode(&send_root.root_key);
    session.recv_chain_key_b64u = Some(crate::keys::base64url_encode(&step.next_chain_key));
    session.send_chain_key_b64u = Some(crate::keys::base64url_encode(&send_root.chain_key));
    session.peer_ratchet_public_key_b64u = Some(body.ratchet_header.dh_pub_b64u.clone());
    session.previous_send_chain_length = session.send_n;
    session.send_n = 0;
    session.recv_n = 1;
    session.ratchet_private_key_b64u = crate::keys::base64url_encode(&new_private.to_bytes());
    session.ratchet_public_key_b64u =
        crate::keys::base64url_encode(&X25519PublicKey::from(&new_private).to_bytes());
    session.status = SESSION_STATUS_ESTABLISHED.to_owned();
    Ok(plaintext)
}

fn ratchet_step(
    session: &mut DirectSessionState,
    new_peer_pub_b64u: &str,
) -> Result<(), DirectE2eeError> {
    let root_key = decode_fixed_32(&session.root_key_b64u)?;
    let local_private =
        X25519StaticSecret::from(decode_fixed_32(&session.ratchet_private_key_b64u)?);
    let peer_public = X25519PublicKey::from(decode_fixed_32(new_peer_pub_b64u)?);
    let recv_root = derive_root_step(
        &root_key,
        &local_private.diffie_hellman(&peer_public).to_bytes(),
    )?;
    let new_private = X25519StaticSecret::random_from_rng(OsRng);
    let send_root = derive_root_step(
        &recv_root.root_key,
        &new_private.diffie_hellman(&peer_public).to_bytes(),
    )?;
    session.root_key_b64u = crate::keys::base64url_encode(&send_root.root_key);
    session.recv_chain_key_b64u = Some(crate::keys::base64url_encode(&recv_root.chain_key));
    session.send_chain_key_b64u = Some(crate::keys::base64url_encode(&send_root.chain_key));
    session.peer_ratchet_public_key_b64u = Some(new_peer_pub_b64u.to_owned());
    session.previous_send_chain_length = session.send_n;
    session.send_n = 0;
    session.recv_n = 0;
    session.ratchet_private_key_b64u = crate::keys::base64url_encode(&new_private.to_bytes());
    session.ratchet_public_key_b64u =
        crate::keys::base64url_encode(&X25519PublicKey::from(&new_private).to_bytes());
    Ok(())
}

fn try_skipped_message_key(
    session: &mut DirectSessionState,
    metadata: &DirectEnvelopeMetadata,
    body: &DirectCipherBody,
) -> Result<Option<ApplicationPlaintext>, DirectE2eeError> {
    let n = parse_u32(&body.ratchet_header.n, "ratchet_header.n")?;
    let Some(index) = session
        .skipped_message_keys
        .iter()
        .position(|item| item.dh_pub_b64u == body.ratchet_header.dh_pub_b64u && item.n == n)
    else {
        return Ok(None);
    };
    let skipped = session.skipped_message_keys.remove(index);
    let message_key = decode_fixed_32(&skipped.message_key_b64u)?;
    let nonce = decode_fixed_12(&skipped.nonce_b64u)?;
    let step = super::ratchet::ChainStep {
        message_key,
        nonce,
        next_chain_key: message_key,
    };
    decrypt_plaintext_with_step(&step, metadata, body).map(Some)
}

fn skip_message_keys(
    session: &mut DirectSessionState,
    until_n: u32,
) -> Result<(), DirectE2eeError> {
    if until_n < session.recv_n {
        return Ok(());
    }
    if until_n.saturating_sub(session.recv_n) > MAX_SKIP {
        return Err(DirectE2eeError::ReplayDetected(
            "message skip exceeded MAX_SKIP".to_owned(),
        ));
    }
    let mut recv_chain_key = decode_fixed_32(
        session
            .recv_chain_key_b64u
            .as_deref()
            .ok_or(DirectE2eeError::MissingField("recv_chain_key_b64u"))?,
    )?;
    while session.recv_n < until_n {
        let step = derive_chain_step(&recv_chain_key);
        session
            .skipped_message_keys
            .push(super::models::SkippedMessageKey {
                dh_pub_b64u: session
                    .peer_ratchet_public_key_b64u
                    .clone()
                    .unwrap_or_default(),
                n: session.recv_n,
                message_key_b64u: crate::keys::base64url_encode(&step.message_key),
                nonce_b64u: crate::keys::base64url_encode(&step.nonce),
            });
        recv_chain_key = step.next_chain_key;
        session.recv_n += 1;
    }
    session.recv_chain_key_b64u = Some(crate::keys::base64url_encode(&recv_chain_key));
    Ok(())
}

fn decrypt_plaintext_with_step(
    step: &super::ratchet::ChainStep,
    metadata: &DirectEnvelopeMetadata,
    body: &DirectCipherBody,
) -> Result<ApplicationPlaintext, DirectE2eeError> {
    let aad = build_message_aad(metadata, body)?;
    let ciphertext = crate::keys::base64url_decode(&body.ciphertext_b64u)
        .map_err(|_| DirectE2eeError::invalid_field("ciphertext_b64u"))?;
    let plaintext_bytes = decrypt_with_step(step, &ciphertext, &aad)?;
    serde_json::from_slice(&plaintext_bytes)
        .map_err(|error| DirectE2eeError::invalid_field(format!("invalid plaintext json: {error}")))
}

fn parse_u32(value: &str, field: &str) -> Result<u32, DirectE2eeError> {
    value
        .parse::<u32>()
        .map_err(|_| DirectE2eeError::invalid_field(field))
}

fn decode_fixed_12(value: &str) -> Result<[u8; 12], DirectE2eeError> {
    crate::keys::base64url_decode(value)
        .map_err(|_| DirectE2eeError::invalid_field("base64url value"))?
        .try_into()
        .map_err(|_| DirectE2eeError::invalid_field("expected 12-byte base64url value"))
}

fn decode_fixed_32(value: &str) -> Result<[u8; 32], DirectE2eeError> {
    crate::keys::base64url_decode(value)
        .map_err(|_| DirectE2eeError::invalid_field("base64url value"))?
        .try_into()
        .map_err(|_| DirectE2eeError::invalid_field("expected 32-byte base64url value"))
}

fn serialize_plaintext(plaintext: &ApplicationPlaintext) -> Result<Vec<u8>, DirectE2eeError> {
    let carriers = plaintext.text.iter().count()
        + plaintext.payload.iter().count()
        + plaintext.payload_b64u.iter().count();
    if plaintext.application_content_type.is_empty() || carriers != 1 {
        return Err(DirectE2eeError::invalid_field(
            "application plaintext must include content type and exactly one payload carrier",
        ));
    }
    let value = serde_json::to_value(plaintext)
        .map_err(|error| DirectE2eeError::invalid_field(format!("invalid plaintext: {error}")))?;
    crate::canonical_json::canonicalize_json(&value).map_err(DirectE2eeError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct_e2ee::models::{PrekeyBundle, SignedPrekey, MTI_DIRECT_E2EE_SUITE};
    use serde_json::json;

    #[test]
    fn skipped_message_key_is_deleted_after_failed_authentication() {
        let alice_static = X25519StaticSecret::from([7u8; 32]);
        let bob_static = X25519StaticSecret::from([9u8; 32]);
        let bob_spk = X25519StaticSecret::from([11u8; 32]);
        let alice_did = "did:wba:a.example:agents:alice";
        let bob_did = "did:wba:b.example:agents:bob";
        let bob_bundle = PrekeyBundle {
            bundle_id: "bundle-bob-001".to_owned(),
            owner_did: bob_did.to_owned(),
            suite: MTI_DIRECT_E2EE_SUITE.to_owned(),
            static_key_agreement_id: format!("{bob_did}#key-3"),
            signed_prekey: SignedPrekey {
                key_id: "spk-bob-001".to_owned(),
                public_key_b64u: crate::keys::base64url_encode(
                    &X25519PublicKey::from(&bob_spk).to_bytes(),
                ),
                expires_at: "2026-04-07T00:00:00Z".to_owned(),
            },
            proof: json!({}),
        };
        let init_metadata = DirectEnvelopeMetadata {
            sender_did: alice_did.to_owned(),
            recipient_did: bob_did.to_owned(),
            message_id: "msg-init".to_owned(),
            profile: "anp.direct.e2ee.v1".to_owned(),
            security_profile: "direct-e2ee".to_owned(),
        };
        let (mut alice_session, _, init_body) = DirectE2eeSession::initiate_session(
            &init_metadata,
            "op-init",
            &format!("{alice_did}#key-3"),
            &alice_static,
            &bob_bundle,
            &X25519PublicKey::from(&bob_static).to_bytes(),
            &X25519PublicKey::from(&bob_spk).to_bytes(),
            &ApplicationPlaintext::new_text("text/plain", "hello bob"),
        )
        .expect("initiate session");
        let (mut bob_session, _) = DirectE2eeSession::accept_incoming_init(
            &init_metadata,
            &format!("{bob_did}#key-3"),
            &bob_static,
            &bob_spk,
            &X25519PublicKey::from(&alice_static).to_bytes(),
            &init_body,
        )
        .expect("accept init");
        let reply_metadata = DirectEnvelopeMetadata {
            sender_did: bob_did.to_owned(),
            recipient_did: alice_did.to_owned(),
            message_id: "msg-reply".to_owned(),
            profile: "anp.direct.e2ee.v1".to_owned(),
            security_profile: "direct-e2ee".to_owned(),
        };
        let (_, reply_body) = DirectE2eeSession::encrypt_follow_up(
            &mut bob_session,
            &reply_metadata,
            "msg-reply",
            &ApplicationPlaintext::new_json("application/json", json!({"ack": "ok"})),
        )
        .expect("encrypt first reply");
        DirectE2eeSession::decrypt_follow_up(
            &mut alice_session,
            &reply_metadata,
            &reply_body,
            "application/json",
        )
        .expect("decrypt first reply");

        let msg2_metadata = DirectEnvelopeMetadata {
            sender_did: alice_did.to_owned(),
            recipient_did: bob_did.to_owned(),
            message_id: "msg-2".to_owned(),
            profile: "anp.direct.e2ee.v1".to_owned(),
            security_profile: "direct-e2ee".to_owned(),
        };
        let (_, msg2_body) = DirectE2eeSession::encrypt_follow_up(
            &mut alice_session,
            &msg2_metadata,
            "msg-2",
            &ApplicationPlaintext::new_json("application/json", json!({"seq": "two"})),
        )
        .expect("encrypt msg-2");
        let msg3_metadata = DirectEnvelopeMetadata {
            sender_did: alice_did.to_owned(),
            recipient_did: bob_did.to_owned(),
            message_id: "msg-3".to_owned(),
            profile: "anp.direct.e2ee.v1".to_owned(),
            security_profile: "direct-e2ee".to_owned(),
        };
        let (_, msg3_body) = DirectE2eeSession::encrypt_follow_up(
            &mut alice_session,
            &msg3_metadata,
            "msg-3",
            &ApplicationPlaintext::new_json("application/json", json!({"seq": "three"})),
        )
        .expect("encrypt msg-3");
        let before_failed_msg3 = bob_session.clone();
        let mut corrupted_msg3 = msg3_body.clone();
        corrupted_msg3.ciphertext_b64u = corrupt_b64u_tail(&corrupted_msg3.ciphertext_b64u);
        assert!(
            DirectE2eeSession::decrypt_follow_up(
                &mut bob_session,
                &msg3_metadata,
                &corrupted_msg3,
                "application/json",
            )
            .is_err(),
            "corrupted future message should fail authentication"
        );
        assert_eq!(bob_session, before_failed_msg3);
        DirectE2eeSession::decrypt_follow_up(
            &mut bob_session,
            &msg3_metadata,
            &msg3_body,
            "application/json",
        )
        .expect("decrypt out-of-order msg-3");
        assert_eq!(bob_session.skipped_message_keys.len(), 1);

        let mut corrupted_msg2 = msg2_body.clone();
        corrupted_msg2.ciphertext_b64u = corrupt_b64u_tail(&corrupted_msg2.ciphertext_b64u);
        assert!(
            DirectE2eeSession::decrypt_follow_up(
                &mut bob_session,
                &msg2_metadata,
                &corrupted_msg2,
                "application/json",
            )
            .is_err(),
            "corrupted skipped message should fail authentication"
        );
        assert!(bob_session.skipped_message_keys.is_empty());

        let retry_result = DirectE2eeSession::decrypt_follow_up(
            &mut bob_session,
            &msg2_metadata,
            &msg2_body,
            "application/json",
        );
        assert!(
            retry_result.is_err(),
            "valid retry should fail after the skipped key was consumed"
        );
        assert!(bob_session.skipped_message_keys.is_empty());
    }

    fn corrupt_b64u_tail(value: &str) -> String {
        let Some(last) = value.as_bytes().last().copied() else {
            return "A".to_owned();
        };
        let replacement = if last == b'A' { 'B' } else { 'A' };
        format!("{}{}", &value[..value.len() - 1], replacement)
    }
}
