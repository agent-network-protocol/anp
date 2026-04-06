use super::aad::{build_init_aad, build_message_aad};
use super::errors::DirectE2eeError;
use super::models::{
    ApplicationPlaintext, DirectCipherBody, DirectEnvelopeMetadata, DirectInitBody,
    DirectSessionState, PendingOutboundRecord, PrekeyBundle, RatchetHeader, MTI_DIRECT_E2EE_SUITE,
};
use super::ratchet::{decrypt_with_step, derive_chain_step, encrypt_with_step, MAX_SKIP};
use super::x3dh::{
    derive_initial_material_for_initiator, derive_initial_material_for_responder,
    initial_secret_key_and_nonce,
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
        if recipient_bundle.suite != MTI_DIRECT_E2EE_SUITE {
            return Err(DirectE2eeError::UnsupportedSuite(
                recipient_bundle.suite.clone(),
            ));
        }
        let sender_ephemeral_private = X25519StaticSecret::random_from_rng(OsRng);
        let sender_ephemeral_public = X25519PublicKey::from(&sender_ephemeral_private).to_bytes();
        let initial_material = derive_initial_material_for_initiator(
            local_static_private,
            &sender_ephemeral_private,
            recipient_static_public,
            recipient_signed_prekey_public,
        )?;
        let mut body = DirectInitBody {
            session_id: initial_material.session_id.clone(),
            suite: MTI_DIRECT_E2EE_SUITE.to_owned(),
            sender_static_key_agreement_id: local_static_key_id.to_owned(),
            recipient_bundle_id: recipient_bundle.bundle_id.clone(),
            recipient_static_key_agreement_id: recipient_bundle.static_key_agreement_id.clone(),
            recipient_signed_prekey_id: recipient_bundle.signed_prekey.key_id.clone(),
            recipient_one_time_prekey_id: None,
            sender_ephemeral_pub_b64u: crate::keys::base64url_encode(&sender_ephemeral_public),
            ciphertext_b64u: String::new(),
        };
        let init_aad = build_init_aad(metadata, &body)?;
        let (key, nonce) = initial_secret_key_and_nonce(&initial_material.initial_secret)?;
        let ciphertext = encrypt_with_raw_key(
            &key,
            &nonce,
            &serde_json::to_vec(plaintext).map_err(|error| {
                DirectE2eeError::invalid_field(format!("invalid plaintext: {error}"))
            })?,
            &init_aad,
        )?;
        body.ciphertext_b64u = crate::keys::base64url_encode(&ciphertext);

        let ratchet_private = X25519StaticSecret::random_from_rng(OsRng);
        let ratchet_public = X25519PublicKey::from(&ratchet_private).to_bytes();
        let session = DirectSessionState {
            session_id: initial_material.session_id.clone(),
            suite: MTI_DIRECT_E2EE_SUITE.to_owned(),
            peer_did: metadata.recipient_did.clone(),
            local_key_agreement_id: local_static_key_id.to_owned(),
            peer_key_agreement_id: recipient_bundle.static_key_agreement_id.clone(),
            root_key_b64u: crate::keys::base64url_encode(&initial_material.root_key),
            send_chain_key_b64u: crate::keys::base64url_encode(
                &initial_material.initiator_chain_key,
            ),
            recv_chain_key_b64u: crate::keys::base64url_encode(
                &initial_material.responder_chain_key,
            ),
            ratchet_public_key_b64u: crate::keys::base64url_encode(&ratchet_public),
            peer_ratchet_public_key_b64u: None,
            send_n: 0,
            recv_n: 0,
            previous_send_chain_length: 0,
            skipped_message_keys: vec![],
            is_initiator: true,
        };
        let pending = PendingOutboundRecord {
            operation_id: operation_id.to_owned(),
            message_id: metadata.message_id.clone(),
            wire_content_type: "application/anp-direct-init+json".to_owned(),
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
        let sender_ephemeral_public = decode_fixed_32(&body.sender_ephemeral_pub_b64u)?;
        let initial_material = derive_initial_material_for_responder(
            local_static_private,
            local_signed_prekey_private,
            sender_static_public,
            &sender_ephemeral_public,
        )?;
        let init_aad = build_init_aad(metadata, body)?;
        let (key, nonce) = initial_secret_key_and_nonce(&initial_material.initial_secret)?;
        let ciphertext = crate::keys::base64url_decode(&body.ciphertext_b64u)
            .map_err(|_| DirectE2eeError::invalid_field("ciphertext_b64u"))?;
        let plaintext_bytes = encrypt_decrypt_with_raw_key(&key, &nonce, &ciphertext, &init_aad)?;
        let plaintext: ApplicationPlaintext =
            serde_json::from_slice(&plaintext_bytes).map_err(|error| {
                DirectE2eeError::invalid_field(format!("invalid plaintext json: {error}"))
            })?;
        let ratchet_private = X25519StaticSecret::random_from_rng(OsRng);
        let ratchet_public = X25519PublicKey::from(&ratchet_private).to_bytes();
        let session = DirectSessionState {
            session_id: body.session_id.clone(),
            suite: MTI_DIRECT_E2EE_SUITE.to_owned(),
            peer_did: metadata.sender_did.clone(),
            local_key_agreement_id: local_static_key_id.to_owned(),
            peer_key_agreement_id: body.sender_static_key_agreement_id.clone(),
            root_key_b64u: crate::keys::base64url_encode(&initial_material.root_key),
            send_chain_key_b64u: crate::keys::base64url_encode(
                &initial_material.responder_chain_key,
            ),
            recv_chain_key_b64u: crate::keys::base64url_encode(
                &initial_material.initiator_chain_key,
            ),
            ratchet_public_key_b64u: crate::keys::base64url_encode(&ratchet_public),
            peer_ratchet_public_key_b64u: None,
            send_n: 0,
            recv_n: 0,
            previous_send_chain_length: 0,
            skipped_message_keys: vec![],
            is_initiator: false,
        };
        Ok((session, plaintext))
    }

    pub fn encrypt_follow_up(
        session: &mut DirectSessionState,
        metadata: &DirectEnvelopeMetadata,
        operation_id: &str,
        plaintext: &ApplicationPlaintext,
    ) -> Result<(PendingOutboundRecord, DirectCipherBody), DirectE2eeError> {
        let send_chain_key = decode_fixed_32(&session.send_chain_key_b64u)?;
        let step = derive_chain_step(&send_chain_key);
        let body = DirectCipherBody {
            session_id: session.session_id.clone(),
            suite: MTI_DIRECT_E2EE_SUITE.to_owned(),
            ratchet_header: RatchetHeader {
                dh_pub_b64u: session.ratchet_public_key_b64u.clone(),
                pn: session.previous_send_chain_length.to_string(),
                n: session.send_n.to_string(),
            },
            ciphertext_b64u: String::new(),
        };
        let aad = build_message_aad(metadata, &body, &plaintext.application_content_type)?;
        let ciphertext = encrypt_with_step(
            &step,
            &serde_json::to_vec(plaintext).map_err(|error| {
                DirectE2eeError::invalid_field(format!("invalid plaintext: {error}"))
            })?,
            &aad,
        )?;
        let body = DirectCipherBody {
            ciphertext_b64u: crate::keys::base64url_encode(&ciphertext),
            ..body
        };
        session.send_chain_key_b64u = crate::keys::base64url_encode(&step.next_chain_key);
        session.send_n += 1;
        let pending = PendingOutboundRecord {
            operation_id: operation_id.to_owned(),
            message_id: metadata.message_id.clone(),
            wire_content_type: "application/anp-direct-cipher+json".to_owned(),
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
        application_content_type: &str,
    ) -> Result<ApplicationPlaintext, DirectE2eeError> {
        let n = body
            .ratchet_header
            .n
            .parse::<u32>()
            .map_err(|_| DirectE2eeError::invalid_field("ratchet_header.n"))?;
        if n < session.recv_n {
            return Err(DirectE2eeError::ReplayDetected(
                "duplicate direct-e2ee message number".to_owned(),
            ));
        }
        if n.saturating_sub(session.recv_n) > MAX_SKIP {
            return Err(DirectE2eeError::ReplayDetected(
                "message skip exceeded MAX_SKIP".to_owned(),
            ));
        }
        session.peer_ratchet_public_key_b64u = Some(body.ratchet_header.dh_pub_b64u.clone());
        let mut recv_chain_key = decode_fixed_32(&session.recv_chain_key_b64u)?;
        for _ in session.recv_n..n {
            let skipped_step = derive_chain_step(&recv_chain_key);
            recv_chain_key = skipped_step.next_chain_key;
        }
        let step = derive_chain_step(&recv_chain_key);
        let aad = build_message_aad(metadata, body, application_content_type)?;
        let ciphertext = crate::keys::base64url_decode(&body.ciphertext_b64u)
            .map_err(|_| DirectE2eeError::invalid_field("ciphertext_b64u"))?;
        let plaintext_bytes = decrypt_with_step(&step, &ciphertext, &aad)?;
        let plaintext: ApplicationPlaintext =
            serde_json::from_slice(&plaintext_bytes).map_err(|error| {
                DirectE2eeError::invalid_field(format!("invalid plaintext json: {error}"))
            })?;
        session.recv_chain_key_b64u = crate::keys::base64url_encode(&step.next_chain_key);
        session.recv_n = n + 1;
        Ok(plaintext)
    }
}

fn decode_fixed_32(value: &str) -> Result<[u8; 32], DirectE2eeError> {
    let bytes = crate::keys::base64url_decode(value)
        .map_err(|_| DirectE2eeError::invalid_field("base64url value"))?;
    bytes
        .try_into()
        .map_err(|_| DirectE2eeError::invalid_field("expected 32-byte base64url value"))
}

fn encrypt_with_raw_key(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, DirectE2eeError> {
    let step = super::ratchet::ChainStep {
        message_key: *key,
        nonce: *nonce,
        next_chain_key: *key,
    };
    encrypt_with_step(&step, plaintext, aad)
}

fn encrypt_decrypt_with_raw_key(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, DirectE2eeError> {
    let step = super::ratchet::ChainStep {
        message_key: *key,
        nonce: *nonce,
        next_chain_key: *key,
    };
    decrypt_with_step(&step, ciphertext, aad)
}

#[cfg(test)]
mod tests {
    use super::DirectE2eeSession;
    use crate::direct_e2ee::bundle::signed_prekey_from_private_key;
    use crate::direct_e2ee::models::{
        ApplicationPlaintext, DirectEnvelopeMetadata, PrekeyBundle, MTI_DIRECT_E2EE_SUITE,
    };
    use serde_json::json;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

    fn metadata(sender: &str, recipient: &str, message_id: &str) -> DirectEnvelopeMetadata {
        DirectEnvelopeMetadata {
            sender_did: sender.to_owned(),
            recipient_did: recipient.to_owned(),
            message_id: message_id.to_owned(),
            profile: "anp.direct.e2ee.v1".to_owned(),
            security_profile: "direct-e2ee".to_owned(),
        }
    }

    fn bundle(owner_did: &str, spk_private: &X25519StaticSecret) -> PrekeyBundle {
        PrekeyBundle {
            bundle_id: "bundle-001".to_owned(),
            owner_did: owner_did.to_owned(),
            suite: MTI_DIRECT_E2EE_SUITE.to_owned(),
            static_key_agreement_id: format!("{owner_did}#ka-1"),
            signed_prekey: signed_prekey_from_private_key(
                "spk-001",
                spk_private,
                "2026-04-07T00:00:00Z",
            ),
            proof: json!({
                "type": "DataIntegrityProof",
                "verificationMethod": format!("{owner_did}#key-1"),
                "proofPurpose": "assertionMethod",
                "created": "2026-03-31T09:58:58Z",
                "proofValue": "stub"
            }),
        }
    }

    #[test]
    fn session_init_and_follow_up_round_trip() {
        let alice_static = X25519StaticSecret::from([11u8; 32]);
        let bob_static = X25519StaticSecret::from([22u8; 32]);
        let bob_spk = X25519StaticSecret::from([33u8; 32]);
        let alice_metadata = metadata(
            "did:wba:a.example:agents:alice:e1",
            "did:wba:b.example:agents:bob:e1",
            "msg-init",
        );
        let bob_metadata = metadata(
            "did:wba:a.example:agents:alice:e1",
            "did:wba:b.example:agents:bob:e1",
            "msg-init",
        );
        let bundle = bundle("did:wba:b.example:agents:bob:e1", &bob_spk);
        let plaintext = ApplicationPlaintext::new_text("text/plain", "hello bob");

        let (mut alice_session, _pending, init_body) = DirectE2eeSession::initiate_session(
            &alice_metadata,
            "op-init",
            "did:wba:a.example:agents:alice:e1#ka-1",
            &alice_static,
            &bundle,
            &X25519PublicKey::from(&bob_static).to_bytes(),
            &X25519PublicKey::from(&bob_spk).to_bytes(),
            &plaintext,
        )
        .expect("initiate");

        let (mut bob_session, init_plaintext) = DirectE2eeSession::accept_incoming_init(
            &bob_metadata,
            "did:wba:b.example:agents:bob:e1#ka-1",
            &bob_static,
            &bob_spk,
            &X25519PublicKey::from(&alice_static).to_bytes(),
            &init_body,
        )
        .expect("accept");
        assert_eq!(init_plaintext.text.as_deref(), Some("hello bob"));

        let alice_follow_up_metadata = metadata(
            "did:wba:a.example:agents:alice:e1",
            "did:wba:b.example:agents:bob:e1",
            "msg-2",
        );
        let bob_follow_up_metadata = metadata(
            "did:wba:a.example:agents:alice:e1",
            "did:wba:b.example:agents:bob:e1",
            "msg-2",
        );
        let follow_up_plaintext =
            ApplicationPlaintext::new_json("application/json", json!({"event": "wave"}));
        let (_pending, cipher_body) = DirectE2eeSession::encrypt_follow_up(
            &mut alice_session,
            &alice_follow_up_metadata,
            "op-2",
            &follow_up_plaintext,
        )
        .expect("encrypt follow up");

        let decrypted = DirectE2eeSession::decrypt_follow_up(
            &mut bob_session,
            &bob_follow_up_metadata,
            &cipher_body,
            "application/json",
        )
        .expect("decrypt follow up");
        assert_eq!(decrypted.payload, Some(json!({"event": "wave"})));
    }
}
