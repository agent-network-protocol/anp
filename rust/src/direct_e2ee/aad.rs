use super::errors::DirectE2eeError;
use super::models::{DirectCipherBody, DirectEnvelopeMetadata, DirectInitBody};
use crate::canonical_json::canonicalize_json;
use serde_json::json;

pub fn build_init_aad(
    metadata: &DirectEnvelopeMetadata,
    body: &DirectInitBody,
) -> Result<Vec<u8>, DirectE2eeError> {
    let payload = json!({
        "sender_did": metadata.sender_did,
        "recipient_did": metadata.recipient_did,
        "suite": body.suite,
        "bundle_id": body.recipient_bundle_id,
        "sender_static_key_agreement_id": body.sender_static_key_agreement_id,
        "recipient_static_key_agreement_id": body.recipient_static_key_agreement_id,
        "recipient_signed_prekey_id": body.recipient_signed_prekey_id,
        "recipient_one_time_prekey_id": body.recipient_one_time_prekey_id,
        "session_id": body.session_id,
        "message_id": metadata.message_id,
        "profile": metadata.profile,
        "security_profile": metadata.security_profile
    });
    canonicalize_json(&payload).map_err(DirectE2eeError::from)
}

pub fn build_message_aad(
    metadata: &DirectEnvelopeMetadata,
    body: &DirectCipherBody,
    application_content_type: &str,
) -> Result<Vec<u8>, DirectE2eeError> {
    let payload = json!({
        "sender_did": metadata.sender_did,
        "recipient_did": metadata.recipient_did,
        "session_id": body.session_id,
        "message_id": metadata.message_id,
        "profile": metadata.profile,
        "security_profile": metadata.security_profile,
        "application_content_type": application_content_type,
        "ratchet_header": body.ratchet_header,
    });
    canonicalize_json(&payload).map_err(DirectE2eeError::from)
}

#[cfg(test)]
mod tests {
    use super::{build_init_aad, build_message_aad};
    use crate::direct_e2ee::models::{
        DirectCipherBody, DirectEnvelopeMetadata, DirectInitBody, RatchetHeader,
        MTI_DIRECT_E2EE_SUITE,
    };

    #[test]
    fn aad_is_canonical_and_deterministic() {
        let metadata = DirectEnvelopeMetadata {
            sender_did: "did:wba:a.example:agents:alice:e1".to_owned(),
            recipient_did: "did:wba:b.example:agents:bob:e1".to_owned(),
            message_id: "msg-001".to_owned(),
            profile: "anp.direct.e2ee.v1".to_owned(),
            security_profile: "direct-e2ee".to_owned(),
        };
        let init = DirectInitBody {
            session_id: "SESSION123".to_owned(),
            suite: MTI_DIRECT_E2EE_SUITE.to_owned(),
            sender_static_key_agreement_id: "did:wba:a.example:agents:alice:e1#ka-1".to_owned(),
            recipient_bundle_id: "bundle-001".to_owned(),
            recipient_static_key_agreement_id: "did:wba:b.example:agents:bob:e1#ka-1".to_owned(),
            recipient_signed_prekey_id: "spk-001".to_owned(),
            recipient_one_time_prekey_id: None,
            sender_ephemeral_pub_b64u: "EPHEMERAL".to_owned(),
            ciphertext_b64u: "CIPHERTEXT".to_owned(),
        };
        let cipher = DirectCipherBody {
            session_id: "SESSION123".to_owned(),
            suite: MTI_DIRECT_E2EE_SUITE.to_owned(),
            ratchet_header: RatchetHeader {
                dh_pub_b64u: "RATCHETPUB".to_owned(),
                pn: "0".to_owned(),
                n: "1".to_owned(),
            },
            ciphertext_b64u: "MESSAGE".to_owned(),
        };

        let init_aad = build_init_aad(&metadata, &init).expect("init aad");
        let msg_aad = build_message_aad(&metadata, &cipher, "text/plain").expect("msg aad");

        assert!(String::from_utf8(init_aad).expect("utf8").contains("\"bundle_id\":\"bundle-001\""));
        assert!(String::from_utf8(msg_aad).expect("utf8").contains("\"application_content_type\":\"text/plain\""));
    }
}
