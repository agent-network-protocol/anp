use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MTI_DIRECT_E2EE_SUITE: &str =
    "ANP-DIRECT-E2EE-X3DH-25519-CHACHA20POLY1305-SHA256-V1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedPrekey {
    pub key_id: String,
    pub public_key_b64u: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PrekeyBundle {
    pub bundle_id: String,
    pub owner_did: String,
    pub suite: String,
    pub static_key_agreement_id: String,
    pub signed_prekey: SignedPrekey,
    pub proof: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectEnvelopeMetadata {
    pub sender_did: String,
    pub recipient_did: String,
    pub message_id: String,
    pub profile: String,
    pub security_profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RatchetHeader {
    pub dh_pub_b64u: String,
    pub pn: String,
    pub n: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectInitBody {
    pub session_id: String,
    pub suite: String,
    pub sender_static_key_agreement_id: String,
    pub recipient_bundle_id: String,
    pub recipient_static_key_agreement_id: String,
    pub recipient_signed_prekey_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_one_time_prekey_id: Option<String>,
    pub sender_ephemeral_pub_b64u: String,
    pub ciphertext_b64u: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectCipherBody {
    pub session_id: String,
    pub suite: String,
    pub ratchet_header: RatchetHeader,
    pub ciphertext_b64u: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApplicationPlaintext {
    pub application_content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_to_message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
}

impl ApplicationPlaintext {
    pub fn new_text(content_type: &str, text: impl Into<String>) -> Self {
        Self {
            application_content_type: content_type.to_owned(),
            conversation_id: None,
            reply_to_message_id: None,
            annotations: None,
            text: Some(text.into()),
            payload: None,
        }
    }

    pub fn new_json(content_type: &str, payload: Value) -> Self {
        Self {
            application_content_type: content_type.to_owned(),
            conversation_id: None,
            reply_to_message_id: None,
            annotations: None,
            text: None,
            payload: Some(payload),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkippedMessageKey {
    pub n: u32,
    pub message_key_b64u: String,
    pub nonce_b64u: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectSessionState {
    pub session_id: String,
    pub suite: String,
    pub peer_did: String,
    pub local_key_agreement_id: String,
    pub peer_key_agreement_id: String,
    pub root_key_b64u: String,
    pub send_chain_key_b64u: String,
    pub recv_chain_key_b64u: String,
    pub ratchet_public_key_b64u: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_ratchet_public_key_b64u: Option<String>,
    pub send_n: u32,
    pub recv_n: u32,
    pub previous_send_chain_length: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped_message_keys: Vec<SkippedMessageKey>,
    pub is_initiator: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PendingOutboundRecord {
    pub operation_id: String,
    pub message_id: String,
    pub wire_content_type: String,
    pub body_json: Value,
}
