use super::aad::{CONTENT_TYPE_DIRECT_CIPHER, CONTENT_TYPE_DIRECT_INIT};
use super::errors::DirectE2eeError;
use super::models::{
    ApplicationPlaintext, DirectCipherBody, DirectInitBody, PendingOutboundRecord, RatchetHeader,
};
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectEnvelopeBody {
    Init(DirectInitBody),
    Cipher(DirectCipherBody),
}

pub fn direct_init_body_to_value(body: &DirectInitBody) -> Value {
    let mut value = json!({
        "session_id": body.session_id,
        "suite": body.suite,
        "sender_static_key_agreement_id": body.sender_static_key_agreement_id,
        "recipient_bundle_id": body.recipient_bundle_id,
        "recipient_signed_prekey_id": body.recipient_signed_prekey_id,
        "sender_ephemeral_pub_b64u": body.sender_ephemeral_pub_b64u,
        "ciphertext_b64u": body.ciphertext_b64u,
    });
    if let Some(opk) = body
        .recipient_one_time_prekey_id
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        value["recipient_one_time_prekey_id"] = json!(opk);
    }
    value
}

pub fn direct_init_body_from_value(value: &Value) -> Result<DirectInitBody, DirectE2eeError> {
    let object = value
        .as_object()
        .ok_or(DirectE2eeError::MissingField("body"))?;
    Ok(DirectInitBody {
        session_id: required_string(object.get("session_id"), "session_id")?,
        suite: required_string(object.get("suite"), "suite")?,
        sender_static_key_agreement_id: required_string(
            object.get("sender_static_key_agreement_id"),
            "sender_static_key_agreement_id",
        )?,
        recipient_bundle_id: required_string(
            object.get("recipient_bundle_id"),
            "recipient_bundle_id",
        )?,
        recipient_signed_prekey_id: required_string(
            object.get("recipient_signed_prekey_id"),
            "recipient_signed_prekey_id",
        )?,
        recipient_one_time_prekey_id: optional_string(object.get("recipient_one_time_prekey_id")),
        sender_ephemeral_pub_b64u: required_string(
            object.get("sender_ephemeral_pub_b64u"),
            "sender_ephemeral_pub_b64u",
        )?,
        ciphertext_b64u: required_string(object.get("ciphertext_b64u"), "ciphertext_b64u")?,
    })
}

pub fn direct_cipher_body_to_value(body: &DirectCipherBody) -> Value {
    let mut value = json!({
        "session_id": body.session_id,
        "ratchet_header": {
            "dh_pub_b64u": body.ratchet_header.dh_pub_b64u,
            "pn": body.ratchet_header.pn,
            "n": body.ratchet_header.n,
        },
        "ciphertext_b64u": body.ciphertext_b64u,
    });
    if let Some(suite) = body.suite.as_deref().filter(|value| !value.is_empty()) {
        value["suite"] = json!(suite);
    }
    value
}

pub fn direct_cipher_body_from_value(value: &Value) -> Result<DirectCipherBody, DirectE2eeError> {
    let object = value
        .as_object()
        .ok_or(DirectE2eeError::MissingField("body"))?;
    let ratchet_header = object
        .get("ratchet_header")
        .and_then(Value::as_object)
        .ok_or(DirectE2eeError::MissingField("ratchet_header"))?;
    Ok(DirectCipherBody {
        session_id: required_string(object.get("session_id"), "session_id")?,
        suite: optional_string(object.get("suite")),
        ratchet_header: RatchetHeader {
            dh_pub_b64u: required_string(
                ratchet_header.get("dh_pub_b64u"),
                "ratchet_header.dh_pub_b64u",
            )?,
            pn: required_string(ratchet_header.get("pn"), "ratchet_header.pn")?,
            n: required_string(ratchet_header.get("n"), "ratchet_header.n")?,
        },
        ciphertext_b64u: required_string(object.get("ciphertext_b64u"), "ciphertext_b64u")?,
    })
}

pub fn direct_body_from_content_type(
    content_type: &str,
    body: &Value,
) -> Result<DirectEnvelopeBody, DirectE2eeError> {
    match content_type {
        CONTENT_TYPE_DIRECT_INIT => {
            Ok(DirectEnvelopeBody::Init(direct_init_body_from_value(body)?))
        }
        CONTENT_TYPE_DIRECT_CIPHER => Ok(DirectEnvelopeBody::Cipher(
            direct_cipher_body_from_value(body)?,
        )),
        _ => Err(DirectE2eeError::invalid_field(format!(
            "unsupported content type: {content_type}"
        ))),
    }
}

pub fn plaintext_to_value(plaintext: &ApplicationPlaintext) -> Value {
    let mut value = json!({
        "application_content_type": plaintext.application_content_type,
    });
    if let Some(conversation_id) = plaintext
        .conversation_id
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        value["conversation_id"] = json!(conversation_id);
    }
    if let Some(reply_to_message_id) = plaintext
        .reply_to_message_id
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        value["reply_to_message_id"] = json!(reply_to_message_id);
    }
    if let Some(annotations) = plaintext.annotations.as_ref() {
        if !is_empty_json_object(annotations) {
            value["annotations"] = annotations.clone();
        }
    }
    if let Some(text) = plaintext.text.as_deref().filter(|value| !value.is_empty()) {
        value["text"] = json!(text);
    }
    if let Some(payload) = plaintext.payload.as_ref() {
        if !is_empty_json_object(payload) {
            value["payload"] = payload.clone();
        }
    }
    if let Some(payload_b64u) = plaintext
        .payload_b64u
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        value["payload_b64u"] = json!(payload_b64u);
    }
    value
}

pub fn validate_direct_send_ids(
    operation_id: &str,
    message_id: &str,
) -> Result<(), DirectE2eeError> {
    if operation_id.is_empty() || message_id.is_empty() {
        return Err(DirectE2eeError::MissingField("operation_id/message_id"));
    }
    if operation_id != message_id {
        return Err(DirectE2eeError::invalid_field(
            "direct-e2ee requires operation_id to equal message_id",
        ));
    }
    Ok(())
}

pub fn direct_send_params(
    local_did: &str,
    peer_did: &str,
    operation_id: &str,
    message_id: &str,
    content_type: &str,
    body: Value,
) -> Result<Value, DirectE2eeError> {
    validate_direct_send_ids(operation_id, message_id)?;
    Ok(json!({
        "meta": {
            "anp_version": "1.0",
            "profile": "anp.direct.e2ee.v1",
            "security_profile": "direct-e2ee",
            "sender_did": local_did,
            "target": {
                "kind": "agent",
                "did": peer_did,
            },
            "operation_id": operation_id,
            "message_id": message_id,
            "content_type": content_type,
        },
        "body": body,
    }))
}

pub fn direct_send_request(
    local_did: &str,
    peer_did: &str,
    operation_id: &str,
    message_id: &str,
    content_type: &str,
    body: Value,
) -> Result<Value, DirectE2eeError> {
    Ok(json!({
        "method": "direct.send",
        "params": direct_send_params(
            local_did,
            peer_did,
            operation_id,
            message_id,
            content_type,
            body,
        )?,
    }))
}

pub fn direct_send_request_from_pending(
    local_did: &str,
    peer_did: &str,
    pending: &PendingOutboundRecord,
) -> Result<Value, DirectE2eeError> {
    direct_send_request(
        local_did,
        peer_did,
        &pending.operation_id,
        &pending.message_id,
        &pending.wire_content_type,
        pending.body_json.clone(),
    )
}

pub fn direct_init_send_request(
    local_did: &str,
    peer_did: &str,
    operation_id: &str,
    message_id: &str,
    body: &DirectInitBody,
) -> Result<Value, DirectE2eeError> {
    direct_send_request(
        local_did,
        peer_did,
        operation_id,
        message_id,
        CONTENT_TYPE_DIRECT_INIT,
        direct_init_body_to_value(body),
    )
}

pub fn direct_cipher_send_request(
    local_did: &str,
    peer_did: &str,
    operation_id: &str,
    message_id: &str,
    body: &DirectCipherBody,
) -> Result<Value, DirectE2eeError> {
    direct_send_request(
        local_did,
        peer_did,
        operation_id,
        message_id,
        CONTENT_TYPE_DIRECT_CIPHER,
        direct_cipher_body_to_value(body),
    )
}

fn is_empty_json_object(value: &Value) -> bool {
    value.as_object().is_some_and(serde_json::Map::is_empty)
}

fn required_string(value: Option<&Value>, field: &'static str) -> Result<String, DirectE2eeError> {
    let text = optional_string(value);
    if text.as_deref().is_some_and(|value| !value.is_empty()) {
        Ok(text.expect("checked Some above"))
    } else {
        Err(DirectE2eeError::MissingField(field))
    }
}

fn optional_string(value: Option<&Value>) -> Option<String> {
    let text = match value? {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(boolean) => boolean.to_string(),
        Value::Null => String::new(),
        other => other.to_string(),
    };
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        direct_body_from_content_type, direct_cipher_body_from_value, direct_cipher_body_to_value,
        direct_cipher_send_request, direct_init_body_from_value, direct_init_body_to_value,
        direct_init_send_request, direct_send_request_from_pending, plaintext_to_value,
        validate_direct_send_ids, DirectEnvelopeBody,
    };
    use crate::direct_e2ee::aad::{CONTENT_TYPE_DIRECT_CIPHER, CONTENT_TYPE_DIRECT_INIT};
    use crate::direct_e2ee::models::{
        ApplicationPlaintext, DirectCipherBody, DirectInitBody, PendingOutboundRecord,
        RatchetHeader, MTI_DIRECT_E2EE_SUITE,
    };
    use serde_json::json;

    #[test]
    fn direct_init_body_value_matches_go_map_shape() {
        let body = DirectInitBody {
            session_id: "sid-001".to_owned(),
            suite: MTI_DIRECT_E2EE_SUITE.to_owned(),
            sender_static_key_agreement_id: "did:wba:a.example:agents:alice:e1#key-3".to_owned(),
            recipient_bundle_id: "bundle-bob-001".to_owned(),
            recipient_signed_prekey_id: "spk-bob-001".to_owned(),
            recipient_one_time_prekey_id: Some("opk-bob-001".to_owned()),
            sender_ephemeral_pub_b64u: "EPHEMERAL".to_owned(),
            ciphertext_b64u: "CIPHERTEXT".to_owned(),
        };

        assert_eq!(
            direct_init_body_to_value(&body),
            json!({
                "session_id": "sid-001",
                "suite": MTI_DIRECT_E2EE_SUITE,
                "sender_static_key_agreement_id": "did:wba:a.example:agents:alice:e1#key-3",
                "recipient_bundle_id": "bundle-bob-001",
                "recipient_signed_prekey_id": "spk-bob-001",
                "recipient_one_time_prekey_id": "opk-bob-001",
                "sender_ephemeral_pub_b64u": "EPHEMERAL",
                "ciphertext_b64u": "CIPHERTEXT",
            })
        );
    }

    #[test]
    fn direct_init_body_value_omits_empty_opk_like_go_omitempty() {
        let body = DirectInitBody {
            session_id: "sid-001".to_owned(),
            suite: MTI_DIRECT_E2EE_SUITE.to_owned(),
            sender_static_key_agreement_id: "ka-alice".to_owned(),
            recipient_bundle_id: "bundle-bob-001".to_owned(),
            recipient_signed_prekey_id: "spk-bob-001".to_owned(),
            recipient_one_time_prekey_id: Some(String::new()),
            sender_ephemeral_pub_b64u: "EPHEMERAL".to_owned(),
            ciphertext_b64u: "CIPHERTEXT".to_owned(),
        };

        assert_eq!(
            direct_init_body_to_value(&body).get("recipient_one_time_prekey_id"),
            None
        );
    }

    #[test]
    fn direct_init_body_from_value_matches_go_map_parser() {
        let body = direct_init_body_from_value(&json!({
            "session_id": "sid-001",
            "suite": MTI_DIRECT_E2EE_SUITE,
            "sender_static_key_agreement_id": "did:wba:a.example:agents:alice:e1#key-3",
            "recipient_bundle_id": "bundle-bob-001",
            "recipient_signed_prekey_id": "spk-bob-001",
            "recipient_one_time_prekey_id": "opk-bob-001",
            "sender_ephemeral_pub_b64u": "EPHEMERAL",
            "ciphertext_b64u": "CIPHERTEXT",
        }))
        .expect("init body");

        assert_eq!(body.session_id, "sid-001");
        assert_eq!(
            body.recipient_one_time_prekey_id.as_deref(),
            Some("opk-bob-001")
        );
        assert_eq!(
            direct_init_body_to_value(&body).pointer("/recipient_bundle_id"),
            Some(&json!("bundle-bob-001"))
        );
    }

    #[test]
    fn direct_init_body_from_value_rejects_missing_required_fields() {
        let error = direct_init_body_from_value(&json!({
            "session_id": "sid-001",
            "suite": MTI_DIRECT_E2EE_SUITE,
            "sender_static_key_agreement_id": "ka-alice",
            "recipient_signed_prekey_id": "spk-bob-001",
            "sender_ephemeral_pub_b64u": "EPHEMERAL",
            "ciphertext_b64u": "CIPHERTEXT",
        }))
        .expect_err("recipient bundle id should be required");

        assert!(error
            .to_string()
            .contains("missing field: recipient_bundle_id"));
    }

    #[test]
    fn direct_cipher_body_value_matches_go_map_shape() {
        let body = DirectCipherBody {
            session_id: "sid-001".to_owned(),
            suite: Some(MTI_DIRECT_E2EE_SUITE.to_owned()),
            ratchet_header: RatchetHeader {
                dh_pub_b64u: "RATCHETPUB".to_owned(),
                pn: "0".to_owned(),
                n: "1".to_owned(),
            },
            ciphertext_b64u: "CIPHERTEXT".to_owned(),
        };

        assert_eq!(
            direct_cipher_body_to_value(&body),
            json!({
                "session_id": "sid-001",
                "suite": MTI_DIRECT_E2EE_SUITE,
                "ratchet_header": {
                    "dh_pub_b64u": "RATCHETPUB",
                    "pn": "0",
                    "n": "1",
                },
                "ciphertext_b64u": "CIPHERTEXT",
            })
        );
    }

    #[test]
    fn direct_cipher_body_from_value_matches_go_map_parser() {
        let body = direct_cipher_body_from_value(&json!({
            "session_id": "sid-001",
            "suite": MTI_DIRECT_E2EE_SUITE,
            "ratchet_header": {
                "dh_pub_b64u": "RATCHETPUB",
                "pn": 0,
                "n": 1,
            },
            "ciphertext_b64u": "CIPHERTEXT",
        }))
        .expect("cipher body");

        assert_eq!(body.session_id, "sid-001");
        assert_eq!(body.ratchet_header.pn, "0");
        assert_eq!(body.ratchet_header.n, "1");
        assert_eq!(
            direct_cipher_body_to_value(&body).pointer("/ratchet_header/n"),
            Some(&json!("1"))
        );
    }

    #[test]
    fn direct_cipher_body_from_value_rejects_missing_header_fields() {
        let error = direct_cipher_body_from_value(&json!({
            "session_id": "sid-001",
            "ratchet_header": {
                "dh_pub_b64u": "RATCHETPUB",
                "pn": "0",
            },
            "ciphertext_b64u": "CIPHERTEXT",
        }))
        .expect_err("ratchet header n should be required");

        assert!(error
            .to_string()
            .contains("missing field: ratchet_header.n"));
    }

    #[test]
    fn direct_body_from_content_type_selects_receive_body_parser() {
        let init = direct_body_from_content_type(
            CONTENT_TYPE_DIRECT_INIT,
            &json!({
                "session_id": "sid-001",
                "suite": MTI_DIRECT_E2EE_SUITE,
                "sender_static_key_agreement_id": "ka-alice",
                "recipient_bundle_id": "bundle-bob-001",
                "recipient_signed_prekey_id": "spk-bob-001",
                "sender_ephemeral_pub_b64u": "EPHEMERAL",
                "ciphertext_b64u": "CIPHERTEXT",
            }),
        )
        .expect("init body");
        let cipher = direct_body_from_content_type(
            CONTENT_TYPE_DIRECT_CIPHER,
            &json!({
                "session_id": "sid-001",
                "ratchet_header": {"dh_pub_b64u": "RATCHETPUB", "pn": "0", "n": "1"},
                "ciphertext_b64u": "CIPHERTEXT",
            }),
        )
        .expect("cipher body");

        assert!(matches!(init, DirectEnvelopeBody::Init(_)));
        assert!(matches!(cipher, DirectEnvelopeBody::Cipher(_)));
    }

    #[test]
    fn direct_body_from_content_type_rejects_unsupported_receive_content_type() {
        let error = direct_body_from_content_type("application/json", &json!({}))
            .expect_err("unsupported receive content type should fail");

        assert!(error
            .to_string()
            .contains("unsupported content type: application/json"));
    }

    #[test]
    fn plaintext_value_omits_empty_optional_fields_like_go_map_shape() {
        let plaintext = ApplicationPlaintext {
            application_content_type: "application/json".to_owned(),
            conversation_id: Some(String::new()),
            reply_to_message_id: None,
            annotations: Some(json!({})),
            text: None,
            payload: Some(json!({"event": "wave"})),
            payload_b64u: None,
        };

        assert_eq!(
            plaintext_to_value(&plaintext),
            json!({
                "application_content_type": "application/json",
                "payload": {"event": "wave"},
            })
        );
    }

    #[test]
    fn direct_send_request_matches_go_client_rpc_shape() {
        let body = DirectInitBody {
            session_id: "sid-001".to_owned(),
            suite: MTI_DIRECT_E2EE_SUITE.to_owned(),
            sender_static_key_agreement_id: "ka-alice".to_owned(),
            recipient_bundle_id: "bundle-bob-001".to_owned(),
            recipient_signed_prekey_id: "spk-bob-001".to_owned(),
            recipient_one_time_prekey_id: None,
            sender_ephemeral_pub_b64u: "EPHEMERAL".to_owned(),
            ciphertext_b64u: "CIPHERTEXT".to_owned(),
        };

        let request = direct_init_send_request(
            "did:wba:a.example:agents:alice:e1_alice",
            "did:wba:b.example:agents:bob:e1_bob",
            "msg-init",
            "msg-init",
            &body,
        )
        .expect("direct.send init request");

        assert_eq!(request.get("method"), Some(&json!("direct.send")));
        assert_eq!(
            request.pointer("/params/meta"),
            Some(&json!({
                "anp_version": "1.0",
                "profile": "anp.direct.e2ee.v1",
                "security_profile": "direct-e2ee",
                "sender_did": "did:wba:a.example:agents:alice:e1_alice",
                "target": {
                    "kind": "agent",
                    "did": "did:wba:b.example:agents:bob:e1_bob",
                },
                "operation_id": "msg-init",
                "message_id": "msg-init",
                "content_type": CONTENT_TYPE_DIRECT_INIT,
            }))
        );
        assert_eq!(
            request.pointer("/params/body/session_id"),
            Some(&json!("sid-001"))
        );
    }

    #[test]
    fn direct_send_helpers_reject_go_client_id_mismatches() {
        assert!(validate_direct_send_ids("", "msg-001")
            .expect_err("missing id should fail")
            .to_string()
            .contains("missing field: operation_id/message_id"));

        assert!(validate_direct_send_ids("op-001", "msg-001")
            .expect_err("mismatched ids should fail")
            .to_string()
            .contains("direct-e2ee requires operation_id to equal message_id"));
    }

    #[test]
    fn direct_send_request_from_pending_uses_pending_outbox_body() {
        let pending = PendingOutboundRecord {
            operation_id: "msg-2".to_owned(),
            message_id: "msg-2".to_owned(),
            wire_content_type: CONTENT_TYPE_DIRECT_CIPHER.to_owned(),
            body_json: json!({
                "session_id": "sid-001",
                "ratchet_header": {"dh_pub_b64u": "RATCHETPUB", "pn": "0", "n": "1"},
                "ciphertext_b64u": "CIPHERTEXT",
            }),
        };

        let request = direct_send_request_from_pending(
            "did:wba:a.example:agents:alice:e1_alice",
            "did:wba:b.example:agents:bob:e1_bob",
            &pending,
        )
        .expect("pending direct.send request");

        assert_eq!(
            request.pointer("/params/meta/content_type"),
            Some(&json!(CONTENT_TYPE_DIRECT_CIPHER))
        );
        assert_eq!(
            request.pointer("/params/body/ratchet_header/n"),
            Some(&json!("1"))
        );
    }

    #[test]
    fn direct_cipher_send_request_uses_cipher_content_type() {
        let body = DirectCipherBody {
            session_id: "sid-001".to_owned(),
            suite: None,
            ratchet_header: RatchetHeader {
                dh_pub_b64u: "RATCHETPUB".to_owned(),
                pn: "0".to_owned(),
                n: "1".to_owned(),
            },
            ciphertext_b64u: "CIPHERTEXT".to_owned(),
        };

        let request = direct_cipher_send_request(
            "did:wba:a.example:agents:alice:e1_alice",
            "did:wba:b.example:agents:bob:e1_bob",
            "msg-2",
            "msg-2",
            &body,
        )
        .expect("direct.send cipher request");

        assert_eq!(
            request.pointer("/params/meta/content_type"),
            Some(&json!(CONTENT_TYPE_DIRECT_CIPHER))
        );
        assert_eq!(request.pointer("/params/body/suite"), None);
    }
}
