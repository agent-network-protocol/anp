use super::errors::DirectE2eeError;
use crate::authentication::ANP_MESSAGE_SERVICE_TYPE;
use serde_json::Value;
use std::collections::BTreeSet;

pub fn message_service_did_from_document(did_document: &Value) -> Result<String, DirectE2eeError> {
    let services = did_document
        .get("service")
        .and_then(Value::as_array)
        .ok_or(DirectE2eeError::MissingField("service"))?;

    let candidates: Vec<String> = services
        .iter()
        .filter_map(Value::as_object)
        .filter(|service| string_value(service.get("type")) == ANP_MESSAGE_SERVICE_TYPE)
        .filter_map(|service| {
            let service_did = string_value(service.get("serviceDid"));
            (!service_did.is_empty()).then_some(service_did)
        })
        .collect();

    match candidates.len() {
        0 => Err(DirectE2eeError::MissingField("serviceDid")),
        1 => Ok(candidates[0].clone()),
        _ => {
            let unique: BTreeSet<&str> = candidates.iter().map(String::as_str).collect();
            if unique.len() == 1 {
                Ok(candidates[0].clone())
            } else {
                Err(DirectE2eeError::invalid_field(
                    "ANPMessageService.serviceDid",
                ))
            }
        }
    }
}

fn string_value(value: Option<&Value>) -> String {
    value.and_then(Value::as_str).unwrap_or_default().to_owned()
}

#[cfg(test)]
mod tests {
    use super::message_service_did_from_document;
    use serde_json::json;

    #[test]
    fn message_service_did_from_document_matches_go_service_did_selection() {
        let service_did = message_service_did_from_document(&json!({
            "id": "did:wba:b.example:agents:bob:e1_bob",
            "service": [
                {
                    "id": "#profile",
                    "type": "ProfileService",
                    "serviceDid": "did:wba:b.example:profile"
                },
                {
                    "id": "#direct",
                    "type": "ANPMessageService",
                    "serviceEndpoint": "https://b.example/anp-im/rpc",
                    "serviceDid": "did:wba:b.example",
                    "profiles": ["anp.direct.base.v1"],
                    "securityProfiles": ["transport-protected"]
                }
            ]
        }))
        .expect("message service DID");

        assert_eq!(service_did, "did:wba:b.example");
    }

    #[test]
    fn message_service_did_from_document_accepts_duplicate_same_service_did() {
        let service_did = message_service_did_from_document(&json!({
            "service": [
                {
                    "type": "ANPMessageService",
                    "serviceDid": "did:wba:b.example",
                    "priority": 1
                },
                {
                    "type": "ANPMessageService",
                    "serviceDid": "did:wba:b.example",
                    "priority": 2
                }
            ]
        }))
        .expect("duplicate same service DID");

        assert_eq!(service_did, "did:wba:b.example");
    }

    #[test]
    fn message_service_did_from_document_rejects_missing_or_ambiguous_service_did() {
        let missing_service = message_service_did_from_document(&json!({}))
            .expect_err("missing service array should fail");
        assert!(missing_service
            .to_string()
            .contains("missing field: service"));

        let missing_service_did = message_service_did_from_document(&json!({
            "service": [
                {"type": "ANPMessageService", "serviceEndpoint": "https://b.example/rpc"}
            ]
        }))
        .expect_err("missing serviceDid should fail");
        assert!(missing_service_did
            .to_string()
            .contains("missing field: serviceDid"));

        let ambiguous = message_service_did_from_document(&json!({
            "service": [
                {"type": "ANPMessageService", "serviceDid": "did:wba:b.example"},
                {"type": "ANPMessageService", "serviceDid": "did:wba:alt.example"}
            ]
        }))
        .expect_err("distinct serviceDids should be ambiguous");
        assert!(ambiguous
            .to_string()
            .contains("invalid field: ANPMessageService.serviceDid"));

        let non_string = message_service_did_from_document(&json!({
            "service": [
                {"type": "ANPMessageService", "serviceDid": 123}
            ]
        }))
        .expect_err("non-string serviceDid should fail");
        assert!(non_string.to_string().contains("missing field: serviceDid"));
    }
}
