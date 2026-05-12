use super::errors::DirectE2eeError;
use super::models::{OneTimePrekey, PrekeyBundle, SignedPrekey, MTI_DIRECT_E2EE_SUITE};
use crate::authentication::{
    create_verification_method, find_verification_method, validate_did_document_binding,
};
use crate::keys::base64url_encode;
use crate::proof::{generate_object_proof, verify_object_proof};
use crate::PrivateKeyMaterial;
use serde_json::{json, Value};
use std::error::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

pub fn signed_prekey_from_private_key(
    key_id: &str,
    private_key: &X25519StaticSecret,
    expires_at: &str,
) -> SignedPrekey {
    let public_key = X25519PublicKey::from(private_key);
    SignedPrekey {
        key_id: key_id.to_owned(),
        public_key_b64u: base64url_encode(&public_key.to_bytes()),
        expires_at: expires_at.to_owned(),
    }
}

pub fn build_prekey_bundle(
    bundle_id: &str,
    owner_did: &str,
    static_key_agreement_id: &str,
    signed_prekey: SignedPrekey,
    signing_private_key: &PrivateKeyMaterial,
    verification_method: &str,
    created: Option<&str>,
) -> Result<PrekeyBundle, DirectE2eeError> {
    let unsigned = json!({
        "bundle_id": bundle_id,
        "owner_did": owner_did,
        "suite": MTI_DIRECT_E2EE_SUITE,
        "static_key_agreement_id": static_key_agreement_id,
        "signed_prekey": signed_prekey,
    });
    let signed = generate_object_proof(
        &unsigned,
        signing_private_key,
        verification_method,
        owner_did,
        created.map(ToOwned::to_owned),
    )?;
    let proof = signed
        .get("proof")
        .cloned()
        .ok_or(DirectE2eeError::MissingField("proof"))?;
    Ok(PrekeyBundle {
        bundle_id: bundle_id.to_owned(),
        owner_did: owner_did.to_owned(),
        suite: MTI_DIRECT_E2EE_SUITE.to_owned(),
        static_key_agreement_id: static_key_agreement_id.to_owned(),
        signed_prekey,
        proof,
    })
}

pub fn prekey_bundle_publish_body(
    bundle: &PrekeyBundle,
    one_time_prekeys: &[OneTimePrekey],
) -> Value {
    let mut body = json!({
        "prekey_bundle": bundle,
    });
    if !one_time_prekeys.is_empty() {
        body["one_time_prekeys"] = json!(one_time_prekeys);
    }
    body
}

pub fn prekey_bundle_publish_request(
    local_did: &str,
    local_service_did: &str,
    bundle: &PrekeyBundle,
    one_time_prekeys: &[OneTimePrekey],
) -> Value {
    json!({
        "method": "direct.e2ee.publish_prekey_bundle",
        "params": {
            "meta": {
                "anp_version": "1.0",
                "profile": "anp.direct.e2ee.v1",
                "security_profile": "transport-protected",
                "sender_did": local_did,
                "target": {
                    "kind": "service",
                    "did": local_service_did,
                },
                "operation_id": format!("op-publish-{}", bundle.bundle_id),
            },
            "body": prekey_bundle_publish_body(bundle, one_time_prekeys),
        },
    })
}

pub fn prekey_bundle_get_body(target_did: &str, require_opk: bool) -> Value {
    json!({
        "target_did": target_did,
        "require_opk": require_opk,
    })
}

pub fn validate_prekey_bundle_get_operation_id(operation_id: &str) -> Result<(), DirectE2eeError> {
    if operation_id.is_empty() {
        return Err(DirectE2eeError::MissingField("operation_id"));
    }
    if !operation_id.starts_with("op-get-prekey-") {
        return Err(DirectE2eeError::invalid_field(
            "get_prekey_bundle operation_id must start with op-get-prekey-",
        ));
    }
    Ok(())
}

pub fn prekey_bundle_get_request(
    local_did: &str,
    target_service_did: &str,
    target_did: &str,
    require_opk: bool,
    operation_id: &str,
) -> Value {
    json!({
        "method": "direct.e2ee.get_prekey_bundle",
        "params": {
            "meta": {
                "anp_version": "1.0",
                "profile": "anp.direct.e2ee.v1",
                "security_profile": "transport-protected",
                "sender_did": local_did,
                "target": {
                    "kind": "service",
                    "did": target_service_did,
                },
                "operation_id": operation_id,
            },
            "body": prekey_bundle_get_body(target_did, require_opk),
        },
    })
}

pub fn checked_prekey_bundle_get_request(
    local_did: &str,
    target_service_did: &str,
    target_did: &str,
    require_opk: bool,
    operation_id: &str,
) -> Result<Value, DirectE2eeError> {
    validate_prekey_bundle_get_operation_id(operation_id)?;
    Ok(prekey_bundle_get_request(
        local_did,
        target_service_did,
        target_did,
        require_opk,
        operation_id,
    ))
}

pub fn should_retry_without_opk(error: &(dyn Error + 'static)) -> bool {
    should_retry_without_opk_message(&error.to_string())
}

pub fn should_retry_without_opk_message(message: &str) -> bool {
    message.contains("anp.direct.e2ee.opk_unavailable")
        || message.contains("direct.e2ee_opk_unsupported")
        || message.contains("4003")
        || message.contains("3402")
}

pub fn verify_prekey_bundle(
    bundle: &PrekeyBundle,
    did_document: &Value,
) -> Result<(), DirectE2eeError> {
    if bundle.suite != MTI_DIRECT_E2EE_SUITE {
        return Err(DirectE2eeError::UnsupportedSuite(bundle.suite.clone()));
    }
    if did_document.get("id").and_then(Value::as_str) != Some(bundle.owner_did.as_str()) {
        return Err(DirectE2eeError::invalid_field(
            "owner_did must match the issuer DID document",
        ));
    }
    if bundle.owner_did.starts_with("did:wba:")
        && !validate_did_document_binding(did_document, false)
    {
        return Err(DirectE2eeError::invalid_field(
            "owner DID document binding validation failed",
        ));
    }
    let key_agreement = did_document
        .get("keyAgreement")
        .and_then(Value::as_array)
        .ok_or(DirectE2eeError::MissingField("keyAgreement"))?;
    let static_key_found = key_agreement
        .iter()
        .any(|entry| entry.as_str() == Some(&bundle.static_key_agreement_id));
    if !static_key_found {
        return Err(DirectE2eeError::invalid_field(
            "static_key_agreement_id must appear in did_document.keyAgreement",
        ));
    }
    let signed_bundle = serde_json::to_value(bundle).map_err(|error| {
        DirectE2eeError::invalid_field(format!("invalid bundle serialization: {error}"))
    })?;
    verify_object_proof(&signed_bundle, &bundle.owner_did, did_document)?;
    Ok(())
}

pub fn extract_x25519_public_key(
    did_document: &Value,
    key_id: &str,
) -> Result<[u8; 32], DirectE2eeError> {
    let method = find_verification_method(did_document, key_id).ok_or_else(|| {
        DirectE2eeError::invalid_field(format!("verification method not found: {key_id}"))
    })?;
    let verification_method = create_verification_method(&method).map_err(|error| {
        DirectE2eeError::invalid_field(format!("invalid verification method: {error}"))
    })?;
    match verification_method.public_key {
        crate::PublicKeyMaterial::X25519(bytes) => Ok(bytes),
        _ => Err(DirectE2eeError::invalid_field(format!(
            "verification method is not X25519: {key_id}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_prekey_bundle, checked_prekey_bundle_get_request, prekey_bundle_get_body,
        prekey_bundle_get_request, prekey_bundle_publish_body, prekey_bundle_publish_request,
        should_retry_without_opk, should_retry_without_opk_message, signed_prekey_from_private_key,
        validate_prekey_bundle_get_operation_id, verify_prekey_bundle,
    };
    use crate::authentication::{create_did_wba_document, DidDocumentOptions, DidProfile};
    use crate::direct_e2ee::models::{
        OneTimePrekey, PrekeyBundle, SignedPrekey, MTI_DIRECT_E2EE_SUITE,
    };
    use crate::direct_e2ee::DirectE2eeError;
    use crate::PrivateKeyMaterial;
    use serde_json::{json, Value};
    use x25519_dalek::StaticSecret as X25519StaticSecret;

    #[test]
    fn bundle_round_trip_verifies_against_did_document() {
        let bundle = create_did_wba_document(
            "bundle.example",
            DidDocumentOptions {
                path_segments: vec!["agents".to_owned(), "alice".to_owned()],
                did_profile: DidProfile::E1,
                ..Default::default()
            },
        )
        .expect("did document");
        let did = bundle.did().expect("did");
        let signing_key = PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
            .expect("private key");
        let spk_private = X25519StaticSecret::from([7u8; 32]);
        let signed_prekey =
            signed_prekey_from_private_key("spk-001", &spk_private, "2026-04-07T00:00:00Z");
        let built = build_prekey_bundle(
            "bundle-001",
            did,
            &format!("{did}#key-3"),
            signed_prekey,
            &signing_key,
            &format!("{did}#key-1"),
            Some("2026-03-31T09:58:58Z"),
        )
        .expect("bundle");

        verify_prekey_bundle(&built, &bundle.did_document).expect("bundle should verify");
    }

    #[test]
    fn publish_body_keeps_one_time_prekeys_top_level() {
        let bundle = create_did_wba_document(
            "bundle.example",
            DidDocumentOptions {
                path_segments: vec!["agents".to_owned(), "alice".to_owned()],
                did_profile: DidProfile::E1,
                ..Default::default()
            },
        )
        .expect("did document");
        let did = bundle.did().expect("did");
        let signing_key = PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
            .expect("private key");
        let spk_private = X25519StaticSecret::from([7u8; 32]);
        let signed_prekey =
            signed_prekey_from_private_key("spk-001", &spk_private, "2026-04-07T00:00:00Z");
        let built = build_prekey_bundle(
            "bundle-001",
            did,
            &format!("{did}#key-3"),
            signed_prekey,
            &signing_key,
            &format!("{did}#key-1"),
            Some("2026-03-31T09:58:58Z"),
        )
        .expect("bundle");

        let body = prekey_bundle_publish_body(
            &built,
            &[
                OneTimePrekey {
                    key_id: "opk-001".to_owned(),
                    public_key_b64u: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".to_owned(),
                },
                OneTimePrekey {
                    key_id: "opk-002".to_owned(),
                    public_key_b64u: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".to_owned(),
                },
            ],
        );

        assert!(body.get("prekey_bundle").is_some());
        assert_eq!(
            body.pointer("/one_time_prekeys/0/key_id"),
            Some(&json!("opk-001"))
        );
        assert_eq!(body.pointer("/prekey_bundle/one_time_prekey"), None);
        assert_eq!(body.pointer("/prekey_bundle/one_time_prekeys"), None);
        assert_eq!(
            body.pointer("/prekey_bundle/signed_prekey/key_id"),
            Some(&json!("spk-001"))
        );

        let bundle_value = body
            .get("prekey_bundle")
            .expect("prekey bundle should be present");
        let bundle_object = bundle_value
            .as_object()
            .expect("prekey bundle should serialize as object");
        for field in [
            "bundle_id",
            "owner_did",
            "suite",
            "static_key_agreement_id",
            "signed_prekey",
            "proof",
        ] {
            assert!(bundle_object.contains_key(field), "missing {field}");
        }
    }

    #[test]
    fn publish_body_omits_empty_one_time_prekeys() {
        let bundle = PrekeyBundle {
            bundle_id: "bundle-001".to_owned(),
            owner_did: "did:wba:bundle.example:agents:alice:e1_alice".to_owned(),
            suite: MTI_DIRECT_E2EE_SUITE.to_owned(),
            static_key_agreement_id: "did:wba:bundle.example:agents:alice:e1_alice#key-3"
                .to_owned(),
            signed_prekey: SignedPrekey {
                key_id: "spk-001".to_owned(),
                public_key_b64u: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM".to_owned(),
                expires_at: "2026-04-07T00:00:00Z".to_owned(),
            },
            proof: Value::Object(Default::default()),
        };

        let body = prekey_bundle_publish_body(&bundle, &[]);

        assert!(body.get("prekey_bundle").is_some());
        assert_eq!(body.get("one_time_prekeys"), None);
    }

    #[test]
    fn publish_request_matches_message_service_rpc_contract() {
        let bundle = PrekeyBundle {
            bundle_id: "bundle-bob-001".to_owned(),
            owner_did: "did:wba:b.example:agents:bob:e1_bob".to_owned(),
            suite: MTI_DIRECT_E2EE_SUITE.to_owned(),
            static_key_agreement_id: "did:wba:b.example:agents:bob:e1_bob#key-3".to_owned(),
            signed_prekey: SignedPrekey {
                key_id: "spk-bob-001".to_owned(),
                public_key_b64u: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM".to_owned(),
                expires_at: "2026-04-07T00:00:00Z".to_owned(),
            },
            proof: json!({
                "type": "DataIntegrityProof",
                "verificationMethod": "did:wba:b.example:agents:bob:e1_bob#key-1",
            }),
        };
        let opks = vec![
            OneTimePrekey {
                key_id: "opk-001".to_owned(),
                public_key_b64u: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE".to_owned(),
            },
            OneTimePrekey {
                key_id: "opk-002".to_owned(),
                public_key_b64u: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI".to_owned(),
            },
        ];

        let request = prekey_bundle_publish_request(
            "did:wba:b.example:agents:bob:e1_bob",
            "did:wba:b.example:services:message:e1_service",
            &bundle,
            &opks,
        );

        assert_eq!(
            request.get("method"),
            Some(&json!("direct.e2ee.publish_prekey_bundle"))
        );
        assert_eq!(
            request.pointer("/params/meta"),
            Some(&json!({
                "anp_version": "1.0",
                "profile": "anp.direct.e2ee.v1",
                "security_profile": "transport-protected",
                "sender_did": "did:wba:b.example:agents:bob:e1_bob",
                "target": {
                    "kind": "service",
                    "did": "did:wba:b.example:services:message:e1_service",
                },
                "operation_id": "op-publish-bundle-bob-001",
            }))
        );
        assert_eq!(
            request.pointer("/params/body/prekey_bundle/bundle_id"),
            Some(&json!("bundle-bob-001"))
        );
        assert_eq!(
            request.pointer("/params/body/one_time_prekeys/1/key_id"),
            Some(&json!("opk-002"))
        );
        assert_eq!(
            request.pointer("/params/body/prekey_bundle/one_time_prekeys"),
            None
        );
    }

    #[test]
    fn get_request_matches_message_service_rpc_contract() {
        let body = prekey_bundle_get_body("did:wba:b.example:agents:bob:e1_bob", true);
        assert_eq!(
            body,
            json!({
                "target_did": "did:wba:b.example:agents:bob:e1_bob",
                "require_opk": true,
            })
        );

        let request = prekey_bundle_get_request(
            "did:wba:a.example:agents:alice:e1_alice",
            "did:wba:b.example:services:message:e1_service",
            "did:wba:b.example:agents:bob:e1_bob",
            false,
            "op-get-prekey-001",
        );

        assert_eq!(
            request.get("method"),
            Some(&json!("direct.e2ee.get_prekey_bundle"))
        );
        assert_eq!(
            request.pointer("/params/meta"),
            Some(&json!({
                "anp_version": "1.0",
                "profile": "anp.direct.e2ee.v1",
                "security_profile": "transport-protected",
                "sender_did": "did:wba:a.example:agents:alice:e1_alice",
                "target": {
                    "kind": "service",
                    "did": "did:wba:b.example:services:message:e1_service",
                },
                "operation_id": "op-get-prekey-001",
            }))
        );
        assert_eq!(
            request.pointer("/params/body"),
            Some(&json!({
                "target_did": "did:wba:b.example:agents:bob:e1_bob",
                "require_opk": false,
            }))
        );
        assert_eq!(request.pointer("/params/meta/message_id"), None);
        assert_eq!(request.pointer("/params/meta/content_type"), None);
    }

    #[test]
    fn checked_get_request_requires_go_operation_id_prefix() {
        let request = checked_prekey_bundle_get_request(
            "did:wba:a.example:agents:alice:e1_alice",
            "did:wba:b.example:services:message:e1_service",
            "did:wba:b.example:agents:bob:e1_bob",
            true,
            "op-get-prekey-001",
        )
        .expect("prefixed get_prekey_bundle request");

        assert_eq!(
            request.pointer("/params/meta/operation_id"),
            Some(&json!("op-get-prekey-001"))
        );
        assert_eq!(
            request.pointer("/params/body/require_opk"),
            Some(&json!(true))
        );
    }

    #[test]
    fn get_operation_id_validation_rejects_missing_or_wrong_prefix() {
        assert!(validate_prekey_bundle_get_operation_id("")
            .expect_err("missing operation id should fail")
            .to_string()
            .contains("missing field: operation_id"));

        assert!(validate_prekey_bundle_get_operation_id("msg-init")
            .expect_err("wrong get_prekey_bundle prefix should fail")
            .to_string()
            .contains("get_prekey_bundle operation_id must start with op-get-prekey-"));
    }

    #[test]
    fn opk_retry_classifier_matches_go_fallback_tokens() {
        for message in [
            "rpc failed: anp.direct.e2ee.opk_unavailable",
            "remote rejected request: direct.e2ee_opk_unsupported",
            "message service error 4003",
            "legacy service code 3402",
        ] {
            assert!(
                should_retry_without_opk_message(message),
                "{message} should retry without OPK"
            );
        }

        let direct_error = DirectE2eeError::invalid_field("direct.e2ee_opk_unsupported");
        assert!(should_retry_without_opk(&direct_error));
    }

    #[test]
    fn opk_retry_classifier_ignores_unrelated_errors() {
        for message in [
            "",
            "missing field: prekey_bundle",
            "rpc failed: unauthorized",
            "unsupported suite: ANP-DIRECT-E2EE-UNKNOWN",
        ] {
            assert!(
                !should_retry_without_opk_message(message),
                "{message} should not retry without OPK"
            );
        }

        let direct_error = DirectE2eeError::MissingField("prekey_bundle");
        assert!(!should_retry_without_opk(&direct_error));
    }
}
