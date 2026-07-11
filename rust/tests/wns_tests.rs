mod common;

use anp::wns::{
    build_handle_service_entry, parse_wba_uri, resolve_handle_with_options, validate_handle,
    verify_handle_binding_with_options, BindingGeneration, BindingVerificationOptions,
    HandleResolutionDocument, HandleStatus, ResolveHandleOptions, SubjectType,
};
use common::JsonTestServer;
use serde_json::json;
use std::fs;
use std::path::PathBuf;

fn binding_generation_vectors() -> serde_json::Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/wns/binding_generation_vectors.json");
    serde_json::from_str(
        &fs::read_to_string(path).expect("read shared WNS binding generation vectors"),
    )
    .expect("parse shared WNS binding generation vectors")
}

#[test]
fn test_validate_handle_and_parse_wba_uri() {
    let (local_part, domain) =
        validate_handle("Alice.Example.COM").expect("handle should validate");
    assert_eq!(local_part, "alice");
    assert_eq!(domain, "example.com");

    let parsed = parse_wba_uri("wba://alice.example.com").expect("URI should parse");
    assert_eq!(parsed.handle, "alice.example.com");
}

#[tokio::test]
async fn test_resolve_handle_with_mock_server() {
    let server = JsonTestServer::start([(
        "/.well-known/handle/alice",
        json!({
            "handle": "alice.example.com",
            "did": "did:wba:example.com:user:alice",
            "status": "active",
            "binding_generation": "8",
            "updated": "2025-01-01T00:00:00Z",
            "profile": {
                "type": "DIDSubjectProfile",
                "subject_did": "did:wba:example.com:user:alice",
                "subject_type": "person",
                "handle": "alice.example.com",
                "display_name": "Alice",
                "avatar_uri": "https://example.com/avatars/alice.png",
                "proof": {"type": "DataIntegrityProof"}
            },
        }),
    )]);

    let result = resolve_handle_with_options(
        "alice.example.com",
        &ResolveHandleOptions {
            base_url_override: Some(server.uri()),
            verify_ssl: false,
            timeout_seconds: 5.0,
        },
    )
    .await
    .expect("handle resolution should succeed");
    assert_eq!(result.did, "did:wba:example.com:user:alice");
    assert_eq!(result.status, HandleStatus::Active);
    assert_eq!(result.binding_generation.as_str(), "8");
    let profile = result.profile.expect("profile should parse");
    assert_eq!(profile.subject_type, SubjectType::Person);
    assert_eq!(profile.display_name.as_deref(), Some("Alice"));
    assert_eq!(profile.proof.unwrap()["type"], "DataIntegrityProof");
}

#[test]
fn test_handle_resolution_document_profile_consistency() {
    let document: HandleResolutionDocument = serde_json::from_value(json!({
        "handle": "alice.example.com",
        "did": "did:wba:example.com:user:alice",
        "status": "active",
        "binding_generation": "8",
        "versionId": "42",
        "ttl": 300,
        "profile": {
            "subject_did": "did:wba:example.com:user:alice",
            "handle": "alice.example.com",
            "display_name": "Alice"
        }
    }))
    .expect("document should deserialize");

    assert_eq!(document.version_id.as_deref(), Some("42"));
    assert_eq!(document.ttl, Some(300));
    let mut normalized_document = document.clone();
    normalized_document.drop_invalid_profile_projection();
    assert!(normalized_document.profile.is_some());
}

#[test]
fn test_handle_resolution_document_new_sets_required_fields() {
    let document = HandleResolutionDocument::new(
        "alice.example.com",
        "did:wba:example.com:user:alice",
        HandleStatus::Active,
        BindingGeneration::new("8").expect("valid generation"),
    );

    assert_eq!(document.handle, "alice.example.com");
    assert_eq!(document.did, "did:wba:example.com:user:alice");
    assert_eq!(document.status, HandleStatus::Active);
    assert_eq!(document.binding_generation.as_str(), "8");
    assert_eq!(document.updated, None);
    assert_eq!(document.version_id, None);
    assert_eq!(document.ttl, None);
    assert_eq!(document.profile, None);
}

#[test]
fn test_binding_generation_requires_canonical_positive_decimal_string() {
    for invalid in ["", "0", "00", "01", "+1", "-1", "1.0", " 1", "1 ", "one"] {
        assert!(
            BindingGeneration::new(invalid).is_err(),
            "{invalid:?} must be rejected"
        );
    }

    for invalid_document in [
        json!({
            "handle": "alice.example.com",
            "did": "did:wba:example.com:user:alice",
            "status": "active"
        }),
        json!({
            "handle": "alice.example.com",
            "did": "did:wba:example.com:user:alice",
            "status": "active",
            "binding_generation": 8
        }),
        json!({
            "handle": "alice.example.com",
            "did": "did:wba:example.com:user:alice",
            "status": "active",
            "binding_generation": "01"
        }),
    ] {
        assert!(serde_json::from_value::<HandleResolutionDocument>(invalid_document).is_err());
    }
}

#[test]
fn test_binding_generation_compares_arbitrary_precision_without_rollback() {
    let previous_value = "9".repeat(512);
    let current_value = format!("1{}", "0".repeat(512));
    let previous =
        BindingGeneration::new(previous_value.clone()).expect("valid previous generation");
    let current = BindingGeneration::new(current_value.clone()).expect("valid current generation");
    let replay = BindingGeneration::new(previous_value).expect("valid replay generation");

    assert!(current.is_newer_than(&previous));
    assert!(!previous.is_newer_than(&current));
    assert!(!replay.is_newer_than(&previous));
    assert_eq!(serde_json::to_value(current).unwrap(), json!(current_value));
}

#[test]
fn test_shared_binding_generation_vectors() {
    let vectors = binding_generation_vectors();

    for case in vectors["validation"]
        .as_array()
        .expect("validation vectors")
    {
        let parsed = serde_json::from_value::<BindingGeneration>(
            case.get("value")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        );
        assert_eq!(
            parsed.is_ok(),
            case["valid"].as_bool().expect("valid flag"),
            "validation vector {}",
            case["name"]
        );
        if let Ok(generation) = parsed {
            assert_eq!(
                generation.as_str(),
                case["canonical"].as_str().expect("canonical generation")
            );
        }
    }

    for transition in vectors["transitions"]
        .as_array()
        .expect("transition vectors")
    {
        let previous = BindingGeneration::new(
            transition["previous"]
                .as_str()
                .expect("previous generation"),
        )
        .expect("valid previous generation");
        let current =
            BindingGeneration::new(transition["current"].as_str().expect("current generation"))
                .expect("valid current generation");
        assert_eq!(
            current.is_newer_than(&previous),
            transition["accepted"].as_bool().expect("accepted flag"),
            "transition vector {}",
            transition["name"]
        );
    }
}

#[tokio::test]
async fn test_resolve_rejects_missing_binding_generation() {
    let server = JsonTestServer::start([(
        "/.well-known/handle/alice",
        json!({
            "handle": "alice.example.com",
            "did": "did:wba:example.com:user:alice",
            "status": "active"
        }),
    )]);

    let error = resolve_handle_with_options(
        "alice.example.com",
        &ResolveHandleOptions {
            base_url_override: Some(server.uri()),
            verify_ssl: false,
            timeout_seconds: 5.0,
        },
    )
    .await
    .expect_err("missing generation must fail closed");
    assert_eq!(error.status_code, 502);
    assert!(error.message.contains("binding_generation"));
}

#[test]
fn test_profile_unknown_subject_type_defaults_to_unknown() {
    let document: HandleResolutionDocument = serde_json::from_value(json!({
        "handle": "alice.example.com",
        "did": "did:wba:example.com:user:alice",
        "status": "active",
        "binding_generation": "8",
        "profile": {
            "subject_did": "did:wba:example.com:user:alice",
            "subject_type": "custom-private-type",
            "display_name": "Alice"
        }
    }))
    .expect("document should deserialize");

    assert_eq!(
        document.profile.expect("profile should parse").subject_type,
        SubjectType::Unknown
    );
}

#[tokio::test]
async fn test_resolve_ignores_profile_subject_did_mismatch() {
    let server = JsonTestServer::start([(
        "/.well-known/handle/alice",
        json!({
            "handle": "alice.example.com",
            "did": "did:wba:example.com:user:alice",
            "status": "active",
            "binding_generation": "8",
            "profile": {
                "subject_did": "did:wba:example.com:user:bob",
                "display_name": "Bob"
            },
        }),
    )]);

    let result = resolve_handle_with_options(
        "alice.example.com",
        &ResolveHandleOptions {
            base_url_override: Some(server.uri()),
            verify_ssl: false,
            timeout_seconds: 5.0,
        },
    )
    .await
    .expect("outer handle resolution should succeed");
    assert_eq!(result.did, "did:wba:example.com:user:alice");
    assert!(result.profile.is_none());
}

#[tokio::test]
async fn test_resolve_ignores_profile_handle_mismatch() {
    let server = JsonTestServer::start([(
        "/.well-known/handle/alice",
        json!({
            "handle": "alice.example.com",
            "did": "did:wba:example.com:user:alice",
            "status": "active",
            "binding_generation": "8",
            "profile": {
                "subject_did": "did:wba:example.com:user:alice",
                "handle": "bob.example.com",
                "display_name": "Bob"
            },
        }),
    )]);

    let result = resolve_handle_with_options(
        "alice.example.com",
        &ResolveHandleOptions {
            base_url_override: Some(server.uri()),
            verify_ssl: false,
            timeout_seconds: 5.0,
        },
    )
    .await
    .expect("outer handle resolution should succeed");
    assert_eq!(result.did, "did:wba:example.com:user:alice");
    assert!(result.profile.is_none());
}

#[tokio::test]
async fn test_verify_handle_binding_with_supplied_did_document() {
    let server = JsonTestServer::start([(
        "/.well-known/handle/alice",
        json!({
            "handle": "alice.example.com",
            "did": "did:wba:example.com:user:alice",
            "status": "active",
            "binding_generation": "8",
        }),
    )]);

    let did_document = json!({
        "id": "did:wba:example.com:user:alice",
        "service": [
            build_handle_service_entry("did:wba:example.com:user:alice", "alice", "example.com")
        ],
    });

    let result = verify_handle_binding_with_options(
        "alice.example.com",
        BindingVerificationOptions {
            did_document: Some(did_document),
            resolution_options: ResolveHandleOptions {
                base_url_override: Some(server.uri()),
                verify_ssl: false,
                timeout_seconds: 5.0,
            },
            ..BindingVerificationOptions::default()
        },
    )
    .await;

    assert!(result.is_valid);
    assert!(result.forward_verified);
    assert!(result.reverse_verified);
    assert_eq!(
        result
            .binding_generation
            .expect("verified generation")
            .as_str(),
        "8"
    );
}

#[tokio::test]
async fn test_verify_handle_binding_accepts_matching_https_domain() {
    let server = JsonTestServer::start([(
        "/.well-known/handle/alice",
        json!({
            "handle": "alice.example.com",
            "did": "did:wba:example.com:user:alice",
            "status": "active",
            "binding_generation": "8",
        }),
    )]);

    let did_document = json!({
        "id": "did:wba:example.com:user:alice",
        "service": [
            {
                "id": "did:wba:example.com:user:alice#handle",
                "type": "ANPHandleService",
                "serviceEndpoint": "https://example.com/providers/wns",
            }
        ],
    });

    let result = verify_handle_binding_with_options(
        "alice.example.com",
        BindingVerificationOptions {
            did_document: Some(did_document),
            resolution_options: ResolveHandleOptions {
                base_url_override: Some(server.uri()),
                verify_ssl: false,
                timeout_seconds: 5.0,
            },
            ..BindingVerificationOptions::default()
        },
    )
    .await;

    assert!(result.is_valid);
    assert!(result.reverse_verified);
}
