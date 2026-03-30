use anp::wns::{
    build_handle_service_entry, parse_wba_uri, resolve_handle_with_options,
    validate_handle, verify_handle_binding_with_options, BindingVerificationOptions,
    HandleStatus, ResolveHandleOptions,
};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn test_validate_handle_and_parse_wba_uri() {
    let (local_part, domain) = validate_handle("Alice.Example.COM").expect("handle should validate");
    assert_eq!(local_part, "alice");
    assert_eq!(domain, "example.com");

    let parsed = parse_wba_uri("wba://alice.example.com").expect("URI should parse");
    assert_eq!(parsed.handle, "alice.example.com");
}

#[tokio::test]
async fn test_resolve_handle_with_mock_server() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/handle/alice"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "handle": "alice.example.com",
                "did": "did:wba:example.com:user:alice",
                "status": "active",
                "updated": "2025-01-01T00:00:00Z",
            })),
        )
        .mount(&server)
        .await;

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
}

#[tokio::test]
async fn test_verify_handle_binding_with_supplied_did_document() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/handle/alice"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({
                "handle": "alice.example.com",
                "did": "did:wba:example.com:user:alice",
                "status": "active",
            })),
        )
        .mount(&server)
        .await;

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
}
