use std::fs;

use anp::authentication::{
    create_did_wba_document, generate_auth_header, generate_http_signature_headers,
    verify_auth_header_signature, verify_http_message_signature, AuthMode,
    DIDWbaAuthHeader, DidDocumentOptions, DidProfile, DidWbaVerifier,
    DidWbaVerifierConfig,
};
use serde_json::json;
use tempfile::tempdir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[test]
fn test_create_did_document_profiles() {
    let e1 = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["user".to_string(), "alice".to_string()],
            ..DidDocumentOptions::default()
        },
    )
    .expect("e1 DID creation should succeed");
    assert!(e1.did_document["id"].as_str().unwrap().contains(":e1_"));
    assert_eq!(e1.did_document["proof"]["type"], json!("DataIntegrityProof"));

    let k1 = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["user".to_string(), "alice".to_string()],
            did_profile: DidProfile::K1,
            ..DidDocumentOptions::default()
        },
    )
    .expect("k1 DID creation should succeed");
    assert!(k1.did_document["id"].as_str().unwrap().contains(":k1_"));

    let legacy = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["user".to_string(), "alice".to_string()],
            did_profile: DidProfile::PlainLegacy,
            ..DidDocumentOptions::default()
        },
    )
    .expect("legacy DID creation should succeed");
    assert_eq!(legacy.did_document["proof"]["type"], json!("EcdsaSecp256k1Signature2019"));
}

#[test]
fn test_legacy_auth_header_generation_and_verification() {
    let bundle = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["user".to_string(), "alice".to_string()],
            did_profile: DidProfile::K1,
            ..DidDocumentOptions::default()
        },
    )
    .expect("DID creation should succeed");
    let private_key = anp::PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
        .expect("private key should load");
    let header = generate_auth_header(
        &bundle.did_document,
        "api.example.com",
        &private_key,
        "1.1",
    )
    .expect("auth header generation should succeed");
    verify_auth_header_signature(&header, &bundle.did_document, "api.example.com")
        .expect("verification should succeed");
}

#[test]
fn test_http_signature_verification_rejects_tampered_body() {
    let bundle = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("DID creation should succeed");
    let private_key = anp::PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
        .expect("private key should load");
    let headers = generate_http_signature_headers(
        &bundle.did_document,
        "https://api.example.com/orders",
        "POST",
        &private_key,
        None,
        Some(br#"{"item":"book"}"#),
        Default::default(),
    )
    .expect("HTTP signature generation should succeed");
    assert!(verify_http_message_signature(
        &bundle.did_document,
        "POST",
        "https://api.example.com/orders",
        &headers,
        Some(br#"{"item":"book"}"#),
    )
    .is_ok());
    assert!(verify_http_message_signature(
        &bundle.did_document,
        "POST",
        "https://api.example.com/orders",
        &headers,
        Some(br#"{"item":"music"}"#),
    )
    .is_err());
}

#[test]
fn test_did_wba_auth_header_reads_files_and_generates_headers() {
    let bundle = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("DID creation should succeed");
    let temp = tempdir().expect("temp dir should exist");
    let did_path = temp.path().join("did.json");
    let key_path = temp.path().join("key.pem");
    fs::write(&did_path, serde_json::to_vec(&bundle.did_document).unwrap()).unwrap();
    fs::write(&key_path, &bundle.keys["key-1"].private_key_pem).unwrap();

    let mut helper = DIDWbaAuthHeader::new(&did_path, &key_path, AuthMode::HttpSignatures);
    let headers = helper
        .get_auth_header("https://api.example.com/orders", false, "GET", None, None)
        .expect("header generation should succeed");
    assert!(headers.contains_key("Signature-Input"));
    assert!(headers.contains_key("Signature"));
}

#[tokio::test]
async fn test_did_wba_verifier_accepts_http_signatures() {
    let bundle = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("DID creation should succeed");
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/.well-known/did.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(bundle.did_document.clone()))
        .mount(&server)
        .await;

    let private_key = anp::PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
        .expect("private key should load");
    let request_url = format!("{}/orders", server.uri());
    let headers = generate_http_signature_headers(
        &bundle.did_document,
        &request_url,
        "GET",
        &private_key,
        None,
        None,
        Default::default(),
    )
    .expect("HTTP signature generation should succeed");

    let mut verifier = DidWbaVerifier::new(DidWbaVerifierConfig {
        jwt_private_key: Some("test-secret".to_string()),
        jwt_public_key: Some("test-secret".to_string()),
        jwt_algorithm: "HS256".to_string(),
        did_resolution_options: anp::authentication::DidResolutionOptions {
            base_url_override: Some(server.uri()),
            verify_ssl: false,
            timeout_seconds: 5.0,
        },
        ..DidWbaVerifierConfig::default()
    });

    let result = verifier
        .verify_request("GET", &request_url, &headers, None, Some("api.example.com"))
        .await
        .expect("verification should succeed");
    assert_eq!(result.auth_scheme, "http_signatures");
    assert!(result.access_token.is_some());
}
