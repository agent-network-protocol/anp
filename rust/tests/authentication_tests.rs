use std::collections::BTreeMap;
use std::fs;

use anp::authentication::{
    build_agent_message_service, build_agent_message_service_with_options,
    build_anp_message_service, build_group_message_service, create_did_wba_document,
    extract_signature_metadata, generate_auth_header, generate_http_signature_headers,
    verify_auth_header_signature, verify_federated_http_request, verify_http_message_signature,
    AnpMessageServiceOptions, AuthMode, DIDWbaAuthHeader, DidDocumentOptions, DidProfile,
    DidWbaVerifier, DidWbaVerifierConfig, FederatedVerificationOptions,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::SigningKey;
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
    assert_eq!(
        e1.did_document["proof"]["type"],
        json!("DataIntegrityProof")
    );

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
    assert_eq!(
        legacy.did_document["proof"]["type"],
        json!("EcdsaSecp256k1Signature2019")
    );

    let bare = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("bare DID creation should succeed");
    assert_eq!(bare.did_document["id"], json!("did:wba:example.com"));
}

#[test]
fn test_build_anp_message_service_helpers() {
    let agent =
        build_agent_message_service("did:wba:example.com:user:alice", "https://example.com/rpc");
    assert_eq!(agent["type"], json!("ANPMessageService"));
    assert_eq!(agent["id"], json!("did:wba:example.com:user:alice#message"));
    assert_eq!(agent["profiles"][1], json!("anp.direct.base.v1"));
    assert_eq!(agent["securityProfiles"][1], json!("direct-e2ee"));

    let group =
        build_group_message_service("did:wba:example.com:groups:test", "https://example.com/rpc");
    assert_eq!(group["type"], json!("ANPMessageService"));
    assert_eq!(group["profiles"][1], json!("anp.group.base.v1"));
    assert_eq!(group["securityProfiles"][1], json!("group-e2ee"));

    let service_ref = build_anp_message_service(
        "#message",
        "https://example.com/rpc",
        AnpMessageServiceOptions::default(),
    );
    assert_eq!(service_ref["id"], json!("#message"));
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
    let header = generate_auth_header(&bundle.did_document, "api.example.com", &private_key, "1.1")
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
fn test_build_agent_message_service_with_service_did() {
    let service = build_agent_message_service_with_options(
        "did:wba:example.com:agents:alice:e1_demo",
        "https://example.com/anp",
        AnpMessageServiceOptions::default().with_service_did("did:wba:example.com"),
    );
    assert_eq!(service["serviceDid"], json!("did:wba:example.com"));
}

#[tokio::test]
async fn test_verify_federated_http_request_with_did_wba_service_did() {
    let sender = create_did_wba_document(
        "a.example.com",
        DidDocumentOptions {
            path_segments: vec!["agents".to_string(), "alice".to_string()],
            ..DidDocumentOptions::default()
        },
    )
    .expect("sender DID creation should succeed");
    let service_identity = create_did_wba_document("a.example.com", DidDocumentOptions::default())
        .expect("service DID creation should succeed");
    let private_key =
        anp::PrivateKeyMaterial::from_pem(&service_identity.keys["key-1"].private_key_pem)
            .expect("private key should load");
    let mut sender_document = sender.did_document.clone();
    sender_document
        .as_object_mut()
        .expect("sender document should be object")
        .insert(
            "service".to_string(),
            json!([build_agent_message_service_with_options(
                sender.did_document["id"].as_str().unwrap(),
                "https://a.example.com/anp",
                AnpMessageServiceOptions::default().with_service_did("did:wba:a.example.com"),
            )]),
        );
    let headers = generate_http_signature_headers(
        &service_identity.did_document,
        "https://b.example.com/anp",
        "POST",
        &private_key,
        None,
        Some(br#"{"message":"hello"}"#),
        Default::default(),
    )
    .expect("headers should generate");

    let result = verify_federated_http_request(
        sender.did_document["id"].as_str().unwrap(),
        "POST",
        "https://b.example.com/anp",
        &headers,
        Some(br#"{"message":"hello"}"#),
        FederatedVerificationOptions {
            sender_did_document: Some(sender_document),
            service_did_document: Some(service_identity.did_document.clone()),
            ..FederatedVerificationOptions::default()
        },
    )
    .await
    .expect("federated verification should succeed");

    assert_eq!(result.service_did, "did:wba:a.example.com");
    assert_eq!(
        result.signature_metadata.keyid,
        "did:wba:a.example.com#key-1"
    );
}

#[tokio::test]
async fn test_verify_federated_http_request_with_did_web_service_did() {
    let sender = create_did_wba_document(
        "a.example.com",
        DidDocumentOptions {
            path_segments: vec!["agents".to_string(), "alice".to_string()],
            ..DidDocumentOptions::default()
        },
    )
    .expect("sender DID creation should succeed");
    let mut sender_document = sender.did_document.clone();
    sender_document
        .as_object_mut()
        .expect("sender document should be object")
        .insert(
            "service".to_string(),
            json!([build_agent_message_service_with_options(
                sender.did_document["id"].as_str().unwrap(),
                "https://a.example.com/anp",
                AnpMessageServiceOptions::default().with_service_did("did:web:a.example.com"),
            )]),
        );

    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    let service_document = json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": "did:web:a.example.com",
        "verificationMethod": [{
            "id": "did:web:a.example.com#key-1",
            "type": "Ed25519VerificationKey2020",
            "controller": "did:web:a.example.com",
            "publicKeyJwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(verifying_key.as_bytes()),
            }
        }],
        "authentication": ["did:web:a.example.com#key-1"]
    });
    let private_key = anp::PrivateKeyMaterial::Ed25519(signing_key);
    let headers = generate_http_signature_headers(
        &service_document,
        "https://b.example.com/anp",
        "POST",
        &private_key,
        None,
        Some(br#"{"message":"hello"}"#),
        Default::default(),
    )
    .expect("headers should generate");

    let result = verify_federated_http_request(
        sender.did_document["id"].as_str().unwrap(),
        "POST",
        "https://b.example.com/anp",
        &headers,
        Some(br#"{"message":"hello"}"#),
        FederatedVerificationOptions {
            sender_did_document: Some(sender_document),
            service_did_document: Some(service_document),
            ..FederatedVerificationOptions::default()
        },
    )
    .await
    .expect("federated verification should succeed");

    assert_eq!(result.service_did, "did:web:a.example.com");
    assert_eq!(
        result.signature_metadata.keyid,
        "did:web:a.example.com#key-1"
    );
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

#[test]
fn test_did_wba_auth_header_reuses_server_nonce_for_challenge() {
    let bundle = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("DID creation should succeed");
    let temp = tempdir().expect("temp dir should exist");
    let did_path = temp.path().join("did.json");
    let key_path = temp.path().join("key.pem");
    fs::write(&did_path, serde_json::to_vec(&bundle.did_document).unwrap()).unwrap();
    fs::write(&key_path, &bundle.keys["key-1"].private_key_pem).unwrap();

    let mut helper = DIDWbaAuthHeader::new(&did_path, &key_path, AuthMode::HttpSignatures);
    let mut response_headers = BTreeMap::new();
    response_headers.insert(
        "WWW-Authenticate".to_string(),
        "DIDWba realm=\"api.example.com\", error=\"invalid_nonce\", error_description=\"Retry\", nonce=\"server-nonce-123\"".to_string(),
    );
    response_headers.insert(
        "Accept-Signature".to_string(),
        "sig1=(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\" \"content-type\");created;expires;nonce;keyid".to_string(),
    );
    let mut request_headers = BTreeMap::new();
    request_headers.insert("Content-Type".to_string(), "application/json".to_string());

    let headers = helper
        .get_challenge_auth_header(
            "https://api.example.com/orders",
            &response_headers,
            "POST",
            Some(&request_headers),
            Some(br#"{"item":"book"}"#),
        )
        .expect("challenge auth headers should be generated");
    let metadata = extract_signature_metadata(&headers).expect("metadata should parse");
    assert_eq!(metadata.nonce.as_deref(), Some("server-nonce-123"));
    assert!(metadata
        .components
        .iter()
        .any(|value| value == "content-type"));
    assert!(headers.contains_key("Content-Digest"));
}

#[test]
fn test_did_wba_auth_header_should_not_retry_invalid_did() {
    let bundle = create_did_wba_document("example.com", DidDocumentOptions::default())
        .expect("DID creation should succeed");
    let temp = tempdir().expect("temp dir should exist");
    let did_path = temp.path().join("did.json");
    let key_path = temp.path().join("key.pem");
    fs::write(&did_path, serde_json::to_vec(&bundle.did_document).unwrap()).unwrap();
    fs::write(&key_path, &bundle.keys["key-1"].private_key_pem).unwrap();

    let helper = DIDWbaAuthHeader::new(&did_path, &key_path, AuthMode::HttpSignatures);
    let mut response_headers = BTreeMap::new();
    response_headers.insert(
        "WWW-Authenticate".to_string(),
        "DIDWba realm=\"api.example.com\", error=\"invalid_did\", error_description=\"Unknown DID\"".to_string(),
    );
    assert!(!helper.should_retry_after_401(&response_headers));
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
