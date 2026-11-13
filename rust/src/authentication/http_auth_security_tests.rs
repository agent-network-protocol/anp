//! Offline unit coverage; never starts a listener or resolves a live DID.

use super::http_auth_security::{HttpReplayContext, HttpSignaturePolicy, MemoryHttpReplayStore};
use super::http_signatures::{
    http_signature_replay_context, verify_http_message_signature,
    verify_http_message_signature_with_policy,
};
use std::collections::BTreeMap;
use std::sync::Arc;

struct FrozenStore {
    memory: MemoryHttpReplayStore,
    now: i64,
    unavailable: bool,
}

impl super::HttpReplayStore for FrozenStore {
    fn consume_once<'a>(
        &'a self,
        context: &'a HttpReplayContext,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<bool, super::HttpReplayUnavailable>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if self.unavailable {
                return Err(super::HttpReplayUnavailable);
            }
            self.memory.consume_once_at(context, self.now)
        })
    }
}

fn corpus() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../testdata/authentication/security_vectors_v1.json"
    ))
    .expect("public test corpus")
}

#[test]
fn shared_http_auth_security_vectors() {
    let corpus = corpus();
    for case in corpus["cases"].as_array().expect("cases") {
        let headers: BTreeMap<String, String> =
            serde_json::from_value(case["headers"].clone()).expect("headers");
        let result = verify_http_message_signature_with_policy(
            &corpus["document"],
            case["method"].as_str().unwrap(),
            case["url"].as_str().unwrap(),
            &headers,
            Some(case["body"].as_str().unwrap().as_bytes()),
            HttpSignaturePolicy::default(),
            corpus["now"].as_i64().unwrap(),
        );
        assert_eq!(
            result.is_ok(),
            case["accepted"].as_bool().unwrap(),
            "case {}: {:?}",
            case["id"],
            result
        );
    }
}

#[test]
fn http_auth_security_default_rejects_historical_signatures() {
    let corpus = corpus();
    let case = &corpus["cases"][2];
    let headers = serde_json::from_value(case["headers"].clone()).unwrap();
    assert!(verify_http_message_signature(
        &corpus["document"],
        "GET",
        case["url"].as_str().unwrap(),
        &headers,
        None
    )
    .is_err());
    assert!(verify_http_message_signature_with_policy(
        &corpus["document"],
        "GET",
        case["url"].as_str().unwrap(),
        &headers,
        None,
        HttpSignaturePolicy {
            check_time: false,
            ..Default::default()
        },
        corpus["now"].as_i64().unwrap(),
    )
    .is_ok());
}

#[test]
fn http_auth_security_ambiguous_headers_and_params_fail_closed() {
    let corpus = corpus();
    let case = &corpus["cases"][0];
    let original: BTreeMap<String, String> =
        serde_json::from_value(case["headers"].clone()).unwrap();
    let mut duplicates = original.clone();
    duplicates.insert(
        "signature-input".into(),
        original["Signature-Input"].clone(),
    );
    let mut overwritten = original.clone();
    overwritten
        .get_mut("Signature-Input")
        .unwrap()
        .push_str(";created=1");
    let mut wrong_extension = original.clone();
    wrong_extension
        .get_mut("Signature-Input")
        .unwrap()
        .push_str(";tag=\"not-signed\"");
    for headers in [duplicates, overwritten, wrong_extension] {
        assert!(verify_http_message_signature_with_policy(
            &corpus["document"],
            "GET",
            case["url"].as_str().unwrap(),
            &headers,
            None,
            HttpSignaturePolicy::default(),
            corpus["now"].as_i64().unwrap(),
        )
        .is_err());
    }
}

#[test]
fn replay_store_atomic_and_retention_boundary() {
    let now = 1794556800;
    let context = Arc::new(HttpReplayContext {
        signer_did: "did:web:test.example".into(),
        verifier_scope: "receiver".into(),
        replay_key: "unit-key".into(),
        valid_until: now + 60,
    });
    let store = Arc::new(MemoryHttpReplayStore::new(1));
    let workers: Vec<_> = (0..16)
        .map(|_| {
            let store = store.clone();
            let context = context.clone();
            std::thread::spawn(move || store.consume_once_at(&context, now).unwrap())
        })
        .collect();
    assert_eq!(
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|accepted| *accepted)
            .count(),
        1
    );
    assert!(!store.consume_once_at(&context, now + 60).unwrap());
    let next = HttpReplayContext {
        replay_key: "another".into(),
        valid_until: now + 120,
        ..(*context).clone()
    };
    assert!(store.consume_once_at(&next, now).is_err());
    assert!(store.consume_once_at(&next, now + 61).unwrap());
}

#[test]
fn http_auth_security_replay_key_uses_verified_base_not_signature_bytes() {
    let corpus = corpus();
    let case = &corpus["cases"][1];
    let headers = serde_json::from_value(case["headers"].clone()).unwrap();
    let policy = HttpSignaturePolicy::default();
    let metadata = verify_http_message_signature_with_policy(
        &corpus["document"],
        "GET",
        case["url"].as_str().unwrap(),
        &headers,
        None,
        policy,
        corpus["now"].as_i64().unwrap(),
    )
    .unwrap();
    let context = http_signature_replay_context(
        &metadata,
        "GET",
        case["url"].as_str().unwrap(),
        &headers,
        "https://receiver.example:443",
        policy,
    )
    .unwrap();
    assert_eq!(context.valid_until, corpus["now"].as_i64().unwrap() + 360);
    assert_eq!(context.replay_key.len(), 64);
    let other = http_signature_replay_context(
        &metadata,
        "GET",
        case["url"].as_str().unwrap(),
        &headers,
        "other-receiver",
        policy,
    )
    .unwrap();
    assert_ne!(context.replay_key, other.replay_key);
}

#[tokio::test]
async fn http_auth_security_two_verifiers_shared_store_and_unavailable() {
    use super::{DidWbaVerifier, DidWbaVerifierConfig};
    let corpus = corpus();
    let now = corpus["now"].as_i64().unwrap();
    let case = &corpus["cases"][1]; // Protocol-permitted nonce-free input.
    let headers: BTreeMap<String, String> =
        serde_json::from_value(case["headers"].clone()).unwrap();
    let make_verifier = |unavailable: bool, store: Option<Arc<dyn super::HttpReplayStore>>| {
        let config = DidWbaVerifierConfig {
            jwt_algorithm: "HS256".into(),
            jwt_private_key: Some("public-unit-test-secret-not-production".into()),
            require_nonce_for_http_signatures: false,
            ..Default::default()
        };
        let store = store.unwrap_or_else(|| {
            Arc::new(FrozenStore {
                memory: MemoryHttpReplayStore::default(),
                now,
                unavailable,
            })
        });
        DidWbaVerifier::new(config)
            .with_clock(Arc::new(move || now))
            .with_replay_store(store, "https://receiver.example:443")
    };
    let store: Arc<dyn super::HttpReplayStore> = Arc::new(FrozenStore {
        memory: MemoryHttpReplayStore::default(),
        now,
        unavailable: false,
    });
    let mut first = make_verifier(false, Some(store.clone()));
    let mut second = make_verifier(false, Some(store));
    let mut bad = headers.clone();
    bad.insert("Signature".into(), "sig1=:AA==:".into());
    let url = case["url"].as_str().unwrap();
    assert!(first
        .verify_request_with_did_document("GET", url, &bad, None, None, &corpus["document"])
        .await
        .is_err());
    let (a, b) = tokio::join!(
        first.verify_request_with_did_document(
            "GET",
            url,
            &headers,
            None,
            None,
            &corpus["document"]
        ),
        second.verify_request_with_did_document(
            "GET",
            url,
            &headers,
            None,
            None,
            &corpus["document"]
        ),
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let error = make_verifier(true, None)
        .verify_request_with_did_document("GET", url, &headers, None, None, &corpus["document"])
        .await
        .unwrap_err();
    assert_eq!(error.status_code, 503);
}

#[tokio::test]
async fn http_auth_security_federation_consumes_and_rejects_offline_policy() {
    use super::{
        verify_federated_http_request_with_security, FederatedHttpSecurity,
        FederatedVerificationOptions,
    };
    assert!(super::FederatedVerificationError::DidResolution(
        "HTTP replay protection unavailable".into()
    )
    .is_replay_store_unavailable());
    assert!(!super::FederatedVerificationError::ServiceDidMismatch.is_replay_store_unavailable());
    let corpus = corpus();
    let now = corpus["now"].as_i64().unwrap();
    let case = &corpus["cases"][0];
    let headers: BTreeMap<String, String> =
        serde_json::from_value(case["headers"].clone()).unwrap();
    let did = "did:web:sender.example:agent";
    let sender = serde_json::json!({"id": did, "service": [{"id": "message", "type": "ANPMessageService", "serviceDid": corpus["document"]["id"], "serviceEndpoint": "https://receiver.example/rpc"}]});
    let options = FederatedVerificationOptions {
        sender_did_document: Some(sender),
        service_did_document: Some(corpus["document"].clone()),
        ..Default::default()
    };
    let store = FrozenStore {
        memory: MemoryHttpReplayStore::default(),
        now,
        unavailable: false,
    };
    for expected in [true, false] {
        let security = FederatedHttpSecurity {
            policy: HttpSignaturePolicy::default(),
            now,
            verifier_scope: "receiver",
            replay_store: &store,
        };
        let result = verify_federated_http_request_with_security(
            did,
            "GET",
            case["url"].as_str().unwrap(),
            &headers,
            None,
            options.clone(),
            security,
        )
        .await;
        assert_eq!(result.is_ok(), expected);
    }
    let security = FederatedHttpSecurity {
        policy: HttpSignaturePolicy {
            check_time: false,
            ..Default::default()
        },
        now,
        verifier_scope: "receiver",
        replay_store: &store,
    };
    assert!(verify_federated_http_request_with_security(
        did,
        "GET",
        case["url"].as_str().unwrap(),
        &headers,
        None,
        options,
        security
    )
    .await
    .is_err());
}

#[test]
fn http_auth_security_origin_isolates_scheme_and_effective_port() {
    use super::http_auth_security::authentication_origin;
    assert_eq!(
        authentication_origin("https://EXAMPLE.com/path").unwrap(),
        "https://example.com:443"
    );
    assert_eq!(
        authentication_origin("https://example.com:443/other").unwrap(),
        "https://example.com:443"
    );
    assert_eq!(
        authentication_origin("http://[::1]:8080/").unwrap(),
        "http://[::1]:8080"
    );
    for url in [
        "https://user@example.com/",
        "https://example.com:0/",
        "file://example.com/a",
        "https://example.com/#x",
        "https://example.com:443@other.example/",
        "https://127.1/",
    ] {
        assert!(authentication_origin(url).is_err(), "{url}");
    }
}

#[test]
fn http_auth_security_token_cache_and_challenge_cannot_cross_origins() {
    use super::{AuthMode, DIDWbaAuthHeader};
    let mut helper = DIDWbaAuthHeader::new(
        "unit-no-document",
        "unit-no-private-key",
        AuthMode::HttpSignatures,
    );
    let headers = BTreeMap::from([(
        "Authentication-Info".into(),
        "access_token=\"public-unit-marker\", token_type=\"Bearer\"".into(),
    )]);
    assert!(helper
        .update_token("https://EXAMPLE.com:8443/", &headers)
        .is_some());
    let own = helper
        .get_auth_header("https://example.com:8443/path", false, "GET", None, None)
        .unwrap();
    assert_eq!(
        own.get("Authorization").unwrap(),
        "Bearer public-unit-marker"
    );
    assert!(helper
        .get_auth_header("https://example.com:443/path", false, "GET", None, None)
        .is_err());
    assert!(helper
        .get_auth_header("http://example.com:8443/path", false, "GET", None, None)
        .is_err());
    assert!(helper
        .update_token("http://example.com:8443/", &headers)
        .is_none());
    let wrong_kind = BTreeMap::from([(
        "Authentication-Info".into(),
        "access_token=\"marker\", token_type=\"Basic\"".into(),
    )]);
    assert!(helper
        .update_token("https://example.com/", &wrong_kind)
        .is_none());
    let covered = super::did_wba_authenticator::normalize_covered_components(
        Some(&vec!["@method".into()]),
        None,
        None,
    )
    .unwrap();
    assert!(covered.iter().any(|c| c == "@target-uri"));
}

#[test]
fn http_auth_security_wba_resource_rejects_ambiguous_inputs() {
    use super::did_wba::build_did_wba_resolution_url;
    assert_eq!(
        build_did_wba_resolution_url("did:wba:example.com:user:e1_fixture").unwrap(),
        "https://example.com/user/e1_fixture/did.json"
    );
    for did in [
        "did:wba:example.com%2fother:user",
        "did:wba:user%40example.com:alice",
        "did:wba:example.com:..",
        "did:wba:example.com:%2fetc",
        "did:wba:example.com:%252fetc",
    ] {
        assert!(build_did_wba_resolution_url(did).is_err(), "{did}");
    }
}

#[cfg(feature = "network")]
#[test]
fn http_auth_security_outbound_addresses_and_decoded_size() {
    use super::did_resolver::DidResolutionAddressPolicy;
    use super::did_web::{append_bounded_chunk, check_resolution_addresses};
    for ip in [
        "127.0.0.1:443",
        "10.0.0.1:443",
        "169.254.169.254:443",
        "[::1]:443",
        "[::ffff:127.0.0.1]:443",
    ] {
        let addresses = vec!["8.8.8.8:443".parse().unwrap(), ip.parse().unwrap()];
        assert!(
            check_resolution_addresses(&addresses, DidResolutionAddressPolicy::PublicOnly).is_err()
        );
    }
    assert!(check_resolution_addresses(
        &["8.8.8.8:443".parse().unwrap()],
        DidResolutionAddressPolicy::PublicOnly
    )
    .is_ok());
    let mut bytes = Vec::new();
    append_bounded_chunk(&mut bytes, b"1234", 4).unwrap();
    assert!(append_bounded_chunk(&mut bytes, b"5", 4).is_err());
    assert_eq!(bytes, b"1234");
}

#[test]
fn http_auth_security_frozen_legacy_authority_and_replay() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../testdata/authentication/authority_compatibility_v1.json"
    ))
    .unwrap();
    for case in corpus["cases"].as_array().unwrap() {
        let headers = serde_json::from_value(case["headers"].clone()).unwrap();
        let url = case["url"].as_str().unwrap();
        let metadata = verify_http_message_signature_with_policy(
            &corpus["document"],
            "GET",
            url,
            &headers,
            None,
            HttpSignaturePolicy::default(),
            corpus["now"].as_i64().unwrap(),
        )
        .unwrap();
        let scope = super::http_auth_security::authentication_origin(url).unwrap();
        let context = http_signature_replay_context(
            &metadata,
            "GET",
            url,
            &headers,
            &scope,
            HttpSignaturePolicy::default(),
        )
        .unwrap();
        assert_eq!(context.replay_key, case["replay_key"].as_str().unwrap());
        assert!(verify_http_message_signature_with_policy(
            &corpus["document"],
            "GET",
            &format!("{url}tampered"),
            &headers,
            None,
            HttpSignaturePolicy::default(),
            corpus["now"].as_i64().unwrap()
        )
        .is_err());
    }
}

#[cfg(feature = "network")]
#[test]
fn http_auth_security_outbound_budget_is_bounded_and_drop_recovers() {
    let mut permits = Vec::new();
    for _ in 0..32 {
        permits.push(super::did_web::public_outbound_permit().unwrap());
    }
    assert!(super::did_web::public_outbound_permit().is_err());
    permits.pop();
    assert!(super::did_web::public_outbound_permit().is_ok());
    drop(permits);
    assert!(super::did_web::public_outbound_permit().is_ok());
}

#[test]
fn http_auth_security_header_budget_and_legacy_ambiguity() {
    let legacy: serde_json::Value = serde_json::from_str(include_str!(
        "../../../testdata/authentication/legacy_compatibility_v1.json"
    ))
    .unwrap();
    let header = legacy["header"].as_str().unwrap();
    assert_eq!(
        super::extract_auth_header_parts(header).unwrap().nonce,
        "public-legacy-fixture"
    );
    for tail in [
        ", nonce=\"duplicate\"",
        ", DID=\"duplicate\"",
        ", v=\"1.0\"",
        " garbage",
    ] {
        assert!(super::extract_auth_header_parts(&format!("{header}{tail}")).is_err());
    }
    let corpus = corpus();
    let case = &corpus["cases"][0];
    let mut headers: BTreeMap<String, String> =
        serde_json::from_value(case["headers"].clone()).unwrap();
    for value in [
        format!("sig1=:{}:", "A".repeat(20000)),
        format!("{}\r\nInjected: value", headers["Signature"].clone()),
    ] {
        headers.insert("Signature".into(), value);
        assert!(verify_http_message_signature_with_policy(
            &corpus["document"],
            "GET",
            case["url"].as_str().unwrap(),
            &headers,
            None,
            HttpSignaturePolicy::default(),
            corpus["now"].as_i64().unwrap()
        )
        .is_err());
    }
}

#[tokio::test]
async fn http_auth_security_federation_expiry_precedes_invalid_sender_resolution() {
    let corpus = corpus();
    let case = &corpus["cases"][2];
    let headers = serde_json::from_value(case["headers"].clone()).unwrap();
    let now = corpus["now"].as_i64().unwrap();
    let store = FrozenStore {
        memory: MemoryHttpReplayStore::default(),
        now,
        unavailable: false,
    };
    let result = super::verify_federated_http_request_with_security(
        "invalid-sender",
        "GET",
        case["url"].as_str().unwrap(),
        &headers,
        None,
        super::FederatedVerificationOptions::default(),
        super::FederatedHttpSecurity {
            policy: HttpSignaturePolicy::default(),
            now,
            verifier_scope: "receiver",
            replay_store: &store,
        },
    )
    .await;
    assert!(matches!(
        result,
        Err(super::FederatedVerificationError::Signature(_))
    ));
}

#[test]
fn http_auth_security_canonical_ipv6_origin() {
    assert_eq!(
        super::authentication_origin("https://[2001:4860:0000:0000:0000:0000:0000:8888]/").unwrap(),
        "https://[2001:4860::8888]:443"
    );
    assert!(super::authentication_origin("https://[::ffff:8.8.8.8]/").is_err());
}
