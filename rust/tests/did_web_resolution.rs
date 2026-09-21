use anp::authentication::did_resolver::build_did_web_resolution_url;
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../fixtures/did-method-lifecycle-v1.json")).unwrap()
}

#[test]
fn web_resolution_shared_urls() {
    for case in fixture()["resolution_cases"].as_array().unwrap() {
        assert_eq!(
            build_did_web_resolution_url(case["did"].as_str().unwrap()).unwrap(),
            case["url"].as_str().unwrap()
        );
    }
}

#[test]
fn web_resolution_rejects_unsafe_dids() {
    for did in fixture()["invalid_resolution_dids"].as_array().unwrap() {
        assert!(
            build_did_web_resolution_url(did.as_str().unwrap()).is_err(),
            "{did}"
        );
    }
}

#[cfg(feature = "network")]
#[tokio::test]
async fn web_response_boundary() {
    use anp::authentication::{resolve_did_document_with_options, DidResolutionOptions};
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };
    use std::time::Duration;
    use tiny_http::{Header, Response, Server};
    let document = fixture()["documents"]["web_single_device"].clone();
    let did = document["id"].as_str().unwrap();
    for mode in [
        "valid",
        "wrong-id",
        "oversized",
        "redirect",
        "html",
        "malformed-proof",
        "timeout",
    ] {
        let server = Server::http("127.0.0.1:0").unwrap();
        let address = format!("http://{}", server.server_addr());
        let stopped = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = stopped.clone();
        let count = requests.clone();
        let body = document.to_string();
        let malformed = serde_json::json!({"id":did,"proof":false}).to_string();
        let thread = std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                if let Some(request) = server.recv_timeout(Duration::from_millis(10)).unwrap() {
                    let first = count.fetch_add(1, Ordering::SeqCst) == 0;
                    if mode == "timeout" {
                        std::thread::sleep(Duration::from_millis(150));
                    }
                    let response = match (mode, first) {
                        ("redirect", true) => Response::from_string("")
                            .with_status_code(302)
                            .with_header(Header::from_bytes("Location", "/redirected").unwrap()),
                        ("oversized", true) => Response::from_string(" ".repeat(1024 * 1024 + 1)),
                        ("wrong-id", true) => {
                            Response::from_string(r#"{"id":"did:web:other.example"}"#)
                        }
                        ("html", true) => Response::from_string("<html>SPA</html>"),
                        ("malformed-proof", true) => Response::from_string(malformed.clone()),
                        _ => Response::from_string(body.clone()),
                    };
                    let _ = request.respond(response);
                }
            }
        });
        let result = resolve_did_document_with_options(
            did,
            true,
            &DidResolutionOptions {
                base_url_override: Some(address),
                timeout_seconds: if mode == "timeout" { 0.05 } else { 10.0 },
                ..Default::default()
            },
        )
        .await;
        stopped.store(true, Ordering::SeqCst);
        thread.join().unwrap();
        if mode == "valid" {
            assert_eq!(result.unwrap(), document);
        } else {
            assert!(result.is_err(), "accepted {mode}");
        }
        assert_eq!(
            requests.load(Ordering::SeqCst),
            1,
            "followed {mode} redirect"
        );
    }
}

#[cfg(feature = "network")]
#[tokio::test]
async fn web_production_requires_tls() {
    use anp::authentication::{resolve_did_document_with_options, DidResolutionOptions};
    assert!(resolve_did_document_with_options(
        "did:web:example.com",
        false,
        &DidResolutionOptions {
            verify_ssl: false,
            ..Default::default()
        }
    )
    .await
    .is_err());
}
