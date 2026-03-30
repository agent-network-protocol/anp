mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anp::authentication::{
    create_did_wba_document, AuthMode, DIDWbaAuthHeader, DidDocumentOptions,
};
use reqwest::Client;
use serde_json::Value;
use tempfile::tempdir;

#[tokio::test]
async fn test_rust_http_client_to_python_server() {
    if which_uv().is_none() {
        eprintln!("Skipping test_rust_http_client_to_python_server because uv is unavailable");
        return;
    }

    let bundle = create_did_wba_document(
        "example.com",
        DidDocumentOptions::default().with_path_segments(["user", "rust-http"]),
    )
    .expect("DID creation should succeed");
    let temp = tempdir().expect("temp dir should exist");
    let did_path = temp.path().join("did.json");
    let key_path = temp.path().join("key-1.pem");
    fs::write(&did_path, serde_json::to_vec(&bundle.did_document).unwrap()).unwrap();
    fs::write(&key_path, bundle.private_key_pem("key-1").unwrap()).unwrap();

    let port = pick_free_port();
    let mut server = spawn_python_server(&did_path, port);
    wait_for_health(port).await;

    let result = exercise_rust_client_flow(&did_path, &key_path, AuthMode::HttpSignatures, port)
        .await;

    server.kill().ok();
    server.wait().ok();

    let (first_scheme, second_scheme, second_auth_header) = result;
    assert_eq!(first_scheme, "http_signatures");
    assert_eq!(second_scheme, "bearer");
    assert!(second_auth_header.starts_with("Bearer "));
}

#[tokio::test]
async fn test_rust_legacy_client_to_python_server() {
    if which_uv().is_none() {
        eprintln!("Skipping test_rust_legacy_client_to_python_server because uv is unavailable");
        return;
    }

    let bundle = create_did_wba_document(
        "example.com",
        DidDocumentOptions::default()
            .with_profile(anp::authentication::DidProfile::K1)
            .with_path_segments(["user", "rust-legacy"]),
    )
    .expect("DID creation should succeed");
    let temp = tempdir().expect("temp dir should exist");
    let did_path = temp.path().join("did.json");
    let key_path = temp.path().join("key-1.pem");
    fs::write(&did_path, serde_json::to_vec(&bundle.did_document).unwrap()).unwrap();
    fs::write(&key_path, bundle.private_key_pem("key-1").unwrap()).unwrap();

    let port = pick_free_port();
    let mut server = spawn_python_server(&did_path, port);
    wait_for_health(port).await;

    let result = exercise_rust_client_flow(&did_path, &key_path, AuthMode::LegacyDidWba, port)
        .await;

    server.kill().ok();
    server.wait().ok();

    let (first_scheme, second_scheme, second_auth_header) = result;
    assert_eq!(first_scheme, "legacy_didwba");
    assert_eq!(second_scheme, "bearer");
    assert!(second_auth_header.starts_with("Bearer "));
}

async fn exercise_rust_client_flow(
    did_path: &Path,
    key_path: &Path,
    auth_mode: AuthMode,
    port: u16,
) -> (String, String, String) {
    let server_url = format!("http://127.0.0.1:{}/auth", port);
    let client = Client::builder().timeout(Duration::from_secs(10)).build().unwrap();
    let mut auth = DIDWbaAuthHeader::new(did_path, key_path, auth_mode);

    let first_headers = auth
        .get_auth_header(&server_url, true, "GET", None, None)
        .expect("initial auth headers should be generated");
    let first_response = client
        .get(&server_url)
        .headers(to_header_map(&first_headers))
        .send()
        .await
        .expect("first request should succeed");
    let first_status = first_response.status();
    let first_response_headers = response_headers(&first_response);
    let first_body_text = first_response.text().await.expect("first body should be readable");
    assert_eq!(first_status, 200, "unexpected first response body: {}", first_body_text);
    let first_body: Value = serde_json::from_str(&first_body_text).expect("first body should be JSON");

    auth.update_token(&server_url, &first_response_headers);
    let second_headers = auth
        .get_auth_header(&server_url, false, "GET", None, None)
        .expect("bearer auth headers should be generated");
    let second_response = client
        .get(&server_url)
        .headers(to_header_map(&second_headers))
        .send()
        .await
        .expect("second request should succeed");
    assert_eq!(second_response.status(), 200);
    let second_body: Value = second_response.json().await.expect("second body should be JSON");

    (
        first_body["auth_scheme"].as_str().unwrap_or_default().to_string(),
        second_body["auth_scheme"].as_str().unwrap_or_default().to_string(),
        second_headers.get("Authorization").cloned().unwrap_or_default(),
    )
}

fn spawn_python_server(did_path: &Path, port: u16) -> Child {
    let repo_root = repo_root();
    let script_path = repo_root.join("examples/python/rust_interop_examples/python_auth_server.py");
    Command::new("uv")
        .args([
            "run",
            "--python",
            "3.13",
            "--with-editable",
            repo_root.to_str().unwrap(),
            "python",
            script_path.to_str().unwrap(),
            "--did-json",
            did_path.to_str().unwrap(),
            "--port",
            &port.to_string(),
            "--jwt-secret",
            "test-secret",
        ])
        .current_dir(std::env::temp_dir())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Python server should start")
}

async fn wait_for_health(port: u16) {
    let client = Client::builder().timeout(Duration::from_secs(1)).build().unwrap();
    let url = format!("http://127.0.0.1:{}/health", port);
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if std::time::Instant::now() > deadline {
            panic!("Python server did not become ready in time");
        }
        match client.get(&url).send().await {
            Ok(response) if response.status() == 200 => return,
            _ => tokio::time::sleep(Duration::from_millis(200)).await,
        }
    }
}

fn to_header_map(headers: &BTreeMap<String, String>) -> reqwest::header::HeaderMap {
    let mut result = reqwest::header::HeaderMap::new();
    for (name, value) in headers {
        result.insert(
            reqwest::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            reqwest::header::HeaderValue::from_str(value).unwrap(),
        );
    }
    result
}

fn response_headers(response: &reqwest::Response) -> BTreeMap<String, String> {
    response
        .headers()
        .iter()
        .map(|(name, value)| (name.as_str().to_string(), value.to_str().unwrap_or_default().to_string()))
        .collect()
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root should exist")
        .to_path_buf()
}

fn which_uv() -> Option<String> {
    Command::new("which")
        .arg("uv")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn pick_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("ephemeral port should bind")
        .local_addr()
        .expect("local addr should exist")
        .port()
}
