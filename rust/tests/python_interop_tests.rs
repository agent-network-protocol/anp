mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use anp::authentication::{
    create_did_wba_document, verify_auth_header_signature, DidDocumentOptions, DidProfile,
    DidResolutionOptions, DidWbaVerifier, DidWbaVerifierConfig,
};
use anp::{PrivateKeyMaterial, PublicKeyMaterial};
use serde_json::Value;

#[test]
fn test_current_python_http_signatures_verify_in_rust() {
    if which_uv().is_none() {
        eprintln!(
            "Skipping test_current_python_http_signatures_verify_in_rust because uv is unavailable"
        );
        return;
    }

    let editable = repo_root().to_string_lossy().to_string();
    let fixture = run_python_json_owned(
        vec![
            "run".to_string(),
            "--python".to_string(),
            "3.13".to_string(),
            "--with-editable".to_string(),
            editable,
            "python".to_string(),
            "-c".to_string(),
            CURRENT_PYTHON_HTTP_SCRIPT.to_string(),
        ],
        &std::env::temp_dir(),
    );
    let did_document = fixture["did_document"].clone();
    let headers = json_headers_to_btree(&fixture["headers"]);
    assert_standard_pem_keys_load_in_rust(&fixture["keys"]);
    let body = fixture["body"]
        .as_str()
        .unwrap_or_default()
        .as_bytes()
        .to_vec();
    let request_url = fixture["request_url"].as_str().unwrap();

    let mut verifier = DidWbaVerifier::new(DidWbaVerifierConfig {
        jwt_private_key: Some("test-secret".to_string()),
        jwt_public_key: Some("test-secret".to_string()),
        jwt_algorithm: "HS256".to_string(),
        did_resolution_options: DidResolutionOptions::default(),
        ..DidWbaVerifierConfig::default()
    });

    let runtime = tokio::runtime::Runtime::new().expect("runtime should start");
    let result = runtime
        .block_on(verifier.verify_request_with_did_document(
            "POST",
            request_url,
            &headers,
            Some(&body),
            Some("api.example.com"),
            &did_document,
        ))
        .expect("Rust verifier should accept the Python HTTP signature request");

    assert_eq!(result.auth_scheme, "http_signatures");
    assert!(result.access_token.is_some());
}

#[test]
fn test_old_python_legacy_auth_verifies_in_rust() {
    if which_uv().is_none() {
        eprintln!(
            "Skipping test_old_python_legacy_auth_verifies_in_rust because uv is unavailable"
        );
        return;
    }

    let fixture = run_python_json_owned(
        vec![
            "run".to_string(),
            "--python".to_string(),
            "3.13".to_string(),
            "--with".to_string(),
            format!("anp=={}", common::released_python_anp_version()),
            "python".to_string(),
            "-c".to_string(),
            OLD_PYTHON_LEGACY_SCRIPT.to_string(),
        ],
        &std::env::temp_dir(),
    );
    let did_document = fixture["did_document"].clone();
    let headers = json_headers_to_btree(&fixture["headers"]);
    assert_standard_pem_keys_load_in_rust(&fixture["keys"]);

    verify_auth_header_signature(
        headers
            .get("Authorization")
            .expect("authorization header should exist"),
        &did_document,
        "api.example.com",
    )
    .expect("Rust low-level verifier should accept the old Python legacy request");

    let mut verifier = DidWbaVerifier::new(DidWbaVerifierConfig {
        jwt_private_key: Some("test-secret".to_string()),
        jwt_public_key: Some("test-secret".to_string()),
        jwt_algorithm: "HS256".to_string(),
        did_resolution_options: DidResolutionOptions::default(),
        ..DidWbaVerifierConfig::default()
    });

    let runtime = tokio::runtime::Runtime::new().expect("runtime should start");
    let result = runtime
        .block_on(verifier.verify_request_with_did_document(
            "GET",
            "https://api.example.com/orders",
            &headers,
            None,
            Some("api.example.com"),
            &did_document,
        ))
        .expect("Rust verifier should accept the old Python legacy request");

    assert_eq!(result.auth_scheme, "legacy_didwba");
    assert!(result.access_token.is_some());
}

#[test]
fn test_rust_generated_standard_pem_keys_load_in_python() {
    if which_uv().is_none() {
        eprintln!(
            "Skipping test_rust_generated_standard_pem_keys_load_in_python because uv is unavailable"
        );
        return;
    }

    let e1 = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["user".to_string(), "rust-to-python".to_string()],
            ..DidDocumentOptions::default()
        },
    )
    .expect("e1 DID should generate");
    let k1 = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["user".to_string(), "rust-to-python-k1".to_string()],
            did_profile: DidProfile::K1,
            enable_e2ee: false,
            ..DidDocumentOptions::default()
        },
    )
    .expect("k1 DID should generate");

    let fixture = serde_json::json!({
        "bundles": [
            {"keys": e1.keys},
            {"keys": k1.keys},
        ]
    });
    let temp = tempfile::NamedTempFile::new().expect("temp file should create");
    std::fs::write(temp.path(), serde_json::to_vec(&fixture).unwrap()).unwrap();

    let payload = run_python_json_owned(
        vec![
            "run".to_string(),
            "--python".to_string(),
            "3.13".to_string(),
            "--with-editable".to_string(),
            repo_root().to_string_lossy().to_string(),
            "python".to_string(),
            "-c".to_string(),
            RUST_KEYS_LOAD_IN_PYTHON_SCRIPT.to_string(),
            temp.path().to_string_lossy().to_string(),
        ],
        repo_root(),
    );
    assert_eq!(payload["verified"], serde_json::json!(true));
}

fn run_python_json_owned(args: Vec<String>, cwd: &Path) -> Value {
    let output = Command::new("uv")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("uv command should execute");
    if !output.status.success() {
        panic!(
            "Python interop command failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).expect("Python output should be valid JSON")
}

fn json_headers_to_btree(value: &Value) -> BTreeMap<String, String> {
    value
        .as_object()
        .expect("headers should be an object")
        .iter()
        .map(|(key, value)| (key.clone(), value.as_str().unwrap_or_default().to_string()))
        .collect()
}

fn assert_standard_pem_keys_load_in_rust(value: &Value) {
    let keys = value.as_object().expect("keys should be an object");
    for (fragment, pair) in keys {
        let private_pem = pair["private_key_pem"]
            .as_str()
            .expect("private key PEM should be a string");
        let public_pem = pair["public_key_pem"]
            .as_str()
            .expect("public key PEM should be a string");
        assert!(
            private_pem.starts_with("-----BEGIN PRIVATE KEY-----"),
            "{fragment} private key must be PKCS#8 PEM"
        );
        assert!(
            public_pem.starts_with("-----BEGIN PUBLIC KEY-----"),
            "{fragment} public key must be SPKI PEM"
        );
        assert!(!private_pem.contains("ANP "));
        assert!(!public_pem.contains("ANP "));

        let private_key =
            PrivateKeyMaterial::from_pem(private_pem).expect("private key should parse");
        let public_key = PublicKeyMaterial::from_pem(public_pem).expect("public key should parse");
        if !matches!(public_key, PublicKeyMaterial::X25519(_)) {
            let signature = private_key
                .sign_message(b"cross-language standard pem")
                .expect("signature should be created");
            public_key
                .verify_message(b"cross-language standard pem", &signature)
                .expect("signature should verify");
        }
    }
}

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root should exist")
}

fn which_uv() -> Option<String> {
    Command::new("which")
        .arg("uv")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
}

const CURRENT_PYTHON_HTTP_SCRIPT: &str = r#"
import json
import tempfile
from pathlib import Path

from anp.authentication import DIDWbaAuthHeader, create_did_wba_document

body = '{"item":"book"}'
did_document, keys = create_did_wba_document(
    'example.com',
    path_segments=['user', 'python-http'],
)
_, k1_keys = create_did_wba_document(
    'example.com',
    path_segments=['user', 'python-k1'],
    did_profile='k1',
    enable_e2ee=False,
)
keys_json = {f'e1-{name}': {'private_key_pem': value[0].decode('ascii'), 'public_key_pem': value[1].decode('ascii')} for name, value in keys.items()}
keys_json.update({f'k1-{name}': {'private_key_pem': value[0].decode('ascii'), 'public_key_pem': value[1].decode('ascii')} for name, value in k1_keys.items()})
with tempfile.TemporaryDirectory() as temp_dir:
    temp_path = Path(temp_dir)
    did_path = temp_path / 'did.json'
    key_path = temp_path / 'key-1.pem'
    did_path.write_text(json.dumps(did_document), encoding='utf-8')
    key_path.write_bytes(keys['key-1'][0])
    auth = DIDWbaAuthHeader(str(did_path), str(key_path))
    headers = auth.get_auth_header(
        'https://api.example.com/orders',
        force_new=True,
        method='POST',
        headers={'Content-Type': 'application/json'},
        body=body.encode('utf-8'),
    )
    print(json.dumps({
        'did_document': did_document,
        'keys': keys_json,
        'headers': headers,
        'request_url': 'https://api.example.com/orders',
        'body': body,
    }))
"#;

const OLD_PYTHON_LEGACY_SCRIPT: &str = r#"
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from anp.authentication import create_did_wba_document, generate_auth_header


def _load_private_key(private_key_pem: bytes):
    return serialization.load_pem_private_key(private_key_pem, password=None)


def _sign_callback(private_key_pem: bytes):
    private_key = _load_private_key(private_key_pem)

    def _callback(content: bytes, verification_method: str) -> bytes:
        if isinstance(private_key, ec.EllipticCurvePrivateKey):
            return private_key.sign(content, ec.ECDSA(hashes.SHA256()))
        if isinstance(private_key, ed25519.Ed25519PrivateKey):
            return private_key.sign(content)
        raise TypeError(f'Unsupported key type: {type(private_key).__name__}')

    return _callback


did_document, keys = create_did_wba_document(
    'example.com',
    path_segments=['user', 'python-legacy'],
)
headers = {
    'Authorization': generate_auth_header(
        did_document,
        'api.example.com',
        _sign_callback(keys['key-1'][0]),
        version='1.0',
    )
}
keys_json = {name: {'private_key_pem': value[0].decode('ascii'), 'public_key_pem': value[1].decode('ascii')} for name, value in keys.items()}
print(json.dumps({
    'did_document': did_document,
    'keys': keys_json,
    'headers': headers,
}))
"#;

const RUST_KEYS_LOAD_IN_PYTHON_SCRIPT: &str = r#"
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

fixture = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
for bundle in fixture['bundles']:
    for value in bundle['keys'].values():
        private_pem = value['private_key_pem'].encode('ascii')
        public_pem = value['public_key_pem'].encode('ascii')
        assert private_pem.startswith(b'-----BEGIN PRIVATE KEY-----')
        assert public_pem.startswith(b'-----BEGIN PUBLIC KEY-----')
        assert b'ANP ' not in private_pem
        assert b'ANP ' not in public_pem
        serialization.load_pem_private_key(private_pem, password=None)
        serialization.load_pem_public_key(public_pem)
print(json.dumps({'verified': True}))
"#;
