use fs2::FileExt;
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::tempdir;

fn run_anp_mls(data_dir: &Path, domain: &str, action: &str, request: Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_anp-mls"))
        .args([
            domain,
            action,
            "--json-in",
            "-",
            "--data-dir",
            data_dir.to_str().expect("data dir path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn anp-mls");
    serde_json::to_writer(child.stdin.as_mut().expect("stdin"), &request).expect("write request");
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("output");
    assert!(
        output.status.success(),
        "request={request}\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("json response")
}

fn run_anp_mls_error(data_dir: &Path, domain: &str, action: &str, request: Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_anp-mls"))
        .args([
            domain,
            action,
            "--json-in",
            "-",
            "--data-dir",
            data_dir.to_str().expect("data dir path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn anp-mls");
    serde_json::to_writer(child.stdin.as_mut().expect("stdin"), &request).expect("write request");
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("output");
    assert!(
        !output.status.success(),
        "expected failure, stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("json error")
}

fn alice() -> &'static str {
    "did:wba:example.com:users:alice:e1"
}

fn bob() -> &'static str {
    "did:wba:example.com:users:bob:e1"
}

#[test]
fn anp_mls_create_add_welcome_encrypt_decrypt_round_trip() {
    let alice_dir = tempdir().expect("alice state");
    let bob_dir = tempdir().expect("bob state");
    let group_did = "did:wba:example.com:groups:mls-demo:e1";

    let bob_kp = run_anp_mls(
        bob_dir.path(),
        "key-package",
        "generate",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-bob-kp",
            "operation_id": "op-bob-kp",
            "params": {"owner_did": bob(), "device_id": "phone"}
        }),
    );
    assert_eq!(bob_kp["ok"], true);
    assert!(
        bob_kp["result"]["group_key_package"]["mls_key_package_b64u"]
            .as_str()
            .unwrap()
            .len()
            > 64
    );

    let create = run_anp_mls(
        alice_dir.path(),
        "group",
        "create",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-create",
            "operation_id": "op-create",
            "params": {"agent_did": alice(), "device_id": "phone", "group_did": group_did}
        }),
    );
    assert_eq!(create["result"]["epoch"], "0");

    let add = run_anp_mls(
        alice_dir.path(),
        "group",
        "add-member",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-add",
            "operation_id": "op-add",
            "params": {
                "actor_did": alice(),
                "device_id": "phone",
                "group_did": group_did,
                "member_did": bob(),
                "group_key_package": bob_kp["result"]["group_key_package"].clone()
            }
        }),
    );
    assert_eq!(add["result"]["epoch"], "1");
    let welcome_b64u = add["result"]["welcome_b64u"].as_str().expect("welcome");
    assert!(!welcome_b64u.is_empty());

    let welcome = run_anp_mls(
        bob_dir.path(),
        "welcome",
        "process",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-welcome",
            "operation_id": "op-welcome",
            "params": {"agent_did": bob(), "device_id": "phone", "group_did": group_did, "welcome_b64u": welcome_b64u}
        }),
    );
    assert_eq!(welcome["result"]["status"], "active");

    let secret = "real OpenMLS hello from Alice";
    let encrypted = run_anp_mls(
        alice_dir.path(),
        "message",
        "encrypt",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-encrypt",
            "operation_id": "op-encrypt",
            "params": {
                "sender_did": alice(),
                "device_id": "phone",
                "group_state_ref": {"group_did": group_did, "group_state_version": "1"},
                "application_plaintext": {"application_content_type": "text/plain", "text": secret}
            }
        }),
    );
    let cipher = encrypted["result"]["group_cipher_object"].clone();
    assert_ne!(cipher["private_message_b64u"].as_str().unwrap(), secret);

    let decrypted = run_anp_mls(
        bob_dir.path(),
        "message",
        "decrypt",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-decrypt",
            "operation_id": "op-decrypt",
            "params": {
                "recipient_did": bob(),
                "device_id": "phone",
                "group_did": group_did,
                "group_cipher_object": cipher
            }
        }),
    );
    assert_eq!(decrypted["result"]["application_plaintext"]["text"], secret);

    let status = run_anp_mls(
        bob_dir.path(),
        "group",
        "status",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-bob-status",
            "operation_id": "op-bob-status",
            "params": {"agent_did": bob(), "device_id": "phone", "group_did": group_did}
        }),
    );
    assert_eq!(status["result"]["status"], "active");
    assert!(alice_dir.path().join("state.db").exists());
    assert!(bob_dir.path().join("state.db").exists());
}

#[test]
fn anp_mls_operation_id_is_idempotent_and_conflicting_input_fails() {
    let data_dir = tempdir().expect("state");
    let request = json!({
        "api_version": "anp-mls/v1",
        "request_id": "req-first",
        "operation_id": "op-idempotent-kp",
        "params": {"owner_did": alice(), "device_id": "phone", "key_package_id": "kp-fixed"}
    });
    let first = run_anp_mls(data_dir.path(), "key-package", "generate", request.clone());
    let second = run_anp_mls(
        data_dir.path(),
        "key-package",
        "generate",
        json!({"api_version":"anp-mls/v1", "request_id":"req-replay", "operation_id":"op-idempotent-kp", "params": request["params"].clone()}),
    );
    assert_eq!(first["result"], second["result"]);
    assert_eq!(second["request_id"], "req-replay");

    let conflict = run_anp_mls_error(
        data_dir.path(),
        "key-package",
        "generate",
        json!({"api_version":"anp-mls/v1", "request_id":"req-conflict", "operation_id":"op-idempotent-kp", "params":{"owner_did": bob(), "device_id":"phone"}}),
    );
    assert_eq!(conflict["error"]["code"], "operation_conflict");
}

#[test]
fn anp_mls_file_lock_rejects_concurrent_mutation() {
    let data_dir = tempdir().expect("state");
    let lock_path = data_dir.path().join("state.lock");
    let mut lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock_path)
        .expect("open lock");
    writeln!(lock_file, "held by test").expect("write lock marker");
    lock_file.try_lock_exclusive().expect("hold test lock");

    let response = run_anp_mls_error(
        data_dir.path(),
        "key-package",
        "generate",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-locked",
            "operation_id": "op-locked",
            "params": {"owner_did": alice()}
        }),
    );
    assert_eq!(response["error"]["code"], "state_locked");
    lock_file.unlock().expect("unlock");
}

#[test]
fn anp_mls_real_mode_does_not_emit_contract_test_markers() {
    let data_dir = tempdir().expect("state");
    let response = run_anp_mls(
        data_dir.path(),
        "key-package",
        "generate",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-real-marker",
            "operation_id": "op-real-marker",
            "params": {"owner_did": alice()}
        }),
    );
    let encoded = serde_json::to_string(&response).expect("response json");
    assert!(!encoded.contains("non_cryptographic"));
    assert!(!encoded.contains("contract-test"));
}

#[test]
fn anp_mls_accepts_exec_provider_top_level_envelope_defaults() {
    let data_dir = tempdir().expect("state");
    let response = run_anp_mls(
        data_dir.path(),
        "key-package",
        "generate",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-top-level-envelope",
            "operation_id": "op-top-level-envelope",
            "agent_did": alice(),
            "device_id": "phone",
            "params": {}
        }),
    );
    assert_eq!(
        response["result"]["group_key_package"]["owner_did"],
        alice()
    );
    assert_eq!(
        response["result"]["group_key_package"]["device_id"],
        "phone"
    );
}
