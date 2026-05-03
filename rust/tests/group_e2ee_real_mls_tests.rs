use fs2::FileExt;
use rusqlite::Connection;
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

fn run_anp_mls_no_data_dir(domain: &str, action: &str, request: Value) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_anp-mls"))
        .args([domain, action, "--json-in", "-"])
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

fn alice() -> &'static str {
    "did:wba:example.com:users:alice:e1"
}

fn bob() -> &'static str {
    "did:wba:example.com:users:bob:e1"
}

fn bootstrap_alice_bob_group_without_welcome(
    alice_dir: &Path,
    bob_dir: &Path,
    group_did: &str,
) -> Value {
    let bob_kp = run_anp_mls(
        bob_dir,
        "key-package",
        "generate",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-bootstrap-bob-kp",
            "operation_id": "op-bootstrap-bob-kp",
            "params": {"owner_did": bob(), "device_id": "phone"}
        }),
    );
    run_anp_mls(
        alice_dir,
        "group",
        "create",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-bootstrap-create",
            "operation_id": "op-bootstrap-create",
            "params": {"agent_did": alice(), "device_id": "phone", "group_did": group_did}
        }),
    );
    let add = run_anp_mls(
        alice_dir,
        "group",
        "add-member",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-bootstrap-add",
            "operation_id": "op-bootstrap-add",
            "params": {
                "actor_did": alice(),
                "device_id": "phone",
                "group_did": group_did,
                "member_did": bob(),
                "group_key_package": bob_kp["result"]["group_key_package"].clone()
            }
        }),
    );
    add
}

fn bootstrap_alice_bob_group(alice_dir: &Path, bob_dir: &Path, group_did: &str) -> Value {
    let add = bootstrap_alice_bob_group_without_welcome(alice_dir, bob_dir, group_did);
    run_anp_mls(
        bob_dir,
        "welcome",
        "process",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-bootstrap-welcome",
            "operation_id": "op-bootstrap-welcome",
            "params": {
                "agent_did": bob(),
                "device_id": "phone",
                "group_did": group_did,
                "welcome_b64u": add["result"]["welcome_b64u"].as_str().expect("welcome"),
                "ratchet_tree_b64u": add["result"]["ratchet_tree_b64u"].as_str().expect("ratchet tree")
            }
        }),
    );
    add
}

fn encrypt_text(
    data_dir: &Path,
    sender_did: &str,
    group_did: &str,
    epoch: &str,
    op: &str,
    message_id: &str,
    text: &str,
) -> Value {
    run_anp_mls(
        data_dir,
        "message",
        "encrypt",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": format!("req-{op}"),
            "operation_id": op,
            "params": {
                "sender_did": sender_did,
                "device_id": "phone",
                "group_state_ref": {
                    "group_did": group_did,
                    "epoch": epoch,
                },
                "content_type": "application/anp-group-cipher+json",
                "security_profile": "group-e2ee",
                "message_id": message_id,
                "operation_id": op,
                "application_plaintext": {"application_content_type": "text/plain", "text": text}
            }
        }),
    )
}

#[test]
fn group_e2ee_anp_mls_system_version_probe_is_stable_json() {
    let response = run_anp_mls_no_data_dir(
        "system",
        "version",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-version-probe"
        }),
    );
    assert_eq!(response["ok"], true);
    assert_eq!(response["api_version"], "anp-mls/v1");
    assert_eq!(response["request_id"], "req-version-probe");
    assert_eq!(response["result"]["api_version"], "anp-mls/v1");
    assert_eq!(response["result"]["binary_name"], "anp-mls");
    assert!(response["result"]["binary_version"]
        .as_str()
        .unwrap()
        .starts_with("0."));
    let supported_commands = response["result"]["supported_commands"]
        .as_array()
        .expect("supported commands");
    assert!(supported_commands
        .iter()
        .any(|value| value.as_str() == Some("system version")));
    assert!(supported_commands
        .iter()
        .any(|value| value.as_str() == Some("message encrypt")));
    assert!(supported_commands
        .iter()
        .any(|value| value.as_str() == Some("group remove-member")));
    assert!(supported_commands
        .iter()
        .any(|value| value.as_str() == Some("group commit-finalize")));
}

#[test]
fn group_e2ee_anp_mls_create_add_welcome_encrypt_decrypt_round_trip() {
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
    let ratchet_tree_b64u = add["result"]["ratchet_tree_b64u"]
        .as_str()
        .expect("ratchet tree");
    assert!(!welcome_b64u.is_empty());
    assert!(!ratchet_tree_b64u.is_empty());

    let welcome = run_anp_mls(
        bob_dir.path(),
        "welcome",
        "process",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-welcome",
            "operation_id": "op-welcome",
            "params": {"agent_did": bob(), "device_id": "phone", "group_did": group_did, "welcome_b64u": welcome_b64u, "ratchet_tree_b64u": ratchet_tree_b64u}
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
                "content_type": "application/anp-group-cipher+json",
                "security_profile": "group-e2ee",
                "message_id": "msg-encrypt",
                "operation_id": "op-encrypt",
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
                "sender_did": alice(),
                "content_type": "application/anp-group-cipher+json",
                "security_profile": "group-e2ee",
                "message_id": "msg-encrypt",
                "operation_id": "op-encrypt",
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
fn group_e2ee_remove_member_prepares_pending_commit_then_finalize_advances_epoch() {
    let alice_dir = tempdir().expect("alice state");
    let bob_dir = tempdir().expect("bob state");
    let group_did = "did:wba:example.com:groups:remove-member:e1";
    let add = bootstrap_alice_bob_group(alice_dir.path(), bob_dir.path(), group_did);
    assert_eq!(add["result"]["epoch"], "1");

    let remove = run_anp_mls(
        alice_dir.path(),
        "group",
        "remove-member",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-remove-bob",
            "operation_id": "op-remove-bob",
            "params": {
                "actor_did": alice(),
                "device_id": "phone",
                "group_did": group_did,
                "member_did": bob(),
                "group_state_ref": {
                    "group_did": group_did,
                    "epoch": "1",
                    "crypto_group_id_b64u": add["result"]["crypto_group_id_b64u"].clone()
                }
            }
        }),
    );
    assert_eq!(remove["result"]["status"], "pending");
    assert_eq!(remove["result"]["subject_did"], bob());
    assert_eq!(remove["result"]["subject_status"], "removed");
    assert_eq!(remove["result"]["from_epoch"], "1");
    assert_eq!(remove["result"]["epoch"], "2");
    assert_eq!(remove["result"]["local_epoch"], "1");
    assert!(remove["result"]["pending_commit_id"].as_str().is_some());
    assert!(remove["result"]["commit_b64u"].as_str().unwrap().len() > 64);

    let status_before_finalize = run_anp_mls(
        alice_dir.path(),
        "group",
        "status",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-remove-status-before-finalize",
            "operation_id": "op-remove-status-before-finalize",
            "params": {"agent_did": alice(), "device_id": "phone", "group_did": group_did}
        }),
    );
    assert_eq!(status_before_finalize["result"]["epoch"], "1");

    let replay = run_anp_mls(
        alice_dir.path(),
        "group",
        "remove-member",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-remove-bob-replay",
            "operation_id": "op-remove-bob",
            "params": {
                "actor_did": alice(),
                "device_id": "phone",
                "group_did": group_did,
                "member_did": bob(),
                "group_state_ref": {
                    "group_did": group_did,
                    "epoch": "1",
                    "crypto_group_id_b64u": add["result"]["crypto_group_id_b64u"].clone()
                }
            }
        }),
    );
    assert_eq!(replay["result"], remove["result"]);
    assert_eq!(replay["request_id"], "req-remove-bob-replay");

    let finalized = run_anp_mls(
        alice_dir.path(),
        "group",
        "commit-finalize",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-remove-finalize",
            "operation_id": "op-remove-finalize",
            "params": {
                "pending_commit_id": remove["result"]["pending_commit_id"].as_str().unwrap()
            }
        }),
    );
    assert_eq!(finalized["result"]["status"], "finalized");
    assert_eq!(finalized["result"]["epoch"], "2");

    let post_remove = encrypt_text(
        alice_dir.path(),
        alice(),
        group_did,
        "2",
        "op-post-remove-encrypt",
        "msg-post-remove",
        "Bob must not decrypt this",
    );
    let cannot_decrypt = run_anp_mls_error(
        bob_dir.path(),
        "message",
        "decrypt",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-bob-decrypt-post-remove",
            "operation_id": "op-bob-decrypt-post-remove",
            "params": {
                "recipient_did": bob(),
                "device_id": "phone",
                "group_did": group_did,
                "sender_did": alice(),
                "content_type": "application/anp-group-cipher+json",
                "security_profile": "group-e2ee",
                "message_id": "msg-post-remove",
                "operation_id": "op-post-remove-encrypt",
                "group_cipher_object": post_remove["result"]["group_cipher_object"].clone()
            }
        }),
    );
    assert_eq!(cannot_decrypt["error"]["code"], "group_epoch_mismatch");

    let processed = run_anp_mls(
        bob_dir.path(),
        "commit",
        "process",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-bob-process-remove",
            "operation_id": "op-bob-process-remove",
            "params": {
                "recipient_did": bob(),
                "device_id": "phone",
                "group_did": group_did,
                "from_epoch": "1",
                "commit_b64u": remove["result"]["commit_b64u"].as_str().unwrap(),
                "subject_did": bob(),
                "subject_status": "removed"
            }
        }),
    );
    assert_eq!(processed["result"]["self_removed"], true);
    assert_eq!(processed["result"]["status"], "inactive");

    let bob_send = run_anp_mls_error(
        bob_dir.path(),
        "message",
        "encrypt",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-bob-send-after-remove",
            "operation_id": "op-bob-send-after-remove",
            "params": {
                "sender_did": bob(),
                "device_id": "phone",
                "group_state_ref": {"group_did": group_did, "epoch": "2"},
                "content_type": "application/anp-group-cipher+json",
                "security_profile": "group-e2ee",
                "message_id": "msg-bob-after-remove",
                "operation_id": "op-bob-send-after-remove",
                "application_plaintext": {"application_content_type": "text/plain", "text": "blocked"}
            }
        }),
    );
    assert_eq!(bob_send["error"]["code"], "group_not_found");
}

#[test]
fn group_e2ee_remove_pending_commit_abort_clears_without_advancing_epoch() {
    let alice_dir = tempdir().expect("alice state");
    let bob_dir = tempdir().expect("bob state");
    let group_did = "did:wba:example.com:groups:remove-abort:e1";
    let add = bootstrap_alice_bob_group(alice_dir.path(), bob_dir.path(), group_did);

    let remove = run_anp_mls(
        alice_dir.path(),
        "group",
        "remove-member",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-remove-abort",
            "operation_id": "op-remove-abort",
            "params": {
                "actor_did": alice(),
                "device_id": "phone",
                "group_did": group_did,
                "member_did": bob(),
                "group_state_ref": {"group_did": group_did, "epoch": "1", "crypto_group_id_b64u": add["result"]["crypto_group_id_b64u"].clone()}
            }
        }),
    );
    let aborted = run_anp_mls(
        alice_dir.path(),
        "group",
        "commit-abort",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-remove-abort-clear",
            "operation_id": "op-remove-abort-clear",
            "params": {"pending_commit_id": remove["result"]["pending_commit_id"].as_str().unwrap()}
        }),
    );
    assert_eq!(aborted["result"]["status"], "aborted");
    assert_eq!(aborted["result"]["local_epoch"], "1");

    let still_epoch_one = encrypt_text(
        alice_dir.path(),
        alice(),
        group_did,
        "1",
        "op-after-abort-encrypt",
        "msg-after-abort",
        "still epoch one",
    );
    assert_eq!(
        still_epoch_one["result"]["group_cipher_object"]["epoch"],
        "1"
    );
}

#[test]
fn group_e2ee_leave_prepares_and_finalize_marks_local_state_left() {
    let alice_dir = tempdir().expect("alice state");
    let bob_dir = tempdir().expect("bob state");
    let group_did = "did:wba:example.com:groups:leave:e1";
    let add = bootstrap_alice_bob_group(alice_dir.path(), bob_dir.path(), group_did);

    let leave = run_anp_mls(
        bob_dir.path(),
        "group",
        "leave",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-bob-leave",
            "operation_id": "op-bob-leave",
            "params": {
                "actor_did": bob(),
                "device_id": "phone",
                "group_did": group_did,
                "group_state_ref": {"group_did": group_did, "epoch": "1", "crypto_group_id_b64u": add["result"]["crypto_group_id_b64u"].clone()}
            }
        }),
    );
    assert_eq!(leave["result"]["status"], "pending");
    assert_eq!(leave["result"]["subject_status"], "left");
    assert_eq!(leave["result"]["local_epoch"], "1");

    let finalized = run_anp_mls(
        bob_dir.path(),
        "group",
        "commit-finalize",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-bob-leave-finalize",
            "operation_id": "op-bob-leave-finalize",
            "params": {"pending_commit_id": leave["result"]["pending_commit_id"].as_str().unwrap()}
        }),
    );
    assert_eq!(finalized["result"]["status"], "finalized");
    assert_eq!(finalized["result"]["subject_status"], "left");

    let bob_send = run_anp_mls_error(
        bob_dir.path(),
        "message",
        "encrypt",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-bob-send-after-leave",
            "operation_id": "op-bob-send-after-leave",
            "params": {
                "sender_did": bob(),
                "device_id": "phone",
                "group_state_ref": {"group_did": group_did, "epoch": "2"},
                "content_type": "application/anp-group-cipher+json",
                "security_profile": "group-e2ee",
                "message_id": "msg-bob-after-leave",
                "operation_id": "op-bob-send-after-leave",
                "application_plaintext": {"application_content_type": "text/plain", "text": "blocked"}
            }
        }),
    );
    assert_eq!(bob_send["error"]["code"], "group_not_found");
}

#[test]
fn group_e2ee_anp_mls_rejects_mismatched_group_state_ref_before_encrypt() {
    let alice_dir = tempdir().expect("alice state");
    let bob_dir = tempdir().expect("bob state");
    let group_did = "did:wba:example.com:groups:binding-mismatch:e1";
    let add = bootstrap_alice_bob_group(alice_dir.path(), bob_dir.path(), group_did);

    let server_state_version_is_not_mls_epoch = run_anp_mls(
        alice_dir.path(),
        "message",
        "encrypt",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-server-version",
            "operation_id": "op-server-version",
            "params": {
                "sender_did": alice(),
                "device_id": "phone",
                "group_state_ref": {
                    "group_did": group_did,
                    "group_state_version": "42",
                    "crypto_group_id_b64u": add["result"]["crypto_group_id_b64u"].clone()
                },
                "content_type": "application/anp-group-cipher+json",
                "security_profile": "group-e2ee",
                "message_id": "msg-server-version",
                "operation_id": "op-server-version",
                "application_plaintext": {"application_content_type": "text/plain", "text": "server version is aad only"}
            }
        }),
    );
    assert!(server_state_version_is_not_mls_epoch["result"]["group_cipher_object"].is_object());

    let wrong_epoch = run_anp_mls_error(
        alice_dir.path(),
        "message",
        "encrypt",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-wrong-epoch",
            "operation_id": "op-wrong-epoch",
            "params": {
                "sender_did": alice(),
                "device_id": "phone",
                "group_state_ref": {
                    "group_did": group_did,
                    "epoch": "0",
                    "crypto_group_id_b64u": add["result"]["crypto_group_id_b64u"].clone()
                },
                "content_type": "application/anp-group-cipher+json",
                "security_profile": "group-e2ee",
                "message_id": "msg-wrong-epoch",
                "operation_id": "op-wrong-epoch",
                "application_plaintext": {"application_content_type": "text/plain", "text": "blocked"}
            }
        }),
    );
    assert_eq!(wrong_epoch["error"]["code"], "group_epoch_mismatch");

    let wrong_crypto_group = run_anp_mls_error(
        alice_dir.path(),
        "message",
        "encrypt",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-wrong-crypto-group",
            "operation_id": "op-wrong-crypto-group",
            "params": {
                "sender_did": alice(),
                "device_id": "phone",
                "group_state_ref": {
                    "group_did": group_did,
                    "group_state_version": "1",
                    "crypto_group_id_b64u": "wrong-local-group"
                },
                "content_type": "application/anp-group-cipher+json",
                "security_profile": "group-e2ee",
                "message_id": "msg-wrong-crypto-group",
                "operation_id": "op-wrong-crypto-group",
                "application_plaintext": {"application_content_type": "text/plain", "text": "blocked"}
            }
        }),
    );
    assert_eq!(
        wrong_crypto_group["error"]["code"],
        "group_binding_mismatch"
    );
}

#[test]
fn group_e2ee_anp_mls_rejects_mismatched_cipher_group_binding_before_decrypt() {
    let alice_dir = tempdir().expect("alice state");
    let bob_dir = tempdir().expect("bob state");
    let group_did = "did:wba:example.com:groups:cipher-binding:e1";
    let add = bootstrap_alice_bob_group(alice_dir.path(), bob_dir.path(), group_did);

    let encrypted = run_anp_mls(
        alice_dir.path(),
        "message",
        "encrypt",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-cipher-binding-encrypt",
            "operation_id": "op-cipher-binding-encrypt",
            "params": {
                "sender_did": alice(),
                "device_id": "phone",
                "group_state_ref": {
                    "group_did": group_did,
                    "group_state_version": "1",
                    "crypto_group_id_b64u": add["result"]["crypto_group_id_b64u"].clone()
                },
                "content_type": "application/anp-group-cipher+json",
                "security_profile": "group-e2ee",
                "message_id": "msg-cipher-binding",
                "operation_id": "op-cipher-binding-encrypt",
                "application_plaintext": {"application_content_type": "text/plain", "text": "binding protected"}
            }
        }),
    );
    let mut cipher = encrypted["result"]["group_cipher_object"].clone();
    cipher["crypto_group_id_b64u"] = json!("wrong-cipher-group");

    let rejected = run_anp_mls_error(
        bob_dir.path(),
        "message",
        "decrypt",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-cipher-binding-decrypt",
            "operation_id": "op-cipher-binding-decrypt",
            "params": {
                "recipient_did": bob(),
                "device_id": "phone",
                "group_did": group_did,
                "sender_did": alice(),
                "content_type": "application/anp-group-cipher+json",
                "security_profile": "group-e2ee",
                "message_id": "msg-cipher-binding",
                "operation_id": "op-cipher-binding-encrypt",
                "group_cipher_object": cipher
            }
        }),
    );
    assert_eq!(rejected["error"]["code"], "group_binding_mismatch");
}

#[test]
fn group_e2ee_anp_mls_requires_ratchet_tree_for_welcome_process() {
    let alice_dir = tempdir().expect("alice state");
    let bob_dir = tempdir().expect("bob state");
    let group_did = "did:wba:example.com:groups:ratchet-required:e1";
    let add =
        bootstrap_alice_bob_group_without_welcome(alice_dir.path(), bob_dir.path(), group_did);

    let missing = run_anp_mls_error(
        bob_dir.path(),
        "welcome",
        "process",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-missing-ratchet-tree",
            "operation_id": "op-missing-ratchet-tree",
            "params": {
                "agent_did": bob(),
                "device_id": "phone",
                "group_did": group_did,
                "welcome_b64u": add["result"]["welcome_b64u"].as_str().expect("welcome")
            }
        }),
    );
    assert_eq!(missing["error"]["code"], "missing_field");

    let invalid = run_anp_mls_error(
        bob_dir.path(),
        "welcome",
        "process",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-invalid-ratchet-tree",
            "operation_id": "op-invalid-ratchet-tree",
            "params": {
                "agent_did": bob(),
                "device_id": "phone",
                "group_did": group_did,
                "welcome_b64u": add["result"]["welcome_b64u"].as_str().expect("welcome"),
                "ratchet_tree_b64u": "AAAA"
            }
        }),
    );
    assert!([
        "ratchet_tree_decode_failed",
        "welcome_stage_failed",
        "invalid_base64url"
    ]
    .contains(&invalid["error"]["code"].as_str().unwrap()));
}

#[test]
fn group_e2ee_anp_mls_rejects_tampered_send_aad_before_plaintext_release() {
    let alice_dir = tempdir().expect("alice state");
    let bob_dir = tempdir().expect("bob state");
    let group_did = "did:wba:example.com:groups:aad-binding:e1";
    let add = bootstrap_alice_bob_group(alice_dir.path(), bob_dir.path(), group_did);

    let encrypted = run_anp_mls(
        alice_dir.path(),
        "message",
        "encrypt",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-aad-encrypt",
            "operation_id": "op-aad-encrypt",
            "params": {
                "sender_did": alice(),
                "device_id": "phone",
                "group_state_ref": {
                    "group_did": group_did,
                    "group_state_version": "1",
                    "crypto_group_id_b64u": add["result"]["crypto_group_id_b64u"].clone()
                },
                "content_type": "application/anp-group-cipher+json",
                "security_profile": "group-e2ee",
                "message_id": "msg-aad-original",
                "operation_id": "op-aad-encrypt",
                "application_plaintext": {"application_content_type": "text/plain", "text": "aad protected"}
            }
        }),
    );
    assert!(encrypted["result"]["authenticated_data_sha256_b64u"]
        .as_str()
        .is_some());

    let rejected = run_anp_mls_error(
        bob_dir.path(),
        "message",
        "decrypt",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-aad-decrypt",
            "operation_id": "op-aad-decrypt",
            "params": {
                "recipient_did": bob(),
                "device_id": "phone",
                "group_did": group_did,
                "sender_did": alice(),
                "content_type": "application/anp-group-cipher+json",
                "security_profile": "group-e2ee",
                "message_id": "msg-aad-tampered",
                "operation_id": "op-aad-encrypt",
                "group_cipher_object": encrypted["result"]["group_cipher_object"].clone()
            }
        }),
    );
    assert_eq!(rejected["error"]["code"], "aad_mismatch");
}

#[test]
fn group_e2ee_anp_mls_rejects_key_package_did_wba_binding_mismatch() {
    let alice_dir = tempdir().expect("alice state");
    let bob_dir = tempdir().expect("bob state");
    let group_did = "did:wba:example.com:groups:binding-validation:e1";
    let mut bob_kp = run_anp_mls(
        bob_dir.path(),
        "key-package",
        "generate",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-binding-bob-kp",
            "operation_id": "op-binding-bob-kp",
            "params": {"owner_did": bob(), "device_id": "phone"}
        }),
    );
    run_anp_mls(
        alice_dir.path(),
        "group",
        "create",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-binding-create",
            "operation_id": "op-binding-create",
            "params": {"agent_did": alice(), "device_id": "phone", "group_did": group_did}
        }),
    );
    bob_kp["result"]["group_key_package"]["did_wba_binding"]["agent_did"] = json!(alice());

    let rejected = run_anp_mls_error(
        alice_dir.path(),
        "group",
        "add-member",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-binding-add",
            "operation_id": "op-binding-add",
            "params": {
                "actor_did": alice(),
                "device_id": "phone",
                "group_did": group_did,
                "member_did": bob(),
                "group_key_package": bob_kp["result"]["group_key_package"].clone()
            }
        }),
    );
    assert_eq!(rejected["error"]["code"], "did_wba_binding_mismatch");
}

#[test]
fn group_e2ee_anp_mls_operation_log_redacts_decrypted_plaintext() {
    let alice_dir = tempdir().expect("alice state");
    let bob_dir = tempdir().expect("bob state");
    let group_did = "did:wba:example.com:groups:operation-log:e1";
    let add = bootstrap_alice_bob_group(alice_dir.path(), bob_dir.path(), group_did);
    let secret = "operation log must not persist this plaintext";

    let encrypted = run_anp_mls(
        alice_dir.path(),
        "message",
        "encrypt",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-log-encrypt",
            "operation_id": "op-log-encrypt",
            "params": {
                "sender_did": alice(),
                "device_id": "phone",
                "group_state_ref": {
                    "group_did": group_did,
                    "group_state_version": "1",
                    "crypto_group_id_b64u": add["result"]["crypto_group_id_b64u"].clone()
                },
                "content_type": "application/anp-group-cipher+json",
                "security_profile": "group-e2ee",
                "message_id": "msg-log-encrypt",
                "operation_id": "op-log-encrypt",
                "application_plaintext": {"application_content_type": "text/plain", "text": secret}
            }
        }),
    );
    let decrypted = run_anp_mls(
        bob_dir.path(),
        "message",
        "decrypt",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-log-decrypt",
            "operation_id": "op-log-decrypt",
            "params": {
                "recipient_did": bob(),
                "device_id": "phone",
                "group_did": group_did,
                "sender_did": alice(),
                "content_type": "application/anp-group-cipher+json",
                "security_profile": "group-e2ee",
                "message_id": "msg-log-encrypt",
                "operation_id": "op-log-encrypt",
                "group_cipher_object": encrypted["result"]["group_cipher_object"].clone()
            }
        }),
    );
    assert_eq!(decrypted["result"]["application_plaintext"]["text"], secret);

    let conn = Connection::open(bob_dir.path().join("state.db")).expect("open bob state");
    let mut stmt = conn
        .prepare("SELECT command, response_json FROM operations ORDER BY operation_id")
        .expect("prepare operations query");
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .expect("query operations");
    for row in rows {
        let (command, response_json) = row.expect("operation row");
        assert!(
            !response_json.contains(secret),
            "plaintext leaked into {command} operation row: {response_json}"
        );
        if command == "message decrypt" {
            assert!(
                !response_json.contains("application_plaintext"),
                "decrypt operation row must redact plaintext field: {response_json}"
            );
            assert!(response_json.contains("\"redacted\":true"));
        }
    }
}

#[test]
fn group_e2ee_anp_mls_operation_id_is_idempotent_and_conflicting_input_fails() {
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
fn group_e2ee_anp_mls_file_lock_rejects_concurrent_mutation() {
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
fn group_e2ee_anp_mls_real_mode_does_not_emit_contract_test_markers() {
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
fn group_e2ee_anp_mls_accepts_exec_provider_top_level_envelope_defaults() {
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
