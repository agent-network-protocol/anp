use anp::group_e2ee::{deterministic_contract_artifact, CONTRACT_ARTIFACT_MODE};
use serde_json::{json, Value};
use std::process::{Command, Stdio};
use tempfile::tempdir;

fn run_contract_anp_mls(
    data_dir: &std::path::Path,
    domain: &str,
    action: &str,
    request: Value,
) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_anp-mls"))
        .args([
            domain,
            action,
            "--json-in",
            "-",
            "--data-dir",
            data_dir.to_str().expect("temp path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn anp-mls");
    serde_json::to_writer(child.stdin.as_mut().expect("stdin"), &request).expect("write request");
    drop(child.stdin.take());
    let output = child.wait_with_output().expect("output");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("json response")
}

#[test]
fn deterministic_contract_artifact_is_marked_non_crypto() {
    let artifact =
        deterministic_contract_artifact("unit", &json!({"b": 2, "a": 1}), true).expect("artifact");
    assert!(artifact.non_cryptographic);
    assert_eq!(artifact.artifact_mode, CONTRACT_ARTIFACT_MODE);
    assert!(!artifact.value_b64u.is_empty());
}

#[test]
fn anp_mls_contract_binary_covers_recover_member_terminal_steps() {
    let data_dir = tempdir().expect("temp data dir");
    let prepare = run_contract_anp_mls(
        data_dir.path(),
        "group",
        "recover-member-prepare",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-recover-prepare",
            "operation_id": "op-recover-prepare",
            "contract_test_enabled": true,
            "params": {
                "group_did": "did:wba:example.com:groups:demo:e1",
                "member_did": "did:wba:example.com:users:bob:e1",
                "pending_commit_id": "pc-recover"
            }
        }),
    );
    assert_eq!(prepare["result"]["status"], "pending");
    assert_eq!(prepare["result"]["pending_commit_id"], "pc-recover");
    assert_eq!(prepare["result"]["subject_status"], "recovered");
    assert_eq!(prepare["result"]["non_cryptographic"], true);
    assert_eq!(prepare["result"]["artifact_mode"], CONTRACT_ARTIFACT_MODE);

    let finalized = run_contract_anp_mls(
        data_dir.path(),
        "group",
        "recover-member-finalize",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-recover-finalize",
            "operation_id": "op-recover-finalize",
            "contract_test_enabled": true,
            "params": {"pending_commit_id": "pc-recover"}
        }),
    );
    assert_eq!(finalized["result"]["status"], "finalized");
    assert_eq!(finalized["result"]["pending_commit_id"], "pc-recover");

    let aborted = run_contract_anp_mls(
        data_dir.path(),
        "group",
        "recover-member-abort",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-recover-abort",
            "operation_id": "op-recover-abort",
            "contract_test_enabled": true,
            "params": {"pending_commit_id": "pc-recover"}
        }),
    );
    assert_eq!(aborted["result"]["status"], "aborted");
    assert_eq!(aborted["result"]["pending_commit_id"], "pc-recover");
}

#[test]
fn anp_mls_contract_binary_uses_stdin_json_and_marks_artifacts() {
    let data_dir = tempdir().expect("temp data dir");
    let mut child = Command::new(env!("CARGO_BIN_EXE_anp-mls"))
        .args([
            "key-package",
            "generate",
            "--json-in",
            "-",
            "--data-dir",
            data_dir.path().to_str().expect("temp path"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn anp-mls");
    serde_json::to_writer(
        child.stdin.as_mut().expect("stdin"),
        &json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-1",
            "contract_test_enabled": true,
            "params": {"owner_did": "did:wba:example.com:users:alice:e1"}
        }),
    )
    .expect("write request");
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("output");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value = serde_json::from_slice(&output.stdout).expect("json response");
    assert_eq!(response["ok"], true);
    assert_eq!(response["result"]["non_cryptographic"], true);
    assert_eq!(response["result"]["artifact_mode"], CONTRACT_ARTIFACT_MODE);
    assert!(data_dir.path().join("contract-operations.jsonl").exists());
}
