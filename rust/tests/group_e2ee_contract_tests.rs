use anp::group_e2ee::{deterministic_contract_artifact, CONTRACT_ARTIFACT_MODE};
use serde_json::{json, Value};
use std::process::{Command, Stdio};
use tempfile::tempdir;

#[test]
fn deterministic_contract_artifact_is_marked_non_crypto() {
    let artifact =
        deterministic_contract_artifact("unit", &json!({"b": 2, "a": 1}), true).expect("artifact");
    assert!(artifact.non_cryptographic);
    assert_eq!(artifact.artifact_mode, CONTRACT_ARTIFACT_MODE);
    assert!(!artifact.value_b64u.is_empty());
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
