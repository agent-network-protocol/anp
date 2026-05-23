#![cfg(feature = "mls")]

mod common;

use common::tempdir;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::path::Path;
use std::process::{Command, Stdio};

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

fn create_alice_group(data_dir: &Path, group_did: &str) -> Value {
    let create = run_anp_mls(
        data_dir,
        "group",
        "create",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-create",
            "operation_id": format!("op-create-{group_did}"),
            "params": {"agent_did": alice(), "device_id": "phone", "group_did": group_did}
        }),
    );
    assert_eq!(create["result"]["status"], "pending");
    assert_eq!(create["result"]["local_epoch"], "0");
    create
}

fn finalize_pending(
    data_dir: &Path,
    pending: &Value,
    request_id: &str,
    operation_id: &str,
) -> Value {
    run_anp_mls(
        data_dir,
        "group",
        "commit-finalize",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": request_id,
            "operation_id": operation_id,
            "params": {
                "pending_commit_id": pending["result"]["pending_commit_id"].as_str().unwrap()
            }
        }),
    )
}

fn create_and_finalize_alice_group(data_dir: &Path, group_did: &str) -> Value {
    let create = create_alice_group(data_dir, group_did);
    let finalized = finalize_pending(
        data_dir,
        &create,
        "req-create-finalize",
        &format!("op-create-finalize-{group_did}"),
    );
    assert_eq!(finalized["result"]["status"], "finalized");
    assert_eq!(finalized["result"]["epoch"], "0");
    create
}

#[test]
fn storage_spike_openmls_can_share_im_core_like_sqlite_without_changing_user_version() {
    let data_dir = tempdir("anp-group-storage-spike").expect("state");
    let db_path = data_dir.path().join("state.db");
    let conn = Connection::open(&db_path).expect("open im-core-like sqlite");
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA user_version = 13;
         CREATE TABLE im_core_probe(
            owner_identity_id TEXT NOT NULL,
            note TEXT NOT NULL
         );",
    )
    .expect("create im-core-like schema");
    drop(conn);

    let response = run_anp_mls(
        data_dir.path(),
        "key-package",
        "generate",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-shared-sqlite",
            "operation_id": "op-shared-sqlite",
            "params": {"owner_did": alice(), "device_id": "phone"}
        }),
    );
    assert_eq!(response["ok"], true);

    let conn = Connection::open(&db_path).expect("reopen shared sqlite");
    let user_version: i64 = conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .expect("read user_version");
    assert_eq!(
        user_version, 13,
        "OpenMLS/anp-mls migrations must not overwrite im-core user_version"
    );

    let probe_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'im_core_probe'",
            [],
            |row| row.get(0),
        )
        .expect("query probe table");
    assert_eq!(probe_count, 1);

    let openmls_table_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name LIKE 'openmls_%'",
            [],
            |row| row.get(0),
        )
        .expect("query openmls tables");
    assert!(
        openmls_table_count > 0,
        "expected openmls_sqlite_storage migrations to create openmls_* tables"
    );
}

#[test]
fn storage_spike_separate_openmls_connection_cannot_join_existing_write_transaction() {
    let data_dir = tempdir("anp-group-storage-spike").expect("state");
    let db_path = data_dir.path().join("state.db");
    let conn = Connection::open(&db_path).expect("open sqlite");
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA busy_timeout = 1;
         CREATE TABLE im_core_probe(id INTEGER PRIMARY KEY, note TEXT NOT NULL);
         BEGIN IMMEDIATE;",
    )
    .expect("hold im-core write transaction");

    let response = run_anp_mls_error(
        data_dir.path(),
        "key-package",
        "generate",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-write-locked",
            "operation_id": "op-write-locked",
            "params": {"owner_did": alice(), "device_id": "phone"}
        }),
    );
    assert_eq!(response["ok"], false);
    let encoded = serde_json::to_string(&response).expect("response json");
    assert!(
        encoded.contains("locked") || encoded.contains("busy"),
        "expected SQLite lock/busy evidence, got {encoded}"
    );

    conn.execute_batch("ROLLBACK")
        .expect("rollback probe transaction");
}

#[test]
fn storage_spike_add_member_prepare_keeps_binding_epoch_and_records_pending_commit() {
    let alice_dir = tempdir("anp-group-storage-spike-alice").expect("alice state");
    let bob_dir = tempdir("anp-group-storage-spike-bob").expect("bob state");
    let group_did = "did:wba:example.com:groups:storage-spike:e1";

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
    create_and_finalize_alice_group(alice_dir.path(), group_did);

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
                "pending_commit_id": "pc-add-spike",
                "group_key_package": bob_kp["result"]["group_key_package"].clone()
            }
        }),
    );
    assert_eq!(add["result"]["status"], "pending");
    assert_eq!(add["result"]["from_epoch"], "0");
    assert_eq!(add["result"]["epoch"], "1");
    assert_eq!(add["result"]["local_epoch"], "0");
    assert_eq!(add["result"]["pending_commit_id"], "pc-add-spike");

    let status = run_anp_mls(
        alice_dir.path(),
        "group",
        "status",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-status",
            "operation_id": "op-status",
            "params": {"agent_did": alice(), "device_id": "phone", "group_did": group_did}
        }),
    );
    assert_eq!(status["result"]["status"], "active");
    assert_eq!(
        status["result"]["local_epoch"], "0",
        "add-member prepare must not merge the pending commit before service acceptance"
    );
    assert_eq!(
        status["result"]["pending_commits"]
            .as_array()
            .expect("pending commits")
            .len(),
        1,
        "add-member prepare must leave a pending commit for finalize/abort"
    );
    assert_eq!(
        status["result"]["pending_commits"][0]["pending_commit_id"],
        "pc-add-spike"
    );

    let conn = Connection::open(alice_dir.path().join("state.db")).expect("open alice state");
    let binding_epoch: i64 = conn
        .query_row(
            "SELECT epoch FROM group_bindings WHERE agent_did = ?1 AND device_id = ?2 AND group_did = ?3",
            params![alice(), "phone", group_did],
            |row| row.get(0),
        )
        .expect("read binding epoch");
    assert_eq!(
        binding_epoch, 0,
        "add-member prepare must not update binding epoch before message-service acceptance"
    );
}

#[test]
fn storage_spike_remove_prepare_keeps_binding_epoch_and_records_pending_commit() {
    let alice_dir = tempdir("anp-group-storage-spike-alice").expect("alice state");
    let bob_dir = tempdir("anp-group-storage-spike-bob").expect("bob state");
    let group_did = "did:wba:example.com:groups:remove-prepare-spike:e1";

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
    create_and_finalize_alice_group(alice_dir.path(), group_did);
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
    finalize_pending(
        alice_dir.path(),
        &add,
        "req-add-finalize",
        "op-add-finalize",
    );

    let prepare = run_anp_mls(
        alice_dir.path(),
        "group",
        "remove-member",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-remove-prepare",
            "operation_id": "op-remove-prepare",
            "params": {
                "actor_did": alice(),
                "device_id": "phone",
                "group_did": group_did,
                "member_did": bob(),
                "pending_commit_id": "pc-remove-spike",
                "group_state_ref": {
                    "group_did": group_did,
                    "group_state_version": "1",
                    "epoch": "1",
                    "crypto_group_id_b64u": add["result"]["crypto_group_id_b64u"].clone()
                }
            }
        }),
    );
    assert_eq!(prepare["result"]["status"], "pending");
    assert_eq!(prepare["result"]["from_epoch"], "1");
    assert_eq!(prepare["result"]["epoch"], "2");
    assert_eq!(prepare["result"]["local_epoch"], "1");

    let status = run_anp_mls(
        alice_dir.path(),
        "group",
        "status",
        json!({
            "api_version": "anp-mls/v1",
            "request_id": "req-status",
            "operation_id": "op-status",
            "params": {"agent_did": alice(), "device_id": "phone", "group_did": group_did}
        }),
    );
    assert_eq!(
        status["result"]["local_epoch"], "1",
        "prepare must not advance loaded group/binding epoch before finalize"
    );
    assert_eq!(
        status["result"]["pending_commits"]
            .as_array()
            .expect("pending commits")
            .len(),
        1
    );
    assert_eq!(
        status["result"]["pending_commits"][0]["pending_commit_id"],
        "pc-remove-spike"
    );
}
