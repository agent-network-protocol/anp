//! [INPUT] One-shot `anp-mls` JSON requests on stdin plus CLI domain/action and optional `--data-dir`; `system version` is the no-state compatibility probe.
//! [OUTPUT] A single JSON response on stdout; real mode persists OpenMLS state, pending membership/recovery/update commits, local active/inactive bindings, and contract-test mode emits explicit non-cryptographic fixtures.
//! [POS] Boundary binary between Go/product clients and Rust MLS state; keep private MLS material local to `--data-dir` while exposing opaque P6 remove/leave/recovery/update/commit artifacts.

use anp::group_e2ee::commands::{
    error_response, ok_response, response_for_operation_log, system_version, DEVICE_ID_DEFAULT,
};
use anp::group_e2ee::operations::{
    real_commit_process, real_group_add_member, real_group_commit_abort,
    real_group_commit_finalize, real_group_create, real_group_leave,
    real_group_recover_member_prepare, real_group_remove_member, real_group_status,
    real_group_update_member_prepare, real_key_package, real_message_decrypt, real_message_encrypt,
    real_welcome_process,
};
use anp::group_e2ee::storage::{init_app_schema, sqlite_mls_provider, StateLock};
use anp::group_e2ee::{
    deterministic_contract_artifact, CONTRACT_ARTIFACT_MODE, METHOD_UPDATE, MTI_SUITE,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn main() {
    let code = match run() {
        Ok(value) => {
            println!("{}", serde_json::to_string(&value).expect("json response"));
            0
        }
        Err(value) => {
            println!("{}", serde_json::to_string(&value).expect("json error"));
            1
        }
    };
    std::process::exit(code);
}

fn run() -> Result<Value, Value> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let invocation = parse_invocation(&args)?;
    if !invocation.json_in {
        return Err(error(
            "invalid_args",
            "usage: anp-mls <domain> <action> --json-in - [--data-dir DIR]",
            None,
        ));
    }
    let command = format!("{} {}", invocation.domain, invocation.action);
    let mut stdin = String::new();
    io::stdin()
        .read_to_string(&mut stdin)
        .map_err(|e| error("stdin_read_failed", &e.to_string(), None))?;
    let req: Value =
        serde_json::from_str(&stdin).map_err(|e| error("invalid_json", &e.to_string(), None))?;
    let request_id = req
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or("req-unknown")
        .to_owned();
    let contract_enabled = req
        .get("contract_test_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || std::env::var("ANP_MLS_CONTRACT_TEST").ok().as_deref() == Some("1");
    let params = request_params(&req);
    if command == "system version" {
        return Ok(ok_response(&request_id, system_version()));
    }
    if contract_enabled {
        return run_contract_mode(&command, &request_id, &params, invocation.data_dir.as_ref());
    }
    run_real_mode(
        &command,
        &request_id,
        &req,
        &params,
        invocation.data_dir.as_ref(),
    )
}

struct Invocation {
    domain: String,
    action: String,
    json_in: bool,
    data_dir: Option<PathBuf>,
}

fn parse_invocation(args: &[String]) -> Result<Invocation, Value> {
    let mut positionals = Vec::new();
    let mut json_in = false;
    let mut data_dir = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--json-in" => {
                json_in = true;
                if args.get(index + 1).map(String::as_str) == Some("-") {
                    index += 2;
                } else {
                    index += 1;
                }
            }
            "--data-dir" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(error("invalid_args", "--data-dir requires a value", None));
                };
                data_dir = Some(PathBuf::from(value));
                index += 2;
            }
            other if other.starts_with("--") => {
                return Err(error(
                    "invalid_args",
                    &format!("unsupported option: {other}"),
                    None,
                ));
            }
            other => {
                positionals.push(other.to_owned());
                index += 1;
            }
        }
    }
    if positionals.len() < 2 {
        return Err(error(
            "invalid_args",
            "usage: anp-mls <domain> <action> --json-in - [--data-dir DIR]",
            None,
        ));
    }
    Ok(Invocation {
        domain: positionals[0].clone(),
        action: positionals[1].clone(),
        json_in,
        data_dir,
    })
}

fn request_params(req: &Value) -> Value {
    let mut params = req.get("params").cloned().unwrap_or_else(|| json!({}));
    let Some(object) = params.as_object_mut() else {
        return json!({});
    };
    for (top_level, param_key) in [
        ("agent_did", "agent_did"),
        ("device_id", "device_id"),
        ("operation_id", "operation_id"),
    ] {
        if !object.contains_key(param_key) {
            if let Some(value) = req.get(top_level).cloned() {
                object.insert(param_key.to_owned(), value);
            }
        }
    }
    if !object.contains_key("owner_did") {
        if let Some(value) = object.get("agent_did").cloned() {
            object.insert("owner_did".to_owned(), value);
        }
    }
    params
}

fn run_contract_mode(
    command: &str,
    request_id: &str,
    params: &Value,
    data_dir: Option<&PathBuf>,
) -> Result<Value, Value> {
    let result = match command {
        "key-package generate" => contract_key_package(params)?,
        "group create" => contract_group_create(params)?,
        "group add-member" => contract_group_add_member(params)?,
        "group update-member-prepare" => contract_group_update_member_prepare(params)?,
        "group update-member-finalize" => contract_group_commit_finalize(params)?,
        "group update-member-abort" => contract_group_commit_abort(params)?,
        "group recover-member-prepare" => contract_group_recover_member_prepare(params)?,
        "group recover-member-finalize" => contract_group_commit_finalize(params)?,
        "group recover-member-abort" => contract_group_commit_abort(params)?,
        "group remove-member" => contract_group_remove_member(params)?,
        "group leave" => contract_group_leave(params)?,
        "group commit-finalize" => contract_group_commit_finalize(params)?,
        "group commit-abort" => contract_group_commit_abort(params)?,
        "welcome process" => contract_welcome_process(params)?,
        "commit process" | "notice process" => contract_commit_process(params)?,
        "message encrypt" => contract_message_encrypt(params)?,
        "message decrypt" => contract_message_decrypt(params)?,
        "group restore" | "group status" => contract_group_status(params, data_dir)?,
        _ => {
            return Err(error(
                "unsupported_command",
                &format!("unsupported command: {command}"),
                Some(request_id.to_owned()),
            ))
        }
    };
    if let Some(data_dir) = data_dir {
        append_contract_operation_log(data_dir, request_id, command)?;
    }
    Ok(ok_response(request_id, result))
}

fn run_real_mode(
    command: &str,
    request_id: &str,
    req: &Value,
    params: &Value,
    data_dir: Option<&PathBuf>,
) -> Result<Value, Value> {
    let data_dir = data_dir.ok_or_else(|| {
        error(
            "missing_data_dir",
            "real anp-mls mode requires --data-dir for SQLite state",
            Some(request_id.to_owned()),
        )
    })?;
    fs::create_dir_all(data_dir).map_err(|e| {
        error(
            "state_write_failed",
            &format!("create data dir: {e}"),
            Some(request_id.to_owned()),
        )
    })?;
    let _lock = StateLock::try_acquire(data_dir)
        .map_err(|e| error(e.code(), &e.to_string(), Some(request_id.to_owned())))?;
    let db_path = data_dir.join("state.db");
    let app_conn =
        Connection::open(&db_path).map_err(|e| sqlite_error("state_open_failed", e, request_id))?;
    init_app_schema(&app_conn)
        .map_err(|e| sqlite_error("state_migration_failed", e, request_id))?;
    let operation_id = req
        .get("operation_id")
        .or_else(|| params.get("operation_id"))
        .and_then(Value::as_str)
        .unwrap_or(request_id);
    let input_digest = digest_json(&json!({"command": command, "params": params}));
    if let Some((saved_digest, saved_response)) = lookup_operation(&app_conn, operation_id)
        .map_err(|e| sqlite_error("state_read_failed", e, request_id))?
    {
        if saved_digest == input_digest {
            let mut response: Value = serde_json::from_str(&saved_response).map_err(|e| {
                error(
                    "state_read_failed",
                    &format!("decode saved operation response: {e}"),
                    Some(request_id.to_owned()),
                )
            })?;
            response["request_id"] = json!(request_id);
            return Ok(response);
        }
        return Err(error(
            "operation_conflict",
            "operation_id was already used with different input",
            Some(request_id.to_owned()),
        ));
    }

    let result = {
        let mut provider = sqlite_mls_provider(&db_path)
            .map_err(|e| error(e.code(), &e.to_string(), Some(request_id.to_owned())))?;
        match command {
            "key-package generate" => {
                real_key_package(&mut provider, &app_conn, params, request_id)?
            }
            "group create" => real_group_create(&mut provider, &app_conn, params, request_id)?,
            "group add-member" => {
                real_group_add_member(&mut provider, &app_conn, params, request_id)?
            }
            "group update-member-prepare" => real_group_update_member_prepare(
                &mut provider,
                &app_conn,
                params,
                operation_id,
                request_id,
            )?,
            "group update-member-finalize" => {
                real_group_commit_finalize(&mut provider, &app_conn, params, request_id)?
            }
            "group update-member-abort" => {
                real_group_commit_abort(&mut provider, &app_conn, params, request_id)?
            }
            "group recover-member-prepare" => real_group_recover_member_prepare(
                &mut provider,
                &app_conn,
                params,
                operation_id,
                request_id,
            )?,
            "group recover-member-finalize" => {
                real_group_commit_finalize(&mut provider, &app_conn, params, request_id)?
            }
            "group recover-member-abort" => {
                real_group_commit_abort(&mut provider, &app_conn, params, request_id)?
            }
            "group remove-member" => real_group_remove_member(
                &mut provider,
                &app_conn,
                params,
                operation_id,
                request_id,
            )?,
            "group leave" => {
                real_group_leave(&mut provider, &app_conn, params, operation_id, request_id)?
            }
            "group commit-finalize" => {
                real_group_commit_finalize(&mut provider, &app_conn, params, request_id)?
            }
            "group commit-abort" => {
                real_group_commit_abort(&mut provider, &app_conn, params, request_id)?
            }
            "welcome process" => {
                real_welcome_process(&mut provider, &app_conn, params, request_id)?
            }
            "commit process" | "notice process" => {
                real_commit_process(&mut provider, &app_conn, params, request_id)?
            }
            "message encrypt" => {
                real_message_encrypt(&mut provider, &app_conn, params, request_id)?
            }
            "message decrypt" => {
                real_message_decrypt(&mut provider, &app_conn, params, request_id)?
            }
            "group restore" | "group status" => {
                real_group_status(&mut provider, &app_conn, params, data_dir, request_id)?
            }
            _ => {
                return Err(error(
                    "unsupported_command",
                    &format!("unsupported command: {command}"),
                    Some(request_id.to_owned()),
                ))
            }
        }
    };
    let response = ok_response(request_id, result);
    let recorded_response = response_for_operation_log(command, &response);
    record_operation(
        &app_conn,
        operation_id,
        command,
        &input_digest,
        &recorded_response,
    )
    .map_err(|e| sqlite_error("state_write_failed", e, request_id))?;
    Ok(response)
}

fn lookup_operation(
    conn: &Connection,
    operation_id: &str,
) -> rusqlite::Result<Option<(String, String)>> {
    conn.query_row(
        "SELECT input_digest, response_json FROM operations WHERE operation_id = ?1 AND status = 'completed'",
        params![operation_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
}

fn record_operation(
    conn: &Connection,
    operation_id: &str,
    command: &str,
    input_digest: &str,
    response: &Value,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO operations(operation_id, command, input_digest, response_json, status, updated_at)
         VALUES (?1, ?2, ?3, ?4, 'completed', CURRENT_TIMESTAMP)",
        params![operation_id, command, input_digest, response.to_string()],
    )?;
    Ok(())
}

fn encode_b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn digest_json(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    encode_b64u(&Sha256::digest(bytes))
}

fn contract_key_package(params: &Value) -> Result<Value, Value> {
    let owner = required(params, "owner_did")?;
    let key_package_id = params
        .get("key_package_id")
        .and_then(Value::as_str)
        .unwrap_or("kp-contract-1");
    let artifact = artifact("key-package", params)?;
    Ok(json!({
        "group_key_package": {
            "key_package_id": key_package_id,
            "owner_did": owner,
            "device_id": params.get("device_id").and_then(Value::as_str).unwrap_or(DEVICE_ID_DEFAULT),
            "purpose": params.get("purpose").and_then(Value::as_str).unwrap_or("normal"),
            "group_did": params.get("group_did").cloned(),
            "suite": params.get("suite").and_then(Value::as_str).unwrap_or(MTI_SUITE),
            "mls_key_package_b64u": artifact["value_b64u"],
            "did_wba_binding": params.get("did_wba_binding").cloned().unwrap_or_else(|| json!({
                "agent_did": owner,
                "verification_method": format!("{}#key-1", owner),
                "leaf_signature_key_b64u": artifact["digest_b64u"],
                "issued_at": "2026-01-01T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
                "non_cryptographic": true,
                "artifact_mode": CONTRACT_ARTIFACT_MODE
            })),
            "non_cryptographic": true,
            "artifact_mode": CONTRACT_ARTIFACT_MODE
        },
        "non_cryptographic": true,
        "artifact_mode": CONTRACT_ARTIFACT_MODE
    }))
}

fn contract_group_create(params: &Value) -> Result<Value, Value> {
    let group_did = required(params, "group_did")?;
    let artifact = artifact("group-create", params)?;
    Ok(json!({
        "group_did": group_did,
        "crypto_group_id_b64u": artifact["digest_b64u"],
        "epoch": "0",
        "epoch_authenticator": artifact["value_b64u"],
        "suite": params.get("suite").and_then(Value::as_str).unwrap_or(MTI_SUITE),
        "non_cryptographic": true,
        "artifact_mode": CONTRACT_ARTIFACT_MODE
    }))
}

fn contract_group_add_member(params: &Value) -> Result<Value, Value> {
    required(params, "group_did")?;
    required(params, "member_did")?;
    let artifact = artifact("group-add-member", params)?;
    Ok(json!({
        "crypto_group_id_b64u": params.get("crypto_group_id_b64u").cloned().unwrap_or_else(|| artifact["digest_b64u"].clone()),
        "epoch": params.get("epoch").and_then(Value::as_str).unwrap_or("1"),
        "commit_b64u": artifact["value_b64u"],
        "welcome_b64u": artifact["digest_b64u"],
        "ratchet_tree_b64u": artifact["value_b64u"],
        "non_cryptographic": true,
        "artifact_mode": CONTRACT_ARTIFACT_MODE
    }))
}

fn contract_group_recover_member_prepare(params: &Value) -> Result<Value, Value> {
    required(params, "group_did")?;
    let subject = params
        .get("member_did")
        .or_else(|| params.get("target_did"))
        .or_else(|| params.pointer("/target/agent_did"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            error(
                "missing_field",
                "member_did/target.agent_did is required",
                None,
            )
        })?;
    let artifact = artifact("group-recover-member", params)?;
    Ok(json!({
        "pending_commit_id": params.get("pending_commit_id").and_then(Value::as_str).unwrap_or("pc-contract-recover"),
        "status": "pending",
        "subject_did": subject,
        "subject_status": "recovered",
        "crypto_group_id_b64u": params.get("crypto_group_id_b64u").cloned().unwrap_or_else(|| artifact["digest_b64u"].clone()),
        "from_epoch": params.get("from_epoch").and_then(Value::as_str).unwrap_or("1"),
        "epoch": params.get("epoch").and_then(Value::as_str).unwrap_or("2"),
        "to_epoch": params.get("epoch").and_then(Value::as_str).unwrap_or("2"),
        "local_epoch": params.get("from_epoch").and_then(Value::as_str).unwrap_or("1"),
        "commit_b64u": artifact["value_b64u"],
        "welcome_b64u": artifact["digest_b64u"],
        "ratchet_tree_b64u": artifact["value_b64u"],
        "epoch_authenticator": artifact["digest_b64u"],
        "non_cryptographic": true,
        "artifact_mode": CONTRACT_ARTIFACT_MODE
    }))
}

fn contract_group_update_member_prepare(params: &Value) -> Result<Value, Value> {
    required(params, "group_did")?;
    let subject = params
        .get("member_did")
        .or_else(|| params.get("target_did"))
        .or_else(|| params.pointer("/target/agent_did"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            error(
                "missing_field",
                "member_did/target.agent_did is required",
                None,
            )
        })?;
    if let Some(package) = params.get("group_key_package") {
        if package.get("purpose").and_then(Value::as_str) != Some("update") {
            return Err(error(
                "invalid_update_key_package",
                "update-member prepare requires group_key_package.purpose=update",
                None,
            ));
        }
    }
    let artifact = artifact("group-update-member", params)?;
    Ok(json!({
        "pending_commit_id": params.get("pending_commit_id").and_then(Value::as_str).unwrap_or("pc-contract-update"),
        "status": "pending",
        "command": "group update-member-prepare",
        "method": METHOD_UPDATE,
        "subject_did": subject,
        "subject_status": "updated",
        "crypto_group_id_b64u": params.get("crypto_group_id_b64u").cloned().unwrap_or_else(|| artifact["digest_b64u"].clone()),
        "from_epoch": params.get("from_epoch").and_then(Value::as_str).unwrap_or("1"),
        "epoch": params.get("epoch").and_then(Value::as_str).unwrap_or("2"),
        "to_epoch": params.get("epoch").and_then(Value::as_str).unwrap_or("2"),
        "local_epoch": params.get("from_epoch").and_then(Value::as_str).unwrap_or("1"),
        "commit_b64u": artifact["value_b64u"],
        "welcome_b64u": artifact["digest_b64u"],
        "ratchet_tree_b64u": artifact["value_b64u"],
        "epoch_authenticator": artifact["digest_b64u"],
        "non_cryptographic": true,
        "artifact_mode": CONTRACT_ARTIFACT_MODE
    }))
}

fn contract_group_remove_member(params: &Value) -> Result<Value, Value> {
    required(params, "group_did")?;
    let subject = params
        .get("subject_did")
        .or_else(|| params.get("member_did"))
        .and_then(Value::as_str)
        .ok_or_else(|| error("missing_field", "subject_did/member_did is required", None))?;
    let artifact = artifact("group-remove-member", params)?;
    Ok(json!({
        "pending_commit_id": params.get("pending_commit_id").and_then(Value::as_str).unwrap_or("pc-contract-remove"),
        "status": "pending",
        "subject_did": subject,
        "subject_status": "removed",
        "crypto_group_id_b64u": params.get("crypto_group_id_b64u").cloned().unwrap_or_else(|| artifact["digest_b64u"].clone()),
        "from_epoch": params.get("from_epoch").and_then(Value::as_str).unwrap_or("1"),
        "epoch": params.get("epoch").and_then(Value::as_str).unwrap_or("2"),
        "to_epoch": params.get("epoch").and_then(Value::as_str).unwrap_or("2"),
        "local_epoch": params.get("from_epoch").and_then(Value::as_str).unwrap_or("1"),
        "commit_b64u": artifact["value_b64u"],
        "ratchet_tree_b64u": artifact["digest_b64u"],
        "epoch_authenticator": artifact["digest_b64u"],
        "non_cryptographic": true,
        "artifact_mode": CONTRACT_ARTIFACT_MODE
    }))
}

fn contract_group_leave(params: &Value) -> Result<Value, Value> {
    required(params, "group_did")?;
    let subject = params
        .get("actor_did")
        .or_else(|| params.get("agent_did"))
        .and_then(Value::as_str)
        .ok_or_else(|| error("missing_field", "actor_did/agent_did is required", None))?;
    let artifact = artifact("group-leave", params)?;
    Ok(json!({
        "pending_commit_id": params.get("pending_commit_id").and_then(Value::as_str).unwrap_or("pc-contract-leave"),
        "status": "pending",
        "subject_did": subject,
        "subject_status": "left",
        "crypto_group_id_b64u": params.get("crypto_group_id_b64u").cloned().unwrap_or_else(|| artifact["digest_b64u"].clone()),
        "from_epoch": params.get("from_epoch").and_then(Value::as_str).unwrap_or("1"),
        "epoch": params.get("epoch").and_then(Value::as_str).unwrap_or("2"),
        "to_epoch": params.get("epoch").and_then(Value::as_str).unwrap_or("2"),
        "local_epoch": params.get("from_epoch").and_then(Value::as_str).unwrap_or("1"),
        "commit_b64u": artifact["value_b64u"],
        "ratchet_tree_b64u": Value::Null,
        "epoch_authenticator": Value::Null,
        "non_cryptographic": true,
        "artifact_mode": CONTRACT_ARTIFACT_MODE
    }))
}

fn contract_group_commit_finalize(params: &Value) -> Result<Value, Value> {
    let pending_commit_id = required(params, "pending_commit_id")?;
    Ok(json!({
        "pending_commit_id": pending_commit_id,
        "status": "finalized",
        "non_cryptographic": true,
        "artifact_mode": CONTRACT_ARTIFACT_MODE
    }))
}

fn contract_group_commit_abort(params: &Value) -> Result<Value, Value> {
    let pending_commit_id = required(params, "pending_commit_id")?;
    Ok(json!({
        "pending_commit_id": pending_commit_id,
        "status": "aborted",
        "non_cryptographic": true,
        "artifact_mode": CONTRACT_ARTIFACT_MODE
    }))
}

fn contract_commit_process(params: &Value) -> Result<Value, Value> {
    required(params, "commit_b64u")?;
    let artifact = artifact("commit-process", params)?;
    Ok(json!({
        "status": params.get("status").and_then(Value::as_str).unwrap_or("active"),
        "self_removed": params.get("self_removed").and_then(Value::as_bool).unwrap_or(false),
        "epoch": params.get("epoch").and_then(Value::as_str).unwrap_or("2"),
        "epoch_authenticator": artifact["digest_b64u"],
        "ratchet_tree_b64u": artifact["value_b64u"],
        "non_cryptographic": true,
        "artifact_mode": CONTRACT_ARTIFACT_MODE
    }))
}

fn contract_welcome_process(params: &Value) -> Result<Value, Value> {
    required(params, "welcome_b64u")?;
    required(params, "ratchet_tree_b64u")?;
    let artifact = artifact("welcome-process", params)?;
    Ok(json!({
        "crypto_group_id_b64u": params.get("crypto_group_id_b64u").cloned().unwrap_or_else(|| artifact["digest_b64u"].clone()),
        "epoch": params.get("epoch").and_then(Value::as_str).unwrap_or("1"),
        "status": "active",
        "non_cryptographic": true,
        "artifact_mode": CONTRACT_ARTIFACT_MODE
    }))
}

fn contract_message_encrypt(params: &Value) -> Result<Value, Value> {
    let group_state_ref = params
        .get("group_state_ref")
        .cloned()
        .ok_or_else(|| error("missing_field", "group_state_ref is required", None))?;
    let artifact = artifact("message-encrypt", params)?;
    Ok(json!({
        "group_cipher_object": {
            "crypto_group_id_b64u": params.get("crypto_group_id_b64u").cloned().unwrap_or_else(|| artifact["digest_b64u"].clone()),
            "epoch": params.get("epoch").and_then(Value::as_str).unwrap_or("0"),
            "private_message_b64u": artifact["value_b64u"],
            "group_state_ref": group_state_ref,
            "epoch_authenticator": artifact["digest_b64u"],
            "non_cryptographic": true,
            "artifact_mode": CONTRACT_ARTIFACT_MODE
        },
        "non_cryptographic": true,
        "artifact_mode": CONTRACT_ARTIFACT_MODE
    }))
}

fn contract_message_decrypt(params: &Value) -> Result<Value, Value> {
    required(params, "private_message_b64u")?;
    Ok(json!({
        "application_plaintext": params.get("application_plaintext").cloned().unwrap_or_else(|| json!({
            "application_content_type": "text/plain",
            "text": "contract-test plaintext"
        })),
        "non_cryptographic": true,
        "artifact_mode": CONTRACT_ARTIFACT_MODE
    }))
}

fn contract_group_status(params: &Value, data_dir: Option<&PathBuf>) -> Result<Value, Value> {
    let operations_logged = data_dir
        .and_then(|dir| contract_operation_log_len(dir).ok())
        .unwrap_or_default();
    Ok(json!({
        "group_did": params.get("group_did").cloned().unwrap_or(Value::Null),
        "data_dir": data_dir.map(|path| path.to_string_lossy().to_string()),
        "operations_logged": operations_logged,
        "status": "contract-test-ready",
        "non_cryptographic": true,
        "artifact_mode": CONTRACT_ARTIFACT_MODE
    }))
}

fn append_contract_operation_log(
    data_dir: &PathBuf,
    request_id: &str,
    command: &str,
) -> Result<(), Value> {
    fs::create_dir_all(data_dir)
        .map_err(|e| error("state_write_failed", &format!("create data dir: {e}"), None))?;
    let state_path = data_dir.join("contract-operations.jsonl");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default();
    let record = json!({
        "request_id": request_id,
        "command": command,
        "created_at_unix": now,
        "non_cryptographic": true,
        "artifact_mode": CONTRACT_ARTIFACT_MODE,
    });
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&state_path)
        .map_err(|e| {
            error(
                "state_write_failed",
                &format!("open operation log: {e}"),
                None,
            )
        })?;
    writeln!(
        file,
        "{}",
        serde_json::to_string(&record).map_err(|e| error(
            "state_write_failed",
            &format!("encode operation log: {e}"),
            None
        ))?
    )
    .map_err(|e| {
        error(
            "state_write_failed",
            &format!("write operation log: {e}"),
            None,
        )
    })?;
    Ok(())
}

fn contract_operation_log_len(data_dir: &PathBuf) -> io::Result<usize> {
    let state_path = data_dir.join("contract-operations.jsonl");
    let contents = fs::read_to_string(state_path)?;
    Ok(contents.lines().count())
}

fn artifact(purpose: &str, params: &Value) -> Result<Value, Value> {
    let artifact = deterministic_contract_artifact(purpose, params, true)
        .map_err(|e| error("artifact_failed", &e.to_string(), None))?;
    serde_json::to_value(artifact).map_err(|e| error("artifact_failed", &e.to_string(), None))
}

fn required<'a>(value: &'a Value, field: &'static str) -> Result<&'a str, Value> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| error("missing_field", &format!("{field} is required"), None))
}

fn sqlite_error(code: &str, err: rusqlite::Error, request_id: &str) -> Value {
    error(code, &err.to_string(), Some(request_id.to_owned()))
}

fn error(code: &str, message: &str, request_id: Option<String>) -> Value {
    error_response(code, message, request_id)
}
