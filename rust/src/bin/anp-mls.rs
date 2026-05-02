use anp::group_e2ee::{deterministic_contract_artifact, CONTRACT_ARTIFACT_MODE, MTI_SUITE};
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

const API_VERSION: &str = "anp-mls/v1";

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
    let enabled = req
        .get("contract_test_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || std::env::var("ANP_MLS_CONTRACT_TEST").ok().as_deref() == Some("1");
    if !enabled {
        return Err(error(
            "contract_test_disabled",
            "anp-mls contract-test artifacts require contract_test_enabled=true or ANP_MLS_CONTRACT_TEST=1",
            Some(request_id),
        ));
    }
    let params = req.get("params").cloned().unwrap_or_else(|| json!({}));
    let result = match command.as_str() {
        "key-package generate" => key_package(&params)?,
        "group create" => group_create(&params)?,
        "group add-member" => group_add_member(&params)?,
        "welcome process" => welcome_process(&params)?,
        "message encrypt" => message_encrypt(&params)?,
        "message decrypt" => message_decrypt(&params)?,
        "group restore" | "group status" => group_status(&params, invocation.data_dir.as_ref())?,
        _ => {
            return Err(error(
                "unsupported_command",
                &format!("unsupported command: {command}"),
                Some(request_id),
            ))
        }
    };
    if let Some(data_dir) = invocation.data_dir.as_ref() {
        append_operation_log(data_dir, &request_id, &command)?;
    }
    Ok(json!({
        "ok": true,
        "api_version": API_VERSION,
        "request_id": request_id,
        "result": result,
    }))
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

fn key_package(params: &Value) -> Result<Value, Value> {
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
            "suite": params.get("suite").and_then(Value::as_str).unwrap_or(MTI_SUITE),
            "mls_key_package_b64u": artifact["value_b64u"],
            "did_wba_binding": params.get("did_wba_binding").cloned().unwrap_or_else(|| json!({
                "agent_did": owner,
                "verification_method": format!("{}#key-1", owner),
                "leaf_signature_key_b64u": artifact["digest_b64u"],
                "issued_at": "2026-01-01T00:00:00Z",
                "expires_at": "2027-01-01T00:00:00Z",
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

fn group_create(params: &Value) -> Result<Value, Value> {
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

fn group_add_member(params: &Value) -> Result<Value, Value> {
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

fn welcome_process(params: &Value) -> Result<Value, Value> {
    required(params, "welcome_b64u")?;
    let artifact = artifact("welcome-process", params)?;
    Ok(json!({
        "crypto_group_id_b64u": params.get("crypto_group_id_b64u").cloned().unwrap_or_else(|| artifact["digest_b64u"].clone()),
        "epoch": params.get("epoch").and_then(Value::as_str).unwrap_or("1"),
        "status": "active",
        "non_cryptographic": true,
        "artifact_mode": CONTRACT_ARTIFACT_MODE
    }))
}

fn message_encrypt(params: &Value) -> Result<Value, Value> {
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

fn message_decrypt(params: &Value) -> Result<Value, Value> {
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

fn group_status(params: &Value, data_dir: Option<&PathBuf>) -> Result<Value, Value> {
    let operations_logged = data_dir
        .and_then(|dir| operation_log_len(dir).ok())
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

fn append_operation_log(data_dir: &PathBuf, request_id: &str, command: &str) -> Result<(), Value> {
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

fn operation_log_len(data_dir: &PathBuf) -> io::Result<usize> {
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

fn error(code: &str, message: &str, request_id: Option<String>) -> Value {
    json!({
        "ok": false,
        "api_version": API_VERSION,
        "request_id": request_id,
        "error": {"code": code, "message": message}
    })
}
