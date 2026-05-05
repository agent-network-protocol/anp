//! [INPUT] One-shot `anp-mls` JSON requests on stdin plus CLI domain/action and optional `--data-dir`; `system version` is the no-state compatibility probe.
//! [OUTPUT] A single JSON response on stdout; real mode persists OpenMLS state, pending membership/recovery/update commits, local active/inactive bindings, and contract-test mode emits explicit non-cryptographic fixtures.
//! [POS] Boundary binary between Go/product clients and Rust MLS state; keep private MLS material local to `--data-dir` while exposing opaque P6 remove/leave/recovery/update/commit artifacts.

use anp::group_e2ee::{
    build_send_aad, deterministic_contract_artifact, CONTRACT_ARTIFACT_MODE, METHOD_UPDATE,
    MTI_SUITE, SECURITY_PROFILE,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use fs2::FileExt;
use openmls::prelude::{
    tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize},
    *,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Connection as MlsConnection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const API_VERSION: &str = "anp-mls/v1";
const DEVICE_ID_DEFAULT: &str = "default";
const BINARY_NAME: &str = "anp-mls";
const GROUP_CIPHER_CONTENT_TYPE: &str = "application/anp-group-cipher+json";
const SUPPORTED_COMMANDS: &[&str] = &[
    "system version",
    "key-package generate",
    "group create",
    "group add-member",
    "group update-member-prepare",
    "group update-member-finalize",
    "group update-member-abort",
    "group recover-member-prepare",
    "group recover-member-finalize",
    "group recover-member-abort",
    "group remove-member",
    "group leave",
    "group commit-finalize",
    "group commit-abort",
    "welcome process",
    "commit process",
    "notice process",
    "message encrypt",
    "message decrypt",
    "group restore",
    "group status",
];

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
        return Ok(json!({
            "ok": true,
            "api_version": API_VERSION,
            "request_id": request_id,
            "result": system_version(),
        }));
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
    Ok(json!({
        "ok": true,
        "api_version": API_VERSION,
        "request_id": request_id,
        "result": result,
    }))
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
    let _lock = StateLock::try_acquire(data_dir, request_id)?;
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
        let mut provider = sqlite_mls_provider(&db_path, request_id)?;
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
    let response = json!({
        "ok": true,
        "api_version": API_VERSION,
        "request_id": request_id,
        "result": result,
    });
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

fn system_version() -> Value {
    json!({
        "api_version": API_VERSION,
        "binary_name": BINARY_NAME,
        "binary_version": env!("CARGO_PKG_VERSION"),
        "build_version": env!("CARGO_PKG_VERSION"),
        "supported_commands": SUPPORTED_COMMANDS,
    })
}

fn response_for_operation_log(command: &str, response: &Value) -> Value {
    let mut stored = response.clone();
    if command == "message decrypt" {
        if let Some(result) = stored.get_mut("result").and_then(Value::as_object_mut) {
            result.remove("application_plaintext");
            result.insert(
                "plaintext_redacted".to_owned(),
                json!({"redacted": true, "reason": "plaintext is never persisted in operations"}),
            );
        }
    }
    stored
}

struct StateLock {
    file: File,
}

impl StateLock {
    fn try_acquire(data_dir: &Path, request_id: &str) -> Result<Self, Value> {
        let lock_path = data_dir.join("state.lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|e| {
                error(
                    "state_lock_failed",
                    &format!("open state lock: {e}"),
                    Some(request_id.to_owned()),
                )
            })?;
        file.try_lock_exclusive().map_err(|e| {
            error(
                "state_locked",
                &format!("state is locked by another anp-mls operation: {e}"),
                Some(request_id.to_owned()),
            )
        })?;
        Ok(Self { file })
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[derive(Default)]
struct JsonCodec;

impl openmls_sqlite_storage::Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

struct SqliteMlsProvider {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, MlsConnection>,
}

impl OpenMlsProvider for SqliteMlsProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, MlsConnection>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

fn sqlite_mls_provider(db_path: &Path, request_id: &str) -> Result<SqliteMlsProvider, Value> {
    let connection = MlsConnection::open(db_path)
        .map_err(|e| sqlite_error("state_open_failed", e, request_id))?;
    let mut storage = SqliteStorageProvider::<JsonCodec, MlsConnection>::new(connection);
    storage.run_migrations().map_err(|e| {
        error(
            "state_migration_failed",
            &format!("OpenMLS SQLite migrations failed: {e}"),
            Some(request_id.to_owned()),
        )
    })?;
    Ok(SqliteMlsProvider {
        crypto: RustCrypto::default(),
        storage,
    })
}

fn init_app_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
         );
         INSERT OR IGNORE INTO schema_migrations(version) VALUES (1);
         CREATE TABLE IF NOT EXISTS operations (
            operation_id TEXT PRIMARY KEY,
            command TEXT NOT NULL,
            input_digest TEXT NOT NULL,
            response_json TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
         );
         CREATE TABLE IF NOT EXISTS agents (
            agent_did TEXT NOT NULL,
            device_id TEXT NOT NULL,
            signature_public_key BLOB NOT NULL,
            signature_scheme TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(agent_did, device_id)
         );
         CREATE TABLE IF NOT EXISTS key_packages (
            agent_did TEXT NOT NULL,
            device_id TEXT NOT NULL,
            key_package_id TEXT PRIMARY KEY,
            public_json TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            consumed_at TEXT
         );
         CREATE TABLE IF NOT EXISTS group_bindings (
            agent_did TEXT NOT NULL,
            device_id TEXT NOT NULL,
            group_did TEXT NOT NULL,
            crypto_group_id_b64u TEXT NOT NULL,
            openmls_group_id_b64u TEXT NOT NULL,
            epoch INTEGER NOT NULL,
            role TEXT NOT NULL,
            status TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(agent_did, device_id, group_did)
         );
         CREATE TABLE IF NOT EXISTS pending_commits (
            pending_commit_id TEXT PRIMARY KEY,
            operation_id TEXT NOT NULL,
            command TEXT NOT NULL,
            agent_did TEXT NOT NULL,
            device_id TEXT NOT NULL,
            group_did TEXT NOT NULL,
            crypto_group_id_b64u TEXT NOT NULL,
            subject_did TEXT NOT NULL,
            subject_status TEXT NOT NULL,
            from_epoch INTEGER NOT NULL,
            to_epoch INTEGER NOT NULL,
            commit_b64u TEXT NOT NULL,
            ratchet_tree_b64u TEXT,
            group_info_b64u TEXT,
            epoch_authenticator_b64u TEXT,
            status TEXT NOT NULL,
            response_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
         );
         CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_commits_operation_id
            ON pending_commits(operation_id);",
    )
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

fn real_key_package(
    provider: &mut SqliteMlsProvider,
    conn: &Connection,
    params: &Value,
    request_id: &str,
) -> Result<Value, Value> {
    let owner = agent_did(params)?;
    let device_id = device_id(params);
    let key_package_id = params
        .get("key_package_id")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| {
            format!(
                "kp-{}",
                short_digest(
                    &json!({"owner": owner, "device_id": device_id, "request_id": request_id})
                )
            )
        });
    let (credential, signer) = ensure_agent(provider, conn, owner, device_id, request_id)?;
    let key_package_bundle = KeyPackage::builder()
        .key_package_extensions(Extensions::default())
        .build(ciphersuite(), provider, &signer, credential)
        .map_err(|e| mls_error("key_package_failed", e, request_id))?;
    let public_bytes = key_package_bundle
        .key_package()
        .tls_serialize_detached()
        .map_err(|e| mls_error("key_package_encode_failed", e, request_id))?;
    let public_b64u = encode_b64u(&public_bytes);
    let purpose = params
        .get("purpose")
        .and_then(Value::as_str)
        .or_else(|| {
            params
                .get("recovery")
                .and_then(Value::as_bool)
                .filter(|enabled| *enabled)
                .map(|_| "recovery")
        })
        .unwrap_or("normal");
    let public_json = json!({
        "key_package_id": key_package_id,
        "owner_did": owner,
        "device_id": device_id,
        "purpose": purpose,
        "group_did": params.get("group_did").cloned(),
        "suite": MTI_SUITE,
        "mls_key_package_b64u": public_b64u,
        "did_wba_binding": did_wba_binding(owner, device_id, &signer),
    });
    conn.execute(
        "INSERT OR REPLACE INTO key_packages(agent_did, device_id, key_package_id, public_json, status)
         VALUES (?1, ?2, ?3, ?4, 'published')",
        params![owner, device_id, key_package_id, public_json.to_string()],
    )
    .map_err(|e| sqlite_error("state_write_failed", e, request_id))?;
    Ok(json!({
        "group_key_package": public_json,
        "private_ref": format!("sqlite://openmls/key_packages/{key_package_id}"),
    }))
}

fn real_group_create(
    provider: &mut SqliteMlsProvider,
    conn: &Connection,
    params: &Value,
    request_id: &str,
) -> Result<Value, Value> {
    let group_did = required(params, "group_did")?;
    let creator = agent_did(params)?;
    let device_id = device_id(params);
    let (credential, signer) = ensure_agent(provider, conn, creator, device_id, request_id)?;
    let openmls_group_id = GroupId::from_slice(group_did.as_bytes());
    let config = group_create_config();
    let group = MlsGroup::new_with_group_id(
        provider,
        &signer,
        &config,
        openmls_group_id.clone(),
        credential,
    )
    .map_err(|e| mls_error("group_create_failed", e, request_id))?;
    upsert_binding(
        conn,
        creator,
        device_id,
        group_did,
        &openmls_group_id,
        group.epoch().as_u64(),
        "creator",
        request_id,
    )?;
    Ok(json!({
        "group_did": group_did,
        "crypto_group_id_b64u": encode_b64u(openmls_group_id.as_slice()),
        "openmls_group_id_b64u": encode_b64u(openmls_group_id.as_slice()),
        "epoch": group.epoch().as_u64().to_string(),
        "epoch_authenticator": encode_b64u(group.epoch_authenticator().as_slice()),
        "suite": MTI_SUITE,
        "group_state_ref": {"group_did": group_did, "group_state_version": group.epoch().as_u64().to_string()},
    }))
}

fn real_group_add_member(
    provider: &mut SqliteMlsProvider,
    conn: &Connection,
    params: &Value,
    request_id: &str,
) -> Result<Value, Value> {
    let group_did = required(params, "group_did")?;
    let member_did = required(params, "member_did")?;
    let actor = params
        .get("actor_did")
        .or_else(|| params.get("owner_did"))
        .or_else(|| params.get("agent_did"))
        .and_then(Value::as_str)
        .ok_or_else(|| error("missing_field", "actor_did or owner_did is required", None))?;
    let device_id = device_id(params);
    let binding = binding(conn, actor, device_id, group_did, request_id)?;
    let mut group = load_group(provider, &binding.openmls_group_id, request_id)?;
    validate_loaded_group_matches_binding(&binding, &group, request_id)?;
    let signer = load_signer(provider, conn, actor, device_id, request_id)?;
    let kp_b64u = params
        .pointer("/group_key_package/mls_key_package_b64u")
        .or_else(|| params.get("mls_key_package_b64u"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            error(
                "missing_field",
                "group_key_package.mls_key_package_b64u is required",
                None,
            )
        })?;
    let key_package_bytes = decode_b64u(kp_b64u, request_id)?;
    let mut key_package_reader = key_package_bytes.as_slice();
    let key_package_in = KeyPackageIn::tls_deserialize(&mut key_package_reader)
        .map_err(|e| mls_error("key_package_decode_failed", e, request_id))?;
    if !key_package_reader.is_empty() {
        return Err(error(
            "key_package_decode_failed",
            "trailing bytes after KeyPackage",
            Some(request_id.to_owned()),
        ));
    }
    let key_package = key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| mls_error("key_package_validate_failed", e, request_id))?;
    validate_key_package_did_wba_binding(params, member_did, &key_package, request_id)?;
    let (commit, welcome, _group_info) = group
        .add_members(provider, &signer, core::slice::from_ref(&key_package))
        .map_err(|e| mls_error("group_add_member_failed", e, request_id))?;
    group
        .merge_pending_commit(provider)
        .map_err(|e| mls_error("group_add_merge_failed", e, request_id))?;
    upsert_binding(
        conn,
        actor,
        device_id,
        group_did,
        &binding.openmls_group_id,
        group.epoch().as_u64(),
        &binding.role,
        request_id,
    )?;
    let commit_b64u = encode_b64u(
        &commit
            .tls_serialize_detached()
            .map_err(|e| mls_error("commit_encode_failed", e, request_id))?,
    );
    let welcome_body = match welcome.body() {
        MlsMessageBodyOut::Welcome(welcome) => welcome.clone(),
        _ => {
            return Err(error(
                "welcome_encode_failed",
                "OpenMLS add-member did not return a Welcome message",
                Some(request_id.to_owned()),
            ))
        }
    };
    let welcome_b64u = encode_b64u(
        &welcome_body
            .tls_serialize_detached()
            .map_err(|e| mls_error("welcome_encode_failed", e, request_id))?,
    );
    let ratchet_tree: RatchetTreeIn = group.export_ratchet_tree().into();
    let ratchet_tree_b64u = encode_b64u(
        &ratchet_tree
            .tls_serialize_detached()
            .map_err(|e| mls_error("ratchet_tree_encode_failed", e, request_id))?,
    );
    Ok(json!({
        "crypto_group_id_b64u": encode_b64u(binding.openmls_group_id.as_slice()),
        "openmls_group_id_b64u": encode_b64u(binding.openmls_group_id.as_slice()),
        "epoch": group.epoch().as_u64().to_string(),
        "commit_b64u": commit_b64u,
        "welcome_b64u": welcome_b64u,
        "ratchet_tree_b64u": ratchet_tree_b64u,
        "member_did": member_did,
        "epoch_authenticator": encode_b64u(group.epoch_authenticator().as_slice()),
    }))
}

fn real_group_update_member_prepare(
    provider: &mut SqliteMlsProvider,
    conn: &Connection,
    params: &Value,
    operation_id: &str,
    request_id: &str,
) -> Result<Value, Value> {
    let group_did = required(params, "group_did")?;
    let member_did = params
        .get("member_did")
        .or_else(|| params.get("target_did"))
        .or_else(|| params.pointer("/target/agent_did"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            error(
                "missing_field",
                "member_did/target.agent_did is required",
                None,
            )
        })?;
    let actor = params
        .get("actor_did")
        .or_else(|| params.get("owner_did"))
        .or_else(|| params.get("agent_did"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| error("missing_field", "actor_did or owner_did is required", None))?;
    let device_id = device_id(params);
    let target_device_id = params
        .get("target_device_id")
        .or_else(|| params.get("member_device_id"))
        .or_else(|| params.pointer("/target/device_id"))
        .or_else(|| params.pointer("/group_key_package/device_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEVICE_ID_DEFAULT);
    validate_update_key_package_context(params, group_did, member_did, target_device_id)?;
    let binding = binding(conn, actor, device_id, group_did, request_id)?;
    let mut group = load_group(provider, &binding.openmls_group_id, request_id)?;
    if let Some(group_state_ref) = params.get("group_state_ref") {
        validate_group_binding_claims(&binding, group_state_ref, request_id)?;
    }
    validate_loaded_group_matches_binding(&binding, &group, request_id)?;
    let target_leaf = member_leaf_index_by_did(&group, member_did).ok_or_else(|| {
        error(
            "member_not_found",
            "target member is not an active MLS leaf in the local group",
            Some(request_id.to_owned()),
        )
    })?;
    let signer = load_signer(provider, conn, actor, device_id, request_id)?;
    let kp_b64u = params
        .pointer("/group_key_package/mls_key_package_b64u")
        .or_else(|| params.get("mls_key_package_b64u"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            error(
                "missing_field",
                "group_key_package.mls_key_package_b64u is required",
                None,
            )
        })?;
    let key_package_bytes = decode_b64u(kp_b64u, request_id)?;
    let mut key_package_reader = key_package_bytes.as_slice();
    let key_package_in = KeyPackageIn::tls_deserialize(&mut key_package_reader)
        .map_err(|e| mls_error("key_package_decode_failed", e, request_id))?;
    if !key_package_reader.is_empty() {
        return Err(error(
            "key_package_decode_failed",
            "trailing bytes after KeyPackage",
            Some(request_id.to_owned()),
        ));
    }
    let key_package = key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| mls_error("key_package_validate_failed", e, request_id))?;
    validate_key_package_did_wba_binding(params, member_did, &key_package, request_id)?;
    let original_tree = group.export_ratchet_tree();
    let update_messages = group
        .swap_members(
            provider,
            &signer,
            &[target_leaf],
            core::slice::from_ref(&key_package),
        )
        .map_err(|e| mls_error("group_update_member_prepare_failed", e, request_id))?;
    let pending = group.pending_commit().ok_or_else(|| {
        error(
            "pending_commit_missing",
            "OpenMLS did not persist a pending update commit",
            Some(request_id.to_owned()),
        )
    })?;
    let to_epoch = pending.epoch().as_u64();
    let epoch_authenticator_b64u = pending
        .epoch_authenticator()
        .map(|value| encode_b64u(value.as_slice()));
    let ratchet_tree_b64u = pending
        .export_ratchet_tree(provider.crypto(), original_tree)
        .map_err(|e| mls_error("ratchet_tree_encode_failed", e, request_id))?
        .map(|tree| {
            let tree_in: RatchetTreeIn = tree.into();
            tree_in
                .tls_serialize_detached()
                .map(|bytes| encode_b64u(&bytes))
                .map_err(|e| mls_error("ratchet_tree_encode_failed", e, request_id))
        })
        .transpose()?;
    let commit_b64u = encode_b64u(
        &update_messages
            .commit
            .tls_serialize_detached()
            .map_err(|e| mls_error("commit_encode_failed", e, request_id))?,
    );
    let welcome_body = match update_messages.welcome.body() {
        MlsMessageBodyOut::Welcome(welcome) => welcome.clone(),
        _ => {
            return Err(error(
                "welcome_encode_failed",
                "OpenMLS update-member prepare did not return a Welcome message",
                Some(request_id.to_owned()),
            ))
        }
    };
    let welcome_b64u = encode_b64u(
        &welcome_body
            .tls_serialize_detached()
            .map_err(|e| mls_error("welcome_encode_failed", e, request_id))?,
    );
    let pending_commit_id = params
        .get("pending_commit_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            format!(
                "pc-{}",
                short_digest(&json!({"operation_id": operation_id}))
            )
        });
    let result = membership_prepare_response(MembershipPrepare {
        pending_commit_id: &pending_commit_id,
        operation_id,
        command: "group update-member-prepare",
        actor_did: actor,
        subject_did: member_did,
        subject_status: "updated",
        group_did,
        crypto_group_id_b64u: &encode_b64u(binding.openmls_group_id.as_slice()),
        from_epoch: binding.epoch,
        to_epoch,
        commit_b64u: &commit_b64u,
        welcome_b64u: Some(&welcome_b64u),
        ratchet_tree_b64u: ratchet_tree_b64u.as_deref(),
        group_info_b64u: None,
        epoch_authenticator_b64u: epoch_authenticator_b64u.as_deref(),
    });
    insert_pending_commit(
        conn,
        &pending_commit_id,
        operation_id,
        "group update-member-prepare",
        actor,
        device_id,
        group_did,
        member_did,
        "updated",
        binding.epoch,
        to_epoch,
        &commit_b64u,
        ratchet_tree_b64u.as_deref(),
        None,
        epoch_authenticator_b64u.as_deref(),
        &result,
        request_id,
    )?;
    Ok(result)
}

fn real_group_recover_member_prepare(
    provider: &mut SqliteMlsProvider,
    conn: &Connection,
    params: &Value,
    operation_id: &str,
    request_id: &str,
) -> Result<Value, Value> {
    let group_did = required(params, "group_did")?;
    let member_did = params
        .get("member_did")
        .or_else(|| params.get("target_did"))
        .or_else(|| params.pointer("/target/agent_did"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            error(
                "missing_field",
                "member_did/target.agent_did is required",
                None,
            )
        })?;
    let actor = params
        .get("actor_did")
        .or_else(|| params.get("owner_did"))
        .or_else(|| params.get("agent_did"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| error("missing_field", "actor_did or owner_did is required", None))?;
    let device_id = device_id(params);
    let target_device_id = params
        .get("target_device_id")
        .or_else(|| params.get("member_device_id"))
        .or_else(|| params.pointer("/target/device_id"))
        .or_else(|| params.pointer("/group_key_package/device_id"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEVICE_ID_DEFAULT);
    validate_recovery_key_package_context(params, group_did, member_did, target_device_id)?;
    let binding = binding(conn, actor, device_id, group_did, request_id)?;
    let mut group = load_group(provider, &binding.openmls_group_id, request_id)?;
    if let Some(group_state_ref) = params.get("group_state_ref") {
        validate_group_binding_claims(&binding, group_state_ref, request_id)?;
    }
    validate_loaded_group_matches_binding(&binding, &group, request_id)?;
    let signer = load_signer(provider, conn, actor, device_id, request_id)?;
    let kp_b64u = params
        .pointer("/group_key_package/mls_key_package_b64u")
        .or_else(|| params.get("mls_key_package_b64u"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            error(
                "missing_field",
                "group_key_package.mls_key_package_b64u is required",
                None,
            )
        })?;
    let key_package_bytes = decode_b64u(kp_b64u, request_id)?;
    let mut key_package_reader = key_package_bytes.as_slice();
    let key_package_in = KeyPackageIn::tls_deserialize(&mut key_package_reader)
        .map_err(|e| mls_error("key_package_decode_failed", e, request_id))?;
    if !key_package_reader.is_empty() {
        return Err(error(
            "key_package_decode_failed",
            "trailing bytes after KeyPackage",
            Some(request_id.to_owned()),
        ));
    }
    let key_package = key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| mls_error("key_package_validate_failed", e, request_id))?;
    validate_key_package_did_wba_binding(params, member_did, &key_package, request_id)?;
    let original_tree = group.export_ratchet_tree();
    let (commit, welcome, _group_info) = group
        .add_members(provider, &signer, core::slice::from_ref(&key_package))
        .map_err(|e| mls_error("group_recover_member_prepare_failed", e, request_id))?;
    let pending = group.pending_commit().ok_or_else(|| {
        error(
            "pending_commit_missing",
            "OpenMLS did not persist a pending recovery commit",
            Some(request_id.to_owned()),
        )
    })?;
    let to_epoch = pending.epoch().as_u64();
    let epoch_authenticator_b64u = pending
        .epoch_authenticator()
        .map(|value| encode_b64u(value.as_slice()));
    let ratchet_tree_b64u = pending
        .export_ratchet_tree(provider.crypto(), original_tree)
        .map_err(|e| mls_error("ratchet_tree_encode_failed", e, request_id))?
        .map(|tree| {
            let tree_in: RatchetTreeIn = tree.into();
            tree_in
                .tls_serialize_detached()
                .map(|bytes| encode_b64u(&bytes))
                .map_err(|e| mls_error("ratchet_tree_encode_failed", e, request_id))
        })
        .transpose()?;
    let commit_b64u = encode_b64u(
        &commit
            .tls_serialize_detached()
            .map_err(|e| mls_error("commit_encode_failed", e, request_id))?,
    );
    let welcome_body = match welcome.body() {
        MlsMessageBodyOut::Welcome(welcome) => welcome.clone(),
        _ => {
            return Err(error(
                "welcome_encode_failed",
                "OpenMLS recover-member prepare did not return a Welcome message",
                Some(request_id.to_owned()),
            ))
        }
    };
    let welcome_b64u = encode_b64u(
        &welcome_body
            .tls_serialize_detached()
            .map_err(|e| mls_error("welcome_encode_failed", e, request_id))?,
    );
    let pending_commit_id = params
        .get("pending_commit_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            format!(
                "pc-{}",
                short_digest(&json!({"operation_id": operation_id}))
            )
        });
    let result = membership_prepare_response(MembershipPrepare {
        pending_commit_id: &pending_commit_id,
        operation_id,
        command: "group recover-member-prepare",
        actor_did: actor,
        subject_did: member_did,
        subject_status: "recovered",
        group_did,
        crypto_group_id_b64u: &encode_b64u(binding.openmls_group_id.as_slice()),
        from_epoch: binding.epoch,
        to_epoch,
        commit_b64u: &commit_b64u,
        welcome_b64u: Some(&welcome_b64u),
        ratchet_tree_b64u: ratchet_tree_b64u.as_deref(),
        group_info_b64u: None,
        epoch_authenticator_b64u: epoch_authenticator_b64u.as_deref(),
    });
    insert_pending_commit(
        conn,
        &pending_commit_id,
        operation_id,
        "group recover-member-prepare",
        actor,
        device_id,
        group_did,
        member_did,
        "recovered",
        binding.epoch,
        to_epoch,
        &commit_b64u,
        ratchet_tree_b64u.as_deref(),
        None,
        epoch_authenticator_b64u.as_deref(),
        &result,
        request_id,
    )?;
    Ok(result)
}

fn real_group_remove_member(
    provider: &mut SqliteMlsProvider,
    conn: &Connection,
    params: &Value,
    operation_id: &str,
    request_id: &str,
) -> Result<Value, Value> {
    let group_did = required(params, "group_did")?;
    let subject = params
        .get("subject_did")
        .or_else(|| params.get("member_did"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| error("missing_field", "subject_did/member_did is required", None))?;
    let actor = params
        .get("actor_did")
        .or_else(|| params.get("owner_did"))
        .or_else(|| params.get("agent_did"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| error("missing_field", "actor_did/agent_did is required", None))?;
    prepare_membership_remove(
        provider,
        conn,
        params,
        operation_id,
        request_id,
        actor,
        subject,
        group_did,
        "group remove-member",
        "removed",
    )
}

fn real_group_leave(
    provider: &mut SqliteMlsProvider,
    conn: &Connection,
    params: &Value,
    operation_id: &str,
    request_id: &str,
) -> Result<Value, Value> {
    let group_did = required(params, "group_did")?;
    let actor = params
        .get("actor_did")
        .or_else(|| params.get("agent_did"))
        .or_else(|| params.get("owner_did"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| error("missing_field", "actor_did/agent_did is required", None))?;
    let device_id = device_id(params);
    let binding = binding(conn, actor, device_id, group_did, request_id)?;
    let group = load_group(provider, &binding.openmls_group_id, request_id)?;
    if let Some(group_state_ref) = params.get("group_state_ref") {
        validate_group_binding_claims(&binding, group_state_ref, request_id)?;
    }
    validate_loaded_group_matches_binding(&binding, &group, request_id)?;
    let commit_b64u = encode_b64u(
        serde_json::to_vec(&json!({
            "artifact_type": "local-terminal-leave",
            "group_did": group_did,
            "actor_did": actor,
            "epoch": binding.epoch.to_string(),
            "protocol_limitation": "OpenMLS 0.8 rejects same-member self-remove commits; service must record leave status and remaining members advance MLS with a separate remove commit/notice."
        }))
        .map_err(|e| error("artifact_failed", &e.to_string(), Some(request_id.to_owned())))?
        .as_slice(),
    );
    let pending_commit_id = params
        .get("pending_commit_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            format!(
                "pc-{}",
                short_digest(&json!({"operation_id": operation_id}))
            )
        });
    let epoch_authenticator_b64u = encode_b64u(group.epoch_authenticator().as_slice());
    let result = membership_prepare_response(MembershipPrepare {
        pending_commit_id: &pending_commit_id,
        operation_id,
        command: "group leave",
        actor_did: actor,
        subject_did: actor,
        subject_status: "left",
        group_did,
        crypto_group_id_b64u: &encode_b64u(binding.openmls_group_id.as_slice()),
        from_epoch: binding.epoch,
        to_epoch: binding.epoch,
        commit_b64u: &commit_b64u,
        welcome_b64u: None,
        ratchet_tree_b64u: None,
        group_info_b64u: None,
        epoch_authenticator_b64u: Some(&epoch_authenticator_b64u),
    });
    let mut result = result;
    result["artifact_type"] = json!("local-terminal-leave");
    result["protocol_limitation"] = json!("OpenMLS 0.8 rejects same-member self-remove commits; local finalize marks the leaver inactive without advancing local epoch.");
    insert_pending_commit(
        conn,
        &pending_commit_id,
        operation_id,
        "group leave",
        actor,
        device_id,
        group_did,
        actor,
        "left",
        binding.epoch,
        binding.epoch,
        &commit_b64u,
        None,
        None,
        Some(&epoch_authenticator_b64u),
        &result,
        request_id,
    )?;
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn prepare_membership_remove(
    provider: &mut SqliteMlsProvider,
    conn: &Connection,
    params: &Value,
    operation_id: &str,
    request_id: &str,
    actor: &str,
    subject: &str,
    group_did: &str,
    command: &str,
    subject_status: &str,
) -> Result<Value, Value> {
    let device_id = device_id(params);
    let binding = binding(conn, actor, device_id, group_did, request_id)?;
    let mut group = load_group(provider, &binding.openmls_group_id, request_id)?;
    if let Some(group_state_ref) = params.get("group_state_ref") {
        validate_group_binding_claims(&binding, group_state_ref, request_id)?;
    }
    validate_loaded_group_matches_binding(&binding, &group, request_id)?;
    let target_leaf = member_leaf_index_by_did(&group, subject).ok_or_else(|| {
        error(
            "member_not_found",
            "subject_did/member_did is not an active MLS leaf in the local group",
            Some(request_id.to_owned()),
        )
    })?;
    let signer = load_signer(provider, conn, actor, device_id, request_id)?;
    let original_tree = group.export_ratchet_tree();
    let (commit, _welcome, group_info) = group
        .remove_members(provider, &signer, &[target_leaf])
        .map_err(|e| mls_error("group_remove_member_failed", e, request_id))?;
    let pending = group.pending_commit().ok_or_else(|| {
        error(
            "pending_commit_missing",
            "OpenMLS did not persist a pending membership commit",
            Some(request_id.to_owned()),
        )
    })?;
    let to_epoch = pending.epoch().as_u64();
    let epoch_authenticator_b64u = pending
        .epoch_authenticator()
        .map(|value| encode_b64u(value.as_slice()));
    let ratchet_tree_b64u = pending
        .export_ratchet_tree(provider.crypto(), original_tree)
        .map_err(|e| mls_error("ratchet_tree_encode_failed", e, request_id))?
        .map(|tree| {
            let tree_in: RatchetTreeIn = tree.into();
            tree_in
                .tls_serialize_detached()
                .map(|bytes| encode_b64u(&bytes))
                .map_err(|e| mls_error("ratchet_tree_encode_failed", e, request_id))
        })
        .transpose()?;
    let group_info_b64u = group_info
        .map(|value| {
            value
                .tls_serialize_detached()
                .map(|bytes| encode_b64u(&bytes))
                .map_err(|e| mls_error("group_info_encode_failed", e, request_id))
        })
        .transpose()?;
    let commit_b64u = encode_b64u(
        &commit
            .tls_serialize_detached()
            .map_err(|e| mls_error("commit_encode_failed", e, request_id))?,
    );
    let pending_commit_id = params
        .get("pending_commit_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| {
            format!(
                "pc-{}",
                short_digest(&json!({"operation_id": operation_id}))
            )
        });
    let result = membership_prepare_response(MembershipPrepare {
        pending_commit_id: &pending_commit_id,
        operation_id,
        command,
        actor_did: actor,
        subject_did: subject,
        subject_status,
        group_did,
        crypto_group_id_b64u: &encode_b64u(binding.openmls_group_id.as_slice()),
        from_epoch: binding.epoch,
        to_epoch,
        commit_b64u: &commit_b64u,
        welcome_b64u: None,
        ratchet_tree_b64u: ratchet_tree_b64u.as_deref(),
        group_info_b64u: group_info_b64u.as_deref(),
        epoch_authenticator_b64u: epoch_authenticator_b64u.as_deref(),
    });
    insert_pending_commit(
        conn,
        &pending_commit_id,
        operation_id,
        command,
        actor,
        device_id,
        group_did,
        subject,
        subject_status,
        binding.epoch,
        to_epoch,
        &commit_b64u,
        ratchet_tree_b64u.as_deref(),
        group_info_b64u.as_deref(),
        epoch_authenticator_b64u.as_deref(),
        &result,
        request_id,
    )?;
    Ok(result)
}

fn real_welcome_process(
    provider: &mut SqliteMlsProvider,
    conn: &Connection,
    params: &Value,
    request_id: &str,
) -> Result<Value, Value> {
    let agent = agent_did(params)?;
    let device_id = device_id(params);
    ensure_agent(provider, conn, agent, device_id, request_id)?;
    let group_did = required(params, "group_did")?;
    let welcome_b64u = required(params, "welcome_b64u")?;
    let ratchet_tree_b64u = required(params, "ratchet_tree_b64u")?;
    let claimed_target_epoch = welcome_target_epoch(params);
    let mut replace_existing_group = false;
    if let (Some(target_epoch), Some(existing)) = (
        claimed_target_epoch,
        active_binding(conn, agent, device_id, group_did, request_id)?,
    ) {
        if existing.epoch >= target_epoch {
            if let Some(group) = MlsGroup::load(provider.storage(), &existing.openmls_group_id)
                .map_err(|e| mls_error("group_load_failed", e, request_id))?
            {
                validate_welcome_outer_binding(
                    params,
                    group_did,
                    group.group_id(),
                    group.epoch().as_u64(),
                    request_id,
                )?;
                return Ok(json!({
                    "crypto_group_id_b64u": encode_b64u(group.group_id().as_slice()),
                    "openmls_group_id_b64u": encode_b64u(group.group_id().as_slice()),
                    "epoch": group.epoch().as_u64().to_string(),
                    "status": "active",
                    "already_processed": true,
                    "epoch_authenticator": encode_b64u(group.epoch_authenticator().as_slice()),
                }));
            }
        } else {
            replace_existing_group = true;
        }
    }
    let welcome = Welcome::tls_deserialize_exact(decode_b64u(welcome_b64u, request_id)?)
        .map_err(|e| mls_error("welcome_decode_failed", e, request_id))?;
    let ratchet_tree =
        RatchetTreeIn::tls_deserialize_exact(decode_b64u(ratchet_tree_b64u, request_id)?)
            .map_err(|e| mls_error("ratchet_tree_decode_failed", e, request_id))?;
    let join_config = group_join_config();
    let mut join_builder = StagedWelcome::build_from_welcome(provider, &join_config, welcome)
        .map_err(|e| mls_error("welcome_stage_failed", e, request_id))?
        .with_ratchet_tree(ratchet_tree);
    if replace_existing_group {
        join_builder = join_builder.replace_old_group();
    }
    let staged = join_builder
        .build()
        .map_err(|e| mls_error("welcome_stage_failed", e, request_id))?;
    let welcome_group_id = staged.group_context().group_id().clone();
    let welcome_epoch = staged.group_context().epoch().as_u64();
    validate_welcome_outer_binding(
        params,
        group_did,
        &welcome_group_id,
        welcome_epoch,
        request_id,
    )?;
    if let Some(existing) = active_binding(conn, agent, device_id, group_did, request_id)? {
        if existing.openmls_group_id == welcome_group_id {
            if existing.epoch >= welcome_epoch {
                if let Some(group) = MlsGroup::load(provider.storage(), &existing.openmls_group_id)
                    .map_err(|e| mls_error("group_load_failed", e, request_id))?
                {
                    return Ok(json!({
                        "crypto_group_id_b64u": encode_b64u(group.group_id().as_slice()),
                        "openmls_group_id_b64u": encode_b64u(group.group_id().as_slice()),
                        "epoch": group.epoch().as_u64().to_string(),
                        "status": "active",
                        "already_processed": true,
                        "epoch_authenticator": encode_b64u(group.epoch_authenticator().as_slice()),
                    }));
                }
            } else {
                delete_openmls_group_state(conn, &existing.openmls_group_id, request_id)?;
            }
        }
    }
    let group = staged
        .into_group(provider)
        .map_err(|e| mls_error("welcome_process_failed", e, request_id))?;
    let group_id = group.group_id().clone();
    upsert_binding(
        conn,
        agent,
        device_id,
        group_did,
        &group_id,
        group.epoch().as_u64(),
        "member",
        request_id,
    )?;
    Ok(json!({
        "crypto_group_id_b64u": encode_b64u(group_id.as_slice()),
        "openmls_group_id_b64u": encode_b64u(group_id.as_slice()),
        "epoch": group.epoch().as_u64().to_string(),
        "status": "active",
        "epoch_authenticator": encode_b64u(group.epoch_authenticator().as_slice()),
    }))
}

fn real_message_encrypt(
    provider: &mut SqliteMlsProvider,
    conn: &Connection,
    params: &Value,
    request_id: &str,
) -> Result<Value, Value> {
    let group_state_ref = params
        .get("group_state_ref")
        .cloned()
        .ok_or_else(|| error("missing_field", "group_state_ref is required", None))?;
    let group_did = group_state_ref
        .get("group_did")
        .and_then(Value::as_str)
        .or_else(|| params.get("group_did").and_then(Value::as_str))
        .ok_or_else(|| error("missing_field", "group_did is required", None))?;
    let sender = agent_did(params)?;
    let device_id = device_id(params);
    let binding = binding(conn, sender, device_id, group_did, request_id)?;
    let mut group = load_group(provider, &binding.openmls_group_id, request_id)?;
    validate_group_binding_claims(&binding, &group_state_ref, request_id)?;
    validate_loaded_group_matches_binding(&binding, &group, request_id)?;
    let signer = load_signer(provider, conn, sender, device_id, request_id)?;
    let plaintext = application_plaintext_bytes(params, request_id)?;
    let aad = build_message_aad(params, &binding, &group_state_ref, request_id)?;
    group.set_aad(aad.clone());
    let message = group
        .create_message(provider, &signer, &plaintext)
        .map_err(|e| mls_error("message_encrypt_failed", e, request_id))?;
    let private_message_b64u = encode_b64u(
        &message
            .tls_serialize_detached()
            .map_err(|e| mls_error("message_encode_failed", e, request_id))?,
    );
    upsert_binding(
        conn,
        sender,
        device_id,
        group_did,
        &binding.openmls_group_id,
        group.epoch().as_u64(),
        &binding.role,
        request_id,
    )?;
    Ok(json!({
        "group_cipher_object": {
            "crypto_group_id_b64u": encode_b64u(binding.openmls_group_id.as_slice()),
            "openmls_group_id_b64u": encode_b64u(binding.openmls_group_id.as_slice()),
            "epoch": group.epoch().as_u64().to_string(),
            "private_message_b64u": private_message_b64u,
            "group_state_ref": group_state_ref,
            "epoch_authenticator": encode_b64u(group.epoch_authenticator().as_slice())
        },
        "authenticated_data_sha256_b64u": encode_b64u(&Sha256::digest(&aad)),
    }))
}

fn real_message_decrypt(
    provider: &mut SqliteMlsProvider,
    conn: &Connection,
    params: &Value,
    request_id: &str,
) -> Result<Value, Value> {
    let recipient = params
        .get("recipient_did")
        .or_else(|| params.get("agent_did"))
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            error(
                "missing_field",
                "recipient_did or agent_did is required",
                None,
            )
        })?;
    let device_id = device_id(params);
    let group_state_ref = params
        .get("group_state_ref")
        .or_else(|| params.pointer("/group_cipher_object/group_state_ref"))
        .cloned()
        .ok_or_else(|| error("missing_field", "group_state_ref is required", None))?;
    let group_did = params
        .pointer("/group_state_ref/group_did")
        .or_else(|| params.pointer("/group_cipher_object/group_state_ref/group_did"))
        .or_else(|| params.get("group_did"))
        .and_then(Value::as_str)
        .ok_or_else(|| error("missing_field", "group_did is required", None))?;
    let private_message_b64u = params
        .pointer("/group_cipher_object/private_message_b64u")
        .or_else(|| params.get("private_message_b64u"))
        .and_then(Value::as_str)
        .ok_or_else(|| error("missing_field", "private_message_b64u is required", None))?;
    let binding = binding(conn, recipient, device_id, group_did, request_id)?;
    let mut group = load_group(provider, &binding.openmls_group_id, request_id)?;
    if let Some(group_cipher_object) = params.get("group_cipher_object") {
        validate_group_binding_claims(&binding, group_cipher_object, request_id)?;
        if let Some(group_state_ref) = group_cipher_object.get("group_state_ref") {
            validate_group_binding_claims(&binding, group_state_ref, request_id)?;
        }
    }
    if let Some(group_state_ref) = params.get("group_state_ref") {
        validate_group_binding_claims(&binding, group_state_ref, request_id)?;
    }
    validate_loaded_group_matches_binding(&binding, &group, request_id)?;
    let expected_aad = build_message_aad(params, &binding, &group_state_ref, request_id)?;
    let message_in =
        MlsMessageIn::tls_deserialize_exact(decode_b64u(private_message_b64u, request_id)?)
            .map_err(|e| mls_error("message_decode_failed", e, request_id))?;
    let protocol = message_in.try_into_protocol_message().map_err(|_| {
        error(
            "message_decode_failed",
            "MLS message is not a protocol message",
            Some(request_id.to_owned()),
        )
    })?;
    let processed = group
        .process_message(provider, protocol)
        .map_err(|e| mls_error("message_decrypt_failed", e, request_id))?;
    if processed.aad() != expected_aad.as_slice() {
        return Err(error(
            "aad_mismatch",
            "MLS authenticated_data does not match P6 outer message binding",
            Some(request_id.to_owned()),
        ));
    }
    upsert_binding(
        conn,
        recipient,
        device_id,
        group_did,
        &binding.openmls_group_id,
        group.epoch().as_u64(),
        &binding.role,
        request_id,
    )?;
    let plaintext = match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(application) => application.into_bytes(),
        other => {
            return Err(error(
                "message_decrypt_failed",
                &format!("expected application message, got {other:?}"),
                Some(request_id.to_owned()),
            ))
        }
    };
    Ok(json!({
        "application_plaintext": application_plaintext_value(&plaintext),
        "epoch": group.epoch().as_u64().to_string(),
    }))
}

fn real_group_commit_finalize(
    provider: &mut SqliteMlsProvider,
    conn: &Connection,
    params: &Value,
    request_id: &str,
) -> Result<Value, Value> {
    let pending_commit_id = pending_commit_id(params)?;
    let pending = pending_commit(conn, pending_commit_id, request_id)?;
    if pending.status == "finalized" {
        return Ok(json!({
            "pending_commit_id": pending.pending_commit_id,
            "operation_id": pending.operation_id,
            "group_did": pending.group_did,
            "status": "finalized",
            "epoch": pending.to_epoch.to_string(),
            "local_epoch": pending.to_epoch.to_string(),
            "subject_did": pending.subject_did,
            "subject_status": pending.subject_status,
        }));
    }
    if pending.status == "aborted" {
        return Err(error(
            "pending_commit_aborted",
            "pending commit was already aborted",
            Some(request_id.to_owned()),
        ));
    }
    let mut epoch_authenticator = None;
    if pending.command != "group leave" {
        let mut group = load_group(
            provider,
            &GroupId::from_slice(&decode_b64u(&pending.crypto_group_id_b64u, request_id)?),
            request_id,
        )?;
        if group.pending_commit().is_none() {
            return Err(error(
                "pending_commit_missing",
                "OpenMLS pending commit is missing; abort and retry prepare",
                Some(request_id.to_owned()),
            ));
        }
        group
            .merge_pending_commit(provider)
            .map_err(|e| mls_error("pending_commit_finalize_failed", e, request_id))?;
        epoch_authenticator = Some(encode_b64u(group.epoch_authenticator().as_slice()));
    }
    if pending.subject_did == pending.agent_did {
        mark_binding_inactive(
            conn,
            &pending.agent_did,
            &pending.device_id,
            &pending.group_did,
            pending.to_epoch,
            &pending.subject_status,
            request_id,
        )?;
    } else {
        set_binding_epoch_status(
            conn,
            &pending.agent_did,
            &pending.device_id,
            &pending.group_did,
            pending.to_epoch,
            "active",
            request_id,
        )?;
    }
    update_pending_commit_status(conn, &pending.pending_commit_id, "finalized", request_id)?;
    Ok(json!({
        "pending_commit_id": pending.pending_commit_id,
        "operation_id": pending.operation_id,
        "group_did": pending.group_did,
        "crypto_group_id_b64u": pending.crypto_group_id_b64u,
        "status": "finalized",
        "from_epoch": pending.from_epoch.to_string(),
        "epoch": pending.to_epoch.to_string(),
        "local_epoch": pending.to_epoch.to_string(),
        "subject_did": pending.subject_did,
        "subject_status": pending.subject_status,
        "epoch_authenticator": epoch_authenticator,
    }))
}

fn real_group_commit_abort(
    provider: &mut SqliteMlsProvider,
    conn: &Connection,
    params: &Value,
    request_id: &str,
) -> Result<Value, Value> {
    let pending_commit_id = pending_commit_id(params)?;
    let pending = pending_commit(conn, pending_commit_id, request_id)?;
    if pending.status == "finalized" {
        return Err(error(
            "pending_commit_finalized",
            "finalized pending commits cannot be aborted",
            Some(request_id.to_owned()),
        ));
    }
    if pending.status != "aborted" {
        if pending.command != "group leave" {
            let mut group = load_group(
                provider,
                &GroupId::from_slice(&decode_b64u(&pending.crypto_group_id_b64u, request_id)?),
                request_id,
            )?;
            group
                .clear_pending_commit(provider.storage())
                .map_err(|e| mls_error("pending_commit_abort_failed", e, request_id))?;
        }
        update_pending_commit_status(conn, &pending.pending_commit_id, "aborted", request_id)?;
    }
    Ok(json!({
        "pending_commit_id": pending.pending_commit_id,
        "operation_id": pending.operation_id,
        "group_did": pending.group_did,
        "crypto_group_id_b64u": pending.crypto_group_id_b64u,
        "status": "aborted",
        "local_epoch": pending.from_epoch.to_string(),
        "subject_did": pending.subject_did,
        "subject_status": pending.subject_status,
    }))
}

fn real_commit_process(
    provider: &mut SqliteMlsProvider,
    conn: &Connection,
    params: &Value,
    request_id: &str,
) -> Result<Value, Value> {
    let agent = params
        .get("recipient_did")
        .or_else(|| params.get("agent_did"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| error("missing_field", "recipient_did/agent_did is required", None))?;
    let device_id = device_id(params);
    let group_did = required(params, "group_did")?;
    let commit_b64u = params
        .get("commit_b64u")
        .or_else(|| params.pointer("/notice/commit_b64u"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| error("missing_field", "commit_b64u is required", None))?;
    let binding = binding(conn, agent, device_id, group_did, request_id)?;
    if let Some(from_epoch) = params.get("from_epoch").and_then(epoch_claim_as_u64) {
        if from_epoch != binding.epoch {
            return Err(error(
                "group_epoch_mismatch",
                "commit from_epoch does not match the local MLS group epoch",
                Some(request_id.to_owned()),
            ));
        }
    }
    let mut group = load_group(provider, &binding.openmls_group_id, request_id)?;
    validate_loaded_group_matches_binding(&binding, &group, request_id)?;
    let original_tree = group.export_ratchet_tree();
    let message_in = MlsMessageIn::tls_deserialize_exact(decode_b64u(commit_b64u, request_id)?)
        .map_err(|e| mls_error("commit_decode_failed", e, request_id))?;
    let protocol = message_in.try_into_protocol_message().map_err(|_| {
        error(
            "commit_decode_failed",
            "commit_b64u is not an MLS protocol message",
            Some(request_id.to_owned()),
        )
    })?;
    let processed = group
        .process_message(provider, protocol)
        .map_err(|e| mls_error("commit_process_failed", e, request_id))?;
    let staged_commit = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => *staged_commit,
        other => {
            return Err(error(
                "commit_process_failed",
                &format!("expected MLS staged commit, got {other:?}"),
                Some(request_id.to_owned()),
            ))
        }
    };
    let self_removed = staged_commit.self_removed();
    let to_epoch = staged_commit.epoch().as_u64();
    let epoch_authenticator_b64u = staged_commit
        .epoch_authenticator()
        .map(|value| encode_b64u(value.as_slice()));
    let ratchet_tree_b64u = staged_commit
        .export_ratchet_tree(provider.crypto(), original_tree)
        .map_err(|e| mls_error("ratchet_tree_encode_failed", e, request_id))?
        .map(|tree| {
            let tree_in: RatchetTreeIn = tree.into();
            tree_in
                .tls_serialize_detached()
                .map(|bytes| encode_b64u(&bytes))
                .map_err(|e| mls_error("ratchet_tree_encode_failed", e, request_id))
        })
        .transpose()?;
    group
        .merge_staged_commit(provider, staged_commit)
        .map_err(|e| mls_error("commit_merge_failed", e, request_id))?;
    let subject_status = params
        .get("subject_status")
        .and_then(Value::as_str)
        .unwrap_or(if self_removed { "removed" } else { "active" });
    if self_removed {
        mark_binding_inactive(
            conn,
            agent,
            device_id,
            group_did,
            to_epoch,
            subject_status,
            request_id,
        )?;
    } else {
        set_binding_epoch_status(
            conn, agent, device_id, group_did, to_epoch, "active", request_id,
        )?;
    }
    Ok(json!({
        "group_did": group_did,
        "crypto_group_id_b64u": encode_b64u(binding.openmls_group_id.as_slice()),
        "status": if self_removed { "inactive" } else { "active" },
        "self_removed": self_removed,
        "from_epoch": binding.epoch.to_string(),
        "epoch": to_epoch.to_string(),
        "epoch_authenticator": epoch_authenticator_b64u,
        "ratchet_tree_b64u": ratchet_tree_b64u,
        "subject_did": params.get("subject_did").cloned().unwrap_or_else(|| json!(agent)),
        "subject_status": subject_status,
    }))
}

fn real_group_status(
    provider: &mut SqliteMlsProvider,
    conn: &Connection,
    params: &Value,
    data_dir: &Path,
    request_id: &str,
) -> Result<Value, Value> {
    let agent = params
        .get("agent_did")
        .or_else(|| params.get("owner_did"))
        .and_then(Value::as_str);
    let device_id = params
        .get("device_id")
        .and_then(Value::as_str)
        .unwrap_or(DEVICE_ID_DEFAULT);
    let group_did = params.get("group_did").and_then(Value::as_str);
    let mut stmt = conn
        .prepare(
            "SELECT agent_did, device_id, group_did, crypto_group_id_b64u, openmls_group_id_b64u, epoch, role, status
             FROM group_bindings
             WHERE (?1 IS NULL OR agent_did = ?1) AND (?2 IS NULL OR group_did = ?2) AND device_id = ?3
             ORDER BY updated_at DESC",
        )
        .map_err(|e| sqlite_error("state_read_failed", e, request_id))?;
    let rows = stmt
        .query_map(params![agent, group_did, device_id], |row| {
            Ok(json!({
                "agent_did": row.get::<_, String>(0)?,
                "device_id": row.get::<_, String>(1)?,
                "group_did": row.get::<_, String>(2)?,
                "crypto_group_id_b64u": row.get::<_, String>(3)?,
                "openmls_group_id_b64u": row.get::<_, String>(4)?,
                "epoch": row.get::<_, i64>(5)?.to_string(),
                "role": row.get::<_, String>(6)?,
                "status": row.get::<_, String>(7)?,
            }))
        })
        .map_err(|e| sqlite_error("state_read_failed", e, request_id))?;
    let mut bindings = Vec::new();
    for row in rows {
        bindings.push(row.map_err(|e| sqlite_error("state_read_failed", e, request_id))?);
    }
    let pending_commits =
        pending_commits_for_status(conn, agent, device_id, group_did, request_id)?;
    if let (Some(agent), Some(group_did)) = (agent, group_did) {
        if let Ok(binding) = binding(conn, agent, device_id, group_did, request_id) {
            if let Some(group) = MlsGroup::load(provider.storage(), &binding.openmls_group_id)
                .map_err(|e| mls_error("group_load_failed", e, request_id))?
            {
                return Ok(json!({
                    "data_dir": data_dir.to_string_lossy(),
                    "state_db": data_dir.join("state.db").to_string_lossy(),
                    "bindings": bindings,
                    "pending_commits": pending_commits,
                    "status": "active",
                    "epoch": group.epoch().as_u64().to_string(),
                    "local_epoch": group.epoch().as_u64().to_string(),
                    "epoch_authenticator": encode_b64u(group.epoch_authenticator().as_slice()),
                }));
            }
        }
    }
    let derived_status = derive_group_status_from_bindings(&bindings);
    let derived_epoch = bindings
        .first()
        .and_then(|binding| binding.get("epoch"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    Ok(json!({
        "data_dir": data_dir.to_string_lossy(),
        "state_db": data_dir.join("state.db").to_string_lossy(),
        "bindings": bindings,
        "pending_commits": pending_commits,
        "status": derived_status,
        "epoch": derived_epoch.clone(),
        "local_epoch": derived_epoch,
    }))
}

fn derive_group_status_from_bindings(bindings: &[Value]) -> String {
    if bindings.is_empty() {
        return "empty".to_owned();
    }
    if bindings
        .iter()
        .any(|binding| binding.get("status").and_then(Value::as_str) == Some("active"))
    {
        return "active".to_owned();
    }
    bindings
        .first()
        .and_then(|binding| binding.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("inactive")
        .to_owned()
}

fn pending_commits_for_status(
    conn: &Connection,
    agent: Option<&str>,
    device_id: &str,
    group_did: Option<&str>,
    request_id: &str,
) -> Result<Vec<Value>, Value> {
    let mut stmt = conn
        .prepare(
            "SELECT pending_commit_id, operation_id, command, agent_did, device_id, group_did, subject_did, subject_status, crypto_group_id_b64u, from_epoch, to_epoch, status
             FROM pending_commits
             WHERE (?1 IS NULL OR agent_did = ?1) AND (?2 IS NULL OR group_did = ?2) AND device_id = ?3 AND status = 'pending'
             ORDER BY created_at DESC",
        )
        .map_err(|e| sqlite_error("state_read_failed", e, request_id))?;
    let rows = stmt
        .query_map(params![agent, group_did, device_id], |row| {
            Ok(json!({
                "pending_commit_id": row.get::<_, String>(0)?,
                "operation_id": row.get::<_, String>(1)?,
                "command": row.get::<_, String>(2)?,
                "agent_did": row.get::<_, String>(3)?,
                "device_id": row.get::<_, String>(4)?,
                "group_did": row.get::<_, String>(5)?,
                "subject_did": row.get::<_, String>(6)?,
                "subject_status": row.get::<_, String>(7)?,
                "crypto_group_id_b64u": row.get::<_, String>(8)?,
                "from_epoch": row.get::<_, i64>(9)?.to_string(),
                "to_epoch": row.get::<_, i64>(10)?.to_string(),
                "status": row.get::<_, String>(11)?,
            }))
        })
        .map_err(|e| sqlite_error("state_read_failed", e, request_id))?;
    let mut pending = Vec::new();
    for row in rows {
        pending.push(row.map_err(|e| sqlite_error("state_read_failed", e, request_id))?);
    }
    Ok(pending)
}

struct Binding {
    openmls_group_id: GroupId,
    epoch: u64,
    role: String,
}

struct MembershipPrepare<'a> {
    pending_commit_id: &'a str,
    operation_id: &'a str,
    command: &'a str,
    actor_did: &'a str,
    subject_did: &'a str,
    subject_status: &'a str,
    group_did: &'a str,
    crypto_group_id_b64u: &'a str,
    from_epoch: u64,
    to_epoch: u64,
    commit_b64u: &'a str,
    welcome_b64u: Option<&'a str>,
    ratchet_tree_b64u: Option<&'a str>,
    group_info_b64u: Option<&'a str>,
    epoch_authenticator_b64u: Option<&'a str>,
}

struct PendingCommitRecord {
    pending_commit_id: String,
    operation_id: String,
    command: String,
    agent_did: String,
    device_id: String,
    group_did: String,
    subject_did: String,
    subject_status: String,
    crypto_group_id_b64u: String,
    from_epoch: u64,
    to_epoch: u64,
    status: String,
}

fn membership_prepare_response(input: MembershipPrepare<'_>) -> Value {
    json!({
        "pending_commit_id": input.pending_commit_id,
        "operation_id": input.operation_id,
        "command": input.command,
        "status": "pending",
        "actor_did": input.actor_did,
        "subject_did": input.subject_did,
        "subject_status": input.subject_status,
        "group_did": input.group_did,
        "crypto_group_id_b64u": input.crypto_group_id_b64u,
        "openmls_group_id_b64u": input.crypto_group_id_b64u,
        "from_epoch": input.from_epoch.to_string(),
        "epoch": input.to_epoch.to_string(),
        "to_epoch": input.to_epoch.to_string(),
        "local_epoch": input.from_epoch.to_string(),
        "commit_b64u": input.commit_b64u,
        "welcome_b64u": input.welcome_b64u,
        "ratchet_tree_b64u": input.ratchet_tree_b64u,
        "group_info_b64u": input.group_info_b64u,
        "epoch_authenticator": input.epoch_authenticator_b64u,
        "epoch_authenticator_b64u": input.epoch_authenticator_b64u,
        "suite": MTI_SUITE,
    })
}

fn upsert_binding(
    conn: &Connection,
    agent_did: &str,
    device_id: &str,
    group_did: &str,
    openmls_group_id: &GroupId,
    epoch: u64,
    role: &str,
    request_id: &str,
) -> Result<(), Value> {
    let group_id_b64u = encode_b64u(openmls_group_id.as_slice());
    conn.execute(
        "INSERT INTO group_bindings(agent_did, device_id, group_did, crypto_group_id_b64u, openmls_group_id_b64u, epoch, role, status, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6, 'active', CURRENT_TIMESTAMP)
         ON CONFLICT(agent_did, device_id, group_did) DO UPDATE SET
           crypto_group_id_b64u = excluded.crypto_group_id_b64u,
           openmls_group_id_b64u = excluded.openmls_group_id_b64u,
           epoch = excluded.epoch,
           role = excluded.role,
           status = 'active',
           updated_at = CURRENT_TIMESTAMP",
        params![agent_did, device_id, group_did, group_id_b64u, epoch as i64, role],
    )
    .map_err(|e| sqlite_error("state_write_failed", e, request_id))?;
    Ok(())
}

fn set_binding_epoch_status(
    conn: &Connection,
    agent_did: &str,
    device_id: &str,
    group_did: &str,
    epoch: u64,
    status: &str,
    request_id: &str,
) -> Result<(), Value> {
    conn.execute(
        "UPDATE group_bindings
         SET epoch = ?4, status = ?5, updated_at = CURRENT_TIMESTAMP
         WHERE agent_did = ?1 AND device_id = ?2 AND group_did = ?3",
        params![agent_did, device_id, group_did, epoch as i64, status],
    )
    .map_err(|e| sqlite_error("state_write_failed", e, request_id))?;
    Ok(())
}

fn mark_binding_inactive(
    conn: &Connection,
    agent_did: &str,
    device_id: &str,
    group_did: &str,
    epoch: u64,
    status: &str,
    request_id: &str,
) -> Result<(), Value> {
    let inactive_status = match status {
        "left" => "left",
        "removed" => "removed",
        other => other,
    };
    set_binding_epoch_status(
        conn,
        agent_did,
        device_id,
        group_did,
        epoch,
        inactive_status,
        request_id,
    )
}

#[allow(clippy::too_many_arguments)]
fn insert_pending_commit(
    conn: &Connection,
    pending_commit_id: &str,
    operation_id: &str,
    command: &str,
    agent_did: &str,
    device_id: &str,
    group_did: &str,
    subject_did: &str,
    subject_status: &str,
    from_epoch: u64,
    to_epoch: u64,
    commit_b64u: &str,
    ratchet_tree_b64u: Option<&str>,
    group_info_b64u: Option<&str>,
    epoch_authenticator_b64u: Option<&str>,
    response: &Value,
    request_id: &str,
) -> Result<(), Value> {
    conn.execute(
        "INSERT INTO pending_commits(
            pending_commit_id, operation_id, command, agent_did, device_id, group_did, crypto_group_id_b64u,
            subject_did, subject_status, from_epoch, to_epoch, commit_b64u,
            ratchet_tree_b64u, group_info_b64u, epoch_authenticator_b64u,
            status, response_json, updated_at
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 'pending', ?16, CURRENT_TIMESTAMP)",
        params![
            pending_commit_id,
            operation_id,
            command,
            agent_did,
            device_id,
            group_did,
            response["crypto_group_id_b64u"].as_str().unwrap_or_default(),
            subject_did,
            subject_status,
            from_epoch as i64,
            to_epoch as i64,
            commit_b64u,
            ratchet_tree_b64u,
            group_info_b64u,
            epoch_authenticator_b64u,
            response.to_string(),
        ],
    )
    .map_err(|e| sqlite_error("state_write_failed", e, request_id))?;
    Ok(())
}

fn pending_commit_id(params: &Value) -> Result<&str, Value> {
    params
        .get("pending_commit_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| error("missing_field", "pending_commit_id is required", None))
}

fn pending_commit(
    conn: &Connection,
    pending_commit_id: &str,
    request_id: &str,
) -> Result<PendingCommitRecord, Value> {
    conn.query_row(
        "SELECT pending_commit_id, operation_id, command, agent_did, device_id, group_did,
                subject_did, subject_status, from_epoch, to_epoch, status,
                crypto_group_id_b64u
         FROM pending_commits
         WHERE pending_commit_id = ?1",
        params![pending_commit_id],
        |row| {
            Ok(PendingCommitRecord {
                pending_commit_id: row.get(0)?,
                operation_id: row.get(1)?,
                command: row.get(2)?,
                agent_did: row.get(3)?,
                device_id: row.get(4)?,
                group_did: row.get(5)?,
                subject_did: row.get(6)?,
                subject_status: row.get(7)?,
                from_epoch: row.get::<_, i64>(8)? as u64,
                to_epoch: row.get::<_, i64>(9)? as u64,
                status: row.get(10)?,
                crypto_group_id_b64u: row.get(11)?,
            })
        },
    )
    .optional()
    .map_err(|e| sqlite_error("state_read_failed", e, request_id))?
    .ok_or_else(|| {
        error(
            "pending_commit_not_found",
            "pending_commit_id was not found",
            Some(request_id.to_owned()),
        )
    })
}

fn update_pending_commit_status(
    conn: &Connection,
    pending_commit_id: &str,
    status: &str,
    request_id: &str,
) -> Result<(), Value> {
    conn.execute(
        "UPDATE pending_commits SET status = ?2, updated_at = CURRENT_TIMESTAMP WHERE pending_commit_id = ?1",
        params![pending_commit_id, status],
    )
    .map_err(|e| sqlite_error("state_write_failed", e, request_id))?;
    Ok(())
}

fn binding(
    conn: &Connection,
    agent_did: &str,
    device_id: &str,
    group_did: &str,
    request_id: &str,
) -> Result<Binding, Value> {
    active_binding(conn, agent_did, device_id, group_did, request_id)?.ok_or_else(|| {
        error(
            "group_not_found",
            "no local MLS group binding found for agent/device/group",
            Some(request_id.to_owned()),
        )
    })
}

fn active_binding(
    conn: &Connection,
    agent_did: &str,
    device_id: &str,
    group_did: &str,
    request_id: &str,
) -> Result<Option<Binding>, Value> {
    let row: Option<(String, String, i64)> = conn
        .query_row(
            "SELECT openmls_group_id_b64u, role, epoch FROM group_bindings WHERE agent_did = ?1 AND device_id = ?2 AND group_did = ?3 AND status = 'active'",
            params![agent_did, device_id, group_did],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|e| sqlite_error("state_read_failed", e, request_id))?;
    let Some((group_id_b64u, role, epoch)) = row else {
        return Ok(None);
    };
    Ok(Some(Binding {
        openmls_group_id: GroupId::from_slice(&decode_b64u(&group_id_b64u, request_id)?),
        epoch: epoch as u64,
        role,
    }))
}

fn welcome_target_epoch(params: &Value) -> Option<u64> {
    ["to_epoch", "epoch", "local_epoch"]
        .into_iter()
        .find_map(|key| params.get(key).and_then(epoch_claim_as_u64))
}

fn validate_welcome_outer_binding(
    params: &Value,
    expected_group_did: &str,
    expected_group_id: &GroupId,
    expected_epoch: u64,
    request_id: &str,
) -> Result<(), Value> {
    let group_state_ref = params
        .get("group_state_ref")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            error(
                "missing_field",
                "welcome process requires group_state_ref",
                Some(request_id.to_owned()),
            )
        })?;
    let ref_group_did = group_state_ref
        .get("group_did")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            error(
                "missing_field",
                "welcome group_state_ref.group_did is required",
                Some(request_id.to_owned()),
            )
        })?;
    if ref_group_did != expected_group_did {
        return Err(error(
            "invalid_target_binding",
            "welcome group_state_ref.group_did does not match group_did",
            Some(request_id.to_owned()),
        ));
    }

    let expected_crypto_group_id = encode_b64u(expected_group_id.as_slice());
    let mut saw_crypto_group_claim = false;
    for (path, actual) in [
        (
            "crypto_group_id_b64u",
            params.get("crypto_group_id_b64u").and_then(Value::as_str),
        ),
        (
            "openmls_group_id_b64u",
            params.get("openmls_group_id_b64u").and_then(Value::as_str),
        ),
        (
            "group_state_ref.crypto_group_id_b64u",
            params
                .pointer("/group_state_ref/crypto_group_id_b64u")
                .and_then(Value::as_str),
        ),
        (
            "group_state_ref.openmls_group_id_b64u",
            params
                .pointer("/group_state_ref/openmls_group_id_b64u")
                .and_then(Value::as_str),
        ),
    ] {
        if let Some(actual) = actual {
            saw_crypto_group_claim = true;
            if actual != expected_crypto_group_id {
                return Err(error(
                    "group_binding_mismatch",
                    &format!("{path} does not match the staged MLS welcome group id"),
                    Some(request_id.to_owned()),
                ));
            }
        }
    }
    if !saw_crypto_group_claim {
        return Err(error(
            "missing_field",
            "welcome process requires crypto_group_id_b64u or openmls_group_id_b64u binding",
            Some(request_id.to_owned()),
        ));
    }

    let mut saw_epoch_claim = false;
    for (path, actual) in [
        (
            "to_epoch",
            params.get("to_epoch").and_then(epoch_claim_as_u64),
        ),
        ("epoch", params.get("epoch").and_then(epoch_claim_as_u64)),
        (
            "local_epoch",
            params.get("local_epoch").and_then(epoch_claim_as_u64),
        ),
        (
            "group_state_ref.epoch",
            params
                .pointer("/group_state_ref/epoch")
                .and_then(epoch_claim_as_u64),
        ),
    ] {
        if let Some(actual) = actual {
            saw_epoch_claim = true;
            if actual != expected_epoch {
                return Err(error(
                    "group_epoch_mismatch",
                    &format!("{path} does not match the staged MLS welcome epoch"),
                    Some(request_id.to_owned()),
                ));
            }
        }
    }
    if !saw_epoch_claim {
        return Err(error(
            "missing_field",
            "welcome process requires to_epoch or epoch binding",
            Some(request_id.to_owned()),
        ));
    }
    Ok(())
}

fn delete_openmls_group_state(
    conn: &Connection,
    group_id: &GroupId,
    request_id: &str,
) -> Result<(), Value> {
    for statement in [
        "DELETE FROM openmls_group_data WHERE group_id = ?1",
        "DELETE FROM openmls_own_leaf_nodes WHERE group_id = ?1",
        "DELETE FROM openmls_proposals WHERE group_id = ?1",
        "DELETE FROM openmls_epoch_keys_pairs WHERE group_id = ?1",
    ] {
        conn.execute(statement, params![group_id.as_slice()])
            .map_err(|e| sqlite_error("state_write_failed", e, request_id))?;
    }
    Ok(())
}

fn member_leaf_index_by_did(group: &MlsGroup, member_did: &str) -> Option<LeafNodeIndex> {
    let credential: Credential = BasicCredential::new(member_did.as_bytes().to_vec()).into();
    group.member_leaf_index(&credential)
}

fn validate_group_binding_claims(
    binding: &Binding,
    claims: &Value,
    request_id: &str,
) -> Result<(), Value> {
    let expected_group_id = encode_b64u(binding.openmls_group_id.as_slice());
    for key in ["crypto_group_id_b64u", "openmls_group_id_b64u"] {
        if let Some(actual) = claims.get(key).and_then(Value::as_str) {
            if actual != expected_group_id {
                return Err(error(
                    "group_binding_mismatch",
                    &format!("{key} does not match the local MLS group binding"),
                    Some(request_id.to_owned()),
                ));
            }
        }
    }
    for key in ["epoch"] {
        if let Some(actual) = claims.get(key).and_then(epoch_claim_as_u64) {
            if actual != binding.epoch {
                return Err(error(
                    "group_epoch_mismatch",
                    &format!("{key} does not match the local MLS group epoch"),
                    Some(request_id.to_owned()),
                ));
            }
        }
    }
    Ok(())
}

fn validate_loaded_group_matches_binding(
    binding: &Binding,
    group: &MlsGroup,
    request_id: &str,
) -> Result<(), Value> {
    let actual_epoch = group.epoch().as_u64();
    if actual_epoch != binding.epoch {
        return Err(error(
            "group_epoch_mismatch",
            "local binding epoch does not match the persisted OpenMLS group epoch",
            Some(request_id.to_owned()),
        ));
    }
    Ok(())
}

fn validate_key_package_did_wba_binding(
    params: &Value,
    member_did: &str,
    key_package: &KeyPackage,
    request_id: &str,
) -> Result<(), Value> {
    if let Some(owner_did) = params
        .pointer("/group_key_package/owner_did")
        .and_then(Value::as_str)
    {
        if owner_did != member_did {
            return Err(error(
                "did_wba_binding_mismatch",
                "group_key_package.owner_did does not match member_did",
                Some(request_id.to_owned()),
            ));
        }
    }
    let binding = params
        .pointer("/group_key_package/did_wba_binding")
        .or_else(|| params.get("did_wba_binding"))
        .ok_or_else(|| {
            error(
                "missing_field",
                "group_key_package.did_wba_binding is required",
                Some(request_id.to_owned()),
            )
        })?;
    let agent_did = binding
        .get("agent_did")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            error(
                "invalid_did_wba_binding",
                "did_wba_binding.agent_did is required",
                Some(request_id.to_owned()),
            )
        })?;
    if agent_did != member_did {
        return Err(error(
            "did_wba_binding_mismatch",
            "did_wba_binding.agent_did does not match member_did",
            Some(request_id.to_owned()),
        ));
    }
    let verification_method = binding
        .get("verification_method")
        .and_then(Value::as_str)
        .filter(|value| {
            value.starts_with(&format!("{member_did}#")) && value.len() > member_did.len() + 1
        })
        .ok_or_else(|| {
            error(
                "invalid_did_wba_binding",
                "did_wba_binding.verification_method must be a fragment under member_did",
                Some(request_id.to_owned()),
            )
        })?;
    let leaf_signature_key = binding
        .get("leaf_signature_key_b64u")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            error(
                "invalid_did_wba_binding",
                "did_wba_binding.leaf_signature_key_b64u is required",
                Some(request_id.to_owned()),
            )
        })?;
    let leaf_signature_key = decode_b64u(leaf_signature_key, request_id)?;
    if leaf_signature_key.as_slice() != key_package.leaf_node().signature_key().as_slice() {
        return Err(error(
            "did_wba_binding_mismatch",
            "did_wba_binding.leaf_signature_key_b64u does not match the MLS KeyPackage leaf signature key",
            Some(request_id.to_owned()),
        ));
    }
    let credential: BasicCredential = key_package
        .leaf_node()
        .credential()
        .clone()
        .try_into()
        .map_err(|e| mls_error("key_package_credential_decode_failed", e, request_id))?;
    if credential.identity() != member_did.as_bytes() {
        return Err(error(
            "did_wba_binding_mismatch",
            "MLS KeyPackage credential identity does not match member_did",
            Some(request_id.to_owned()),
        ));
    }
    validate_binding_time_window(binding, request_id)?;
    if let Some(proof) = binding.get("proof") {
        validate_binding_proof_shape(proof, verification_method, request_id)?;
    }
    Ok(())
}

fn validate_recovery_key_package_context(
    params: &Value,
    group_did: &str,
    member_did: &str,
    target_device_id: &str,
) -> Result<(), Value> {
    let package = params.get("group_key_package").ok_or_else(|| {
        error(
            "missing_field",
            "group_key_package is required for recover-member prepare",
            None,
        )
    })?;
    if package.get("purpose").and_then(Value::as_str) != Some("recovery") {
        return Err(error(
            "invalid_recovery_key_package",
            "recover-member prepare requires group_key_package.purpose=recovery",
            None,
        ));
    }
    if package.get("group_did").and_then(Value::as_str) != Some(group_did) {
        return Err(error(
            "recovery_key_package_group_mismatch",
            "group_key_package.group_did does not match group_did",
            None,
        ));
    }
    if package.get("owner_did").and_then(Value::as_str) != Some(member_did) {
        return Err(error(
            "recovery_key_package_did_mismatch",
            "group_key_package.owner_did does not match member_did",
            None,
        ));
    }
    if package.get("device_id").and_then(Value::as_str) != Some(target_device_id) {
        return Err(error(
            "recovery_key_package_device_mismatch",
            "group_key_package.device_id does not match target device",
            None,
        ));
    }
    Ok(())
}

fn validate_update_key_package_context(
    params: &Value,
    group_did: &str,
    member_did: &str,
    target_device_id: &str,
) -> Result<(), Value> {
    let package = params.get("group_key_package").ok_or_else(|| {
        error(
            "missing_field",
            "group_key_package is required for update-member prepare",
            None,
        )
    })?;
    if package.get("purpose").and_then(Value::as_str) != Some("update") {
        return Err(error(
            "invalid_update_key_package",
            "update-member prepare requires group_key_package.purpose=update",
            None,
        ));
    }
    if package.get("group_did").and_then(Value::as_str) != Some(group_did) {
        return Err(error(
            "update_key_package_group_mismatch",
            "group_key_package.group_did does not match group_did",
            None,
        ));
    }
    if package.get("owner_did").and_then(Value::as_str) != Some(member_did) {
        return Err(error(
            "update_key_package_did_mismatch",
            "group_key_package.owner_did does not match member_did",
            None,
        ));
    }
    if package.get("device_id").and_then(Value::as_str) != Some(target_device_id) {
        return Err(error(
            "update_key_package_device_mismatch",
            "group_key_package.device_id does not match target device",
            None,
        ));
    }
    if let Some(update_key_package_id) = params
        .get("update_key_package_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        if package.get("key_package_id").and_then(Value::as_str) != Some(update_key_package_id) {
            return Err(error(
                "update_key_package_id_mismatch",
                "update_key_package_id does not match group_key_package.key_package_id",
                None,
            ));
        }
    }
    Ok(())
}

fn validate_binding_time_window(binding: &Value, request_id: &str) -> Result<(), Value> {
    let issued_at = parse_binding_time(binding, "issued_at", request_id)?;
    let expires_at = parse_binding_time(binding, "expires_at", request_id)?;
    if expires_at <= issued_at {
        return Err(error(
            "invalid_did_wba_binding",
            "did_wba_binding.expires_at must be after issued_at",
            Some(request_id.to_owned()),
        ));
    }
    if expires_at <= Utc::now() {
        return Err(error(
            "did_wba_binding_expired",
            "did_wba_binding.expires_at is in the past",
            Some(request_id.to_owned()),
        ));
    }
    Ok(())
}

fn parse_binding_time(
    binding: &Value,
    field: &'static str,
    request_id: &str,
) -> Result<DateTime<Utc>, Value> {
    let raw = binding
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            error(
                "invalid_did_wba_binding",
                &format!("did_wba_binding.{field} is required"),
                Some(request_id.to_owned()),
            )
        })?;
    DateTime::parse_from_rfc3339(raw)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|e| {
            error(
                "invalid_did_wba_binding",
                &format!("did_wba_binding.{field} must be RFC3339: {e}"),
                Some(request_id.to_owned()),
            )
        })
}

fn validate_binding_proof_shape(
    proof: &Value,
    verification_method: &str,
    request_id: &str,
) -> Result<(), Value> {
    let Some(proof_object) = proof.as_object() else {
        return Err(error(
            "invalid_did_wba_binding",
            "did_wba_binding.proof must be an object when present",
            Some(request_id.to_owned()),
        ));
    };
    let proof_verification_method = proof_object
        .get("verificationMethod")
        .or_else(|| proof_object.get("verification_method"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            error(
                "invalid_did_wba_binding",
                "did_wba_binding.proof.verificationMethod is required when proof is present",
                Some(request_id.to_owned()),
            )
        })?;
    if proof_verification_method != verification_method {
        return Err(error(
            "did_wba_binding_mismatch",
            "did_wba_binding.proof.verificationMethod does not match verification_method",
            Some(request_id.to_owned()),
        ));
    }
    Ok(())
}

fn build_message_aad(
    params: &Value,
    binding: &Binding,
    group_state_ref: &Value,
    request_id: &str,
) -> Result<Vec<u8>, Value> {
    let group_did = group_state_ref
        .get("group_did")
        .and_then(Value::as_str)
        .or_else(|| params.get("group_did").and_then(Value::as_str))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            error(
                "missing_field",
                "group_state_ref.group_did is required",
                Some(request_id.to_owned()),
            )
        })?;
    let sender_did = params
        .get("sender_did")
        .or_else(|| params.get("agent_did"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            error(
                "missing_field",
                "sender_did is required for P6 MLS AAD",
                Some(request_id.to_owned()),
            )
        })?;
    let message_id = params
        .get("message_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            error(
                "missing_field",
                "message_id is required for P6 MLS AAD",
                Some(request_id.to_owned()),
            )
        })?;
    let operation_id = params
        .get("operation_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            error(
                "missing_field",
                "operation_id is required for P6 MLS AAD",
                Some(request_id.to_owned()),
            )
        })?;
    let content_type = params
        .get("content_type")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(GROUP_CIPHER_CONTENT_TYPE);
    if content_type != GROUP_CIPHER_CONTENT_TYPE {
        return Err(error(
            "invalid_aad_binding",
            "group.e2ee.send content_type must be application/anp-group-cipher+json",
            Some(request_id.to_owned()),
        ));
    }
    let security_profile = params
        .get("security_profile")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(SECURITY_PROFILE);
    if security_profile != SECURITY_PROFILE {
        return Err(error(
            "invalid_aad_binding",
            "group.e2ee.send security_profile must be group-e2ee",
            Some(request_id.to_owned()),
        ));
    }
    let value = json!({
        "content_type": content_type,
        "group_did": group_did,
        "crypto_group_id_b64u": encode_b64u(binding.openmls_group_id.as_slice()),
        "group_state_ref": group_state_ref,
        "security_profile": security_profile,
        "sender_did": sender_did,
        "message_id": message_id,
        "operation_id": operation_id,
    });
    build_send_aad(&value).map_err(|e| {
        error(
            "invalid_aad_binding",
            &format!("build P6 send AAD: {e}"),
            Some(request_id.to_owned()),
        )
    })
}

fn epoch_claim_as_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|text| text.parse::<u64>().ok()))
}

fn load_group(
    provider: &SqliteMlsProvider,
    group_id: &GroupId,
    request_id: &str,
) -> Result<MlsGroup, Value> {
    MlsGroup::load(provider.storage(), group_id)
        .map_err(|e| mls_error("group_load_failed", e, request_id))?
        .ok_or_else(|| {
            error(
                "group_not_found",
                "OpenMLS group state was not found in SQLite",
                Some(request_id.to_owned()),
            )
        })
}

fn ensure_agent(
    provider: &SqliteMlsProvider,
    conn: &Connection,
    agent_did: &str,
    device_id: &str,
    request_id: &str,
) -> Result<(CredentialWithKey, SignatureKeyPair), Value> {
    if let Some((public_key, scheme)) = conn
        .query_row(
            "SELECT signature_public_key, signature_scheme FROM agents WHERE agent_did = ?1 AND device_id = ?2",
            params![agent_did, device_id],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()
        .map_err(|e| sqlite_error("state_read_failed", e, request_id))?
    {
        let signature_scheme = signature_scheme_from_name(&scheme)?;
        let signer = SignatureKeyPair::read(provider.storage(), &public_key, signature_scheme).ok_or_else(|| {
            error(
                "agent_key_missing",
                "agent signature key metadata exists but private key is missing from OpenMLS storage",
                Some(request_id.to_owned()),
            )
        })?;
        let credential = BasicCredential::new(agent_did.as_bytes().to_vec());
        return Ok((
            CredentialWithKey {
                credential: credential.into(),
                signature_key: public_key.into(),
            },
            signer,
        ));
    }
    let signature_scheme = ciphersuite().signature_algorithm();
    let signer = SignatureKeyPair::new(signature_scheme)
        .map_err(|e| mls_error("agent_key_generate_failed", e, request_id))?;
    signer
        .store(provider.storage())
        .map_err(|e| mls_error("agent_key_store_failed", e, request_id))?;
    let public_key = signer.to_public_vec();
    conn.execute(
        "INSERT INTO agents(agent_did, device_id, signature_public_key, signature_scheme, updated_at)
         VALUES (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP)",
        params![agent_did, device_id, public_key, signature_scheme_name(signature_scheme)],
    )
    .map_err(|e| sqlite_error("state_write_failed", e, request_id))?;
    let credential = BasicCredential::new(agent_did.as_bytes().to_vec());
    Ok((
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.to_public_vec().into(),
        },
        signer,
    ))
}

fn load_signer(
    provider: &SqliteMlsProvider,
    conn: &Connection,
    agent_did: &str,
    device_id: &str,
    request_id: &str,
) -> Result<SignatureKeyPair, Value> {
    let (_, signer) = ensure_agent(provider, conn, agent_did, device_id, request_id)?;
    Ok(signer)
}

fn group_create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .padding_size(100)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 2000))
        .use_ratchet_tree_extension(true)
        .build()
}

fn group_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .padding_size(100)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(10, 2000))
        .use_ratchet_tree_extension(true)
        .build()
}

fn ciphersuite() -> Ciphersuite {
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
}

fn signature_scheme_name(scheme: SignatureScheme) -> &'static str {
    match scheme {
        SignatureScheme::ED25519 => "ED25519",
        SignatureScheme::ECDSA_SECP256R1_SHA256 => "ECDSA_SECP256R1_SHA256",
        _ => "UNKNOWN",
    }
}

fn signature_scheme_from_name(name: &str) -> Result<SignatureScheme, Value> {
    match name {
        "ED25519" => Ok(SignatureScheme::ED25519),
        "ECDSA_SECP256R1_SHA256" => Ok(SignatureScheme::ECDSA_SECP256R1_SHA256),
        _ => Err(error("unsupported_signature_scheme", name, None)),
    }
}

fn agent_did(params: &Value) -> Result<&str, Value> {
    params
        .get("agent_did")
        .or_else(|| params.get("owner_did"))
        .or_else(|| params.get("sender_did"))
        .or_else(|| params.get("recipient_did"))
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            error(
                "missing_field",
                "agent_did/owner_did/sender_did is required",
                None,
            )
        })
}

fn device_id(params: &Value) -> &str {
    params
        .get("device_id")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .unwrap_or(DEVICE_ID_DEFAULT)
}

fn did_wba_binding(owner: &str, device_id: &str, signer: &SignatureKeyPair) -> Value {
    let issued_at = Utc::now();
    let expires_at = issued_at + ChronoDuration::days(365);
    json!({
        "agent_did": owner,
        "device_id": device_id,
        "verification_method": format!("{}#{}", owner, device_id),
        "leaf_signature_key_b64u": encode_b64u(&signer.to_public_vec()),
        "issued_at": issued_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "expires_at": expires_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    })
}

fn application_plaintext_bytes(params: &Value, request_id: &str) -> Result<Vec<u8>, Value> {
    let plaintext = params
        .get("application_plaintext")
        .or_else(|| params.get("plaintext"))
        .ok_or_else(|| {
            error(
                "missing_field",
                "application_plaintext is required",
                Some(request_id.to_owned()),
            )
        })?;
    if let Some(text) = plaintext.get("text").and_then(Value::as_str) {
        return Ok(text.as_bytes().to_vec());
    }
    if let Some(payload_b64u) = plaintext.get("payload_b64u").and_then(Value::as_str) {
        return decode_b64u(payload_b64u, request_id);
    }
    serde_json::to_vec(plaintext).map_err(|e| {
        error(
            "invalid_plaintext",
            &e.to_string(),
            Some(request_id.to_owned()),
        )
    })
}

fn application_plaintext_value(bytes: &[u8]) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(text) => json!({"application_content_type": "text/plain", "text": text}),
        Err(_) => {
            json!({"application_content_type": "application/octet-stream", "payload_b64u": encode_b64u(bytes)})
        }
    }
}

fn encode_b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_b64u(value: &str, request_id: &str) -> Result<Vec<u8>, Value> {
    URL_SAFE_NO_PAD.decode(value).map_err(|e| {
        error(
            "invalid_base64url",
            &format!("base64url decode failed: {e}"),
            Some(request_id.to_owned()),
        )
    })
}

fn digest_json(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    encode_b64u(&Sha256::digest(bytes))
}

fn short_digest(value: &Value) -> String {
    digest_json(value).chars().take(16).collect()
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

fn mls_error(code: &str, err: impl std::fmt::Display, request_id: &str) -> Value {
    error(code, &err.to_string(), Some(request_id.to_owned()))
}

fn error(code: &str, message: &str, request_id: Option<String>) -> Value {
    json!({
        "ok": false,
        "api_version": API_VERSION,
        "request_id": request_id,
        "error": {"code": code, "message": message}
    })
}
