//! [INPUT] One-shot `anp-mls` JSON requests on stdin plus CLI domain/action and optional `--data-dir`.
//! [OUTPUT] A single JSON response on stdout; real mode persists OpenMLS state in SQLite and contract-test mode emits explicit non-cryptographic fixtures.
//! [POS] Boundary binary between Go/product clients and Rust MLS state; keep private MLS material local to `--data-dir`.

use anp::group_e2ee::{deterministic_contract_artifact, CONTRACT_ARTIFACT_MODE, MTI_SUITE};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
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
        "welcome process" => contract_welcome_process(params)?,
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
            "welcome process" => {
                real_welcome_process(&mut provider, &app_conn, params, request_id)?
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
    record_operation(&app_conn, operation_id, command, &input_digest, &response)
        .map_err(|e| sqlite_error("state_write_failed", e, request_id))?;
    Ok(response)
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
         );",
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
    let public_json = json!({
        "key_package_id": key_package_id,
        "owner_did": owner,
        "device_id": device_id,
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
    let (commit, welcome, group_info) = group
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
    let group_info_b64u = match group_info {
        Some(info) => {
            Some(encode_b64u(&info.tls_serialize_detached().map_err(
                |e| mls_error("group_info_encode_failed", e, request_id),
            )?))
        }
        None => None,
    };
    Ok(json!({
        "crypto_group_id_b64u": encode_b64u(binding.openmls_group_id.as_slice()),
        "openmls_group_id_b64u": encode_b64u(binding.openmls_group_id.as_slice()),
        "epoch": group.epoch().as_u64().to_string(),
        "commit_b64u": commit_b64u,
        "welcome_b64u": welcome_b64u,
        "ratchet_tree_b64u": group_info_b64u,
        "member_did": member_did,
        "epoch_authenticator": encode_b64u(group.epoch_authenticator().as_slice()),
    }))
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
    let welcome = Welcome::tls_deserialize_exact(decode_b64u(welcome_b64u, request_id)?)
        .map_err(|e| mls_error("welcome_decode_failed", e, request_id))?;
    let join_config = group_join_config();
    let staged = StagedWelcome::new_from_welcome(provider, &join_config, welcome, None)
        .map_err(|e| mls_error("welcome_stage_failed", e, request_id))?;
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
    let signer = load_signer(provider, conn, sender, device_id, request_id)?;
    let plaintext = application_plaintext_bytes(params, request_id)?;
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
        }
    }))
}

fn real_message_decrypt(
    provider: &mut SqliteMlsProvider,
    conn: &Connection,
    params: &Value,
    request_id: &str,
) -> Result<Value, Value> {
    let recipient = agent_did(params)?;
    let device_id = device_id(params);
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
    if let (Some(agent), Some(group_did)) = (agent, group_did) {
        if let Ok(binding) = binding(conn, agent, device_id, group_did, request_id) {
            if let Some(group) = MlsGroup::load(provider.storage(), &binding.openmls_group_id)
                .map_err(|e| mls_error("group_load_failed", e, request_id))?
            {
                return Ok(json!({
                    "data_dir": data_dir.to_string_lossy(),
                    "state_db": data_dir.join("state.db").to_string_lossy(),
                    "bindings": bindings,
                    "status": "active",
                    "epoch": group.epoch().as_u64().to_string(),
                    "epoch_authenticator": encode_b64u(group.epoch_authenticator().as_slice()),
                }));
            }
        }
    }
    Ok(json!({
        "data_dir": data_dir.to_string_lossy(),
        "state_db": data_dir.join("state.db").to_string_lossy(),
        "bindings": bindings,
        "status": if bindings.is_empty() { "empty" } else { "active" },
    }))
}

struct Binding {
    openmls_group_id: GroupId,
    role: String,
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

fn binding(
    conn: &Connection,
    agent_did: &str,
    device_id: &str,
    group_did: &str,
    request_id: &str,
) -> Result<Binding, Value> {
    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT openmls_group_id_b64u, role FROM group_bindings WHERE agent_did = ?1 AND device_id = ?2 AND group_did = ?3 AND status = 'active'",
            params![agent_did, device_id, group_did],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|e| sqlite_error("state_read_failed", e, request_id))?;
    let Some((group_id_b64u, role)) = row else {
        return Err(error(
            "group_not_found",
            "no local MLS group binding found for agent/device/group",
            Some(request_id.to_owned()),
        ));
    };
    Ok(Binding {
        openmls_group_id: GroupId::from_slice(&decode_b64u(&group_id_b64u, request_id)?),
        role,
    })
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
    json!({
        "agent_did": owner,
        "device_id": device_id,
        "verification_method": format!("{}#{}", owner, device_id),
        "leaf_signature_key_b64u": encode_b64u(&signer.to_public_vec()),
        "issued_at": "2026-01-01T00:00:00Z",
        "expires_at": "2027-01-01T00:00:00Z"
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

fn contract_welcome_process(params: &Value) -> Result<Value, Value> {
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
