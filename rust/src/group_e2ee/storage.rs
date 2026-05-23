//! SQLite-backed OpenMLS provider and compatibility metadata schema.

use fs2::FileExt;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Connection as MlsConnection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::Connection;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs::{File, OpenOptions},
    path::Path,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StateLockError {
    #[error("open state lock: {0}")]
    Open(#[source] std::io::Error),
    #[error("state is locked by another anp-mls operation: {0}")]
    Locked(#[source] std::io::Error),
}

impl StateLockError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Open(_) => "state_lock_failed",
            Self::Locked(_) => "state_locked",
        }
    }
}

pub struct StateLock {
    file: File,
}

impl StateLock {
    pub fn try_acquire(data_dir: &Path) -> Result<Self, StateLockError> {
        let lock_path = data_dir.join("state.lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(StateLockError::Open)?;
        file.try_lock_exclusive().map_err(StateLockError::Locked)?;
        Ok(Self { file })
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[derive(Default)]
pub struct JsonCodec;

impl openmls_sqlite_storage::Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

pub struct SqliteMlsProvider {
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

#[derive(Debug, Error)]
pub enum SqliteMlsProviderError {
    #[error("{0}")]
    Open(#[source] rusqlite::Error),
    #[error("OpenMLS SQLite migrations failed: {0}")]
    Migration(String),
}

impl SqliteMlsProviderError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Open(_) => "state_open_failed",
            Self::Migration(_) => "state_migration_failed",
        }
    }
}

pub fn sqlite_mls_provider(db_path: &Path) -> Result<SqliteMlsProvider, SqliteMlsProviderError> {
    let connection = MlsConnection::open(db_path).map_err(SqliteMlsProviderError::Open)?;
    let mut storage = SqliteStorageProvider::<JsonCodec, MlsConnection>::new(connection);
    storage
        .run_migrations()
        .map_err(|e| SqliteMlsProviderError::Migration(e.to_string()))?;
    Ok(SqliteMlsProvider {
        crypto: RustCrypto::default(),
        storage,
    })
}

pub fn init_app_schema(conn: &Connection) -> rusqlite::Result<()> {
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
