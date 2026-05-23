//! SQLite-backed OpenMLS provider and compatibility metadata schema.

use fs2::FileExt;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Connection as MlsConnection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::Connection;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs,
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
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

#[derive(Debug, Error)]
pub enum GroupMlsStoreError {
    #[error("create group MLS data dir {path}: {source}")]
    CreateDataDir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    StateLock(#[from] StateLockError),
    #[error("open group MLS app SQLite {path}: {source}")]
    OpenAppSqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
    #[error("initialize group MLS app schema: {0}")]
    InitAppSchema(#[source] rusqlite::Error),
    #[error(transparent)]
    OpenMlsProvider(#[from] SqliteMlsProviderError),
}

impl GroupMlsStoreError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::CreateDataDir { .. } => "state_write_failed",
            Self::StateLock(err) => err.code(),
            Self::OpenAppSqlite { .. } => "state_open_failed",
            Self::InitAppSchema(_) => "state_migration_failed",
            Self::OpenMlsProvider(err) => err.code(),
        }
    }
}

pub trait GroupMlsStore {
    fn open_operation(&self) -> Result<GroupMlsOperationScope, GroupMlsStoreError>;
}

pub struct GroupMlsOperationScope {
    _lock: StateLock,
    data_dir: PathBuf,
    pub(crate) app_conn: Connection,
    pub(crate) provider: SqliteMlsProvider,
}

impl GroupMlsOperationScope {
    pub(crate) fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

#[derive(Debug, Clone)]
pub struct CompatDataDirStore {
    data_dir: PathBuf,
}

impl CompatDataDirStore {
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
        }
    }

    fn state_db_path(&self) -> PathBuf {
        self.data_dir.join("state.db")
    }
}

impl GroupMlsStore for CompatDataDirStore {
    fn open_operation(&self) -> Result<GroupMlsOperationScope, GroupMlsStoreError> {
        fs::create_dir_all(&self.data_dir).map_err(|source| GroupMlsStoreError::CreateDataDir {
            path: self.data_dir.clone(),
            source,
        })?;
        let lock = StateLock::try_acquire(&self.data_dir)?;
        let state_db_path = self.state_db_path();
        let app_conn = Connection::open(&state_db_path).map_err(|source| {
            GroupMlsStoreError::OpenAppSqlite {
                path: state_db_path.clone(),
                source,
            }
        })?;
        init_app_schema(&app_conn).map_err(GroupMlsStoreError::InitAppSchema)?;
        let provider = sqlite_mls_provider(&state_db_path)?;
        Ok(GroupMlsOperationScope {
            _lock: lock,
            data_dir: self.data_dir.clone(),
            app_conn,
            provider,
        })
    }
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
