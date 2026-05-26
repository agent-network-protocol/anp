//! SQLite-backed OpenMLS provider and compatibility metadata schema.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use fs2::FileExt;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Connection as MlsConnection, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::Connection;
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
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
    #[error("state is locked by another group MLS operation: {0}")]
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
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

#[derive(Default)]
pub(crate) struct JsonCodec;

impl openmls_sqlite_storage::Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

pub(crate) struct SqliteMlsProvider {
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

fn sqlite_mls_provider(db_path: &Path) -> Result<SqliteMlsProvider, SqliteMlsProviderError> {
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
    #[error("invalid group MLS owner scope: {field} is required")]
    InvalidScope { field: &'static str },
}

impl GroupMlsStoreError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::CreateDataDir { .. } => "state_write_failed",
            Self::StateLock(err) => err.code(),
            Self::OpenAppSqlite { .. } => "state_open_failed",
            Self::InitAppSchema(_) => "state_migration_failed",
            Self::OpenMlsProvider(err) => err.code(),
            Self::InvalidScope { .. } => "invalid_owner_scope",
        }
    }
}

pub trait GroupMlsStore {
    fn open_operation(&self) -> Result<GroupMlsOperationScope, GroupMlsStoreError>;

    fn owner_scope(&self) -> Option<GroupMlsOwnerScope> {
        None
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMlsOwnerScope {
    pub owner_identity_id: String,
    pub owner_did: String,
    pub device_id: String,
}

impl GroupMlsOwnerScope {
    pub fn new(
        owner_identity_id: impl Into<String>,
        owner_did: impl Into<String>,
        device_id: impl Into<String>,
    ) -> Result<Self, GroupMlsStoreError> {
        let owner_identity_id = non_empty_scope_value("owner_identity_id", owner_identity_id)?;
        let owner_did = non_empty_scope_value("owner_did", owner_did)?;
        let device_id = non_empty_scope_value("device_id", device_id)?;
        Ok(Self {
            owner_identity_id,
            owner_did,
            device_id,
        })
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

#[derive(Debug, Clone)]
pub struct ImCoreSqliteGroupMlsStore {
    state_db_path: PathBuf,
    lock_dir: PathBuf,
    scope: GroupMlsOwnerScope,
}

impl ImCoreSqliteGroupMlsStore {
    pub fn from_local_state_sqlite_path(
        local_state_sqlite_path: impl AsRef<Path>,
        owner_identity_id: impl Into<String>,
        owner_did: impl Into<String>,
        device_id: impl Into<String>,
    ) -> Result<Self, GroupMlsStoreError> {
        let scope = GroupMlsOwnerScope::new(owner_identity_id, owner_did, device_id)?;
        let local_state_sqlite_path = local_state_sqlite_path.as_ref();
        let local_state_dir = local_state_sqlite_path
            .parent()
            .unwrap_or_else(|| Path::new("."));
        let scoped_dir = local_state_dir
            .join("group_mls")
            .join(scope_path_component(&scope));
        Ok(Self::new_scoped_state_db(
            scoped_dir.join("mls_state.sqlite"),
            scope,
        ))
    }

    pub fn new_scoped_state_db(
        state_db_path: impl Into<PathBuf>,
        scope: GroupMlsOwnerScope,
    ) -> Self {
        let state_db_path = state_db_path.into();
        let lock_dir = state_db_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        Self {
            state_db_path,
            lock_dir,
            scope,
        }
    }

    pub fn state_db_path(&self) -> &Path {
        &self.state_db_path
    }

    pub fn lock_dir(&self) -> &Path {
        &self.lock_dir
    }
}

impl GroupMlsStore for ImCoreSqliteGroupMlsStore {
    fn open_operation(&self) -> Result<GroupMlsOperationScope, GroupMlsStoreError> {
        if let Some(parent) = self.state_db_path.parent() {
            fs::create_dir_all(parent).map_err(|source| GroupMlsStoreError::CreateDataDir {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        fs::create_dir_all(&self.lock_dir).map_err(|source| GroupMlsStoreError::CreateDataDir {
            path: self.lock_dir.clone(),
            source,
        })?;
        let lock = StateLock::try_acquire(&self.lock_dir)?;
        let provider = sqlite_mls_provider(&self.state_db_path)?;
        let app_conn = Connection::open(&self.state_db_path).map_err(|source| {
            GroupMlsStoreError::OpenAppSqlite {
                path: self.state_db_path.clone(),
                source,
            }
        })?;
        init_im_core_group_mls_schema(&app_conn).map_err(GroupMlsStoreError::InitAppSchema)?;
        install_im_core_compat_views(&app_conn, &self.scope)
            .map_err(GroupMlsStoreError::InitAppSchema)?;
        Ok(GroupMlsOperationScope {
            _lock: lock,
            data_dir: self.lock_dir.clone(),
            app_conn,
            provider,
        })
    }

    fn owner_scope(&self) -> Option<GroupMlsOwnerScope> {
        Some(self.scope.clone())
    }
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

fn init_im_core_group_mls_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA foreign_keys=ON;
         PRAGMA busy_timeout=5000;
         CREATE TABLE IF NOT EXISTS group_mls_operations (
            owner_identity_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            operation_id TEXT NOT NULL,
            command TEXT NOT NULL,
            input_digest TEXT NOT NULL,
            response_json TEXT NOT NULL,
            redaction_version TEXT NOT NULL DEFAULT 'v1',
            contains_sensitive INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(owner_identity_id, device_id, operation_id)
         );
         CREATE TABLE IF NOT EXISTS group_mls_agents (
            owner_identity_id TEXT NOT NULL,
            owner_did TEXT NOT NULL,
            device_id TEXT NOT NULL,
            signature_public_key BLOB NOT NULL,
            signature_scheme TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(owner_identity_id, device_id)
         );
         CREATE TABLE IF NOT EXISTS group_mls_key_packages (
            owner_identity_id TEXT NOT NULL,
            owner_did TEXT NOT NULL,
            device_id TEXT NOT NULL,
            key_package_id TEXT NOT NULL,
            public_json TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            consumed_at TEXT,
            PRIMARY KEY(owner_identity_id, device_id, key_package_id)
         );
         CREATE TABLE IF NOT EXISTS group_mls_bindings (
            owner_identity_id TEXT NOT NULL,
            owner_did TEXT NOT NULL,
            device_id TEXT NOT NULL,
            group_did TEXT NOT NULL,
            crypto_group_id_b64u TEXT NOT NULL,
            openmls_group_id_b64u TEXT NOT NULL,
            epoch INTEGER NOT NULL,
            role TEXT NOT NULL,
            status TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(owner_identity_id, device_id, group_did)
         );
         CREATE TABLE IF NOT EXISTS group_mls_pending_commits (
            owner_identity_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            pending_commit_id TEXT NOT NULL,
            operation_id TEXT NOT NULL,
            command TEXT NOT NULL,
            owner_did TEXT NOT NULL,
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
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(owner_identity_id, device_id, pending_commit_id),
            UNIQUE(owner_identity_id, device_id, operation_id)
         );",
    )
}

fn install_im_core_compat_views(
    conn: &Connection,
    scope: &GroupMlsOwnerScope,
) -> rusqlite::Result<()> {
    conn.execute_batch(
        "DROP VIEW IF EXISTS temp.agents;
         DROP VIEW IF EXISTS temp.key_packages;
         DROP VIEW IF EXISTS temp.group_bindings;
         DROP VIEW IF EXISTS temp.pending_commits;
         DROP TABLE IF EXISTS temp.group_mls_scope;
         CREATE TEMP TABLE group_mls_scope (
            owner_identity_id TEXT NOT NULL,
            owner_did TEXT NOT NULL,
            device_id TEXT NOT NULL
         );",
    )?;
    conn.execute(
        "INSERT INTO temp.group_mls_scope(owner_identity_id, owner_did, device_id)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![scope.owner_identity_id, scope.owner_did, scope.device_id],
    )?;
    conn.execute_batch(
        "CREATE TEMP VIEW agents AS
            SELECT owner_did AS agent_did,
                   device_id,
                   signature_public_key,
                   signature_scheme,
                   created_at,
                   updated_at
            FROM group_mls_agents
            WHERE owner_identity_id = (SELECT owner_identity_id FROM temp.group_mls_scope)
              AND device_id = (SELECT device_id FROM temp.group_mls_scope);
         CREATE TEMP TRIGGER agents_insert
         INSTEAD OF INSERT ON agents
         BEGIN
            SELECT CASE
                WHEN NEW.agent_did != (SELECT owner_did FROM temp.group_mls_scope)
                THEN RAISE(ABORT, 'agent_did outside group MLS owner scope')
            END;
            SELECT CASE
                WHEN NEW.device_id != (SELECT device_id FROM temp.group_mls_scope)
                THEN RAISE(ABORT, 'device_id outside group MLS owner scope')
            END;
            INSERT INTO group_mls_agents(
                owner_identity_id, owner_did, device_id,
                signature_public_key, signature_scheme, updated_at
            )
            VALUES (
                (SELECT owner_identity_id FROM temp.group_mls_scope),
                NEW.agent_did,
                NEW.device_id,
                NEW.signature_public_key,
                NEW.signature_scheme,
                CURRENT_TIMESTAMP
            )
            ON CONFLICT(owner_identity_id, device_id) DO UPDATE SET
                signature_public_key = excluded.signature_public_key,
                signature_scheme = excluded.signature_scheme,
                updated_at = CURRENT_TIMESTAMP;
         END;

         CREATE TEMP VIEW key_packages AS
            SELECT owner_did AS agent_did,
                   device_id,
                   key_package_id,
                   public_json,
                   status,
                   created_at,
                   consumed_at
            FROM group_mls_key_packages
            WHERE owner_identity_id = (SELECT owner_identity_id FROM temp.group_mls_scope)
              AND device_id = (SELECT device_id FROM temp.group_mls_scope);
         CREATE TEMP TRIGGER key_packages_insert
         INSTEAD OF INSERT ON key_packages
         BEGIN
            SELECT CASE
                WHEN NEW.agent_did != (SELECT owner_did FROM temp.group_mls_scope)
                THEN RAISE(ABORT, 'key package owner outside group MLS owner scope')
            END;
            SELECT CASE
                WHEN NEW.device_id != (SELECT device_id FROM temp.group_mls_scope)
                THEN RAISE(ABORT, 'key package device outside group MLS owner scope')
            END;
            INSERT INTO group_mls_key_packages(
                owner_identity_id, owner_did, device_id,
                key_package_id, public_json, status, consumed_at
            )
            VALUES (
                (SELECT owner_identity_id FROM temp.group_mls_scope),
                NEW.agent_did,
                NEW.device_id,
                NEW.key_package_id,
                NEW.public_json,
                NEW.status,
                NEW.consumed_at
            )
            ON CONFLICT(owner_identity_id, device_id, key_package_id) DO UPDATE SET
                public_json = excluded.public_json,
                status = excluded.status,
                consumed_at = excluded.consumed_at;
         END;

         CREATE TEMP VIEW group_bindings AS
            SELECT owner_did AS agent_did,
                   device_id,
                   group_did,
                   crypto_group_id_b64u,
                   openmls_group_id_b64u,
                   epoch,
                   role,
                   status,
                   updated_at
            FROM group_mls_bindings
            WHERE owner_identity_id = (SELECT owner_identity_id FROM temp.group_mls_scope)
              AND device_id = (SELECT device_id FROM temp.group_mls_scope);
         CREATE TEMP TRIGGER group_bindings_insert
         INSTEAD OF INSERT ON group_bindings
         BEGIN
            SELECT CASE
                WHEN NEW.agent_did != (SELECT owner_did FROM temp.group_mls_scope)
                THEN RAISE(ABORT, 'group binding owner outside group MLS owner scope')
            END;
            SELECT CASE
                WHEN NEW.device_id != (SELECT device_id FROM temp.group_mls_scope)
                THEN RAISE(ABORT, 'group binding device outside group MLS owner scope')
            END;
            INSERT INTO group_mls_bindings(
                owner_identity_id, owner_did, device_id, group_did,
                crypto_group_id_b64u, openmls_group_id_b64u,
                epoch, role, status, updated_at
            )
            VALUES (
                (SELECT owner_identity_id FROM temp.group_mls_scope),
                NEW.agent_did,
                NEW.device_id,
                NEW.group_did,
                NEW.crypto_group_id_b64u,
                NEW.openmls_group_id_b64u,
                NEW.epoch,
                NEW.role,
                NEW.status,
                CURRENT_TIMESTAMP
            )
            ON CONFLICT(owner_identity_id, device_id, group_did) DO UPDATE SET
                crypto_group_id_b64u = excluded.crypto_group_id_b64u,
                openmls_group_id_b64u = excluded.openmls_group_id_b64u,
                epoch = excluded.epoch,
                role = excluded.role,
                status = excluded.status,
                updated_at = CURRENT_TIMESTAMP;
         END;
         CREATE TEMP TRIGGER group_bindings_update
         INSTEAD OF UPDATE ON group_bindings
         BEGIN
            UPDATE group_mls_bindings
            SET crypto_group_id_b64u = NEW.crypto_group_id_b64u,
                openmls_group_id_b64u = NEW.openmls_group_id_b64u,
                epoch = NEW.epoch,
                role = NEW.role,
                status = NEW.status,
                updated_at = CURRENT_TIMESTAMP
            WHERE owner_identity_id = (SELECT owner_identity_id FROM temp.group_mls_scope)
              AND device_id = (SELECT device_id FROM temp.group_mls_scope)
              AND group_did = OLD.group_did;
         END;
         CREATE TEMP TRIGGER group_bindings_delete
         INSTEAD OF DELETE ON group_bindings
         BEGIN
            DELETE FROM group_mls_bindings
            WHERE owner_identity_id = (SELECT owner_identity_id FROM temp.group_mls_scope)
              AND device_id = (SELECT device_id FROM temp.group_mls_scope)
              AND group_did = OLD.group_did;
         END;

         CREATE TEMP VIEW pending_commits AS
            SELECT pending_commit_id,
                   operation_id,
                   command,
                   owner_did AS agent_did,
                   device_id,
                   group_did,
                   crypto_group_id_b64u,
                   subject_did,
                   subject_status,
                   from_epoch,
                   to_epoch,
                   commit_b64u,
                   ratchet_tree_b64u,
                   group_info_b64u,
                   epoch_authenticator_b64u,
                   status,
                   response_json,
                   created_at,
                   updated_at
            FROM group_mls_pending_commits
            WHERE owner_identity_id = (SELECT owner_identity_id FROM temp.group_mls_scope)
              AND device_id = (SELECT device_id FROM temp.group_mls_scope);
         CREATE TEMP TRIGGER pending_commits_insert
         INSTEAD OF INSERT ON pending_commits
         BEGIN
            SELECT CASE
                WHEN NEW.agent_did != (SELECT owner_did FROM temp.group_mls_scope)
                THEN RAISE(ABORT, 'pending commit owner outside group MLS owner scope')
            END;
            SELECT CASE
                WHEN NEW.device_id != (SELECT device_id FROM temp.group_mls_scope)
                THEN RAISE(ABORT, 'pending commit device outside group MLS owner scope')
            END;
            INSERT INTO group_mls_pending_commits(
                owner_identity_id, device_id, pending_commit_id,
                operation_id, command, owner_did, group_did,
                crypto_group_id_b64u, subject_did, subject_status,
                from_epoch, to_epoch, commit_b64u, ratchet_tree_b64u,
                group_info_b64u, epoch_authenticator_b64u,
                status, response_json, updated_at
            )
            VALUES (
                (SELECT owner_identity_id FROM temp.group_mls_scope),
                NEW.device_id,
                NEW.pending_commit_id,
                NEW.operation_id,
                NEW.command,
                NEW.agent_did,
                NEW.group_did,
                NEW.crypto_group_id_b64u,
                NEW.subject_did,
                NEW.subject_status,
                NEW.from_epoch,
                NEW.to_epoch,
                NEW.commit_b64u,
                NEW.ratchet_tree_b64u,
                NEW.group_info_b64u,
                NEW.epoch_authenticator_b64u,
                NEW.status,
                NEW.response_json,
                CURRENT_TIMESTAMP
            );
         END;
         CREATE TEMP TRIGGER pending_commits_update
         INSTEAD OF UPDATE ON pending_commits
         BEGIN
            UPDATE group_mls_pending_commits
            SET status = NEW.status,
                response_json = NEW.response_json,
                updated_at = CURRENT_TIMESTAMP
            WHERE owner_identity_id = (SELECT owner_identity_id FROM temp.group_mls_scope)
              AND device_id = (SELECT device_id FROM temp.group_mls_scope)
              AND pending_commit_id = OLD.pending_commit_id;
         END;",
    )
}

fn non_empty_scope_value(
    field: &'static str,
    value: impl Into<String>,
) -> Result<String, GroupMlsStoreError> {
    let value = value.into();
    if value.trim().is_empty() {
        return Err(GroupMlsStoreError::InvalidScope { field });
    }
    Ok(value)
}

fn scope_path_component(scope: &GroupMlsOwnerScope) -> String {
    let mut digest = Sha256::new();
    digest.update(scope.owner_identity_id.as_bytes());
    digest.update([0]);
    digest.update(scope.device_id.as_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(digest.finalize());
    encoded[..32].to_owned()
}
