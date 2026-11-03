#![cfg(feature = "mls")]

use anp::group_e2ee::storage::{
    GroupMlsOwnerScope, GroupMlsStore, ImCoreSqliteGroupMlsStore, StateLock,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("anp-mls-lock-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn an_uncontended_lock_has_no_retry_delay() {
    let sandbox = Sandbox::new();
    let lock = StateLock::try_acquire(sandbox.path()).unwrap();
    drop(lock);
    let second = StateLock::try_acquire(sandbox.path()).unwrap();
    drop(second);
}

#[test]
fn a_waiting_operation_acquires_after_the_owner_releases() {
    let sandbox = Sandbox::new();
    let owner = StateLock::try_acquire(sandbox.path()).unwrap();
    let path = sandbox.path().to_path_buf();
    let (started_tx, started_rx) = mpsc::channel();
    let (result_tx, result_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        started_tx.send(()).unwrap();
        result_tx
            .send(StateLock::try_acquire(&path).map(|lock| {
                drop(lock);
            }))
            .unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    let early = result_rx.recv_timeout(Duration::from_millis(50));
    drop(owner);
    worker.join().unwrap();
    assert!(
        matches!(early, Err(mpsc::RecvTimeoutError::Timeout)),
        "A normal contended operation returned before its bounded wait"
    );
    result_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .unwrap();
}

#[test]
fn an_explicit_nonblocking_store_still_yields_while_busy() {
    let sandbox = Sandbox::new();
    let owner = StateLock::try_acquire(sandbox.path()).unwrap();
    let scope = GroupMlsOwnerScope::new("owner", "did:example:owner", "device").unwrap();
    let store =
        ImCoreSqliteGroupMlsStore::new_scoped_state_db(sandbox.path().join("state.sqlite"), scope)
            .with_nonblocking_lock();
    let started = std::time::Instant::now();
    let error = store
        .open_operation()
        .err()
        .expect("A busy nonblocking store must yield");
    assert_eq!(error.code(), "state_locked");
    assert!(started.elapsed() < Duration::from_secs(1));
    drop(owner);
}
