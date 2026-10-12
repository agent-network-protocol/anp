use super::*;

pub(super) fn assert_live_prepare_is_preserved(
    store: &ImCoreSqliteGroupMlsStore,
    live_pending_id: &str,
) {
    force_pending_status(store, "legacy-orphan", "preparing");
    assert!(reconcile_pending_v2(
        store,
        V2ReconcilePendingInput {
            request_id: "legacy-recovery-with-live-prepare".to_owned(),
        }
    )
    .is_err());
    let connection = Connection::open(store.state_db_path()).unwrap();
    for (id, expected) in [
        (live_pending_id, "prepared"),
        ("legacy-orphan", "preparing"),
    ] {
        assert_eq!(
            connection
                .query_row(
                    "SELECT status FROM group_mls_pending_commits WHERE pending_commit_id=?1",
                    [id],
                    |row| row.get::<_, String>(0),
                )
                .unwrap(),
            expected
        );
    }
}

pub(super) fn assert_recovery_after_further_epoch_advance(store: &ImCoreSqliteGroupMlsStore) {
    let result = reconcile_pending_v2(
        store,
        V2ReconcilePendingInput {
            request_id: "legacy-recovery-after-newer-commit".to_owned(),
        },
    )
    .expect("an older superseded journal can retire without rewinding later accepted state");
    assert_eq!(result.pending_commits.len(), 1);
    assert_eq!(result.pending_commits[0].pending_commit_id, "legacy-orphan");
    assert_eq!(
        result.pending_commits[0].action,
        "discarded-superseded-prepare"
    );
}

pub(super) fn assert_recovery_preserves_finalized_membership(
    owner_store: &ImCoreSqliteGroupMlsStore,
    owner: &DidFixture,
    owner_device: &DeviceFixture,
    finalized_id: &str,
) {
    // Recreate only the metadata written by the pre-guard SDK. The original
    // finalized operation and all OpenMLS state remain the real fixture state.
    let connection = Connection::open(owner_store.state_db_path()).unwrap();
    connection
        .execute(
            "INSERT INTO group_mls_pending_commits (
            owner_identity_id, device_id, pending_commit_id, operation_id, command,
            owner_did, group_did, crypto_group_id_b64u, subject_did, subject_status,
            from_epoch, to_epoch, commit_b64u, status, response_json)
         SELECT owner_identity_id, device_id, 'legacy-orphan', 'legacy-operation', command,
            owner_did, group_did, crypto_group_id_b64u, subject_did, subject_status,
            from_epoch, to_epoch, '', 'preparing', ?2
         FROM group_mls_pending_commits WHERE pending_commit_id = ?1",
            params![
                finalized_id,
                json!({"journal_version":"p6-v2-prepare-journal-v1", "prepared_response":null})
                    .to_string()
            ],
        )
        .unwrap();
    let inspect = || {
        inspect_local_group_v2(
            owner_store,
            V2InspectLocalGroupInput {
                owner_did: owner.did.clone(),
                owner_device_id: owner_device.device_id.clone(),
                group_did: GROUP_DID.to_owned(),
                request_id: "inspect-legacy-prepare".to_owned(),
            },
        )
        .unwrap()
    };
    assert_eq!(inspect().auto_reconcile_pending_count, 1);
    let reconcile = || {
        reconcile_pending_v2(
            owner_store,
            V2ReconcilePendingInput {
                request_id: "check-legacy-prepare-boundary".to_owned(),
            },
        )
    };
    let orphan_status = || {
        connection.query_row(
        "SELECT status FROM group_mls_pending_commits WHERE pending_commit_id='legacy-orphan'",
        [], |row| row.get::<_, String>(0),
    ).unwrap()
    };
    // Missing, ambiguous, cross-scope, malformed or already-prepared evidence
    // must never become authority to discard an operation.
    use rusqlite::types::Value as SqlValue;
    for (id, column, replacement) in [
        ("legacy-orphan", "commit_b64u", SqlValue::Text("AQ".into())),
        (
            "legacy-orphan",
            "ratchet_tree_b64u",
            SqlValue::Text("AQ".into()),
        ),
        (
            "legacy-orphan",
            "response_json",
            SqlValue::Text("{}".into()),
        ),
        (
            "legacy-orphan",
            "response_json",
            SqlValue::Text("malformed".into()),
        ),
        (
            "legacy-orphan",
            "response_json",
            SqlValue::Text(
                json!({
                    "journal_version":"unsupported", "prepared_response":null,
                })
                .to_string(),
            ),
        ),
        (
            "legacy-orphan",
            "response_json",
            SqlValue::Text(
                json!({
                    "journal_version":"p6-v2-prepare-journal-v1", "prepared_response":{},
                })
                .to_string(),
            ),
        ),
        (finalized_id, "status", SqlValue::Text("prepared".into())),
        (
            finalized_id,
            "owner_did",
            SqlValue::Text("did:example:other-owner".into()),
        ),
        (
            finalized_id,
            "group_did",
            SqlValue::Text("did:example:other-group".into()),
        ),
        (finalized_id, "commit_b64u", SqlValue::Text("AQ".into())),
        (finalized_id, "response_json", SqlValue::Text("{}".into())),
    ] {
        let previous: SqlValue = connection
            .query_row(
                &format!(
                    "SELECT {column} FROM group_mls_pending_commits WHERE pending_commit_id=?1"
                ),
                [id],
                |row| row.get(0),
            )
            .unwrap();
        let update =
            format!("UPDATE group_mls_pending_commits SET {column}=?2 WHERE pending_commit_id=?1");
        connection
            .execute(&update, params![id, replacement])
            .unwrap();
        assert!(
            reconcile().is_err(),
            "invalid {column} must preserve the orphan"
        );
        assert_eq!(orphan_status(), "preparing");
        connection.execute(&update, params![id, previous]).unwrap();
    }
    connection.execute(
        "CREATE TEMP TABLE duplicate_proof AS SELECT * FROM group_mls_pending_commits WHERE pending_commit_id=?1",
        [finalized_id],
    ).unwrap();
    connection.execute_batch(
        "UPDATE duplicate_proof SET pending_commit_id='duplicate-proof', operation_id='duplicate-operation';
         INSERT INTO group_mls_pending_commits SELECT * FROM duplicate_proof;",
    ).unwrap();
    assert!(
        reconcile().is_err(),
        "two finalized operations are ambiguous"
    );
    assert_eq!(orphan_status(), "preparing");
    connection
        .execute(
            "DELETE FROM group_mls_pending_commits WHERE pending_commit_id='duplicate-proof'",
            [],
        )
        .unwrap();

    force_pending_status(owner_store, "legacy-orphan", "prepared");
    let undecided = reconcile().unwrap();
    assert_eq!(undecided.pending_commits[0].status, "prepared");
    assert_eq!(
        undecided.pending_commits[0].action,
        "awaiting-service-decision"
    );
    assert_eq!(orphan_status(), "prepared");
    force_pending_status(owner_store, "legacy-orphan", "preparing");
    let result = reconcile_pending_v2(
        owner_store,
        V2ReconcilePendingInput {
            request_id: "recover-legacy-prepare".to_owned(),
        },
    )
    .expect("a proven superseded prepare must not roll back the completed membership");
    assert_eq!(result.pending_commits.len(), 1);
    assert_eq!(result.pending_commits[0].status, "aborted");
    assert_eq!(
        result.pending_commits[0].action,
        "discarded-superseded-prepare"
    );
    let after = inspect();
    assert_eq!(after.readiness, V2LocalGroupReadiness::Active);
    assert_eq!(after.auto_reconcile_pending_count, 0);
    assert_eq!(after.host_recheck_pending_count, 0);
    assert!(reconcile_pending_v2(
        owner_store,
        V2ReconcilePendingInput {
            request_id: "recover-legacy-prepare-again".to_owned(),
        }
    )
    .unwrap()
    .pending_commits
    .is_empty());
    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM group_mls_pending_commits WHERE pending_commit_id=?1",
                [finalized_id],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
        "finalized"
    );
}
