//! Recognize a legacy competing prepare without rolling back accepted MLS state.

use super::*;

pub(super) fn superseded_by_finalized_commit(
    scope: &GroupMlsOperationScope,
    pending: &super::super::PendingCommitRecord,
    group: &MlsGroup,
    request_id: &str,
) -> GroupMlsOperationResult<bool> {
    if pending.status != "preparing"
        || !matches!(
            pending.command.as_str(),
            "group add-member" | "group remove-member"
        )
        || pending.from_epoch.checked_add(1) != Some(pending.to_epoch)
        || group.epoch().as_u64() < pending.to_epoch
        || group.pending_commit().is_some()
    {
        return Ok(false);
    }
    let (empty_artifacts, journal): (bool, String) = scope
        .app_conn
        .query_row(
            "SELECT commit_b64u = '' AND ratchet_tree_b64u IS NULL
                AND group_info_b64u IS NULL AND epoch_authenticator_b64u IS NULL,
                response_json
         FROM pending_commits WHERE pending_commit_id = ?1",
            [&pending.pending_commit_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    let journal: Value = serde_json::from_str(&journal).map_err(|_| invalid_journal(request_id))?;
    if !empty_artifacts
        || journal.as_object().is_none_or(|object| object.len() != 2)
        || journal["journal_version"] != "p6-v2-prepare-journal-v1"
        || journal.get("prepared_response") != Some(&Value::Null)
    {
        return Ok(false);
    }
    let local_binding = binding(
        &scope.app_conn,
        &pending.agent_did,
        &pending.device_id,
        &pending.group_did,
        request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    ensure_group_head(group, &local_binding, &pending.group_did, request_id)?;

    // The scoped view plus explicit owner/group/crypto/epoch predicates must
    // identify one DIFFERENT operation that completed this exact transition.
    // An advanced epoch alone is never authority to discard a journal.
    let mut statement = scope
        .app_conn
        .prepare(
            "SELECT pending_commit_id FROM pending_commits
         WHERE status = 'finalized' AND pending_commit_id != ?1 AND operation_id != ?2
           AND agent_did = ?3 AND device_id = ?4 AND group_did = ?5
           AND crypto_group_id_b64u = ?6 AND from_epoch = ?7 AND to_epoch = ?8
         LIMIT 2",
        )
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    let ids = statement
        .query_map(
            params![
                pending.pending_commit_id,
                pending.operation_id,
                pending.agent_did,
                pending.device_id,
                pending.group_did,
                pending.crypto_group_id_b64u,
                pending.from_epoch as i64,
                pending.to_epoch as i64,
            ],
            |row| row.get::<_, String>(0),
        )
        .map_err(|err| sqlite_operation_error(err, request_id))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    if ids.len() != 1 {
        return Ok(false);
    }
    let completed = pending_commit(&scope.app_conn, &ids[0], request_id)
        .map_err(GroupMlsOperationError::from)?;
    let (commit, journal): (String, String) = scope
        .app_conn
        .query_row(
            "SELECT commit_b64u, response_json FROM pending_commits WHERE pending_commit_id = ?1",
            [&ids[0]],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    let journal: V2PrepareJournalResponse<Value> =
        serde_json::from_str(&journal).map_err(|_| invalid_journal(request_id))?;
    if journal.journal_version != "p6-v2-prepare-journal-v1" {
        return Err(invalid_journal(request_id));
    }
    let body = journal
        .prepared_response
        .ok_or_else(|| invalid_journal(request_id))?;
    let (group_did, crypto_id, epoch, body_commit, subject, subject_status) =
        match completed.command.as_str() {
            "group add-member" => {
                let body: V2GroupAddBody =
                    serde_json::from_value(body).map_err(|_| invalid_journal(request_id))?;
                body.validate().map_err(|_| invalid_journal(request_id))?;
                (
                    body.group_state_ref.group_did,
                    body.crypto_group_id_b64u,
                    body.epoch,
                    body.commit_b64u,
                    body.member_did,
                    "active",
                )
            }
            "group remove-member" => {
                let body: V2GroupRemoveBody =
                    serde_json::from_value(body).map_err(|_| invalid_journal(request_id))?;
                body.validate().map_err(|_| invalid_journal(request_id))?;
                (
                    body.group_state_ref.group_did,
                    body.crypto_group_id_b64u,
                    body.epoch,
                    body.commit_b64u,
                    body.member_did,
                    "removed",
                )
            }
            _ => return Err(invalid_journal(request_id)),
        };
    if group_did != completed.group_did
        || crypto_id != completed.crypto_group_id_b64u
        || epoch != completed.to_epoch.to_string()
        || body_commit != commit
        || subject != completed.subject_did
        || subject_status != completed.subject_status
    {
        return Err(invalid_journal(request_id));
    }
    // No OpenMLS mutation: the caller marks only the obsolete journal aborted.
    Ok(true)
}

fn invalid_journal(request_id: &str) -> GroupMlsOperationError {
    operation_error(
        "group.e2ee.state_not_ready",
        "membership recovery journal is invalid",
        request_id,
    )
}
