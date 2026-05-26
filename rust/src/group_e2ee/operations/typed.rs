//! Typed one-shot group MLS operation facade.
//!
//! This module keeps provider, SQLite path, and OpenMLS storage details behind
//! `GroupMlsStore` while reusing the internal OpenMLS operation implementation.

use super::{
    real_commit_process, real_group_add_member, real_group_commit_abort,
    real_group_commit_finalize, real_group_create, real_group_leave,
    real_group_recover_member_prepare, real_group_remove_member, real_group_status,
    real_group_update_member_prepare, real_key_package, real_message_decrypt, real_message_encrypt,
    real_welcome_process,
};
use crate::group_e2ee::storage::{GroupMlsOperationScope, GroupMlsOwnerScope, GroupMlsStore};
use crate::group_e2ee::{
    GroupApplicationPlaintext, GroupCipherObject, GroupKeyPackage, GroupStateRef,
    GROUP_CIPHER_CONTENT_TYPE, SECURITY_PROFILE,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenerateKeyPackageInput {
    pub owner_did: String,
    pub device_id: String,
    pub operation_id: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_package_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_did: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupKeyPackageOutput {
    pub group_key_package: GroupKeyPackage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CreateGroupInput {
    pub creator_did: String,
    pub device_id: String,
    pub group_did: String,
    pub operation_id: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_commit_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AddMemberInput {
    pub actor_did: String,
    pub device_id: String,
    pub group_did: String,
    pub member_did: String,
    pub group_key_package: GroupKeyPackage,
    pub operation_id: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_commit_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RemoveMemberInput {
    pub actor_did: String,
    pub device_id: String,
    pub group_did: String,
    pub member_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_state_ref: Option<GroupStateRef>,
    pub operation_id: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_commit_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeaveGroupInput {
    pub actor_did: String,
    pub device_id: String,
    pub group_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_state_ref: Option<GroupStateRef>,
    pub operation_id: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_commit_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateMemberInput {
    pub actor_did: String,
    pub device_id: String,
    pub group_did: String,
    pub member_did: String,
    pub target_device_id: String,
    pub group_key_package: GroupKeyPackage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_state_ref: Option<GroupStateRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_key_package_id: Option<String>,
    pub operation_id: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_commit_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoverMemberInput {
    pub actor_did: String,
    pub device_id: String,
    pub group_did: String,
    pub member_did: String,
    pub target_device_id: String,
    pub group_key_package: GroupKeyPackage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_state_ref: Option<GroupStateRef>,
    pub operation_id: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_commit_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalizeCommitInput {
    pub pending_commit_id: String,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbortCommitInput {
    pub pending_commit_id: String,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusInput {
    pub request_id: String,
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_did: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessWelcomeInput {
    pub agent_did: String,
    pub device_id: String,
    pub group_did: String,
    pub welcome_b64u: String,
    pub ratchet_tree_b64u: String,
    pub group_state_ref: GroupStateRef,
    pub crypto_group_id_b64u: String,
    pub epoch: String,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessNoticeInput {
    pub recipient_did: String,
    pub device_id: String,
    pub group_did: String,
    pub commit_b64u: String,
    pub from_epoch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_did: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_status: Option<String>,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncryptInput {
    pub sender_did: String,
    pub device_id: String,
    pub group_state_ref: GroupStateRef,
    pub message_id: String,
    pub operation_id: String,
    pub application_plaintext: GroupApplicationPlaintext,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecryptInput {
    pub recipient_did: String,
    pub device_id: String,
    pub group_did: String,
    pub sender_did: String,
    pub message_id: String,
    pub operation_id: String,
    pub group_cipher_object: GroupCipherObject,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedMlsCommitOutput {
    pub pending_commit_id: String,
    pub operation_id: String,
    pub status: String,
    pub actor_did: String,
    pub subject_did: String,
    pub subject_status: String,
    pub group_did: String,
    pub crypto_group_id_b64u: String,
    pub from_epoch: String,
    pub epoch: String,
    pub to_epoch: String,
    pub local_epoch: String,
    pub commit_b64u: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub welcome_b64u: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree_b64u: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_info_b64u: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_authenticator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_authenticator_b64u: Option<String>,
    pub suite: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_did: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalizeCommitOutput {
    pub pending_commit_id: String,
    pub operation_id: String,
    pub group_did: String,
    pub crypto_group_id_b64u: String,
    pub status: String,
    pub from_epoch: String,
    pub epoch: String,
    pub local_epoch: String,
    pub subject_did: String,
    pub subject_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_authenticator: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AbortCommitOutput {
    pub pending_commit_id: String,
    pub operation_id: String,
    pub group_did: String,
    pub crypto_group_id_b64u: String,
    pub status: String,
    pub local_epoch: String,
    pub subject_did: String,
    pub subject_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusOutput {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_epoch: Option<String>,
    #[serde(default)]
    pub pending_commits: Vec<PendingCommitStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_authenticator: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessWelcomeOutput {
    pub crypto_group_id_b64u: String,
    pub epoch: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub already_processed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_authenticator: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessNoticeOutput {
    pub crypto_group_id_b64u: String,
    pub status: String,
    pub self_removed: bool,
    pub from_epoch: String,
    pub epoch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch_authenticator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree_b64u: Option<String>,
    pub subject_did: String,
    pub subject_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptOutput {
    pub group_cipher_object: GroupCipherObject,
    pub authenticated_data_sha256_b64u: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecryptOutput {
    pub application_plaintext: GroupApplicationPlaintext,
    pub epoch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingCommitStatus {
    pub pending_commit_id: String,
    pub operation_id: String,
    pub agent_did: String,
    pub device_id: String,
    pub group_did: String,
    pub subject_did: String,
    pub subject_status: String,
    pub from_epoch: String,
    pub to_epoch: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupMlsOperationError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

impl std::fmt::Display for GroupMlsOperationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.request_id {
            Some(request_id) => write!(f, "{}: {} ({request_id})", self.code, self.message),
            None => write!(f, "{}: {}", self.code, self.message),
        }
    }
}

impl std::error::Error for GroupMlsOperationError {}

impl From<Value> for GroupMlsOperationError {
    fn from(value: Value) -> Self {
        let error_value = value.get("error").unwrap_or(&value);
        Self {
            code: error_value
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("group_mls_operation_failed")
                .to_owned(),
            message: error_value
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("group MLS operation failed")
                .to_owned(),
            request_id: error_value
                .get("request_id")
                .or_else(|| value.get("request_id"))
                .and_then(Value::as_str)
                .map(str::to_owned),
        }
    }
}

pub type GroupMlsOperationResult<T> = Result<T, GroupMlsOperationError>;

pub fn generate_key_package<S: GroupMlsStore>(
    store: &S,
    input: GenerateKeyPackageInput,
) -> GroupMlsOperationResult<GroupKeyPackageOutput> {
    let owner_scope = store.owner_scope();
    validate_store_scope(
        owner_scope.as_ref(),
        Some(input.owner_did.as_str()),
        input.device_id.as_str(),
        &input.request_id,
    )?;
    let mut scope = open_scope(store, &input.request_id)?;
    let mut params = json!({
        "owner_did": input.owner_did,
        "device_id": input.device_id,
    });
    insert_optional_string(&mut params, "key_package_id", input.key_package_id);
    insert_optional_string(&mut params, "purpose", input.purpose);
    insert_optional_string(&mut params, "group_did", input.group_did);
    let result = real_key_package(
        &mut scope.provider,
        &scope.app_conn,
        &params,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    decode_output(result)
}

pub fn create_group_prepare<S: GroupMlsStore>(
    store: &S,
    input: CreateGroupInput,
) -> GroupMlsOperationResult<PreparedMlsCommitOutput> {
    let owner_scope = store.owner_scope();
    validate_store_scope(
        owner_scope.as_ref(),
        Some(input.creator_did.as_str()),
        input.device_id.as_str(),
        &input.request_id,
    )?;
    let mut scope = open_scope(store, &input.request_id)?;
    let mut params = json!({
        "agent_did": input.creator_did,
        "device_id": input.device_id,
        "group_did": input.group_did,
    });
    insert_optional_string(&mut params, "pending_commit_id", input.pending_commit_id);
    let result = real_group_create(
        &mut scope.provider,
        &scope.app_conn,
        &params,
        &input.operation_id,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    decode_output(result)
}

pub fn add_member_prepare<S: GroupMlsStore>(
    store: &S,
    input: AddMemberInput,
) -> GroupMlsOperationResult<PreparedMlsCommitOutput> {
    let owner_scope = store.owner_scope();
    validate_store_scope(
        owner_scope.as_ref(),
        Some(input.actor_did.as_str()),
        input.device_id.as_str(),
        &input.request_id,
    )?;
    let mut scope = open_scope(store, &input.request_id)?;
    let mut params = json!({
        "actor_did": input.actor_did,
        "device_id": input.device_id,
        "group_did": input.group_did,
        "member_did": input.member_did,
        "group_key_package": input.group_key_package,
    });
    insert_optional_string(&mut params, "pending_commit_id", input.pending_commit_id);
    let result = real_group_add_member(
        &mut scope.provider,
        &scope.app_conn,
        &params,
        &input.operation_id,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    decode_output(result)
}

pub fn remove_member_prepare<S: GroupMlsStore>(
    store: &S,
    input: RemoveMemberInput,
) -> GroupMlsOperationResult<PreparedMlsCommitOutput> {
    let owner_scope = store.owner_scope();
    validate_store_scope(
        owner_scope.as_ref(),
        Some(input.actor_did.as_str()),
        input.device_id.as_str(),
        &input.request_id,
    )?;
    let mut scope = open_scope(store, &input.request_id)?;
    let mut params = json!({
        "actor_did": input.actor_did,
        "device_id": input.device_id,
        "group_did": input.group_did,
        "member_did": input.member_did,
    });
    insert_optional_value(&mut params, "group_state_ref", input.group_state_ref);
    insert_optional_string(&mut params, "pending_commit_id", input.pending_commit_id);
    let result = real_group_remove_member(
        &mut scope.provider,
        &scope.app_conn,
        &params,
        &input.operation_id,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    decode_output(result)
}

pub fn leave_prepare<S: GroupMlsStore>(
    store: &S,
    input: LeaveGroupInput,
) -> GroupMlsOperationResult<PreparedMlsCommitOutput> {
    let owner_scope = store.owner_scope();
    validate_store_scope(
        owner_scope.as_ref(),
        Some(input.actor_did.as_str()),
        input.device_id.as_str(),
        &input.request_id,
    )?;
    let mut scope = open_scope(store, &input.request_id)?;
    let mut params = json!({
        "actor_did": input.actor_did,
        "device_id": input.device_id,
        "group_did": input.group_did,
    });
    insert_optional_value(&mut params, "group_state_ref", input.group_state_ref);
    insert_optional_string(&mut params, "pending_commit_id", input.pending_commit_id);
    let result = real_group_leave(
        &mut scope.provider,
        &scope.app_conn,
        &params,
        &input.operation_id,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    decode_output(result)
}

pub fn update_member_prepare<S: GroupMlsStore>(
    store: &S,
    input: UpdateMemberInput,
) -> GroupMlsOperationResult<PreparedMlsCommitOutput> {
    let owner_scope = store.owner_scope();
    validate_store_scope(
        owner_scope.as_ref(),
        Some(input.actor_did.as_str()),
        input.device_id.as_str(),
        &input.request_id,
    )?;
    let mut scope = open_scope(store, &input.request_id)?;
    let mut params = json!({
        "actor_did": input.actor_did,
        "device_id": input.device_id,
        "group_did": input.group_did,
        "member_did": input.member_did,
        "target_device_id": input.target_device_id,
        "group_key_package": input.group_key_package,
    });
    insert_optional_value(&mut params, "group_state_ref", input.group_state_ref);
    insert_optional_string(
        &mut params,
        "update_key_package_id",
        input.update_key_package_id,
    );
    insert_optional_string(&mut params, "pending_commit_id", input.pending_commit_id);
    let result = real_group_update_member_prepare(
        &mut scope.provider,
        &scope.app_conn,
        &params,
        &input.operation_id,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    decode_output(result)
}

pub fn recover_member_prepare<S: GroupMlsStore>(
    store: &S,
    input: RecoverMemberInput,
) -> GroupMlsOperationResult<PreparedMlsCommitOutput> {
    let owner_scope = store.owner_scope();
    validate_store_scope(
        owner_scope.as_ref(),
        Some(input.actor_did.as_str()),
        input.device_id.as_str(),
        &input.request_id,
    )?;
    let mut scope = open_scope(store, &input.request_id)?;
    let mut params = json!({
        "actor_did": input.actor_did,
        "device_id": input.device_id,
        "group_did": input.group_did,
        "member_did": input.member_did,
        "target_device_id": input.target_device_id,
        "group_key_package": input.group_key_package,
    });
    insert_optional_value(&mut params, "group_state_ref", input.group_state_ref);
    insert_optional_string(&mut params, "pending_commit_id", input.pending_commit_id);
    let result = real_group_recover_member_prepare(
        &mut scope.provider,
        &scope.app_conn,
        &params,
        &input.operation_id,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    decode_output(result)
}

pub fn finalize_commit<S: GroupMlsStore>(
    store: &S,
    input: FinalizeCommitInput,
) -> GroupMlsOperationResult<FinalizeCommitOutput> {
    let mut scope = open_scope(store, &input.request_id)?;
    let params = json!({
        "pending_commit_id": input.pending_commit_id,
    });
    let result = real_group_commit_finalize(
        &mut scope.provider,
        &scope.app_conn,
        &params,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    decode_output(result)
}

pub fn abort_commit<S: GroupMlsStore>(
    store: &S,
    input: AbortCommitInput,
) -> GroupMlsOperationResult<AbortCommitOutput> {
    let mut scope = open_scope(store, &input.request_id)?;
    let params = json!({
        "pending_commit_id": input.pending_commit_id,
    });
    let result = real_group_commit_abort(
        &mut scope.provider,
        &scope.app_conn,
        &params,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    decode_output(result)
}

pub fn status<S: GroupMlsStore>(
    store: &S,
    input: StatusInput,
) -> GroupMlsOperationResult<StatusOutput> {
    let owner_scope = store.owner_scope();
    validate_store_scope(
        owner_scope.as_ref(),
        input.agent_did.as_deref(),
        input.device_id.as_str(),
        &input.request_id,
    )?;
    let mut scope = open_scope(store, &input.request_id)?;
    let data_dir = scope.data_dir().to_path_buf();
    let mut params = json!({
        "device_id": input.device_id,
    });
    insert_optional_string(&mut params, "agent_did", input.agent_did);
    insert_optional_string(&mut params, "group_did", input.group_did);
    let result = real_group_status(
        &mut scope.provider,
        &scope.app_conn,
        &params,
        &data_dir,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    status_output_from_value(result)
}

pub fn process_welcome<S: GroupMlsStore>(
    store: &S,
    input: ProcessWelcomeInput,
) -> GroupMlsOperationResult<ProcessWelcomeOutput> {
    let owner_scope = store.owner_scope();
    validate_store_scope(
        owner_scope.as_ref(),
        Some(input.agent_did.as_str()),
        input.device_id.as_str(),
        &input.request_id,
    )?;
    let mut scope = open_scope(store, &input.request_id)?;
    let params = json!({
        "agent_did": input.agent_did,
        "device_id": input.device_id,
        "group_did": input.group_did,
        "welcome_b64u": input.welcome_b64u,
        "ratchet_tree_b64u": input.ratchet_tree_b64u,
        "group_state_ref": input.group_state_ref,
        "crypto_group_id_b64u": input.crypto_group_id_b64u,
        "epoch": input.epoch,
    });
    let result = real_welcome_process(
        &mut scope.provider,
        &scope.app_conn,
        &params,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    process_welcome_output_from_value(result)
}

pub fn process_notice<S: GroupMlsStore>(
    store: &S,
    input: ProcessNoticeInput,
) -> GroupMlsOperationResult<ProcessNoticeOutput> {
    let owner_scope = store.owner_scope();
    validate_store_scope(
        owner_scope.as_ref(),
        Some(input.recipient_did.as_str()),
        input.device_id.as_str(),
        &input.request_id,
    )?;
    let mut scope = open_scope(store, &input.request_id)?;
    let mut params = json!({
        "recipient_did": input.recipient_did,
        "device_id": input.device_id,
        "group_did": input.group_did,
        "from_epoch": input.from_epoch,
        "commit_b64u": input.commit_b64u,
    });
    insert_optional_string(&mut params, "subject_did", input.subject_did);
    insert_optional_string(&mut params, "subject_status", input.subject_status);
    let result = real_commit_process(
        &mut scope.provider,
        &scope.app_conn,
        &params,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    process_notice_output_from_value(result)
}

pub fn encrypt<S: GroupMlsStore>(
    store: &S,
    input: EncryptInput,
) -> GroupMlsOperationResult<EncryptOutput> {
    let owner_scope = store.owner_scope();
    validate_store_scope(
        owner_scope.as_ref(),
        Some(input.sender_did.as_str()),
        input.device_id.as_str(),
        &input.request_id,
    )?;
    let mut scope = open_scope(store, &input.request_id)?;
    let params = json!({
        "sender_did": input.sender_did,
        "device_id": input.device_id,
        "group_state_ref": input.group_state_ref,
        "content_type": GROUP_CIPHER_CONTENT_TYPE,
        "security_profile": SECURITY_PROFILE,
        "message_id": input.message_id,
        "operation_id": input.operation_id,
        "application_plaintext": input.application_plaintext,
    });
    let result = real_message_encrypt(
        &mut scope.provider,
        &scope.app_conn,
        &params,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    encrypt_output_from_value(result)
}

pub fn decrypt<S: GroupMlsStore>(
    store: &S,
    input: DecryptInput,
) -> GroupMlsOperationResult<DecryptOutput> {
    let owner_scope = store.owner_scope();
    validate_store_scope(
        owner_scope.as_ref(),
        Some(input.recipient_did.as_str()),
        input.device_id.as_str(),
        &input.request_id,
    )?;
    let mut scope = open_scope(store, &input.request_id)?;
    let params = json!({
        "recipient_did": input.recipient_did,
        "device_id": input.device_id,
        "group_did": input.group_did,
        "sender_did": input.sender_did,
        "content_type": GROUP_CIPHER_CONTENT_TYPE,
        "security_profile": SECURITY_PROFILE,
        "message_id": input.message_id,
        "operation_id": input.operation_id,
        "group_cipher_object": input.group_cipher_object,
    });
    let result = real_message_decrypt(
        &mut scope.provider,
        &scope.app_conn,
        &params,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    decode_output(result)
}

fn open_scope<S: GroupMlsStore>(
    store: &S,
    request_id: &str,
) -> GroupMlsOperationResult<GroupMlsOperationScope> {
    store
        .open_operation()
        .map_err(|err| GroupMlsOperationError {
            code: err.code().to_owned(),
            message: err.to_string(),
            request_id: Some(request_id.to_owned()),
        })
}

fn validate_store_scope(
    scope: Option<&GroupMlsOwnerScope>,
    owner_did: Option<&str>,
    device_id: &str,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    let Some(scope) = scope else {
        return Ok(());
    };
    if let Some(owner_did) = owner_did {
        if owner_did != scope.owner_did {
            return Err(GroupMlsOperationError {
                code: "owner_scope_mismatch".to_owned(),
                message: "operation owner_did is outside the group MLS store owner scope"
                    .to_owned(),
                request_id: Some(request_id.to_owned()),
            });
        }
    }
    if device_id != scope.device_id {
        return Err(GroupMlsOperationError {
            code: "owner_scope_mismatch".to_owned(),
            message: "operation device_id is outside the group MLS store owner scope".to_owned(),
            request_id: Some(request_id.to_owned()),
        });
    }
    Ok(())
}

fn decode_output<T: for<'de> Deserialize<'de>>(value: Value) -> GroupMlsOperationResult<T> {
    serde_json::from_value(value).map_err(|err| GroupMlsOperationError {
        code: "operation_output_decode_failed".to_owned(),
        message: err.to_string(),
        request_id: None,
    })
}

fn status_output_from_value(value: Value) -> GroupMlsOperationResult<StatusOutput> {
    let pending_commits = value
        .get("pending_commits")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .cloned()
                .map(decode_output)
                .collect::<GroupMlsOperationResult<Vec<PendingCommitStatus>>>()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(StatusOutput {
        status: required_output_string(&value, "status")?,
        epoch: output_string(&value, "epoch"),
        local_epoch: output_string(&value, "local_epoch"),
        pending_commits,
        epoch_authenticator: output_string(&value, "epoch_authenticator"),
    })
}

fn process_welcome_output_from_value(
    value: Value,
) -> GroupMlsOperationResult<ProcessWelcomeOutput> {
    Ok(ProcessWelcomeOutput {
        crypto_group_id_b64u: required_output_string(&value, "crypto_group_id_b64u")?,
        epoch: required_output_string(&value, "epoch")?,
        status: required_output_string(&value, "status")?,
        already_processed: value.get("already_processed").and_then(Value::as_bool),
        epoch_authenticator: output_string(&value, "epoch_authenticator"),
    })
}

fn process_notice_output_from_value(value: Value) -> GroupMlsOperationResult<ProcessNoticeOutput> {
    Ok(ProcessNoticeOutput {
        crypto_group_id_b64u: required_output_string(&value, "crypto_group_id_b64u")?,
        status: required_output_string(&value, "status")?,
        self_removed: value
            .get("self_removed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        from_epoch: required_output_string(&value, "from_epoch")?,
        epoch: required_output_string(&value, "epoch")?,
        epoch_authenticator: output_string(&value, "epoch_authenticator"),
        ratchet_tree_b64u: output_string(&value, "ratchet_tree_b64u"),
        subject_did: required_output_string(&value, "subject_did")?,
        subject_status: required_output_string(&value, "subject_status")?,
    })
}

fn encrypt_output_from_value(value: Value) -> GroupMlsOperationResult<EncryptOutput> {
    let group_cipher_object = value
        .get("group_cipher_object")
        .cloned()
        .ok_or_else(|| GroupMlsOperationError {
            code: "operation_output_decode_failed".to_owned(),
            message: "missing output field: group_cipher_object".to_owned(),
            request_id: None,
        })
        .and_then(decode_output)?;
    Ok(EncryptOutput {
        group_cipher_object,
        authenticated_data_sha256_b64u: required_output_string(
            &value,
            "authenticated_data_sha256_b64u",
        )?,
    })
}

fn output_string(value: &Value, key: &'static str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn required_output_string(value: &Value, key: &'static str) -> GroupMlsOperationResult<String> {
    output_string(value, key).ok_or_else(|| GroupMlsOperationError {
        code: "operation_output_decode_failed".to_owned(),
        message: format!("missing output field: {key}"),
        request_id: None,
    })
}

fn insert_optional_string(target: &mut Value, key: &str, value: Option<String>) {
    if let Some(value) = value {
        target[key] = json!(value);
    }
}

fn insert_optional_value<T: Serialize>(target: &mut Value, key: &str, value: Option<T>) {
    if let Some(value) = value {
        target[key] = json!(value);
    }
}
