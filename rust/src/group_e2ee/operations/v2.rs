//! Persistent P6 v2 OpenMLS operations.
//!
//! This module deliberately does not reinterpret the legacy typed runtime as
//! v2.  It uses the same device-scoped [`GroupMlsStore`] boundary while
//! enforcing the v2 LeafNode device binding, exact-device membership changes,
//! and RFC 8785 authenticated data.

use super::{
    active_binding, binding, binding_status, ciphersuite, decode_b64u, delete_binding,
    delete_openmls_group_state, encode_b64u, ensure_agent, load_group, load_signer,
    mark_binding_inactive, pending_commit, set_binding_epoch_status, sqlite_error,
    update_pending_commit_status, upsert_binding, upsert_binding_status,
};
use crate::group_e2ee::storage::{GroupMlsOperationScope, GroupMlsOwnerScope, GroupMlsStore};
use crate::group_e2ee::{
    canonical_group_application_plaintext_v2, generate_did_wba_binding_v2,
    group_add_submission_binding_v2, group_remove_submission_binding_v2,
    group_send_authenticated_data_v2, parse_group_application_plaintext_v2,
    validate_group_key_package_binding_v2, validate_leaf_identity_set_v2,
    verify_did_wba_binding_v2, V2DidWbaBinding, V2DidWbaBindingUnsigned, V2E2eeNotice,
    V2GroupAddBody, V2GroupApplicationPlaintext, V2GroupCipherObject, V2GroupControlMetadata,
    V2GroupCreateBody, V2GroupKeyPackage, V2GroupNoticeMetadata, V2GroupRemoveBody,
    V2GroupSendMetadata, V2GroupStateRef, V2KeyPackageBindingEvidence, V2LeafBindingEvidence,
    V2LeafExtension, V2LeafIdentity, V2PublishKeyPackageBody, V2PublishKeyPackageResult,
    V2ServiceMetadata, DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2, GROUP_E2EE_MTI_SUITE_V2,
    GROUP_E2EE_SECURITY_PROFILE_V2, GROUP_E2EE_TRANSPORT_PROFILE_V2, METHOD_GROUP_ADD_V2,
    METHOD_GROUP_REMOVE_V2,
};
use crate::PrivateKeyMaterial;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::DateTime;
use openmls::prelude::{
    tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize},
    *,
};
use openmls_traits::OpenMlsProvider;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

use super::typed::{GroupMlsOperationError, GroupMlsOperationResult};

const CRYPTO_GROUP_ID_LEN: usize = 32;
const KEY_PACKAGE_PUBLISH_COMMAND: &str = "group.e2ee.publish-key-package.v2";
const KEY_PACKAGE_PUBLISH_JOURNAL_VERSION: &str = "v1";
const P6_V2_WIRE_FORMAT_POLICY: WireFormatPolicy = PURE_PLAINTEXT_WIRE_FORMAT_POLICY;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V2DidDocument {
    pub did: String,
    pub document: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2GenerateKeyPackageInput {
    pub owner_did: String,
    pub owner_device_id: String,
    pub verification_method: String,
    pub key_package_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub now: String,
    pub draft_extension_negotiated: bool,
    pub request_id: String,
}

/// Stable input for preparing or resuming one device-scoped P6 publish.
///
/// `issued_at`, `expires_at`, `now`, and `request_id` are retry-time inputs.
/// The first generated public package is persisted and wins; later retries
/// return that exact package rather than regenerating it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V2PrepareKeyPackagePublishInput {
    pub meta: V2ServiceMetadata,
    pub owner_did: String,
    pub owner_device_id: String,
    pub verification_method: String,
    pub key_package_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub now: String,
    pub draft_extension_negotiated: bool,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum V2KeyPackagePublishStatus {
    Prepared,
    Accepted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2PreparedKeyPackagePublish {
    pub meta: V2ServiceMetadata,
    pub body: V2PublishKeyPackageBody,
    pub status: V2KeyPackagePublishStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_result: Option<V2PublishKeyPackageResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2AcceptKeyPackagePublishInput {
    pub owner_did: String,
    pub owner_device_id: String,
    pub operation_id: String,
    pub result: V2PublishKeyPackageResult,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct V2KeyPackagePublishJournal {
    journal_version: String,
    #[serde(default)]
    generation: u64,
    #[serde(default)]
    base_operation_id: String,
    #[serde(default)]
    base_key_package_id: String,
    #[serde(default)]
    family_digest: String,
    meta: V2ServiceMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<V2PublishKeyPackageBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_result: Option<V2PublishKeyPackageResult>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    superseded_attempts: Vec<V2SupersededKeyPackagePublishAttempt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct V2SupersededKeyPackagePublishAttempt {
    generation: u64,
    operation_id: String,
    key_package_id: String,
    input_digest: String,
    status: String,
    superseded_at: String,
}

type LoadedKeyPackagePublishOperation = (String, String, String, String, String);

#[derive(Clone, Copy, PartialEq, Eq)]
enum UnresolvedLegacyFamilyPolicy {
    FailClosed,
    Ignore,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V2CreateGroupInput {
    pub meta: crate::group_e2ee::V2ServiceMetadata,
    pub group_state_ref: V2GroupStateRef,
    pub creator_key_package: V2GroupKeyPackage,
    pub creator_did_document: Value,
    pub now: String,
    pub draft_extension_negotiated: bool,
    pub pending_commit_id: String,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V2AddMemberInput {
    pub meta: V2GroupControlMetadata,
    pub group_state_ref: V2GroupStateRef,
    pub group_key_package: V2GroupKeyPackage,
    pub member_did_document: Value,
    pub now: String,
    pub draft_extension_negotiated: bool,
    pub pending_commit_id: String,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V2RemoveMemberInput {
    pub meta: V2GroupControlMetadata,
    pub group_state_ref: V2GroupStateRef,
    pub member_did: String,
    pub member_device_id: String,
    pub member_did_document: Value,
    pub now: String,
    pub draft_extension_negotiated: bool,
    pub pending_commit_id: String,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2PreparedCreate {
    pub pending_commit_id: String,
    pub body: V2GroupCreateBody,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2PreparedAdd {
    pub pending_commit_id: String,
    pub from_epoch: String,
    pub body: V2GroupAddBody,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2PreparedRemove {
    pub pending_commit_id: String,
    pub from_epoch: String,
    pub body: V2GroupRemoveBody,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2FinalizeInput {
    pub pending_commit_id: String,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2FinalizeOutput {
    pub pending_commit_id: String,
    pub operation_id: String,
    pub group_did: String,
    pub crypto_group_id_b64u: String,
    pub from_epoch: String,
    pub epoch: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V2ProcessWelcomeInput {
    pub recipient_did: String,
    pub recipient_device_id: String,
    pub group_did: String,
    pub group_state_ref: V2GroupStateRef,
    pub crypto_group_id_b64u: String,
    pub epoch: String,
    pub welcome_b64u: String,
    pub ratchet_tree_b64u: String,
    pub member_documents: Vec<V2DidDocument>,
    pub now: String,
    pub draft_extension_negotiated: bool,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum V2MembershipCommitMethod {
    Add,
    Remove,
}

impl V2MembershipCommitMethod {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Add => METHOD_GROUP_ADD_V2,
            Self::Remove => METHOD_GROUP_REMOVE_V2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V2ProcessCommitInput {
    pub recipient_did: String,
    pub recipient_device_id: String,
    pub meta: V2GroupControlMetadata,
    pub group_state_ref: V2GroupStateRef,
    pub crypto_group_id_b64u: String,
    pub epoch: String,
    pub member_did: String,
    pub member_device_id: String,
    pub commit_b64u: String,
    pub method: V2MembershipCommitMethod,
    pub sender_did_document: Value,
    pub member_did_document: Value,
    pub now: String,
    pub draft_extension_negotiated: bool,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2ProcessCommitOutput {
    pub crypto_group_id_b64u: String,
    pub from_epoch: String,
    pub epoch: String,
    pub self_removed: bool,
}

/// Standard P6 v2 notice input for one exact local device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V2ProcessNoticeInput {
    pub recipient_did: String,
    pub recipient_device_id: String,
    pub meta: V2GroupNoticeMetadata,
    pub notice: V2E2eeNotice,
    pub member_documents: Vec<V2DidDocument>,
    pub now: String,
    pub draft_extension_negotiated: bool,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2ProcessNoticeOutput {
    pub notice_operation_id: String,
    pub source_operation_id: Option<String>,
    pub notice_type: String,
    pub crypto_group_id_b64u: String,
    pub from_epoch: String,
    pub epoch: String,
    pub self_removed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2ReconcilePendingInput {
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2ReconciledPendingCommit {
    pub pending_commit_id: String,
    pub operation_id: String,
    pub group_did: String,
    pub previous_status: String,
    pub status: String,
    pub action: String,
    pub prepared_response: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2ReconcilePendingOutput {
    pub pending_commits: Vec<V2ReconciledPendingCommit>,
}

/// Secret-free local readiness for one exact DID/device/group store.
///
/// This is a local SDK API, not an ANP wire object. It deliberately exposes no
/// OpenMLS group id, Leaf index, epoch authenticator, key material, Commit, or
/// Welcome bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2InspectLocalGroupInput {
    pub owner_did: String,
    pub owner_device_id: String,
    pub group_did: String,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum V2LocalGroupReadiness {
    Missing,
    Active,
    Inactive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2InspectLocalGroupOutput {
    pub group_did: String,
    pub readiness: V2LocalGroupReadiness,
    pub auto_reconcile_pending_count: u32,
    pub host_recheck_pending_count: u32,
}

/// One secret-free DID/device endpoint in the locally accepted MLS tree.
///
/// This is local product state, not an ANP wire object. Current P2 Manifest
/// eligibility and P4 business membership remain product-layer checks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct V2LocalGroupMemberEndpoint {
    pub member_did: String,
    pub member_device_id: String,
}

/// Secret-free current endpoint inventory for one local P6 v2 group.
///
/// The output deliberately omits Leaf indexes, MLS signature keys, epochs,
/// authenticators, Commit/Welcome bytes, and all private state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2ListLocalGroupMemberEndpointsOutput {
    pub group_did: String,
    pub member_endpoints: Vec<V2LocalGroupMemberEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct V2MembershipAuthenticatedData {
    group_did: String,
    crypto_group_id_b64u: String,
    group_state_ref: V2GroupStateRef,
    subject_method: String,
    member_did: String,
    member_device_id: String,
    epoch: String,
    security_profile: String,
    sender_did: String,
    sender_device_id: String,
    operation_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct V2PrepareJournalResponse<T> {
    journal_version: String,
    prepared_response: Option<T>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V2EncryptInput {
    pub meta: V2GroupSendMetadata,
    pub group_state_ref: V2GroupStateRef,
    pub application_plaintext: V2GroupApplicationPlaintext,
    pub sender_did_document: Value,
    pub now: String,
    pub draft_extension_negotiated: bool,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V2DecryptInput {
    pub recipient_did: String,
    pub recipient_device_id: String,
    pub originating_meta: V2GroupSendMetadata,
    pub group_cipher_object: V2GroupCipherObject,
    pub sender_did_document: Value,
    pub now: String,
    pub draft_extension_negotiated: bool,
    pub request_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct V2DecryptOutput {
    pub application_plaintext: V2GroupApplicationPlaintext,
    pub epoch: String,
    pub sender_did: String,
    pub sender_device_id: String,
    pub sender_leaf_signature_key_b64u: String,
}

pub fn generate_key_package_v2<S: GroupMlsStore>(
    store: &S,
    input: V2GenerateKeyPackageInput,
    did_document: &Value,
    device_signing_private_key: &PrivateKeyMaterial,
) -> GroupMlsOperationResult<V2GroupKeyPackage> {
    validate_store_scope(
        store.owner_scope().as_ref(),
        &input.owner_did,
        &input.owner_device_id,
        &input.request_id,
    )?;
    require_non_empty("key_package_id", &input.key_package_id, &input.request_id)?;
    let scope = open_scope(store, &input.request_id)?;
    if key_package_id_exists(&scope, &input.key_package_id, &input.request_id)? {
        return Err(operation_error(
            "group.e2ee.key_package_consumed",
            "key_package_id already exists in this device store",
            &input.request_id,
        ));
    }
    generate_key_package_in_scope(&scope, &input, did_document, device_signing_private_key)
}

/// Persist the public P6 publish before any host/network call and resume it
/// byte-for-byte after a retry or process restart.
pub fn prepare_or_resume_key_package_publish_v2<S: GroupMlsStore>(
    store: &S,
    input: V2PrepareKeyPackagePublishInput,
    did_document: &Value,
    device_signing_private_key: &PrivateKeyMaterial,
) -> GroupMlsOperationResult<V2PreparedKeyPackagePublish> {
    validate_key_package_publish_input(store.owner_scope().as_ref(), &input)?;
    let input_digest = key_package_publish_input_digest(&input)?;
    let family_digest = key_package_publish_family_digest(&input)?;
    let mut scope = open_scope(store, &input.request_id)?;
    let existing = load_key_package_publish_operation(
        &scope.app_conn,
        &input.meta.operation_id,
        &input.request_id,
    )?;

    let mut resumes_preparing = false;
    let mut journal = if let Some((command, stored_digest, response_json, status)) = existing {
        if command != KEY_PACKAGE_PUBLISH_COMMAND {
            return Err(operation_error(
                "group.e2ee.commit_invalid",
                "operation_id is already bound to another group E2EE command",
                &input.request_id,
            ));
        }
        let mut journal = parse_key_package_publish_journal(&response_json, &input.request_id)?;
        let needs_legacy_key_claim = status == "preparing"
            && journal.generation == 0
            && journal.body.is_none()
            && journal.base_key_package_id.is_empty();
        let needs_legacy_terminal_hydration = status == "superseded"
            && journal.generation == 0
            && journal.body.is_none()
            && journal.base_key_package_id.is_empty();
        hydrate_key_package_publish_family(&mut journal, &input, &stored_digest, &family_digest)?;
        validate_key_package_publish_family(&journal, &input, &family_digest)?;
        if needs_legacy_terminal_hydration {
            if stored_digest != input_digest {
                return Err(operation_error(
                    "group.e2ee.commit_invalid",
                    "superseded legacy KeyPackage family was retried with different stable input",
                    &input.request_id,
                ));
            }
            persist_hydrated_legacy_superseded_family(
                &mut scope,
                &input,
                &stored_digest,
                &response_json,
                &journal,
            )?;
            return Err(operation_error(
                "group.e2ee.state_not_ready",
                "legacy KeyPackage publish family is terminally superseded",
                &input.request_id,
            ));
        }
        if status == "accepted" {
            return validate_key_package_publish_journal(
                &scope,
                journal,
                &status,
                &input,
                did_document,
            );
        }
        if status == "prepared" {
            if !key_package_publish_attempt_expired(&scope, &journal, &input, did_document)? {
                if stored_digest != input_digest {
                    return Err(operation_error(
                        "group.e2ee.commit_invalid",
                        "KeyPackage publish operation_id was replayed with different stable input",
                        &input.request_id,
                    ));
                }
                return validate_key_package_publish_journal(
                    &scope,
                    journal,
                    &status,
                    &input,
                    did_document,
                );
            }
            journal = rotate_expired_key_package_publish_attempt(
                &mut scope,
                &input,
                &stored_digest,
                &response_json,
                input_digest.as_str(),
                family_digest.as_str(),
                journal,
            )?;
            resumes_preparing = true;
            journal
        } else {
            if status != "preparing" {
                return Err(operation_error(
                    "group.e2ee.state_not_ready",
                    "KeyPackage publish journal has an unsupported state",
                    &input.request_id,
                ));
            }
            if stored_digest != input_digest {
                return Err(operation_error(
                    "group.e2ee.commit_invalid",
                    "KeyPackage publish operation_id was replayed with different stable input",
                    &input.request_id,
                ));
            }
            if needs_legacy_key_claim
                && !claim_legacy_key_package_publish_family(
                    &mut scope,
                    &input,
                    &stored_digest,
                    &response_json,
                    &journal,
                )?
            {
                return Err(operation_error(
                    "group.e2ee.commit_invalid",
                    "legacy KeyPackage publish family was superseded by an existing wire-ID owner",
                    &input.request_id,
                ));
            }
            resumes_preparing = true;
            journal
        }
    } else {
        if key_package_publish_wire_ids_bound_elsewhere(
            &scope.app_conn,
            &input.meta.operation_id,
            &input.key_package_id,
            None,
            UnresolvedLegacyFamilyPolicy::FailClosed,
            &input.request_id,
        )? {
            return Err(operation_error(
                "group.e2ee.commit_invalid",
                "wire operation_id or key_package_id is already bound to another publish family",
                &input.request_id,
            ));
        }
        if key_package_id_exists(&scope, &input.key_package_id, &input.request_id)? {
            return Err(operation_error(
                "group.e2ee.key_package_consumed",
                "key_package_id already belongs to another local publish operation",
                &input.request_id,
            ));
        }
        let journal = V2KeyPackagePublishJournal {
            journal_version: KEY_PACKAGE_PUBLISH_JOURNAL_VERSION.to_owned(),
            generation: 0,
            base_operation_id: input.meta.operation_id.clone(),
            base_key_package_id: input.key_package_id.clone(),
            family_digest,
            meta: input.meta.clone(),
            body: None,
            accepted_result: None,
            superseded_attempts: Vec::new(),
        };
        scope
            .app_conn
            .execute(
                "INSERT INTO operations(operation_id, command, input_digest, response_json, status, updated_at)\n                 VALUES (?1, ?2, ?3, ?4, 'preparing', CURRENT_TIMESTAMP)",
                params![
                    input.meta.operation_id,
                    KEY_PACKAGE_PUBLISH_COMMAND,
                    input_digest,
                    serialize_key_package_publish_journal(&journal, &input.request_id)?
                ],
            )
            .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
        journal
    };

    if resumes_preparing {
        remove_unreferenced_openmls_key_packages(&scope, journal.body.as_ref(), &input.request_id)?;
    }

    let current_key_package_id = key_package_publish_attempt_id(
        "awiki.group-e2ee.key-package-publish.key-package.v1",
        "kp-attempt-",
        &journal.base_key_package_id,
        journal.generation,
        &input.request_id,
    )?;
    let package = if let Some(body) = journal.body.as_ref() {
        body.group_key_package.clone()
    } else if let Some(package) =
        load_public_key_package(&scope, &current_key_package_id, &input.request_id)?
    {
        if !resumes_preparing {
            return Err(operation_error(
                "group.e2ee.key_package_consumed",
                "key_package_id already belongs to another local publish operation",
                &input.request_id,
            ));
        }
        package
    } else {
        generate_key_package_in_scope(
            &scope,
            &V2GenerateKeyPackageInput {
                owner_did: input.owner_did.clone(),
                owner_device_id: input.owner_device_id.clone(),
                verification_method: input.verification_method.clone(),
                key_package_id: current_key_package_id,
                issued_at: input.issued_at.clone(),
                expires_at: input.expires_at.clone(),
                now: input.now.clone(),
                draft_extension_negotiated: input.draft_extension_negotiated,
                request_id: input.request_id.clone(),
            },
            did_document,
            device_signing_private_key,
        )?
    };
    journal.body = Some(V2PublishKeyPackageBody {
        group_key_package: package,
    });
    journal.accepted_result = None;
    persist_key_package_publish_journal(
        &scope.app_conn,
        &journal.base_operation_id,
        &journal,
        "prepared",
        &input.request_id,
    )?;
    validate_key_package_publish_journal(&scope, journal, "prepared", &input, did_document)
}

/// Record the typed host acceptance for a previously prepared P6 publish.
/// Repeating a semantically equivalent acceptance returns the first cached
/// result; a different owner, device, or KeyPackage fails closed.
pub fn accept_key_package_publish_v2<S: GroupMlsStore>(
    store: &S,
    input: V2AcceptKeyPackagePublishInput,
) -> GroupMlsOperationResult<V2PreparedKeyPackagePublish> {
    validate_store_scope(
        store.owner_scope().as_ref(),
        &input.owner_did,
        &input.owner_device_id,
        &input.request_id,
    )?;
    require_non_empty("operation_id", &input.operation_id, &input.request_id)?;
    input
        .result
        .validate()
        .map_err(|err| v2_error("group.e2ee.state_not_ready", err, &input.request_id))?;
    let scope = open_scope(store, &input.request_id)?;
    let Some((family_operation_id, command, _, response_json, status)) =
        load_key_package_publish_operation_by_wire_id(
            &scope.app_conn,
            &input.operation_id,
            &input.request_id,
        )?
    else {
        return Err(operation_error(
            "group.e2ee.state_not_ready",
            "KeyPackage publish operation is not prepared",
            &input.request_id,
        ));
    };
    if command != KEY_PACKAGE_PUBLISH_COMMAND {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "operation_id is already bound to another group E2EE command",
            &input.request_id,
        ));
    }
    if status != "prepared" && status != "accepted" {
        return Err(operation_error(
            "group.e2ee.state_not_ready",
            "KeyPackage publish must be prepared before acceptance",
            &input.request_id,
        ));
    }
    let mut journal = parse_key_package_publish_journal(&response_json, &input.request_id)?;
    validate_key_package_publish_family_structure(&journal, &input.request_id)?;
    let body = journal.body.as_ref().ok_or_else(|| {
        operation_error(
            "group.e2ee.state_not_ready",
            "prepared KeyPackage publish has no public body",
            &input.request_id,
        )
    })?;
    if journal.meta.operation_id != input.operation_id {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "KeyPackage publish acceptance does not identify the current wire attempt",
            &input.request_id,
        ));
    }
    if input.owner_did != journal.meta.sender_did
        || input.owner_device_id != journal.meta.sender_device_id
        || input.owner_did != body.group_key_package.owner_did
        || input.owner_device_id != body.group_key_package.owner_device_id
    {
        return Err(operation_error(
            "group.e2ee.did_binding_invalid",
            "acceptance owner/device does not match the prepared publish",
            &input.request_id,
        ));
    }
    validate_publish_result_matches(
        &input.result,
        &journal.meta,
        &body.group_key_package,
        &input.request_id,
    )?;
    if journal.accepted_result.is_none() {
        journal.accepted_result = Some(input.result);
        persist_key_package_publish_journal(
            &scope.app_conn,
            &family_operation_id,
            &journal,
            "accepted",
            &input.request_id,
        )?;
    }
    key_package_publish_output(journal, "accepted", &input.request_id)
}

fn generate_key_package_in_scope(
    scope: &GroupMlsOperationScope,
    input: &V2GenerateKeyPackageInput,
    did_document: &Value,
    device_signing_private_key: &PrivateKeyMaterial,
) -> GroupMlsOperationResult<V2GroupKeyPackage> {
    let (credential, signer) = ensure_agent(
        &scope.provider,
        &scope.app_conn,
        &input.owner_did,
        &input.owner_device_id,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    let binding = generate_did_wba_binding_v2(
        V2DidWbaBindingUnsigned {
            agent_did: input.owner_did.clone(),
            device_id: input.owner_device_id.clone(),
            verification_method: input.verification_method.clone(),
            leaf_signature_key_b64u: URL_SAFE_NO_PAD.encode(signer.to_public_vec()),
            issued_at: input.issued_at.clone(),
            expires_at: input.expires_at.clone(),
        },
        device_signing_private_key,
        Some(input.issued_at.clone()),
    )
    .map_err(|err| v2_error("group.e2ee.did_binding_invalid", err, &input.request_id))?;
    let bundle = KeyPackage::builder()
        .leaf_node_capabilities(v2_capabilities())
        .leaf_node_extensions(binding_extensions(&binding, &input.request_id)?)
        .build(ciphersuite(), &scope.provider, &signer, credential)
        .map_err(|err| {
            mls_operation_error("group.e2ee.invalid_key_package", err, &input.request_id)
        })?;
    let result = (|| {
        let bytes = bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|err| {
                mls_operation_error("group.e2ee.invalid_key_package", err, &input.request_id)
            })?;
        let package = V2GroupKeyPackage {
            key_package_id: input.key_package_id.clone(),
            owner_did: input.owner_did.clone(),
            owner_device_id: input.owner_device_id.clone(),
            suite: GROUP_E2EE_MTI_SUITE_V2.to_owned(),
            mls_key_package_b64u: URL_SAFE_NO_PAD.encode(&bytes),
            did_wba_binding: binding,
            expires_at: Some(input.expires_at.clone()),
        };
        let (_, evidence) = parse_and_validate_key_package(
            &scope.provider,
            &package,
            did_document,
            &input.now,
            input.draft_extension_negotiated,
            &input.request_id,
        )?;
        if evidence.leaf.leaf_signature_key_b64u != URL_SAFE_NO_PAD.encode(signer.to_public_vec()) {
            return Err(operation_error(
                "group.e2ee.did_binding_invalid",
                "generated KeyPackage leaf does not use this device's persisted MLS signer",
                &input.request_id,
            ));
        }
        scope
            .app_conn
            .execute(
                "INSERT INTO key_packages(agent_did, device_id, key_package_id, public_json, status)\n             VALUES (?1, ?2, ?3, ?4, 'published')",
                params![
                    &package.owner_did,
                    &package.owner_device_id,
                    &package.key_package_id,
                    serde_json::to_string(&package).map_err(|err| operation_error(
                        "group.e2ee.invalid_key_package",
                        err,
                        &input.request_id,
                    ))?
                ],
            )
            .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
        Ok(package)
    })();
    if result.is_err() {
        remove_unreferenced_openmls_key_packages(scope, None, &input.request_id)?;
    }
    result
}

fn validate_key_package_publish_input(
    scope: Option<&GroupMlsOwnerScope>,
    input: &V2PrepareKeyPackagePublishInput,
) -> GroupMlsOperationResult<()> {
    input
        .meta
        .validate(GROUP_E2EE_TRANSPORT_PROFILE_V2)
        .map_err(|err| v2_error("group.e2ee.state_not_ready", err, &input.request_id))?;
    validate_store_scope(
        scope,
        &input.owner_did,
        &input.owner_device_id,
        &input.request_id,
    )?;
    if input.meta.sender_did != input.owner_did
        || input.meta.sender_device_id != input.owner_device_id
    {
        return Err(operation_error(
            "group.e2ee.did_binding_invalid",
            "publish metadata must identify the exact owner device",
            &input.request_id,
        ));
    }
    for (field, value) in [
        ("verification_method", input.verification_method.as_str()),
        ("key_package_id", input.key_package_id.as_str()),
        ("issued_at", input.issued_at.as_str()),
        ("expires_at", input.expires_at.as_str()),
        ("now", input.now.as_str()),
    ] {
        require_non_empty(field, value, &input.request_id)?;
    }
    Ok(())
}

fn key_package_publish_input_digest(
    input: &V2PrepareKeyPackagePublishInput,
) -> GroupMlsOperationResult<String> {
    // Retry clocks and request IDs deliberately stay out of the digest. The
    // first persisted public package owns its binding timestamps; all stable
    // identity, routing, and authorization inputs remain bound here.
    let canonical = crate::canonical_json::canonicalize_json(&json!({
        "journal_version": KEY_PACKAGE_PUBLISH_JOURNAL_VERSION,
        "meta": input.meta,
        "owner_did": input.owner_did,
        "owner_device_id": input.owner_device_id,
        "verification_method": input.verification_method,
        "key_package_id": input.key_package_id,
        "draft_extension_negotiated": input.draft_extension_negotiated,
    }))
    .map_err(|err| operation_error("group.e2ee.state_not_ready", err, &input.request_id))?;
    Ok(encode_b64u(&Sha256::digest(canonical)))
}

fn key_package_publish_family_digest(
    input: &V2PrepareKeyPackagePublishInput,
) -> GroupMlsOperationResult<String> {
    let canonical = crate::canonical_json::canonicalize_json(&json!({
        "journal_version": KEY_PACKAGE_PUBLISH_JOURNAL_VERSION,
        "anp_version": input.meta.anp_version,
        "profile": input.meta.profile,
        "security_profile": input.meta.security_profile,
        "sender_did": input.meta.sender_did,
        "sender_device_id": input.meta.sender_device_id,
        "target_kind": input.meta.target.kind,
        "target_did": input.meta.target.did,
        "base_operation_id": input.meta.operation_id,
        "owner_did": input.owner_did,
        "owner_device_id": input.owner_device_id,
        "verification_method": input.verification_method,
        "base_key_package_id": input.key_package_id,
        "draft_extension_negotiated": input.draft_extension_negotiated,
    }))
    .map_err(|err| operation_error("group.e2ee.state_not_ready", err, &input.request_id))?;
    Ok(encode_b64u(&Sha256::digest(canonical)))
}

fn key_package_publish_attempt_id(
    domain: &str,
    prefix: &str,
    base_id: &str,
    generation: u64,
    request_id: &str,
) -> GroupMlsOperationResult<String> {
    if generation == 0 {
        return Ok(base_id.to_owned());
    }
    let mut digest = Sha256::new();
    for value in [domain.as_bytes(), base_id.as_bytes()] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.update(generation.to_be_bytes());
    let derived = format!("{prefix}{}", URL_SAFE_NO_PAD.encode(digest.finalize()));
    require_non_empty("derived_attempt_id", &derived, request_id)?;
    Ok(derived)
}

fn key_package_publish_attempt_meta(
    base: &V2ServiceMetadata,
    generation: u64,
    request_id: &str,
) -> GroupMlsOperationResult<V2ServiceMetadata> {
    let mut meta = base.clone();
    meta.operation_id = key_package_publish_attempt_id(
        "awiki.group-e2ee.key-package-publish.operation.v1",
        "kp-op-attempt-",
        &base.operation_id,
        generation,
        request_id,
    )?;
    Ok(meta)
}

fn hydrate_key_package_publish_family(
    journal: &mut V2KeyPackagePublishJournal,
    input: &V2PrepareKeyPackagePublishInput,
    stored_digest: &str,
    family_digest: &str,
) -> GroupMlsOperationResult<()> {
    if journal.base_operation_id.is_empty() {
        if journal.generation != 0 || journal.meta.operation_id != input.meta.operation_id {
            return Err(operation_error(
                "group.e2ee.state_not_ready",
                "legacy KeyPackage publish journal cannot be rebound to another family",
                &input.request_id,
            ));
        }
        journal.base_operation_id = journal.meta.operation_id.clone();
    }
    if journal.base_key_package_id.is_empty() {
        let persisted = journal
            .body
            .as_ref()
            .map(|body| body.group_key_package.key_package_id.as_str())
            .unwrap_or(input.key_package_id.as_str());
        journal.base_key_package_id = persisted.to_owned();
    }
    if journal.family_digest.is_empty() {
        if stored_digest != key_package_publish_input_digest(input)? {
            return Err(operation_error(
                "group.e2ee.commit_invalid",
                "legacy KeyPackage publish journal was replayed with different stable input",
                &input.request_id,
            ));
        }
        journal.family_digest = family_digest.to_owned();
    }
    Ok(())
}

fn validate_key_package_publish_family(
    journal: &V2KeyPackagePublishJournal,
    input: &V2PrepareKeyPackagePublishInput,
    family_digest: &str,
) -> GroupMlsOperationResult<()> {
    if journal.base_operation_id != input.meta.operation_id
        || journal.base_key_package_id != input.key_package_id
        || journal.family_digest != family_digest
    {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "KeyPackage publish family was replayed with different identity input",
            &input.request_id,
        ));
    }
    let expected_meta =
        key_package_publish_attempt_meta(&input.meta, journal.generation, &input.request_id)?;
    if journal.meta.operation_id != expected_meta.operation_id
        || journal.meta.anp_version != input.meta.anp_version
        || journal.meta.profile != input.meta.profile
        || journal.meta.security_profile != input.meta.security_profile
        || journal.meta.sender_did != input.meta.sender_did
        || journal.meta.sender_device_id != input.meta.sender_device_id
        || journal.meta.target.kind != input.meta.target.kind
        || journal.meta.target.did != input.meta.target.did
    {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "persisted KeyPackage publish attempt is not bound to its family",
            &input.request_id,
        ));
    }
    validate_key_package_publish_family_structure(journal, &input.request_id)
}

fn validate_key_package_publish_family_structure(
    journal: &V2KeyPackagePublishJournal,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    if journal.journal_version != KEY_PACKAGE_PUBLISH_JOURNAL_VERSION {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "KeyPackage publish journal version is unsupported",
            request_id,
        ));
    }
    let legacy_generation_zero = journal.generation == 0 && journal.superseded_attempts.is_empty();
    let base_operation_id = if journal.base_operation_id.is_empty() && legacy_generation_zero {
        journal.meta.operation_id.as_str()
    } else {
        require_non_empty("base_operation_id", &journal.base_operation_id, request_id)?;
        journal.base_operation_id.as_str()
    };
    let base_key_package_id = if journal.base_key_package_id.is_empty() && legacy_generation_zero {
        journal
            .body
            .as_ref()
            .map(|body| body.group_key_package.key_package_id.as_str())
            .ok_or_else(|| {
                operation_error(
                    "group.e2ee.state_not_ready",
                    "legacy KeyPackage publish journal has no public body",
                    request_id,
                )
            })?
    } else {
        require_non_empty(
            "base_key_package_id",
            &journal.base_key_package_id,
            request_id,
        )?;
        journal.base_key_package_id.as_str()
    };
    if journal.generation > 0 {
        require_non_empty("family_digest", &journal.family_digest, request_id)?;
    }
    if journal.superseded_attempts.len() as u64 != journal.generation {
        return Err(operation_error(
            "group.e2ee.state_not_ready",
            "KeyPackage publish attempt history is incomplete",
            request_id,
        ));
    }
    let mut operation_ids = HashSet::new();
    let mut key_package_ids = HashSet::new();
    for (expected_generation, attempt) in journal.superseded_attempts.iter().enumerate() {
        let expected_generation = expected_generation as u64;
        let expected_operation_id = key_package_publish_attempt_id(
            "awiki.group-e2ee.key-package-publish.operation.v1",
            "kp-op-attempt-",
            base_operation_id,
            expected_generation,
            request_id,
        )?;
        let expected_key_package_id = key_package_publish_attempt_id(
            "awiki.group-e2ee.key-package-publish.key-package.v1",
            "kp-attempt-",
            base_key_package_id,
            expected_generation,
            request_id,
        )?;
        if attempt.generation != expected_generation
            || attempt.operation_id != expected_operation_id
            || attempt.key_package_id != expected_key_package_id
            || attempt.status != "superseded"
            || !operation_ids.insert(attempt.operation_id.as_str())
            || !key_package_ids.insert(attempt.key_package_id.as_str())
        {
            return Err(operation_error(
                "group.e2ee.commit_invalid",
                "KeyPackage publish attempt history contains a duplicate or invalid binding",
                request_id,
            ));
        }
    }
    let expected_current_operation_id = key_package_publish_attempt_id(
        "awiki.group-e2ee.key-package-publish.operation.v1",
        "kp-op-attempt-",
        base_operation_id,
        journal.generation,
        request_id,
    )?;
    let current_key_package_id = key_package_publish_attempt_id(
        "awiki.group-e2ee.key-package-publish.key-package.v1",
        "kp-attempt-",
        base_key_package_id,
        journal.generation,
        request_id,
    )?;
    if journal.meta.operation_id != expected_current_operation_id
        || !operation_ids.insert(journal.meta.operation_id.as_str())
        || !key_package_ids.insert(current_key_package_id.as_str())
    {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "current KeyPackage publish attempt duplicates its history",
            request_id,
        ));
    }
    if let Some(body) = journal.body.as_ref() {
        if body.group_key_package.key_package_id != current_key_package_id {
            return Err(operation_error(
                "group.e2ee.did_binding_invalid",
                "current KeyPackage is not bound to its publish generation",
                request_id,
            ));
        }
    }
    Ok(())
}

fn load_key_package_publish_operation(
    conn: &rusqlite::Connection,
    operation_id: &str,
    request_id: &str,
) -> GroupMlsOperationResult<Option<(String, String, String, String)>> {
    conn.query_row(
        "SELECT command, input_digest, response_json, status\n         FROM operations WHERE operation_id = ?1",
        params![operation_id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )
    .optional()
    .map_err(|err| sqlite_operation_error(err, request_id))
}

fn load_key_package_publish_operation_by_wire_id(
    conn: &rusqlite::Connection,
    wire_operation_id: &str,
    request_id: &str,
) -> GroupMlsOperationResult<Option<LoadedKeyPackagePublishOperation>> {
    let mut statement = conn
        .prepare(
            "SELECT operation_id, command, input_digest, response_json, status\n             FROM operations WHERE command = ?1",
        )
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    let rows = statement
        .query_map(params![KEY_PACKAGE_PUBLISH_COMMAND], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(|err| sqlite_operation_error(err, request_id))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    drop(statement);
    let mut matches = Vec::new();
    for row in rows {
        if row.4 == "superseded" {
            continue;
        }
        let journal = parse_key_package_publish_journal(&row.3, request_id)?;
        if journal.meta.operation_id == wire_operation_id {
            matches.push(row);
        }
    }
    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.pop()),
        _ => Err(operation_error(
            "group.e2ee.commit_invalid",
            "wire operation_id is ambiguously bound to multiple publish families",
            request_id,
        )),
    }
}

fn key_package_publish_wire_ids_bound_elsewhere(
    conn: &rusqlite::Connection,
    wire_operation_id: &str,
    wire_key_package_id: &str,
    excluded_family_operation_id: Option<&str>,
    unresolved_legacy_policy: UnresolvedLegacyFamilyPolicy,
    request_id: &str,
) -> GroupMlsOperationResult<bool> {
    let mut statement = conn
        .prepare("SELECT operation_id, response_json, status FROM operations WHERE command = ?1")
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    let rows = statement
        .query_map(params![KEY_PACKAGE_PUBLISH_COMMAND], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|err| sqlite_operation_error(err, request_id))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    drop(statement);
    for (family_operation_id, response_json, status) in rows {
        if excluded_family_operation_id == Some(family_operation_id.as_str()) {
            continue;
        }
        let journal = parse_key_package_publish_journal(&response_json, request_id)?;
        if journal.meta.operation_id == wire_operation_id
            || journal
                .superseded_attempts
                .iter()
                .any(|attempt| attempt.operation_id == wire_operation_id)
        {
            return Ok(true);
        }
        let current_key_package_matches = if let Some(body) = journal.body.as_ref() {
            body.group_key_package.key_package_id == wire_key_package_id
        } else if journal.base_key_package_id.is_empty() {
            if status == "superseded"
                || unresolved_legacy_policy == UnresolvedLegacyFamilyPolicy::FailClosed
            {
                return Err(operation_error(
                    "group.e2ee.state_not_ready",
                    format!(
                        "legacy {status} KeyPackage publish family has no recoverable key_package_id; retry its base operation before creating another family"
                    ),
                    request_id,
                ));
            }
            false
        } else {
            key_package_publish_attempt_id(
                "awiki.group-e2ee.key-package-publish.key-package.v1",
                "kp-attempt-",
                &journal.base_key_package_id,
                journal.generation,
                request_id,
            )? == wire_key_package_id
        };
        if current_key_package_matches
            || journal
                .superseded_attempts
                .iter()
                .any(|attempt| attempt.key_package_id == wire_key_package_id)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn parse_key_package_publish_journal(
    response_json: &str,
    request_id: &str,
) -> GroupMlsOperationResult<V2KeyPackagePublishJournal> {
    let journal: V2KeyPackagePublishJournal = serde_json::from_str(response_json)
        .map_err(|err| operation_error("group.e2ee.state_not_ready", err, request_id))?;
    if journal.journal_version != KEY_PACKAGE_PUBLISH_JOURNAL_VERSION {
        return Err(operation_error(
            "group.e2ee.state_not_ready",
            "unsupported KeyPackage publish journal version",
            request_id,
        ));
    }
    Ok(journal)
}

fn serialize_key_package_publish_journal(
    journal: &V2KeyPackagePublishJournal,
    request_id: &str,
) -> GroupMlsOperationResult<String> {
    serde_json::to_string(journal)
        .map_err(|err| operation_error("group.e2ee.state_not_ready", err, request_id))
}

fn key_package_publish_attempt_expired(
    scope: &GroupMlsOperationScope,
    journal: &V2KeyPackagePublishJournal,
    input: &V2PrepareKeyPackagePublishInput,
    did_document: &Value,
) -> GroupMlsOperationResult<bool> {
    let body = journal.body.as_ref().ok_or_else(|| {
        operation_error(
            "group.e2ee.state_not_ready",
            "prepared KeyPackage publish has no public body",
            &input.request_id,
        )
    })?;
    let package = &body.group_key_package;
    parse_and_validate_key_package(
        &scope.provider,
        package,
        did_document,
        package.did_wba_binding.issued_at.as_str(),
        input.draft_extension_negotiated,
        &input.request_id,
    )?;
    let now = DateTime::parse_from_rfc3339(&input.now)
        .map_err(|err| operation_error("group.e2ee.did_binding_invalid", err, &input.request_id))?;
    let binding_expires = DateTime::parse_from_rfc3339(&package.did_wba_binding.expires_at)
        .map_err(|err| operation_error("group.e2ee.did_binding_invalid", err, &input.request_id))?;
    let public_expires = package
        .expires_at
        .as_deref()
        .map(DateTime::parse_from_rfc3339)
        .transpose()
        .map_err(|err| operation_error("group.e2ee.did_binding_invalid", err, &input.request_id))?;
    Ok(now >= binding_expires || public_expires.is_some_and(|expires| now >= expires))
}

fn claim_legacy_key_package_publish_family(
    scope: &mut GroupMlsOperationScope,
    input: &V2PrepareKeyPackagePublishInput,
    stored_digest: &str,
    stored_response_json: &str,
    journal: &V2KeyPackagePublishJournal,
) -> GroupMlsOperationResult<bool> {
    // Old bodyless journals do not retain their base KeyPackage ID. The
    // device-store lock serializes recovery, and this transaction makes the
    // first digest-valid retry the durable owner. A later conflicting retry is
    // terminally superseded instead of adopting the first family's package.
    let transaction = scope
        .app_conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
    let conflict = key_package_publish_wire_ids_bound_elsewhere(
        &transaction,
        &journal.meta.operation_id,
        &journal.base_key_package_id,
        Some(&journal.base_operation_id),
        UnresolvedLegacyFamilyPolicy::Ignore,
        &input.request_id,
    )?;
    let next_response_json = serialize_key_package_publish_journal(journal, &input.request_id)?;
    let next_status = if conflict { "superseded" } else { "preparing" };
    cas_persist_legacy_key_package_publish_family(
        &transaction,
        &journal.base_operation_id,
        stored_digest,
        stored_response_json,
        "preparing",
        &next_response_json,
        next_status,
        &input.request_id,
    )?;
    transaction
        .commit()
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
    Ok(!conflict)
}

fn persist_hydrated_legacy_superseded_family(
    scope: &mut GroupMlsOperationScope,
    input: &V2PrepareKeyPackagePublishInput,
    stored_digest: &str,
    stored_response_json: &str,
    journal: &V2KeyPackagePublishJournal,
) -> GroupMlsOperationResult<()> {
    let transaction = scope
        .app_conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
    let next_response_json = serialize_key_package_publish_journal(journal, &input.request_id)?;
    cas_persist_legacy_key_package_publish_family(
        &transaction,
        &journal.base_operation_id,
        stored_digest,
        stored_response_json,
        "superseded",
        &next_response_json,
        "superseded",
        &input.request_id,
    )?;
    transaction
        .commit()
        .map_err(|err| sqlite_operation_error(err, &input.request_id))
}

#[allow(clippy::too_many_arguments)]
fn cas_persist_legacy_key_package_publish_family(
    transaction: &rusqlite::Transaction<'_>,
    family_operation_id: &str,
    expected_digest: &str,
    expected_response_json: &str,
    expected_status: &str,
    next_response_json: &str,
    next_status: &str,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    let current: Option<(String, String, String)> = transaction
        .query_row(
            "SELECT input_digest, response_json, status FROM operations\n             WHERE operation_id = ?1 AND command = ?2",
            params![family_operation_id, KEY_PACKAGE_PUBLISH_COMMAND],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    if current
        .as_ref()
        .map(|(digest, response, status)| (digest.as_str(), response.as_str(), status.as_str()))
        != Some((expected_digest, expected_response_json, expected_status))
    {
        return Err(operation_error(
            "state_locked",
            "legacy KeyPackage publish family changed during recovery",
            request_id,
        ));
    }
    transaction
        .execute(
            "UPDATE operations\n             SET response_json = ?2, status = ?3, updated_at = CURRENT_TIMESTAMP\n             WHERE operation_id = ?1 AND command = ?4",
            params![
                family_operation_id,
                next_response_json,
                next_status,
                KEY_PACKAGE_PUBLISH_COMMAND,
            ],
        )
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    let persisted: Option<(String, String)> = transaction
        .query_row(
            "SELECT response_json, status FROM operations\n             WHERE operation_id = ?1 AND command = ?2",
            params![family_operation_id, KEY_PACKAGE_PUBLISH_COMMAND],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    if persisted
        .as_ref()
        .map(|(response, status)| (response.as_str(), status.as_str()))
        != Some((next_response_json, next_status))
    {
        return Err(operation_error(
            "group.e2ee.state_not_ready",
            "legacy KeyPackage publish recovery was not persisted",
            request_id,
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn rotate_expired_key_package_publish_attempt(
    scope: &mut GroupMlsOperationScope,
    input: &V2PrepareKeyPackagePublishInput,
    stored_digest: &str,
    stored_response_json: &str,
    next_input_digest: &str,
    next_family_digest: &str,
    mut journal: V2KeyPackagePublishJournal,
) -> GroupMlsOperationResult<V2KeyPackagePublishJournal> {
    let old_body = journal.body.as_ref().ok_or_else(|| {
        operation_error(
            "group.e2ee.state_not_ready",
            "expired KeyPackage publish has no public body",
            &input.request_id,
        )
    })?;
    let old_package = old_body.group_key_package.clone();
    let old_private_ref = openmls_key_package_ref_bytes(
        &scope.provider,
        &old_package.mls_key_package_b64u,
        &input.request_id,
    )?;
    if load_public_key_package(scope, &old_package.key_package_id, &input.request_id)?.as_ref()
        != Some(&old_package)
    {
        return Err(operation_error(
            "group.e2ee.state_not_ready",
            "expired KeyPackage public row does not match its journal",
            &input.request_id,
        ));
    }
    let next_generation = journal.generation.checked_add(1).ok_or_else(|| {
        operation_error(
            "group.e2ee.state_not_ready",
            "KeyPackage publish generation overflow",
            &input.request_id,
        )
    })?;
    let next_meta =
        key_package_publish_attempt_meta(&input.meta, next_generation, &input.request_id)?;
    let next_key_package_id = key_package_publish_attempt_id(
        "awiki.group-e2ee.key-package-publish.key-package.v1",
        "kp-attempt-",
        &journal.base_key_package_id,
        next_generation,
        &input.request_id,
    )?;
    if journal.superseded_attempts.iter().any(|attempt| {
        attempt.operation_id == next_meta.operation_id
            || attempt.key_package_id == next_key_package_id
    }) || journal.meta.operation_id == next_meta.operation_id
        || old_package.key_package_id == next_key_package_id
    {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "derived KeyPackage publish attempt collides with an existing binding",
            &input.request_id,
        ));
    }
    journal
        .superseded_attempts
        .push(V2SupersededKeyPackagePublishAttempt {
            generation: journal.generation,
            operation_id: journal.meta.operation_id.clone(),
            key_package_id: old_package.key_package_id.clone(),
            input_digest: stored_digest.to_owned(),
            status: "superseded".to_owned(),
            superseded_at: input.now.clone(),
        });
    journal.generation = next_generation;
    journal.family_digest = next_family_digest.to_owned();
    journal.meta = next_meta;
    journal.body = None;
    journal.accepted_result = None;
    let next_response_json = serialize_key_package_publish_journal(&journal, &input.request_id)?;

    let transaction = scope
        .app_conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
    let current: Option<(String, String, String)> = transaction
        .query_row(
            "SELECT input_digest, response_json, status FROM operations\n             WHERE operation_id = ?1 AND command = ?2",
            params![&journal.base_operation_id, KEY_PACKAGE_PUBLISH_COMMAND],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
    if current
        .as_ref()
        .map(|(digest, response, status)| (digest.as_str(), response.as_str(), status.as_str()))
        != Some((stored_digest, stored_response_json, "prepared"))
    {
        return Err(operation_error(
            "state_locked",
            "KeyPackage publish attempt changed during rotation",
            &input.request_id,
        ));
    }
    if key_package_publish_wire_ids_bound_elsewhere(
        &transaction,
        &journal.meta.operation_id,
        &next_key_package_id,
        Some(&journal.base_operation_id),
        UnresolvedLegacyFamilyPolicy::FailClosed,
        &input.request_id,
    )? {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "derived wire operation_id or key_package_id is already bound to another publish family",
            &input.request_id,
        ));
    }
    transaction
        .execute(
            "UPDATE operations\n             SET input_digest = ?2, response_json = ?3, status = 'preparing', updated_at = CURRENT_TIMESTAMP\n             WHERE operation_id = ?1 AND command = ?4",
            params![
                &journal.base_operation_id,
                next_input_digest,
                next_response_json,
                KEY_PACKAGE_PUBLISH_COMMAND,
            ],
        )
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
    let updated: Option<(String, String)> = transaction
        .query_row(
            "SELECT input_digest, status FROM operations\n             WHERE operation_id = ?1 AND command = ?2",
            params![&journal.base_operation_id, KEY_PACKAGE_PUBLISH_COMMAND],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
    if updated
        .as_ref()
        .map(|(digest, status)| (digest.as_str(), status.as_str()))
        != Some((next_input_digest, "preparing"))
    {
        return Err(operation_error(
            "group.e2ee.state_not_ready",
            "KeyPackage publish attempt did not enter preparing state",
            &input.request_id,
        ));
    }
    transaction
        .execute(
            "DELETE FROM key_packages\n             WHERE agent_did = ?1 AND device_id = ?2 AND key_package_id = ?3",
            params![
                &old_package.owner_did,
                &old_package.owner_device_id,
                &old_package.key_package_id,
            ],
        )
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
    let public_remaining: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM key_packages\n             WHERE agent_did = ?1 AND device_id = ?2 AND key_package_id = ?3",
            params![
                &old_package.owner_did,
                &old_package.owner_device_id,
                &old_package.key_package_id,
            ],
            |row| row.get(0),
        )
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
    if public_remaining != 0 {
        return Err(operation_error(
            "group.e2ee.state_not_ready",
            "expired KeyPackage public row disappeared during rotation",
            &input.request_id,
        ));
    }
    let private_deleted = transaction
        .execute(
            "DELETE FROM openmls_key_packages WHERE key_package_ref = ?1",
            params![old_private_ref],
        )
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
    if private_deleted > 1 {
        return Err(operation_error(
            "group.e2ee.state_not_ready",
            "expired OpenMLS KeyPackage has multiple private bundles",
            &input.request_id,
        ));
    }
    transaction
        .commit()
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
    Ok(journal)
}

fn persist_key_package_publish_journal(
    conn: &rusqlite::Connection,
    operation_id: &str,
    journal: &V2KeyPackagePublishJournal,
    status: &str,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    conn.execute(
            "UPDATE operations\n             SET response_json = ?2, status = ?3, updated_at = CURRENT_TIMESTAMP\n             WHERE operation_id = ?1 AND command = ?4",
            params![
                operation_id,
                serialize_key_package_publish_journal(journal, request_id)?,
                status,
                KEY_PACKAGE_PUBLISH_COMMAND
            ],
        )
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    let persisted_status: Option<String> = conn
        .query_row(
            "SELECT status FROM operations\n             WHERE operation_id = ?1 AND command = ?2",
            params![operation_id, KEY_PACKAGE_PUBLISH_COMMAND],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    if persisted_status.as_deref() != Some(status) {
        return Err(operation_error(
            "group.e2ee.state_not_ready",
            "KeyPackage publish journal disappeared during processing",
            request_id,
        ));
    }
    Ok(())
}

fn load_public_key_package(
    scope: &GroupMlsOperationScope,
    key_package_id: &str,
    request_id: &str,
) -> GroupMlsOperationResult<Option<V2GroupKeyPackage>> {
    let public_json: Option<String> = scope
        .app_conn
        .query_row(
            "SELECT public_json FROM key_packages WHERE key_package_id = ?1",
            params![key_package_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    public_json
        .map(|value| {
            serde_json::from_str(&value)
                .map_err(|err| operation_error("group.e2ee.state_not_ready", err, request_id))
        })
        .transpose()
}

/// Removes OpenMLS KeyPackage bundles that have no public SDK row.
///
/// OpenMLS persists the private bundle as part of `KeyPackage::build`, while
/// the public SDK row is written immediately afterwards through another SQLite
/// connection. A process can therefore stop between those writes. Only the
/// serialized public hash references are inspected here; private bundle bytes
/// never leave the OpenMLS table.
fn remove_unreferenced_openmls_key_packages(
    scope: &GroupMlsOperationScope,
    journal_body: Option<&V2PublishKeyPackageBody>,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    let mut referenced = HashSet::new();
    let mut statement = scope
        .app_conn
        .prepare("SELECT public_json FROM key_packages")
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    let public_rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|err| sqlite_operation_error(err, request_id))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    drop(statement);
    for public_json in public_rows {
        let value: Value = serde_json::from_str(&public_json)
            .map_err(|err| operation_error("group.e2ee.state_not_ready", err, request_id))?;
        let encoded = value
            .get("mls_key_package_b64u")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                operation_error(
                    "group.e2ee.state_not_ready",
                    "persisted KeyPackage public row has no MLS package",
                    request_id,
                )
            })?;
        referenced.insert(openmls_key_package_ref_bytes(
            &scope.provider,
            encoded,
            request_id,
        )?);
    }
    if let Some(body) = journal_body {
        referenced.insert(openmls_key_package_ref_bytes(
            &scope.provider,
            &body.group_key_package.mls_key_package_b64u,
            request_id,
        )?);
    }

    let mut statement = scope
        .app_conn
        .prepare("SELECT key_package_ref FROM openmls_key_packages")
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    let stored_refs = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|err| sqlite_operation_error(err, request_id))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    drop(statement);
    for stored_ref in stored_refs {
        if !referenced.contains(&stored_ref) {
            scope
                .app_conn
                .execute(
                    "DELETE FROM openmls_key_packages WHERE key_package_ref = ?1",
                    params![stored_ref],
                )
                .map_err(|err| sqlite_operation_error(err, request_id))?;
        }
    }
    Ok(())
}

fn openmls_key_package_ref_bytes(
    provider: &super::super::storage::SqliteMlsProvider,
    encoded: &str,
    request_id: &str,
) -> GroupMlsOperationResult<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|err| operation_error("group.e2ee.invalid_key_package", err, request_id))?;
    let mut reader = bytes.as_slice();
    let package = KeyPackageIn::tls_deserialize(&mut reader)
        .map_err(|err| mls_operation_error("group.e2ee.invalid_key_package", err, request_id))?;
    if !reader.is_empty() {
        return Err(operation_error(
            "group.e2ee.invalid_key_package",
            "trailing bytes after MLS KeyPackage",
            request_id,
        ));
    }
    let package = package
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|err| mls_operation_error("group.e2ee.invalid_key_package", err, request_id))?;
    let hash_ref = package
        .hash_ref(provider.crypto())
        .map_err(|err| mls_operation_error("group.e2ee.invalid_key_package", err, request_id))?;
    serde_json::to_vec(&hash_ref)
        .map_err(|err| operation_error("group.e2ee.state_not_ready", err, request_id))
}

fn validate_key_package_publish_journal(
    scope: &GroupMlsOperationScope,
    journal: V2KeyPackagePublishJournal,
    status: &str,
    input: &V2PrepareKeyPackagePublishInput,
    did_document: &Value,
) -> GroupMlsOperationResult<V2PreparedKeyPackagePublish> {
    let family_digest = key_package_publish_family_digest(input)?;
    validate_key_package_publish_family(&journal, input, &family_digest)?;
    let expected_meta =
        key_package_publish_attempt_meta(&input.meta, journal.generation, &input.request_id)?;
    if journal.journal_version != KEY_PACKAGE_PUBLISH_JOURNAL_VERSION
        || (status != "accepted" && journal.meta != expected_meta)
    {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "persisted KeyPackage publish metadata does not match its operation",
            &input.request_id,
        ));
    }
    let body = journal.body.as_ref().ok_or_else(|| {
        operation_error(
            "group.e2ee.state_not_ready",
            "prepared KeyPackage publish has no public body",
            &input.request_id,
        )
    })?;
    let package = &body.group_key_package;
    let expected_key_package_id = key_package_publish_attempt_id(
        "awiki.group-e2ee.key-package-publish.key-package.v1",
        "kp-attempt-",
        &journal.base_key_package_id,
        journal.generation,
        &input.request_id,
    )?;
    package
        .validate_structure()
        .map_err(|err| v2_error("group.e2ee.invalid_key_package", err, &input.request_id))?;
    if package.owner_did != input.owner_did
        || package.owner_device_id != input.owner_device_id
        || package.key_package_id != expected_key_package_id
        || package.did_wba_binding.verification_method != input.verification_method
    {
        return Err(operation_error(
            "group.e2ee.did_binding_invalid",
            "persisted KeyPackage does not match the exact publish owner/device/key",
            &input.request_id,
        ));
    }
    // An accepted journal is a cached terminal fact, not a request to publish
    // the package again.  Revalidate its public MLS/DID binding at the
    // persisted binding's issuance time so a later retry cannot turn a
    // successful publish into a failure solely because the package expired.
    // A merely prepared publish still has to be fresh at the caller's current
    // time before it may be sent to the Host.
    let validation_time = if status == "accepted" {
        package.did_wba_binding.issued_at.as_str()
    } else {
        input.now.as_str()
    };
    parse_and_validate_key_package(
        &scope.provider,
        package,
        did_document,
        validation_time,
        input.draft_extension_negotiated,
        &input.request_id,
    )?;
    match status {
        "prepared" if journal.accepted_result.is_none() => {}
        "accepted" => {
            let result = journal.accepted_result.as_ref().ok_or_else(|| {
                operation_error(
                    "group.e2ee.state_not_ready",
                    "accepted KeyPackage publish has no typed host result",
                    &input.request_id,
                )
            })?;
            validate_publish_result_matches(result, &journal.meta, package, &input.request_id)?;
        }
        _ => {
            return Err(operation_error(
                "group.e2ee.state_not_ready",
                "KeyPackage publish journal status/result is inconsistent",
                &input.request_id,
            ))
        }
    }
    key_package_publish_output(journal, status, &input.request_id)
}

fn validate_publish_result_matches(
    result: &V2PublishKeyPackageResult,
    meta: &V2ServiceMetadata,
    package: &V2GroupKeyPackage,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    result
        .validate()
        .map_err(|err| v2_error("group.e2ee.state_not_ready", err, request_id))?;
    if result.owner_did != meta.sender_did
        || result.owner_device_id != meta.sender_device_id
        || result.owner_did != package.owner_did
        || result.owner_device_id != package.owner_device_id
        || result.key_package_id != package.key_package_id
    {
        return Err(operation_error(
            "group.e2ee.did_binding_invalid",
            "host publish result does not match the prepared owner/device/key",
            request_id,
        ));
    }
    Ok(())
}

fn key_package_publish_output(
    journal: V2KeyPackagePublishJournal,
    status: &str,
    request_id: &str,
) -> GroupMlsOperationResult<V2PreparedKeyPackagePublish> {
    let body = journal.body.ok_or_else(|| {
        operation_error(
            "group.e2ee.state_not_ready",
            "KeyPackage publish journal has no public body",
            request_id,
        )
    })?;
    let status = match status {
        "prepared" => V2KeyPackagePublishStatus::Prepared,
        "accepted" => V2KeyPackagePublishStatus::Accepted,
        _ => {
            return Err(operation_error(
                "group.e2ee.state_not_ready",
                "KeyPackage publish journal has an unsupported state",
                request_id,
            ))
        }
    };
    Ok(V2PreparedKeyPackagePublish {
        meta: journal.meta,
        body,
        status,
        accepted_result: journal.accepted_result,
    })
}

pub fn create_group_prepare_v2<S: GroupMlsStore>(
    store: &S,
    input: V2CreateGroupInput,
) -> GroupMlsOperationResult<V2PreparedCreate> {
    input
        .meta
        .validate(crate::group_e2ee::GROUP_E2EE_SECURITY_PROFILE_V2)
        .map_err(|err| v2_error("group.e2ee.state_not_ready", err, &input.request_id))?;
    input
        .group_state_ref
        .validate()
        .map_err(|err| v2_error("group.e2ee.state_not_ready", err, &input.request_id))?;
    if input.meta.sender_did != input.creator_key_package.owner_did
        || input.meta.sender_device_id != input.creator_key_package.owner_device_id
    {
        return Err(operation_error(
            "group.e2ee.did_binding_invalid",
            "creator KeyPackage must belong to the exact sender device",
            &input.request_id,
        ));
    }
    validate_store_scope(
        store.owner_scope().as_ref(),
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &input.request_id,
    )?;
    let scope = open_scope(store, &input.request_id)?;
    if binding_status(
        &scope.app_conn,
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &input.group_state_ref.group_did,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?
    .is_some()
    {
        return Err(operation_error(
            "group.e2ee.state_not_ready",
            "a local MLS group binding already exists",
            &input.request_id,
        ));
    }
    let (_, evidence) = parse_and_validate_key_package(
        &scope.provider,
        &input.creator_key_package,
        &input.creator_did_document,
        &input.now,
        input.draft_extension_negotiated,
        &input.request_id,
    )?;
    let (credential, signer) = ensure_agent(
        &scope.provider,
        &scope.app_conn,
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    if evidence.leaf.leaf_signature_key_b64u != URL_SAFE_NO_PAD.encode(signer.to_public_vec()) {
        return Err(operation_error(
            "group.e2ee.did_binding_invalid",
            "creator KeyPackage does not use this device's persisted MLS signer",
            &input.request_id,
        ));
    }
    let crypto_group_id = scope
        .provider
        .rand()
        .random_vec(CRYPTO_GROUP_ID_LEN)
        .map_err(|err| mls_operation_error("group.e2ee.state_not_ready", err, &input.request_id))?;
    let group_id = GroupId::from_slice(&crypto_group_id);
    let body = V2GroupCreateBody {
        group_did: input.group_state_ref.group_did.clone(),
        group_state_ref: input.group_state_ref,
        suite: GROUP_E2EE_MTI_SUITE_V2.to_owned(),
        creator_key_package: input.creator_key_package,
        crypto_group_id_b64u: encode_b64u(group_id.as_slice()),
        epoch: "0".to_owned(),
    };
    body.validate()
        .map_err(|err| v2_error("group.e2ee.state_not_ready", err, &input.request_id))?;
    insert_v2_preparing(
        &scope.app_conn,
        &input.pending_commit_id,
        &input.meta.operation_id,
        "group create",
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &body.group_did,
        &body.crypto_group_id_b64u,
        &input.meta.sender_did,
        "active",
        0,
        0,
        &input.request_id,
    )?;
    let group = MlsGroup::new_with_group_id(
        &scope.provider,
        &signer,
        &v2_group_create_config(&body.creator_key_package.did_wba_binding, &input.request_id)?,
        group_id.clone(),
        credential,
    )
    .map_err(|err| mls_operation_error("group.e2ee.state_not_ready", err, &input.request_id))?;
    validate_leaf_exact(
        group.own_leaf_node().ok_or_else(|| {
            operation_error(
                "group.e2ee.state_not_ready",
                "created group has no local leaf",
                &input.request_id,
            )
        })?,
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &input.creator_did_document,
        required_extension_ids(&group),
        &input.now,
        input.draft_extension_negotiated,
        &input.request_id,
    )?;
    upsert_binding_status(
        &scope.app_conn,
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &body.group_state_ref.group_did,
        &group_id,
        0,
        "creator",
        "pending_create",
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    let local_artifact = encode_b64u(b"p6-v2-local-create");
    mark_v2_prepared(
        &scope.app_conn,
        &input.pending_commit_id,
        &local_artifact,
        None,
        None,
        Some(&encode_b64u(group.epoch_authenticator().as_slice())),
        &body,
        &input.request_id,
    )?;
    Ok(V2PreparedCreate {
        pending_commit_id: input.pending_commit_id,
        body,
    })
}

pub fn add_member_prepare_v2<S: GroupMlsStore>(
    store: &S,
    input: V2AddMemberInput,
) -> GroupMlsOperationResult<V2PreparedAdd> {
    validate_control_meta(&input.meta, &input.group_state_ref, &input.request_id)?;
    validate_store_scope(
        store.owner_scope().as_ref(),
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &input.request_id,
    )?;
    let scope = open_scope(store, &input.request_id)?;
    let local_binding = binding(
        &scope.app_conn,
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &input.group_state_ref.group_did,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    let mut group = load_group(
        &scope.provider,
        &local_binding.openmls_group_id,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    ensure_group_head(
        &group,
        &local_binding,
        &input.group_state_ref.group_did,
        &input.request_id,
    )?;
    let (key_package, evidence) = parse_and_validate_key_package(
        &scope.provider,
        &input.group_key_package,
        &input.member_did_document,
        &input.now,
        input.draft_extension_negotiated,
        &input.request_id,
    )?;
    let target = V2LeafIdentity {
        agent_did: input.group_key_package.owner_did.clone(),
        device_id: input.group_key_package.owner_device_id.clone(),
        leaf_signature_key_b64u: evidence.leaf.leaf_signature_key_b64u,
    };
    ensure_leaf_absent(&scope, &group, &target, &input.request_id)?;
    let next_epoch = group.epoch().as_u64().checked_add(1).ok_or_else(|| {
        operation_error(
            "group.e2ee.epoch_conflict",
            "epoch overflow",
            &input.request_id,
        )
    })?;
    let crypto_group_id_b64u = encode_b64u(group.group_id().as_slice());
    let aad = membership_aad(
        METHOD_GROUP_ADD_V2,
        &input.meta,
        &input.group_state_ref,
        &crypto_group_id_b64u,
        next_epoch,
        &target.agent_did,
        &target.device_id,
        &input.request_id,
    )?;
    group.set_aad(aad.clone());
    let original_tree = group.export_ratchet_tree();
    let signer = load_signer(
        &scope.provider,
        &scope.app_conn,
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    insert_v2_preparing(
        &scope.app_conn,
        &input.pending_commit_id,
        &input.meta.operation_id,
        "group add-member",
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &input.group_state_ref.group_did,
        &crypto_group_id_b64u,
        &target.agent_did,
        "active",
        local_binding.epoch,
        next_epoch,
        &input.request_id,
    )?;
    let (commit, welcome, _) = group
        .add_members(&scope.provider, &signer, &[key_package])
        .map_err(|err| mls_operation_error("group.e2ee.commit_invalid", err, &input.request_id))?;
    let pending = group.pending_commit().ok_or_else(|| {
        operation_error(
            "group.e2ee.commit_invalid",
            "OpenMLS did not persist the Add pending commit",
            &input.request_id,
        )
    })?;
    if pending.epoch().as_u64() != next_epoch {
        return Err(operation_error(
            "group.e2ee.epoch_conflict",
            "Add pending epoch is not exactly current epoch plus one",
            &input.request_id,
        ));
    }
    let welcome = match welcome.body() {
        MlsMessageBodyOut::Welcome(value) => value,
        _ => {
            return Err(operation_error(
                "group.e2ee.welcome_invalid",
                "OpenMLS Add did not return a Welcome",
                &input.request_id,
            ))
        }
    };
    let tree: RatchetTreeIn = pending
        .export_ratchet_tree(scope.provider.crypto(), original_tree)
        .map_err(|err| mls_operation_error("group.e2ee.welcome_invalid", err, &input.request_id))?
        .ok_or_else(|| {
            operation_error(
                "group.e2ee.welcome_invalid",
                "Add pending commit did not expose the post-commit ratchet tree",
                &input.request_id,
            )
        })?
        .into();
    let body = V2GroupAddBody {
        member_did: target.agent_did,
        member_device_id: target.device_id,
        group_state_ref: input.group_state_ref,
        group_key_package: input.group_key_package,
        crypto_group_id_b64u,
        epoch: next_epoch.to_string(),
        commit_b64u: encode_tls(&commit, "group.e2ee.commit_invalid", &input.request_id)?,
        welcome_b64u: encode_tls(welcome, "group.e2ee.welcome_invalid", &input.request_id)?,
        ratchet_tree_b64u: encode_tls(&tree, "group.e2ee.welcome_invalid", &input.request_id)?,
    };
    body.validate()
        .map_err(|err| v2_error("group.e2ee.commit_invalid", err, &input.request_id))?;
    if group_add_submission_binding_v2(&input.meta, &body)
        .map_err(|err| v2_error("group.e2ee.commit_invalid", err, &input.request_id))?
        != aad
    {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "Add authenticated_data does not equal the P6 v2 submission binding",
            &input.request_id,
        ));
    }
    persist_pending_membership(
        &scope,
        &input.pending_commit_id,
        &body.commit_b64u,
        Some(&body.ratchet_tree_b64u),
        &body,
        &input.request_id,
    )?;
    Ok(V2PreparedAdd {
        pending_commit_id: input.pending_commit_id,
        from_epoch: local_binding.epoch.to_string(),
        body,
    })
}

pub fn remove_member_prepare_v2<S: GroupMlsStore>(
    store: &S,
    input: V2RemoveMemberInput,
) -> GroupMlsOperationResult<V2PreparedRemove> {
    validate_control_meta(&input.meta, &input.group_state_ref, &input.request_id)?;
    validate_store_scope(
        store.owner_scope().as_ref(),
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &input.request_id,
    )?;
    let scope = open_scope(store, &input.request_id)?;
    if input.meta.sender_did == input.member_did
        && input.meta.sender_device_id == input.member_device_id
    {
        return Err(operation_error(
            "group.e2ee.controller_required",
            "the preparing controller cannot remove its own exact MLS leaf",
            &input.request_id,
        ));
    }
    let local_binding = binding(
        &scope.app_conn,
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &input.group_state_ref.group_did,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    let mut group = load_group(
        &scope.provider,
        &local_binding.openmls_group_id,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    ensure_group_head(
        &group,
        &local_binding,
        &input.group_state_ref.group_did,
        &input.request_id,
    )?;
    let leaf = find_exact_accepted_leaf(
        &scope,
        &group,
        &input.member_did,
        &input.member_device_id,
        &input.member_did_document,
        input.draft_extension_negotiated,
        &input.request_id,
    )?;
    let next_epoch = group.epoch().as_u64().checked_add(1).ok_or_else(|| {
        operation_error(
            "group.e2ee.epoch_conflict",
            "epoch overflow",
            &input.request_id,
        )
    })?;
    let crypto_group_id_b64u = encode_b64u(group.group_id().as_slice());
    let aad = membership_aad(
        METHOD_GROUP_REMOVE_V2,
        &input.meta,
        &input.group_state_ref,
        &crypto_group_id_b64u,
        next_epoch,
        &input.member_did,
        &input.member_device_id,
        &input.request_id,
    )?;
    group.set_aad(aad.clone());
    let signer = load_signer(
        &scope.provider,
        &scope.app_conn,
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    insert_v2_preparing(
        &scope.app_conn,
        &input.pending_commit_id,
        &input.meta.operation_id,
        "group remove-member",
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &input.group_state_ref.group_did,
        &crypto_group_id_b64u,
        &input.member_did,
        "removed",
        local_binding.epoch,
        next_epoch,
        &input.request_id,
    )?;
    let (commit, welcome, _) = group
        .remove_members(&scope.provider, &signer, &[leaf.index])
        .map_err(|err| mls_operation_error("group.e2ee.commit_invalid", err, &input.request_id))?;
    if welcome.is_some() {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "Remove unexpectedly produced a Welcome",
            &input.request_id,
        ));
    }
    let pending = group.pending_commit().ok_or_else(|| {
        operation_error(
            "group.e2ee.commit_invalid",
            "OpenMLS did not persist the Remove pending commit",
            &input.request_id,
        )
    })?;
    if pending.epoch().as_u64() != next_epoch {
        return Err(operation_error(
            "group.e2ee.epoch_conflict",
            "Remove pending epoch is not exactly current epoch plus one",
            &input.request_id,
        ));
    }
    let body = V2GroupRemoveBody {
        member_did: input.member_did,
        member_device_id: input.member_device_id,
        group_state_ref: input.group_state_ref,
        crypto_group_id_b64u,
        epoch: next_epoch.to_string(),
        commit_b64u: encode_tls(&commit, "group.e2ee.commit_invalid", &input.request_id)?,
    };
    body.validate()
        .map_err(|err| v2_error("group.e2ee.commit_invalid", err, &input.request_id))?;
    if group_remove_submission_binding_v2(&input.meta, &body)
        .map_err(|err| v2_error("group.e2ee.commit_invalid", err, &input.request_id))?
        != aad
    {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "Remove authenticated_data does not equal the P6 v2 submission binding",
            &input.request_id,
        ));
    }
    persist_pending_membership(
        &scope,
        &input.pending_commit_id,
        &body.commit_b64u,
        None,
        &body,
        &input.request_id,
    )?;
    Ok(V2PreparedRemove {
        pending_commit_id: input.pending_commit_id,
        from_epoch: local_binding.epoch.to_string(),
        body,
    })
}

pub fn finalize_commit_v2<S: GroupMlsStore>(
    store: &S,
    input: V2FinalizeInput,
) -> GroupMlsOperationResult<V2FinalizeOutput> {
    let scope = open_scope(store, &input.request_id)?;
    let pending = pending_commit(&scope.app_conn, &input.pending_commit_id, &input.request_id)
        .map_err(GroupMlsOperationError::from)?;
    if pending.status == "aborted" {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "pending commit was already aborted",
            &input.request_id,
        ));
    }
    if pending.status == "preparing" {
        return Err(operation_error(
            "group.e2ee.state_not_ready",
            "prepare was interrupted; reconcile_pending_v2 is required",
            &input.request_id,
        ));
    }
    if matches!(pending.status.as_str(), "prepared" | "pending") {
        update_pending_commit_status(
            &scope.app_conn,
            &pending.pending_commit_id,
            "accepted",
            &input.request_id,
        )
        .map_err(GroupMlsOperationError::from)?;
    }
    if pending.status != "finalized" {
        complete_accepted_pending(&scope, &pending, &input.request_id)?;
    }
    Ok(V2FinalizeOutput {
        pending_commit_id: pending.pending_commit_id,
        operation_id: pending.operation_id,
        group_did: pending.group_did,
        crypto_group_id_b64u: pending.crypto_group_id_b64u,
        from_epoch: pending.from_epoch.to_string(),
        epoch: pending.to_epoch.to_string(),
        status: "finalized".to_owned(),
    })
}

pub fn abort_commit_v2<S: GroupMlsStore>(
    store: &S,
    input: V2FinalizeInput,
) -> GroupMlsOperationResult<V2FinalizeOutput> {
    let scope = open_scope(store, &input.request_id)?;
    let pending = pending_commit(&scope.app_conn, &input.pending_commit_id, &input.request_id)
        .map_err(GroupMlsOperationError::from)?;
    if matches!(pending.status.as_str(), "accepted" | "finalized") {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "an accepted or finalized pending commit cannot be aborted",
            &input.request_id,
        ));
    }
    if pending.status != "aborted" {
        rollback_pending(&scope, &pending, &input.request_id)?;
        update_pending_commit_status(
            &scope.app_conn,
            &pending.pending_commit_id,
            "aborted",
            &input.request_id,
        )
        .map_err(GroupMlsOperationError::from)?;
    }
    Ok(V2FinalizeOutput {
        pending_commit_id: pending.pending_commit_id,
        operation_id: pending.operation_id,
        group_did: pending.group_did,
        crypto_group_id_b64u: pending.crypto_group_id_b64u,
        from_epoch: pending.from_epoch.to_string(),
        epoch: pending.from_epoch.to_string(),
        status: "aborted".to_owned(),
    })
}

/// Repairs write-ahead prepare/finalize state after a process restart.
///
/// `preparing` entries are conservatively rolled back because the service has
/// not yet received a complete prepared artifact. `prepared` entries remain
/// pending an explicit service decision. `accepted` entries are completed
/// idempotently from the persisted OpenMLS state.
pub fn reconcile_pending_v2<S: GroupMlsStore>(
    store: &S,
    input: V2ReconcilePendingInput,
) -> GroupMlsOperationResult<V2ReconcilePendingOutput> {
    let scope = open_scope(store, &input.request_id)?;
    let mut statement = scope
        .app_conn
        .prepare(
            "SELECT pending_commit_id
             FROM pending_commits
             WHERE status IN ('preparing', 'prepared', 'pending', 'accepted')
             ORDER BY created_at, pending_commit_id",
        )
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
    let ids = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
    drop(statement);

    let mut reconciled = Vec::with_capacity(ids.len());
    for pending_commit_id in ids {
        let pending = pending_commit(&scope.app_conn, &pending_commit_id, &input.request_id)
            .map_err(GroupMlsOperationError::from)?;
        let previous_status = pending.status.clone();
        let (status, action) = match pending.status.as_str() {
            "preparing" => {
                rollback_pending(&scope, &pending, &input.request_id)?;
                update_pending_commit_status(
                    &scope.app_conn,
                    &pending.pending_commit_id,
                    "aborted",
                    &input.request_id,
                )
                .map_err(GroupMlsOperationError::from)?;
                ("aborted", "rolled-back-interrupted-prepare")
            }
            "prepared" | "pending" => ("prepared", "awaiting-service-decision"),
            "accepted" => {
                complete_accepted_pending(&scope, &pending, &input.request_id)?;
                ("finalized", "completed-accepted-commit")
            }
            _ => continue,
        };
        let prepared_response = if status == "prepared" {
            pending_prepared_response(
                &scope.app_conn,
                &pending.pending_commit_id,
                &input.request_id,
            )?
        } else {
            None
        };
        reconciled.push(V2ReconciledPendingCommit {
            pending_commit_id: pending.pending_commit_id,
            operation_id: pending.operation_id,
            group_did: pending.group_did,
            previous_status,
            status: status.to_owned(),
            action: action.to_owned(),
            prepared_response,
        });
    }
    Ok(V2ReconcilePendingOutput {
        pending_commits: reconciled,
    })
}

/// Inspects only secret-free application metadata owned by the SDK.
///
/// Product integrations must use this API instead of reading the SDK SQLite
/// schema or interpreting journal status strings themselves.
pub fn inspect_local_group_v2<S: GroupMlsStore>(
    store: &S,
    input: V2InspectLocalGroupInput,
) -> GroupMlsOperationResult<V2InspectLocalGroupOutput> {
    let owner_scope = store.owner_scope().ok_or_else(|| {
        operation_error(
            "owner_scope_required",
            "P6 v2 local inspection requires an exact DID/device store scope",
            &input.request_id,
        )
    })?;
    validate_store_scope(
        Some(&owner_scope),
        &input.owner_did,
        &input.owner_device_id,
        &input.request_id,
    )?;
    require_non_empty("group_did", &input.group_did, &input.request_id)?;
    if !input.group_did.starts_with("did:") {
        return Err(operation_error(
            "invalid_field",
            "group_did must be a DID",
            &input.request_id,
        ));
    }
    let scope = open_scope(store, &input.request_id)?;
    let (binding_count, binding_status) = scope
        .app_conn
        .query_row(
            "SELECT COUNT(*), MIN(status)
             FROM group_bindings
             WHERE agent_did = ?1 AND device_id = ?2 AND group_did = ?3",
            params![input.owner_did, input.owner_device_id, input.group_did],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?)),
        )
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
    let readiness = match (binding_count, binding_status.as_deref()) {
        (0, None) => V2LocalGroupReadiness::Missing,
        (1, Some("active")) => V2LocalGroupReadiness::Active,
        (1, Some("removed")) => V2LocalGroupReadiness::Inactive,
        (1, Some("pending_create")) => V2LocalGroupReadiness::Missing,
        (count, _) => {
            return Err(operation_error(
                "group.e2ee.state_not_ready",
                format!("invalid local group binding cardinality/status ({count})"),
                &input.request_id,
            ));
        }
    };
    let mut statement = scope
        .app_conn
        .prepare(
            "SELECT status, COUNT(*)
             FROM pending_commits
             WHERE group_did = ?1
             GROUP BY status",
        )
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
    let rows = statement
        .query_map(params![input.group_did], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
    let mut auto_reconcile = 0_u32;
    let mut host_recheck = 0_u32;
    for (status, count) in rows {
        let count = u32::try_from(count).map_err(|_| {
            operation_error(
                "group.e2ee.state_not_ready",
                "invalid local pending commit count",
                &input.request_id,
            )
        })?;
        match status.as_str() {
            "preparing" | "accepted" => {
                auto_reconcile = auto_reconcile.checked_add(count).ok_or_else(|| {
                    operation_error(
                        "group.e2ee.state_not_ready",
                        "local pending commit count overflow",
                        &input.request_id,
                    )
                })?;
            }
            "prepared" | "pending" => {
                host_recheck = host_recheck.checked_add(count).ok_or_else(|| {
                    operation_error(
                        "group.e2ee.state_not_ready",
                        "local pending commit count overflow",
                        &input.request_id,
                    )
                })?;
            }
            "finalized" | "aborted" => {}
            _ => {
                return Err(operation_error(
                    "group.e2ee.state_not_ready",
                    "unknown local pending commit status",
                    &input.request_id,
                ));
            }
        }
    }
    Ok(V2InspectLocalGroupOutput {
        group_did: input.group_did,
        readiness,
        auto_reconcile_pending_count: auto_reconcile,
        host_recheck_pending_count: host_recheck,
    })
}

/// Lists the secret-free DID/device projection of the locally accepted tree.
///
/// Product integrations may compare this projection with current P2 Manifest
/// eligibility and P4 membership when planning Add/Remove repair. They must not
/// treat it as current authorization or read the SDK SQLite schema instead.
pub fn list_local_group_member_endpoints_v2<S: GroupMlsStore>(
    store: &S,
    input: V2InspectLocalGroupInput,
) -> GroupMlsOperationResult<V2ListLocalGroupMemberEndpointsOutput> {
    let owner_scope = store.owner_scope().ok_or_else(|| {
        operation_error(
            "owner_scope_required",
            "P6 v2 local member inspection requires an exact DID/device store scope",
            &input.request_id,
        )
    })?;
    validate_store_scope(
        Some(&owner_scope),
        &input.owner_did,
        &input.owner_device_id,
        &input.request_id,
    )?;
    require_non_empty("group_did", &input.group_did, &input.request_id)?;
    if !input.group_did.starts_with("did:") {
        return Err(operation_error(
            "invalid_field",
            "group_did must be a DID",
            &input.request_id,
        ));
    }

    let scope = open_scope(store, &input.request_id)?;
    let binding = active_binding(
        &scope.app_conn,
        &input.owner_did,
        &input.owner_device_id,
        &input.group_did,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?
    .ok_or_else(|| {
        operation_error(
            "group.e2ee.state_not_ready",
            "local P6 v2 group is not active",
            &input.request_id,
        )
    })?;
    let group = load_group(
        &scope.provider,
        &binding.openmls_group_id,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    ensure_group_head(&group, &binding, &input.group_did, &input.request_id)?;
    let public_group = load_public_group(&scope, &group, &input.request_id)?;

    let mut identities = Vec::new();
    let mut member_endpoints = Vec::new();
    for member in group.members() {
        let member_index = member.index;
        let credential = BasicCredential::try_from(member.credential).map_err(|_| {
            operation_error(
                "group.e2ee.did_binding_invalid",
                "P6 v2 member credential must be a basic DID credential",
                &input.request_id,
            )
        })?;
        let credential_did = String::from_utf8(credential.identity().to_vec()).map_err(|_| {
            operation_error(
                "group.e2ee.did_binding_invalid",
                "P6 v2 member credential identity must be a UTF-8 DID",
                &input.request_id,
            )
        })?;
        let leaf = public_group.leaf(member_index).ok_or_else(|| {
            operation_error(
                "group.e2ee.did_binding_invalid",
                "member leaf is missing from the public group",
                &input.request_id,
            )
        })?;
        let (leaf_binding, evidence) = leaf_binding_evidence(leaf, &input.request_id)?;
        if credential_did != leaf_binding.agent_did {
            return Err(operation_error(
                "group.e2ee.did_binding_invalid",
                "member credential DID does not match the device-binding extension",
                &input.request_id,
            ));
        }
        identities.push(V2LeafIdentity {
            agent_did: leaf_binding.agent_did.clone(),
            device_id: leaf_binding.device_id.clone(),
            leaf_signature_key_b64u: evidence.leaf_signature_key_b64u,
        });
        member_endpoints.push(V2LocalGroupMemberEndpoint {
            member_did: leaf_binding.agent_did,
            member_device_id: leaf_binding.device_id,
        });
    }
    validate_leaf_identity_set_v2(&identities)
        .map_err(|err| v2_error("group.e2ee.did_binding_invalid", err, &input.request_id))?;
    member_endpoints.sort();

    Ok(V2ListLocalGroupMemberEndpointsOutput {
        group_did: input.group_did,
        member_endpoints,
    })
}

fn complete_accepted_pending(
    scope: &GroupMlsOperationScope,
    pending: &super::PendingCommitRecord,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    let group_id = GroupId::from_slice(
        &decode_b64u(&pending.crypto_group_id_b64u, request_id)
            .map_err(GroupMlsOperationError::from)?,
    );
    let mut group =
        load_group(&scope.provider, &group_id, request_id).map_err(GroupMlsOperationError::from)?;
    if pending.command == "group create" {
        if group.epoch().as_u64() != pending.to_epoch {
            return Err(operation_error(
                "group.e2ee.epoch_conflict",
                "created group epoch changed before service acceptance",
                request_id,
            ));
        }
    } else if group.epoch().as_u64() == pending.from_epoch {
        let staged = group.pending_commit().ok_or_else(|| {
            operation_error(
                "group.e2ee.commit_invalid",
                "OpenMLS pending commit is missing",
                request_id,
            )
        })?;
        if staged.epoch().as_u64() != pending.to_epoch {
            return Err(operation_error(
                "group.e2ee.epoch_conflict",
                "OpenMLS pending epoch changed before service acceptance",
                request_id,
            ));
        }
        group
            .merge_pending_commit(&scope.provider)
            .map_err(|err| mls_operation_error("group.e2ee.commit_invalid", err, request_id))?;
    } else if group.epoch().as_u64() != pending.to_epoch || group.pending_commit().is_some() {
        return Err(operation_error(
            "group.e2ee.epoch_conflict",
            "persisted OpenMLS state cannot complete the accepted commit",
            request_id,
        ));
    }

    // P6 v2 changes one exact leaf. A sibling leaf can share the local
    // controller DID, so DID equality must never deactivate this device.
    set_binding_epoch_status(
        &scope.app_conn,
        &pending.agent_did,
        &pending.device_id,
        &pending.group_did,
        pending.to_epoch,
        "active",
        request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    update_pending_commit_status(
        &scope.app_conn,
        &pending.pending_commit_id,
        "finalized",
        request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    Ok(())
}

fn rollback_pending(
    scope: &GroupMlsOperationScope,
    pending: &super::PendingCommitRecord,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    let group_id = GroupId::from_slice(
        &decode_b64u(&pending.crypto_group_id_b64u, request_id)
            .map_err(GroupMlsOperationError::from)?,
    );
    if pending.command == "group create" {
        delete_openmls_group_state(&scope.app_conn, &group_id, request_id)
            .map_err(GroupMlsOperationError::from)?;
        delete_binding(
            &scope.app_conn,
            &pending.agent_did,
            &pending.device_id,
            &pending.group_did,
            request_id,
        )
        .map_err(GroupMlsOperationError::from)?;
        return Ok(());
    }

    let Some(mut group) = MlsGroup::load(scope.provider.storage(), &group_id)
        .map_err(|err| mls_operation_error("group.e2ee.state_not_ready", err, request_id))?
    else {
        return Err(operation_error(
            "group.e2ee.state_not_ready",
            "OpenMLS group state is missing during prepare reconciliation",
            request_id,
        ));
    };
    if group.epoch().as_u64() == pending.to_epoch {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "a merged membership commit cannot be rolled back",
            request_id,
        ));
    }
    if group.epoch().as_u64() != pending.from_epoch {
        return Err(operation_error(
            "group.e2ee.epoch_conflict",
            "OpenMLS epoch changed during prepare reconciliation",
            request_id,
        ));
    }
    group
        .clear_pending_commit(scope.provider.storage())
        .map_err(|err| mls_operation_error("group.e2ee.commit_invalid", err, request_id))?;
    Ok(())
}

pub fn process_welcome_v2<S: GroupMlsStore>(
    store: &S,
    input: V2ProcessWelcomeInput,
) -> GroupMlsOperationResult<V2ProcessCommitOutput> {
    validate_store_scope(
        store.owner_scope().as_ref(),
        &input.recipient_did,
        &input.recipient_device_id,
        &input.request_id,
    )?;
    let scope = open_scope(store, &input.request_id)?;
    process_welcome_with_scope(&scope, input)
}

fn process_welcome_with_scope(
    scope: &GroupMlsOperationScope,
    input: V2ProcessWelcomeInput,
) -> GroupMlsOperationResult<V2ProcessCommitOutput> {
    if input.group_state_ref.group_did != input.group_did {
        return Err(operation_error(
            "group.e2ee.welcome_invalid",
            "Welcome group_state_ref does not match group_did",
            &input.request_id,
        ));
    }
    let target_epoch = parse_epoch(&input.epoch, &input.request_id)?;
    ensure_agent(
        &scope.provider,
        &scope.app_conn,
        &input.recipient_did,
        &input.recipient_device_id,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    if let Some(existing) = active_binding(
        &scope.app_conn,
        &input.recipient_did,
        &input.recipient_device_id,
        &input.group_did,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?
    {
        if existing.epoch == target_epoch
            && encode_b64u(existing.openmls_group_id.as_slice()) == input.crypto_group_id_b64u
        {
            let group = load_group(
                &scope.provider,
                &existing.openmls_group_id,
                &input.request_id,
            )
            .map_err(GroupMlsOperationError::from)?;
            ensure_group_head(&group, &existing, &input.group_did, &input.request_id)?;
            return Ok(V2ProcessCommitOutput {
                crypto_group_id_b64u: input.crypto_group_id_b64u,
                from_epoch: target_epoch.saturating_sub(1).to_string(),
                epoch: existing.epoch.to_string(),
                self_removed: false,
            });
        }
        return Err(operation_error(
            "group.e2ee.epoch_conflict",
            "Welcome conflicts with the existing local group binding",
            &input.request_id,
        ));
    }
    let welcome = Welcome::tls_deserialize_exact(
        decode_b64u(&input.welcome_b64u, &input.request_id)
            .map_err(GroupMlsOperationError::from)?,
    )
    .map_err(|err| mls_operation_error("group.e2ee.welcome_invalid", err, &input.request_id))?;
    let tree = RatchetTreeIn::tls_deserialize_exact(
        decode_b64u(&input.ratchet_tree_b64u, &input.request_id)
            .map_err(GroupMlsOperationError::from)?,
    )
    .map_err(|err| mls_operation_error("group.e2ee.welcome_invalid", err, &input.request_id))?;
    let staged =
        StagedWelcome::build_from_welcome(&scope.provider, &v2_group_join_config(), welcome)
            .map_err(|err| {
                mls_operation_error("group.e2ee.welcome_invalid", err, &input.request_id)
            })?
            .with_ratchet_tree(tree)
            .build()
            .map_err(|err| {
                mls_operation_error("group.e2ee.welcome_invalid", err, &input.request_id)
            })?;
    if encode_b64u(staged.group_context().group_id().as_slice()) != input.crypto_group_id_b64u
        || staged.group_context().epoch().as_u64() != target_epoch
    {
        return Err(operation_error(
            "group.e2ee.welcome_invalid",
            "Welcome crypto group or epoch does not match the exact outer notice",
            &input.request_id,
        ));
    }
    let group = staged
        .into_group(&scope.provider)
        .map_err(|err| mls_operation_error("group.e2ee.welcome_invalid", err, &input.request_id))?;
    let validation = validate_all_group_leaves(
        scope,
        &group,
        &input.member_documents,
        &input.now,
        input.draft_extension_negotiated,
        &input.request_id,
    )
    .and_then(|leaves| {
        let own = leaves
            .iter()
            .filter(|leaf| {
                leaf.agent_did == input.recipient_did && leaf.device_id == input.recipient_device_id
            })
            .count();
        if own == 1 {
            Ok(())
        } else {
            Err(operation_error(
                "group.e2ee.welcome_invalid",
                "Welcome does not contain exactly one leaf for this recipient device",
                &input.request_id,
            ))
        }
    });
    if let Err(err) = validation {
        delete_openmls_group_state(&scope.app_conn, group.group_id(), &input.request_id)
            .map_err(GroupMlsOperationError::from)?;
        return Err(err);
    }
    upsert_binding(
        &scope.app_conn,
        &input.recipient_did,
        &input.recipient_device_id,
        &input.group_did,
        group.group_id(),
        group.epoch().as_u64(),
        "member",
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    Ok(V2ProcessCommitOutput {
        crypto_group_id_b64u: input.crypto_group_id_b64u,
        from_epoch: target_epoch.saturating_sub(1).to_string(),
        epoch: target_epoch.to_string(),
        self_removed: false,
    })
}

/// Processes the standard device-targeted P6 v2 `group.e2ee.notice` shape.
///
/// Commit callers do not provide a second, synthetic control metadata object.
/// The originating operation, sender DID/device, affected leaf, state reference,
/// crypto group and epoch are recovered from the authenticated MLS Commit AAD
/// and checked against the notice plus current DID documents.
pub fn process_notice_v2<S: GroupMlsStore>(
    store: &S,
    input: V2ProcessNoticeInput,
) -> GroupMlsOperationResult<V2ProcessNoticeOutput> {
    validate_notice_outer(&input)?;
    validate_store_scope(
        store.owner_scope().as_ref(),
        &input.recipient_did,
        &input.recipient_device_id,
        &input.request_id,
    )?;
    let scope = open_scope(store, &input.request_id)?;
    let digest = notice_input_digest(&input)?;
    let receipt_key = format!("p6-v2-notice:{}", input.meta.operation_id);
    match begin_notice_receipt(&scope.app_conn, &receipt_key, &digest, &input.request_id)? {
        NoticeReceiptState::Finalized(output) => return Ok(output),
        NoticeReceiptState::Processing(Some(output)) => {
            if recover_notice_if_applied(&scope, &input, &output)? {
                finalize_notice_receipt(&scope.app_conn, &receipt_key, &output, &input.request_id)?;
                return Ok(output);
            }
        }
        NoticeReceiptState::New | NoticeReceiptState::Processing(None) => {}
    }

    let output = match input.notice.notice_type.as_str() {
        "welcome-delivery" => {
            let processed = process_welcome_with_scope(
                &scope,
                V2ProcessWelcomeInput {
                    recipient_did: input.recipient_did.clone(),
                    recipient_device_id: input.recipient_device_id.clone(),
                    group_did: input.notice.group_did.clone(),
                    group_state_ref: input.notice.group_state_ref.clone(),
                    crypto_group_id_b64u: input.notice.crypto_group_id_b64u.clone(),
                    epoch: input.notice.epoch.clone(),
                    welcome_b64u: input.notice.welcome_b64u.clone().ok_or_else(|| {
                        operation_error(
                            "group.e2ee.welcome_invalid",
                            "welcome-delivery is missing welcome_b64u",
                            &input.request_id,
                        )
                    })?,
                    ratchet_tree_b64u: input.notice.ratchet_tree_b64u.clone().ok_or_else(|| {
                        operation_error(
                            "group.e2ee.welcome_invalid",
                            "welcome-delivery is missing ratchet_tree_b64u",
                            &input.request_id,
                        )
                    })?,
                    member_documents: input.member_documents.clone(),
                    now: input.now.clone(),
                    draft_extension_negotiated: input.draft_extension_negotiated,
                    request_id: input.request_id.clone(),
                },
            )?;
            if let Err(err) = validate_persisted_epoch_authenticator(
                &scope,
                &input.notice.crypto_group_id_b64u,
                input.notice.epoch_authenticator.as_deref(),
                &input.request_id,
            ) {
                let group_id = GroupId::from_slice(
                    &decode_b64u(&input.notice.crypto_group_id_b64u, &input.request_id)
                        .map_err(GroupMlsOperationError::from)?,
                );
                delete_openmls_group_state(&scope.app_conn, &group_id, &input.request_id)
                    .map_err(GroupMlsOperationError::from)?;
                delete_binding(
                    &scope.app_conn,
                    &input.recipient_did,
                    &input.recipient_device_id,
                    &input.notice.group_did,
                    &input.request_id,
                )
                .map_err(GroupMlsOperationError::from)?;
                return Err(err);
            }
            V2ProcessNoticeOutput {
                notice_operation_id: input.meta.operation_id.clone(),
                source_operation_id: None,
                notice_type: input.notice.notice_type.clone(),
                crypto_group_id_b64u: processed.crypto_group_id_b64u,
                from_epoch: processed.from_epoch,
                epoch: processed.epoch,
                self_removed: processed.self_removed,
            }
        }
        "commit-delivery" => process_notice_commit(&scope, &input, &receipt_key)?,
        _ => {
            return Err(operation_error(
                "group.e2ee.notice_type_unsupported",
                "unsupported P6 v2 notice type",
                &input.request_id,
            ))
        }
    };
    set_notice_receipt_output(
        &scope.app_conn,
        &receipt_key,
        &output,
        "processing",
        &input.request_id,
    )?;
    finalize_notice_receipt(&scope.app_conn, &receipt_key, &output, &input.request_id)?;
    Ok(output)
}

fn process_notice_commit(
    scope: &GroupMlsOperationScope,
    input: &V2ProcessNoticeInput,
    receipt_key: &str,
) -> GroupMlsOperationResult<V2ProcessNoticeOutput> {
    let local_binding = binding(
        &scope.app_conn,
        &input.recipient_did,
        &input.recipient_device_id,
        &input.notice.group_did,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    let mut group = load_group(
        &scope.provider,
        &local_binding.openmls_group_id,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    ensure_group_head(
        &group,
        &local_binding,
        &input.notice.group_did,
        &input.request_id,
    )?;
    if input.notice.crypto_group_id_b64u != encode_b64u(group.group_id().as_slice()) {
        return Err(operation_error(
            "group.e2ee.crypto_group_mismatch",
            "notice crypto group does not match local state",
            &input.request_id,
        ));
    }
    let target_epoch = parse_epoch(&input.notice.epoch, &input.request_id)?;
    if target_epoch == local_binding.epoch {
        return process_finalized_self_echo(scope, input, &group, target_epoch);
    }
    if target_epoch
        != local_binding.epoch.checked_add(1).ok_or_else(|| {
            operation_error(
                "group.e2ee.epoch_conflict",
                "epoch overflow",
                &input.request_id,
            )
        })?
    {
        return Err(operation_error(
            "group.e2ee.epoch_conflict",
            "notice Commit epoch is not exactly local epoch plus one",
            &input.request_id,
        ));
    }
    let message = MlsMessageIn::tls_deserialize_exact(
        decode_b64u(
            input.notice.commit_b64u.as_deref().ok_or_else(|| {
                operation_error(
                    "group.e2ee.commit_invalid",
                    "commit-delivery is missing commit_b64u",
                    &input.request_id,
                )
            })?,
            &input.request_id,
        )
        .map_err(GroupMlsOperationError::from)?,
    )
    .map_err(|err| mls_operation_error("group.e2ee.commit_invalid", err, &input.request_id))?;
    let protocol = message.try_into_protocol_message().map_err(|_| {
        operation_error(
            "group.e2ee.commit_invalid",
            "commit_b64u is not an MLS protocol message",
            &input.request_id,
        )
    })?;
    let processed = group
        .process_message(&scope.provider, protocol)
        .map_err(|err| mls_operation_error("group.e2ee.commit_invalid", err, &input.request_id))?;
    let authenticated = parse_membership_authenticated_data(processed.aad(), &input.request_id)?;
    validate_notice_membership_binding(&authenticated, &input.notice, &input.request_id)?;
    let sender_document = exact_did_document(
        &input.member_documents,
        &authenticated.sender_did,
        &input.request_id,
    )?;
    validate_processed_sender(
        scope,
        &group,
        processed.sender(),
        &authenticated.sender_did,
        &authenticated.sender_device_id,
        sender_document,
        &input.now,
        input.draft_extension_negotiated,
        &input.request_id,
    )?;
    let staged = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(value) => *value,
        _ => {
            return Err(operation_error(
                "group.e2ee.commit_invalid",
                "commit_b64u does not contain a staged Commit",
                &input.request_id,
            ))
        }
    };
    if staged.epoch().as_u64() != target_epoch {
        return Err(operation_error(
            "group.e2ee.epoch_conflict",
            "staged Commit epoch does not match the notice epoch",
            &input.request_id,
        ));
    }
    let method = if authenticated.subject_method == METHOD_GROUP_ADD_V2 {
        V2MembershipCommitMethod::Add
    } else {
        V2MembershipCommitMethod::Remove
    };
    let member_document = exact_did_document(
        &input.member_documents,
        &input.notice.subject_did,
        &input.request_id,
    )?;
    validate_staged_membership_delta(
        scope,
        &group,
        &staged,
        &method,
        &input.notice.subject_did,
        &input.notice.subject_device_id,
        member_document,
        &input.now,
        input.draft_extension_negotiated,
        &input.request_id,
    )?;
    if let Some(expected) = input.notice.epoch_authenticator.as_deref() {
        let actual = staged.epoch_authenticator().ok_or_else(|| {
            operation_error(
                "group.e2ee.commit_invalid",
                "notice carries an epoch authenticator for a removed local leaf",
                &input.request_id,
            )
        })?;
        if encode_b64u(actual.as_slice()) != expected {
            return Err(operation_error(
                "group.e2ee.commit_invalid",
                "notice epoch_authenticator does not match the staged Commit",
                &input.request_id,
            ));
        }
    }
    let self_removed = staged.self_removed();
    let output = V2ProcessNoticeOutput {
        notice_operation_id: input.meta.operation_id.clone(),
        source_operation_id: Some(authenticated.operation_id),
        notice_type: input.notice.notice_type.clone(),
        crypto_group_id_b64u: input.notice.crypto_group_id_b64u.clone(),
        from_epoch: local_binding.epoch.to_string(),
        epoch: target_epoch.to_string(),
        self_removed,
    };
    set_notice_receipt_output(
        &scope.app_conn,
        receipt_key,
        &output,
        "processing",
        &input.request_id,
    )?;
    group
        .merge_staged_commit(&scope.provider, staged)
        .map_err(|err| mls_operation_error("group.e2ee.commit_invalid", err, &input.request_id))?;
    let status = if self_removed { "removed" } else { "active" };
    set_binding_epoch_status(
        &scope.app_conn,
        &input.recipient_did,
        &input.recipient_device_id,
        &input.notice.group_did,
        target_epoch,
        status,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    Ok(output)
}

#[derive(Debug)]
struct V2FinalizedSelfEchoRecord {
    operation_id: String,
    commit_b64u: String,
    response_json: String,
}

fn process_finalized_self_echo(
    scope: &GroupMlsOperationScope,
    input: &V2ProcessNoticeInput,
    group: &MlsGroup,
    target_epoch: u64,
) -> GroupMlsOperationResult<V2ProcessNoticeOutput> {
    if group.pending_commit().is_some() {
        return Err(operation_error(
            "group.e2ee.state_not_ready",
            "a same-epoch Commit notice cannot match an unmerged local pending commit",
            &input.request_id,
        ));
    }
    let from_epoch = target_epoch.checked_sub(1).ok_or_else(|| {
        operation_error(
            "group.e2ee.epoch_conflict",
            "a membership Commit echo cannot target epoch zero",
            &input.request_id,
        )
    })?;
    let command = match input.notice.subject_status.as_str() {
        "active" => "group add-member",
        "removed" => "group remove-member",
        _ => {
            return Err(operation_error(
                "group.e2ee.commit_invalid",
                "notice subject_status cannot identify Add or Remove",
                &input.request_id,
            ))
        }
    };
    let mut statement = scope
        .app_conn
        .prepare(
            "SELECT operation_id, commit_b64u, response_json
             FROM pending_commits
             WHERE status = 'finalized'
               AND command = ?1
               AND agent_did = ?2
               AND device_id = ?3
               AND group_did = ?4
               AND crypto_group_id_b64u = ?5
               AND subject_did = ?6
               AND subject_status = ?7
               AND from_epoch = ?8
               AND to_epoch = ?9",
        )
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
    let records = statement
        .query_map(
            params![
                command,
                input.recipient_did,
                input.recipient_device_id,
                input.notice.group_did,
                input.notice.crypto_group_id_b64u,
                input.notice.subject_did,
                input.notice.subject_status,
                from_epoch as i64,
                target_epoch as i64,
            ],
            |row| {
                Ok(V2FinalizedSelfEchoRecord {
                    operation_id: row.get(0)?,
                    commit_b64u: row.get(1)?,
                    response_json: row.get(2)?,
                })
            },
        )
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
    if records.len() != 1 {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "same-epoch Commit notice has no unique finalized local operation",
            &input.request_id,
        ));
    }
    let record = &records[0];
    let notice_commit = input.notice.commit_b64u.as_deref().ok_or_else(|| {
        operation_error(
            "group.e2ee.commit_invalid",
            "commit-delivery is missing commit_b64u",
            &input.request_id,
        )
    })?;
    if record.commit_b64u != notice_commit
        || commit_digest(&record.commit_b64u, &input.request_id)?
            != commit_digest(notice_commit, &input.request_id)?
    {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "same-epoch Commit notice does not match the finalized commit digest",
            &input.request_id,
        ));
    }
    validate_finalized_self_echo_body(record, &input.notice, command, &input.request_id)?;
    if let Some(expected) = input.notice.epoch_authenticator.as_deref() {
        if encode_b64u(group.epoch_authenticator().as_slice()) != expected {
            return Err(operation_error(
                "group.e2ee.commit_invalid",
                "same-epoch Commit notice has a conflicting epoch authenticator",
                &input.request_id,
            ));
        }
    }
    Ok(V2ProcessNoticeOutput {
        notice_operation_id: input.meta.operation_id.clone(),
        source_operation_id: Some(record.operation_id.clone()),
        notice_type: input.notice.notice_type.clone(),
        crypto_group_id_b64u: input.notice.crypto_group_id_b64u.clone(),
        from_epoch: from_epoch.to_string(),
        epoch: target_epoch.to_string(),
        self_removed: false,
    })
}

fn validate_finalized_self_echo_body(
    record: &V2FinalizedSelfEchoRecord,
    notice: &V2E2eeNotice,
    command: &str,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    let journal: V2PrepareJournalResponse<Value> = serde_json::from_str(&record.response_json)
        .map_err(|err| operation_error("group.e2ee.state_not_ready", err, request_id))?;
    if journal.journal_version != "p6-v2-prepare-journal-v1" {
        return Err(operation_error(
            "group.e2ee.state_not_ready",
            "finalized self-echo journal version is unsupported",
            request_id,
        ));
    }
    let prepared = journal.prepared_response.ok_or_else(|| {
        operation_error(
            "group.e2ee.state_not_ready",
            "finalized self-echo journal has no prepared public body",
            request_id,
        )
    })?;
    let matches = match command {
        "group add-member" => {
            let body: V2GroupAddBody = serde_json::from_value(prepared)
                .map_err(|err| operation_error("group.e2ee.state_not_ready", err, request_id))?;
            body.validate()
                .map_err(|err| v2_error("group.e2ee.commit_invalid", err, request_id))?;
            body.member_did == notice.subject_did
                && body.member_device_id == notice.subject_device_id
                && body.group_state_ref == notice.group_state_ref
                && body.crypto_group_id_b64u == notice.crypto_group_id_b64u
                && body.epoch == notice.epoch
                && body.commit_b64u == record.commit_b64u
        }
        "group remove-member" => {
            let body: V2GroupRemoveBody = serde_json::from_value(prepared)
                .map_err(|err| operation_error("group.e2ee.state_not_ready", err, request_id))?;
            body.validate()
                .map_err(|err| v2_error("group.e2ee.commit_invalid", err, request_id))?;
            body.member_did == notice.subject_did
                && body.member_device_id == notice.subject_device_id
                && body.group_state_ref == notice.group_state_ref
                && body.crypto_group_id_b64u == notice.crypto_group_id_b64u
                && body.epoch == notice.epoch
                && body.commit_b64u == record.commit_b64u
        }
        _ => false,
    };
    if !matches {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "same-epoch Commit notice conflicts with the finalized public request body",
            request_id,
        ));
    }
    Ok(())
}

fn commit_digest(commit_b64u: &str, request_id: &str) -> GroupMlsOperationResult<String> {
    let commit = decode_b64u(commit_b64u, request_id).map_err(GroupMlsOperationError::from)?;
    Ok(encode_b64u(&Sha256::digest(commit)))
}

enum NoticeReceiptState {
    New,
    Processing(Option<V2ProcessNoticeOutput>),
    Finalized(V2ProcessNoticeOutput),
}

fn validate_notice_outer(input: &V2ProcessNoticeInput) -> GroupMlsOperationResult<()> {
    input
        .meta
        .validate()
        .map_err(|err| v2_error("group.e2ee.state_not_ready", err, &input.request_id))?;
    input
        .notice
        .validate()
        .map_err(|err| v2_error("group.e2ee.state_not_ready", err, &input.request_id))?;
    if input.meta.sender_did != input.notice.group_did {
        return Err(operation_error(
            "group.e2ee.state_not_ready",
            "notice sender_did must equal its group_did business anchor",
            &input.request_id,
        ));
    }
    if input.meta.target.did != input.recipient_did
        || input.meta.recipient_device_id != input.recipient_device_id
    {
        return Err(operation_error(
            "group.e2ee.did_binding_invalid",
            "notice target does not identify the exact local recipient device",
            &input.request_id,
        ));
    }
    if input.notice.notice_type == "welcome-delivery"
        && (input.notice.subject_did != input.recipient_did
            || input.notice.subject_device_id != input.recipient_device_id
            || input.notice.subject_status != "active")
    {
        return Err(operation_error(
            "group.e2ee.did_binding_invalid",
            "Welcome target must equal the active added subject device",
            &input.request_id,
        ));
    }
    Ok(())
}

fn notice_input_digest(input: &V2ProcessNoticeInput) -> GroupMlsOperationResult<String> {
    let canonical = crate::canonical_json::canonicalize_json(&json!({
        "meta": input.meta,
        "notice": input.notice,
        "recipient_did": input.recipient_did,
        "recipient_device_id": input.recipient_device_id,
    }))
    .map_err(|err| operation_error("group.e2ee.state_not_ready", err, &input.request_id))?;
    Ok(encode_b64u(&Sha256::digest(canonical)))
}

fn begin_notice_receipt(
    conn: &rusqlite::Connection,
    receipt_key: &str,
    digest: &str,
    request_id: &str,
) -> GroupMlsOperationResult<NoticeReceiptState> {
    let existing = conn
        .query_row(
            "SELECT input_digest, response_json, status
             FROM operations WHERE operation_id = ?1",
            params![receipt_key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    if let Some((stored_digest, response_json, status)) = existing {
        if stored_digest != digest {
            return Err(operation_error(
                "group.e2ee.commit_invalid",
                "notice operation_id was replayed with different content",
                request_id,
            ));
        }
        let output =
            if response_json == "null" {
                None
            } else {
                Some(serde_json::from_str(&response_json).map_err(|err| {
                    operation_error("group.e2ee.state_not_ready", err, request_id)
                })?)
            };
        return match status.as_str() {
            "processing" => Ok(NoticeReceiptState::Processing(output)),
            "finalized" => output.map(NoticeReceiptState::Finalized).ok_or_else(|| {
                operation_error(
                    "group.e2ee.state_not_ready",
                    "finalized notice receipt has no output",
                    request_id,
                )
            }),
            _ => Err(operation_error(
                "group.e2ee.state_not_ready",
                "notice receipt has an unsupported state",
                request_id,
            )),
        };
    }
    conn.execute(
        "INSERT INTO operations(operation_id, command, input_digest, response_json, status, updated_at)
         VALUES (?1, 'group.e2ee.notice.v2', ?2, 'null', 'processing', CURRENT_TIMESTAMP)",
        params![receipt_key, digest],
    )
    .map_err(|err| sqlite_operation_error(err, request_id))?;
    Ok(NoticeReceiptState::New)
}

fn set_notice_receipt_output(
    conn: &rusqlite::Connection,
    receipt_key: &str,
    output: &V2ProcessNoticeOutput,
    status: &str,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    let expected_status = status;
    conn.execute(
        "UPDATE operations
             SET response_json = ?2, status = ?3, updated_at = CURRENT_TIMESTAMP
             WHERE operation_id = ?1",
        params![
            receipt_key,
            serde_json::to_string(output).map_err(|err| operation_error(
                "group.e2ee.state_not_ready",
                err,
                request_id,
            ))?,
            expected_status,
        ],
    )
    .map_err(|err| sqlite_operation_error(err, request_id))?;
    let persisted_status: Option<String> = conn
        .query_row(
            "SELECT status FROM operations WHERE operation_id = ?1",
            params![receipt_key],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    if persisted_status.as_deref() != Some(expected_status) {
        return Err(operation_error(
            "group.e2ee.state_not_ready",
            "notice receipt disappeared during processing",
            request_id,
        ));
    }
    Ok(())
}

fn finalize_notice_receipt(
    conn: &rusqlite::Connection,
    receipt_key: &str,
    output: &V2ProcessNoticeOutput,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    set_notice_receipt_output(conn, receipt_key, output, "finalized", request_id)
}

fn recover_notice_if_applied(
    scope: &GroupMlsOperationScope,
    input: &V2ProcessNoticeInput,
    output: &V2ProcessNoticeOutput,
) -> GroupMlsOperationResult<bool> {
    let expected_epoch = parse_epoch(&output.epoch, &input.request_id)?;
    let group_id = GroupId::from_slice(
        &decode_b64u(&output.crypto_group_id_b64u, &input.request_id)
            .map_err(GroupMlsOperationError::from)?,
    );
    let Some(group) = MlsGroup::load(scope.provider.storage(), &group_id)
        .map_err(|err| mls_operation_error("group.e2ee.state_not_ready", err, &input.request_id))?
    else {
        return Ok(false);
    };
    if group.epoch().as_u64() != expected_epoch {
        return Ok(false);
    }
    let status = if output.self_removed {
        "removed"
    } else {
        "active"
    };
    if binding_status(
        &scope.app_conn,
        &input.recipient_did,
        &input.recipient_device_id,
        &input.notice.group_did,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?
    .is_some()
    {
        set_binding_epoch_status(
            &scope.app_conn,
            &input.recipient_did,
            &input.recipient_device_id,
            &input.notice.group_did,
            expected_epoch,
            status,
            &input.request_id,
        )
        .map_err(GroupMlsOperationError::from)?;
    } else if !output.self_removed {
        upsert_binding(
            &scope.app_conn,
            &input.recipient_did,
            &input.recipient_device_id,
            &input.notice.group_did,
            &group_id,
            expected_epoch,
            "member",
            &input.request_id,
        )
        .map_err(GroupMlsOperationError::from)?;
    } else {
        return Ok(false);
    }
    Ok(true)
}

fn validate_persisted_epoch_authenticator(
    scope: &GroupMlsOperationScope,
    crypto_group_id_b64u: &str,
    expected: Option<&str>,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let group_id = GroupId::from_slice(
        &decode_b64u(crypto_group_id_b64u, request_id).map_err(GroupMlsOperationError::from)?,
    );
    let group =
        load_group(&scope.provider, &group_id, request_id).map_err(GroupMlsOperationError::from)?;
    if encode_b64u(group.epoch_authenticator().as_slice()) != expected {
        return Err(operation_error(
            "group.e2ee.welcome_invalid",
            "notice epoch_authenticator does not match the Welcome state",
            request_id,
        ));
    }
    Ok(())
}

fn parse_membership_authenticated_data(
    aad: &[u8],
    request_id: &str,
) -> GroupMlsOperationResult<V2MembershipAuthenticatedData> {
    let value: Value = serde_json::from_slice(aad)
        .map_err(|err| operation_error("group.e2ee.commit_invalid", err, request_id))?;
    let canonical = crate::canonical_json::canonicalize_json(&value)
        .map_err(|err| operation_error("group.e2ee.commit_invalid", err, request_id))?;
    if canonical != aad {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "Commit authenticated_data is not exact RFC 8785 JCS",
            request_id,
        ));
    }
    let authenticated: V2MembershipAuthenticatedData = serde_json::from_value(value)
        .map_err(|err| operation_error("group.e2ee.commit_invalid", err, request_id))?;
    for (field, value) in [
        ("sender_did", authenticated.sender_did.as_str()),
        ("sender_device_id", authenticated.sender_device_id.as_str()),
        ("operation_id", authenticated.operation_id.as_str()),
    ] {
        require_non_empty(field, value, request_id)?;
    }
    Ok(authenticated)
}

fn validate_notice_membership_binding(
    authenticated: &V2MembershipAuthenticatedData,
    notice: &V2E2eeNotice,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    let expected_method = match notice.subject_status.as_str() {
        "active" => METHOD_GROUP_ADD_V2,
        "removed" => METHOD_GROUP_REMOVE_V2,
        _ => {
            return Err(operation_error(
                "group.e2ee.commit_invalid",
                "notice subject_status cannot identify Add or Remove",
                request_id,
            ))
        }
    };
    if authenticated.group_did != notice.group_did
        || authenticated.crypto_group_id_b64u != notice.crypto_group_id_b64u
        || authenticated.group_state_ref != notice.group_state_ref
        || authenticated.subject_method != expected_method
        || authenticated.member_did != notice.subject_did
        || authenticated.member_device_id != notice.subject_device_id
        || authenticated.epoch != notice.epoch
        || authenticated.security_profile != GROUP_E2EE_SECURITY_PROFILE_V2
    {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "Commit authenticated_data does not match the standard notice",
            request_id,
        ));
    }
    Ok(())
}

fn exact_did_document<'a>(
    documents: &'a [V2DidDocument],
    did: &str,
    request_id: &str,
) -> GroupMlsOperationResult<&'a Value> {
    let mut matches = documents.iter().filter(|entry| entry.did == did);
    let document = matches.next().ok_or_else(|| {
        operation_error(
            "group.e2ee.did_binding_invalid",
            format!("missing DID document for {did}"),
            request_id,
        )
    })?;
    if matches.next().is_some() || document.document.get("id").and_then(Value::as_str) != Some(did)
    {
        return Err(operation_error(
            "group.e2ee.did_binding_invalid",
            format!("DID document set is ambiguous or mismatched for {did}"),
            request_id,
        ));
    }
    Ok(&document.document)
}

pub fn process_commit_v2<S: GroupMlsStore>(
    store: &S,
    input: V2ProcessCommitInput,
) -> GroupMlsOperationResult<V2ProcessCommitOutput> {
    validate_store_scope(
        store.owner_scope().as_ref(),
        &input.recipient_did,
        &input.recipient_device_id,
        &input.request_id,
    )?;
    validate_control_meta(&input.meta, &input.group_state_ref, &input.request_id)?;
    let scope = open_scope(store, &input.request_id)?;
    let local_binding = binding(
        &scope.app_conn,
        &input.recipient_did,
        &input.recipient_device_id,
        &input.group_state_ref.group_did,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    let mut group = load_group(
        &scope.provider,
        &local_binding.openmls_group_id,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    ensure_group_head(
        &group,
        &local_binding,
        &input.group_state_ref.group_did,
        &input.request_id,
    )?;
    if input.crypto_group_id_b64u != encode_b64u(group.group_id().as_slice()) {
        return Err(operation_error(
            "group.e2ee.crypto_group_mismatch",
            "Commit crypto group does not match local state",
            &input.request_id,
        ));
    }
    let target_epoch = parse_epoch(&input.epoch, &input.request_id)?;
    if target_epoch
        != local_binding.epoch.checked_add(1).ok_or_else(|| {
            operation_error(
                "group.e2ee.epoch_conflict",
                "epoch overflow",
                &input.request_id,
            )
        })?
    {
        return Err(operation_error(
            "group.e2ee.epoch_conflict",
            "Commit epoch is not exactly local epoch plus one",
            &input.request_id,
        ));
    }
    let expected_aad = membership_aad(
        input.method.as_str(),
        &input.meta,
        &input.group_state_ref,
        &input.crypto_group_id_b64u,
        target_epoch,
        &input.member_did,
        &input.member_device_id,
        &input.request_id,
    )?;
    let message = MlsMessageIn::tls_deserialize_exact(
        decode_b64u(&input.commit_b64u, &input.request_id).map_err(GroupMlsOperationError::from)?,
    )
    .map_err(|err| mls_operation_error("group.e2ee.commit_invalid", err, &input.request_id))?;
    let protocol = message.try_into_protocol_message().map_err(|_| {
        operation_error(
            "group.e2ee.commit_invalid",
            "commit_b64u is not an MLS protocol message",
            &input.request_id,
        )
    })?;
    let processed = group
        .process_message(&scope.provider, protocol)
        .map_err(|err| mls_operation_error("group.e2ee.commit_invalid", err, &input.request_id))?;
    if processed.aad() != expected_aad {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "Commit authenticated_data does not match its exact outer context",
            &input.request_id,
        ));
    }
    validate_processed_sender(
        &scope,
        &group,
        processed.sender(),
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &input.sender_did_document,
        &input.now,
        input.draft_extension_negotiated,
        &input.request_id,
    )?;
    let staged = match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(value) => *value,
        _ => {
            return Err(operation_error(
                "group.e2ee.commit_invalid",
                "commit_b64u does not contain a staged Commit",
                &input.request_id,
            ))
        }
    };
    if staged.epoch().as_u64() != target_epoch {
        return Err(operation_error(
            "group.e2ee.epoch_conflict",
            "staged Commit epoch does not match the exact outer epoch",
            &input.request_id,
        ));
    }
    validate_staged_membership_delta(
        &scope,
        &group,
        &staged,
        &input.method,
        &input.member_did,
        &input.member_device_id,
        &input.member_did_document,
        &input.now,
        input.draft_extension_negotiated,
        &input.request_id,
    )?;
    let self_removed = staged.self_removed();
    group
        .merge_staged_commit(&scope.provider, staged)
        .map_err(|err| mls_operation_error("group.e2ee.commit_invalid", err, &input.request_id))?;
    if self_removed {
        mark_binding_inactive(
            &scope.app_conn,
            &input.recipient_did,
            &input.recipient_device_id,
            &input.group_state_ref.group_did,
            target_epoch,
            "removed",
            &input.request_id,
        )
        .map_err(GroupMlsOperationError::from)?;
    } else {
        set_binding_epoch_status(
            &scope.app_conn,
            &input.recipient_did,
            &input.recipient_device_id,
            &input.group_state_ref.group_did,
            target_epoch,
            "active",
            &input.request_id,
        )
        .map_err(GroupMlsOperationError::from)?;
    }
    Ok(V2ProcessCommitOutput {
        crypto_group_id_b64u: input.crypto_group_id_b64u,
        from_epoch: local_binding.epoch.to_string(),
        epoch: target_epoch.to_string(),
        self_removed,
    })
}

pub fn encrypt_v2<S: GroupMlsStore>(
    store: &S,
    input: V2EncryptInput,
) -> GroupMlsOperationResult<V2GroupCipherObject> {
    input
        .meta
        .validate()
        .map_err(|err| v2_error("group.e2ee.private_message_invalid", err, &input.request_id))?;
    validate_store_scope(
        store.owner_scope().as_ref(),
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &input.request_id,
    )?;
    if input.meta.target.did != input.group_state_ref.group_did {
        return Err(operation_error(
            "group.e2ee.private_message_invalid",
            "send target must equal group_state_ref.group_did",
            &input.request_id,
        ));
    }
    let scope = open_scope(store, &input.request_id)?;
    let local_binding = binding(
        &scope.app_conn,
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &input.group_state_ref.group_did,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    let mut group = load_group(
        &scope.provider,
        &local_binding.openmls_group_id,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    ensure_group_head(
        &group,
        &local_binding,
        &input.group_state_ref.group_did,
        &input.request_id,
    )?;
    validate_leaf_exact(
        group.own_leaf_node().ok_or_else(|| {
            operation_error(
                "group.e2ee.did_binding_invalid",
                "local MLS group has no own leaf",
                &input.request_id,
            )
        })?,
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &input.sender_did_document,
        required_extension_ids(&group),
        &input.now,
        input.draft_extension_negotiated,
        &input.request_id,
    )?;
    let plaintext = canonical_group_application_plaintext_v2(&input.application_plaintext)
        .map_err(|err| v2_error("group.e2ee.private_message_invalid", err, &input.request_id))?;
    let mut body = V2GroupCipherObject {
        crypto_group_id_b64u: encode_b64u(group.group_id().as_slice()),
        epoch: group.epoch().as_u64().to_string(),
        private_message_b64u: "AA".to_owned(),
        group_state_ref: input.group_state_ref,
        epoch_authenticator: Some(encode_b64u(group.epoch_authenticator().as_slice())),
    };
    let aad = group_send_authenticated_data_v2(&input.meta, &body)
        .map_err(|err| v2_error("group.e2ee.private_message_invalid", err, &input.request_id))?;
    group.set_aad(aad.clone());
    let message = group
        .create_message(
            &scope.provider,
            &load_signer(
                &scope.provider,
                &scope.app_conn,
                &input.meta.sender_did,
                &input.meta.sender_device_id,
                &input.request_id,
            )
            .map_err(GroupMlsOperationError::from)?,
            &plaintext,
        )
        .map_err(|err| {
            mls_operation_error("group.e2ee.private_message_invalid", err, &input.request_id)
        })?;
    let private_message = match message.body() {
        MlsMessageBodyOut::PrivateMessage(private_message) => private_message,
        _ => {
            return Err(operation_error(
                "group.e2ee.private_message_invalid",
                "OpenMLS did not produce a PrivateMessage",
                &input.request_id,
            ))
        }
    };
    body.private_message_b64u = encode_tls(
        private_message,
        "group.e2ee.private_message_invalid",
        &input.request_id,
    )?;
    if group_send_authenticated_data_v2(&input.meta, &body)
        .map_err(|err| v2_error("group.e2ee.private_message_invalid", err, &input.request_id))?
        != aad
    {
        return Err(operation_error(
            "group.e2ee.private_message_invalid",
            "final group cipher changed its authenticated_data context",
            &input.request_id,
        ));
    }
    Ok(body)
}

pub fn decrypt_v2<S: GroupMlsStore>(
    store: &S,
    input: V2DecryptInput,
) -> GroupMlsOperationResult<V2DecryptOutput> {
    input
        .originating_meta
        .validate()
        .map_err(|err| v2_error("group.e2ee.private_message_invalid", err, &input.request_id))?;
    input
        .group_cipher_object
        .validate()
        .map_err(|err| v2_error("group.e2ee.private_message_invalid", err, &input.request_id))?;
    validate_store_scope(
        store.owner_scope().as_ref(),
        &input.recipient_did,
        &input.recipient_device_id,
        &input.request_id,
    )?;
    let scope = open_scope(store, &input.request_id)?;
    let local_binding = binding(
        &scope.app_conn,
        &input.recipient_did,
        &input.recipient_device_id,
        &input.group_cipher_object.group_state_ref.group_did,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    let mut group = load_group(
        &scope.provider,
        &local_binding.openmls_group_id,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
    ensure_group_head(
        &group,
        &local_binding,
        &input.group_cipher_object.group_state_ref.group_did,
        &input.request_id,
    )?;
    if input.group_cipher_object.crypto_group_id_b64u != encode_b64u(group.group_id().as_slice())
        || parse_epoch(&input.group_cipher_object.epoch, &input.request_id)?
            != group.epoch().as_u64()
    {
        return Err(operation_error(
            "group.e2ee.epoch_conflict",
            "group cipher does not match the local crypto group and epoch",
            &input.request_id,
        ));
    }
    if input
        .group_cipher_object
        .epoch_authenticator
        .as_deref()
        .is_some_and(|value| value != encode_b64u(group.epoch_authenticator().as_slice()))
    {
        return Err(operation_error(
            "group.e2ee.epoch_conflict",
            "group cipher epoch_authenticator conflicts with local MLS state",
            &input.request_id,
        ));
    }
    let expected_aad =
        group_send_authenticated_data_v2(&input.originating_meta, &input.group_cipher_object)
            .map_err(|err| {
                v2_error("group.e2ee.private_message_invalid", err, &input.request_id)
            })?;
    let private_message = PrivateMessageIn::tls_deserialize_exact(
        decode_b64u(
            &input.group_cipher_object.private_message_b64u,
            &input.request_id,
        )
        .map_err(GroupMlsOperationError::from)?,
    )
    .map_err(|err| {
        mls_operation_error("group.e2ee.private_message_invalid", err, &input.request_id)
    })?;
    let protocol: ProtocolMessage = private_message.into();
    let processed = group
        .process_message(&scope.provider, protocol)
        .map_err(|err| {
            mls_operation_error("group.e2ee.private_message_invalid", err, &input.request_id)
        })?;
    if processed.aad() != expected_aad {
        return Err(operation_error(
            "group.e2ee.private_message_invalid",
            "MLS authenticated_data does not match the originating send",
            &input.request_id,
        ));
    }
    let sender = validate_processed_sender(
        &scope,
        &group,
        processed.sender(),
        &input.originating_meta.sender_did,
        &input.originating_meta.sender_device_id,
        &input.sender_did_document,
        &input.now,
        input.draft_extension_negotiated,
        &input.request_id,
    )?;
    let plaintext = match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(value) => value.into_bytes(),
        _ => {
            return Err(operation_error(
                "group.e2ee.private_message_invalid",
                "group cipher is not an MLS application message",
                &input.request_id,
            ))
        }
    };
    let value: Value = serde_json::from_slice(&plaintext).map_err(|err| {
        operation_error("group.e2ee.private_message_invalid", err, &input.request_id)
    })?;
    let application_plaintext = parse_group_application_plaintext_v2(&value)
        .map_err(|err| v2_error("group.e2ee.private_message_invalid", err, &input.request_id))?;
    if canonical_group_application_plaintext_v2(&application_plaintext)
        .map_err(|err| v2_error("group.e2ee.private_message_invalid", err, &input.request_id))?
        != plaintext
    {
        return Err(operation_error(
            "group.e2ee.private_message_invalid",
            "group application plaintext is not RFC 8785 canonical JSON",
            &input.request_id,
        ));
    }
    Ok(V2DecryptOutput {
        application_plaintext,
        epoch: group.epoch().as_u64().to_string(),
        sender_did: sender.agent_did,
        sender_device_id: sender.device_id,
        sender_leaf_signature_key_b64u: sender.leaf_signature_key_b64u,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_staged_membership_delta(
    scope: &GroupMlsOperationScope,
    group: &MlsGroup,
    staged: &StagedCommit,
    method: &V2MembershipCommitMethod,
    member_did: &str,
    member_device_id: &str,
    member_document: &Value,
    now: &str,
    draft_extension_negotiated: bool,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    if staged.update_proposals().next().is_some() || staged.queued_proposals().count() != 1 {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "P6 v2 membership Commit must contain exactly one Add or Remove proposal",
            request_id,
        ));
    }
    match method {
        V2MembershipCommitMethod::Add => {
            let mut adds = staged.add_proposals();
            let add = adds.next().ok_or_else(|| {
                operation_error(
                    "group.e2ee.commit_invalid",
                    "Add Commit does not contain one Add proposal",
                    request_id,
                )
            })?;
            if adds.next().is_some() || staged.remove_proposals().next().is_some() {
                return Err(operation_error(
                    "group.e2ee.commit_invalid",
                    "Add Commit contains another membership proposal",
                    request_id,
                ));
            }
            validate_leaf_exact(
                add.add_proposal().key_package().leaf_node(),
                member_did,
                member_device_id,
                member_document,
                required_extension_ids(group),
                now,
                draft_extension_negotiated,
                request_id,
            )?;
        }
        V2MembershipCommitMethod::Remove => {
            let exact = find_exact_accepted_leaf(
                scope,
                group,
                member_did,
                member_device_id,
                member_document,
                draft_extension_negotiated,
                request_id,
            )?;
            let mut removes = staged.remove_proposals();
            let remove = removes.next().ok_or_else(|| {
                operation_error(
                    "group.e2ee.commit_invalid",
                    "Remove Commit does not contain one Remove proposal",
                    request_id,
                )
            })?;
            if removes.next().is_some()
                || staged.add_proposals().next().is_some()
                || remove.remove_proposal().removed() != exact.index
            {
                return Err(operation_error(
                    "group.e2ee.commit_invalid",
                    "Remove Commit does not remove the exact target device leaf",
                    request_id,
                ));
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_processed_sender(
    scope: &GroupMlsOperationScope,
    group: &MlsGroup,
    sender: &Sender,
    expected_did: &str,
    expected_device_id: &str,
    did_document: &Value,
    now: &str,
    draft_extension_negotiated: bool,
    request_id: &str,
) -> GroupMlsOperationResult<V2LeafIdentity> {
    let Sender::Member(index) = sender else {
        return Err(operation_error(
            "group.e2ee.did_binding_invalid",
            "P6 v2 only accepts messages from an existing device leaf",
            request_id,
        ));
    };
    let public_group = load_public_group(scope, group, request_id)?;
    let leaf = public_group.leaf(*index).ok_or_else(|| {
        operation_error(
            "group.e2ee.did_binding_invalid",
            "MLS sender leaf is absent from the current tree",
            request_id,
        )
    })?;
    validate_leaf_exact(
        leaf,
        expected_did,
        expected_device_id,
        did_document,
        required_extension_ids(group),
        now,
        draft_extension_negotiated,
        request_id,
    )
}

fn validate_all_group_leaves(
    scope: &GroupMlsOperationScope,
    group: &MlsGroup,
    documents: &[V2DidDocument],
    now: &str,
    draft_extension_negotiated: bool,
    request_id: &str,
) -> GroupMlsOperationResult<Vec<V2LeafIdentity>> {
    let public_group = load_public_group(scope, group, request_id)?;
    let required = required_extension_ids(group);
    let mut identities = Vec::new();
    for member in group.members() {
        let leaf = public_group.leaf(member.index).ok_or_else(|| {
            operation_error(
                "group.e2ee.did_binding_invalid",
                "member leaf is missing from the public group",
                request_id,
            )
        })?;
        let (binding, _) = leaf_binding_evidence(leaf, request_id)?;
        let document = documents
            .iter()
            .find(|entry| entry.did == binding.agent_did)
            .ok_or_else(|| {
                operation_error(
                    "group.e2ee.did_binding_invalid",
                    format!("missing current DID document for {}", binding.agent_did),
                    request_id,
                )
            })?;
        identities.push(validate_leaf_exact(
            leaf,
            &binding.agent_did,
            &binding.device_id,
            &document.document,
            required.clone(),
            now,
            draft_extension_negotiated,
            request_id,
        )?);
    }
    validate_leaf_identity_set_v2(&identities)
        .map_err(|err| v2_error("group.e2ee.did_binding_invalid", err, request_id))?;
    Ok(identities)
}

/// Selects one endpoint from the authenticated, locally accepted MLS tree.
///
/// A Remove target may already be absent from the current P2 Manifest: loss of
/// Manifest eligibility is itself a protocol trigger for Remove.  Therefore
/// this check revalidates the immutable DID/device/credential/leaf-key binding
/// carried by the accepted tree, but deliberately does not require the target's
/// old Manifest entry, Object Proof key or validity window to remain current.
/// The supplied document must still identify the requested DID. The product
/// and Group Host remain responsible for current P4 state and the allowed
/// trigger.
fn find_exact_accepted_leaf(
    scope: &GroupMlsOperationScope,
    group: &MlsGroup,
    did: &str,
    device_id: &str,
    did_document: &Value,
    draft_extension_negotiated: bool,
    request_id: &str,
) -> GroupMlsOperationResult<Member> {
    if did_document.get("id").and_then(Value::as_str) != Some(did) {
        return Err(operation_error(
            "group.e2ee.did_binding_invalid",
            "Remove target DID document id does not match member_did",
            request_id,
        ));
    }
    if !draft_extension_negotiated {
        return Err(operation_error(
            "group.e2ee.did_binding_invalid",
            "draft MLS binding extension requires explicit anp.group.e2ee.v2 negotiation",
            request_id,
        ));
    }
    let public_group = load_public_group(scope, group, request_id)?;
    let required = required_extension_ids(group);
    crate::group_e2ee::validate_group_required_capabilities_v2(&required)
        .map_err(|err| v2_error("group.e2ee.did_binding_invalid", err, request_id))?;
    let mut identities = Vec::new();
    let mut matches = Vec::new();
    for member in group.members() {
        let leaf = public_group.leaf(member.index).ok_or_else(|| {
            operation_error(
                "group.e2ee.did_binding_invalid",
                "member leaf is missing from the public group",
                request_id,
            )
        })?;
        let (binding, evidence) = leaf_binding_evidence(leaf, request_id)?;
        binding
            .validate_structure()
            .map_err(|err| v2_error("group.e2ee.did_binding_invalid", err, request_id))?;
        if evidence.credential_identity.as_slice() != binding.agent_did.as_bytes() {
            return Err(operation_error(
                "group.e2ee.did_binding_invalid",
                "MLS credential.identity must equal the accepted leaf agent_did",
                request_id,
            ));
        }
        if evidence.leaf_signature_key_b64u != binding.leaf_signature_key_b64u {
            return Err(operation_error(
                "group.e2ee.did_binding_invalid",
                "accepted MLS leaf signature key does not match its device binding",
                request_id,
            ));
        }
        let canonical_binding = serde_json_canonicalizer::to_vec(&binding)
            .map_err(|err| operation_error("group.e2ee.did_binding_invalid", err, request_id))?;
        let binding_extension = evidence
            .extensions
            .iter()
            .find(|extension| extension.extension_type == DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2)
            .ok_or_else(|| {
                operation_error(
                    "group.e2ee.did_binding_invalid",
                    "accepted MLS leaf is missing its device-binding extension",
                    request_id,
                )
            })?;
        if binding_extension.extension_data != canonical_binding {
            return Err(operation_error(
                "group.e2ee.did_binding_invalid",
                "accepted MLS binding extension is not canonical",
                request_id,
            ));
        }
        if evidence
            .leaf_capability_extensions
            .iter()
            .filter(|extension| **extension == DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2)
            .count()
            != 1
        {
            return Err(operation_error(
                "group.e2ee.did_binding_invalid",
                "accepted MLS leaf must advertise the device-binding extension exactly once",
                request_id,
            ));
        }
        identities.push(V2LeafIdentity {
            agent_did: binding.agent_did.clone(),
            device_id: binding.device_id.clone(),
            leaf_signature_key_b64u: evidence.leaf_signature_key_b64u,
        });
        if binding.agent_did == did && binding.device_id == device_id {
            matches.push(member);
        }
    }
    validate_leaf_identity_set_v2(&identities)
        .map_err(|err| v2_error("group.e2ee.did_binding_invalid", err, request_id))?;
    if matches.len() != 1 {
        return Err(operation_error(
            "group.e2ee.did_binding_invalid",
            "exact DID/device pair must identify one current MLS leaf",
            request_id,
        ));
    }
    Ok(matches.remove(0))
}

fn ensure_leaf_absent(
    scope: &GroupMlsOperationScope,
    group: &MlsGroup,
    target: &V2LeafIdentity,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    let public_group = load_public_group(scope, group, request_id)?;
    for member in group.members() {
        let leaf = public_group.leaf(member.index).ok_or_else(|| {
            operation_error(
                "group.e2ee.did_binding_invalid",
                "member leaf is missing from the public group",
                request_id,
            )
        })?;
        let (binding, evidence) = leaf_binding_evidence(leaf, request_id)?;
        if (binding.agent_did == target.agent_did && binding.device_id == target.device_id)
            || evidence.leaf_signature_key_b64u == target.leaf_signature_key_b64u
        {
            return Err(operation_error(
                "group.e2ee.key_package_consumed",
                "KeyPackage device pair or leaf signature key already exists in the group",
                request_id,
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_leaf_exact(
    leaf: &LeafNode,
    expected_did: &str,
    expected_device_id: &str,
    did_document: &Value,
    required_extensions: Vec<u16>,
    now: &str,
    draft_extension_negotiated: bool,
    request_id: &str,
) -> GroupMlsOperationResult<V2LeafIdentity> {
    let (binding, evidence) = leaf_binding_evidence(leaf, request_id)?;
    if binding.agent_did != expected_did || binding.device_id != expected_device_id {
        return Err(operation_error(
            "group.e2ee.did_binding_invalid",
            "MLS leaf binding does not equal the expected DID/device pair",
            request_id,
        ));
    }
    verify_did_wba_binding_v2(
        &binding,
        did_document,
        &evidence,
        &required_extensions,
        now,
        draft_extension_negotiated,
    )
    .map_err(|err| v2_error("group.e2ee.did_binding_invalid", err, request_id))?;
    Ok(V2LeafIdentity {
        agent_did: binding.agent_did,
        device_id: binding.device_id,
        leaf_signature_key_b64u: evidence.leaf_signature_key_b64u,
    })
}

fn leaf_binding_evidence(
    leaf: &LeafNode,
    request_id: &str,
) -> GroupMlsOperationResult<(V2DidWbaBinding, V2LeafBindingEvidence)> {
    let extensions = leaf
        .extensions()
        .iter()
        .filter_map(|extension| match extension {
            Extension::Unknown(extension_type, value) => Some(V2LeafExtension {
                extension_type: *extension_type,
                extension_data: value.0.clone(),
            }),
            _ => None,
        })
        .collect::<Vec<_>>();
    let binding_extensions = extensions
        .iter()
        .filter(|entry| entry.extension_type == DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2)
        .collect::<Vec<_>>();
    if binding_extensions.len() != 1 {
        return Err(operation_error(
            "group.e2ee.did_binding_invalid",
            "leaf must contain exactly one P6 v2 device-binding extension",
            request_id,
        ));
    }
    let binding: V2DidWbaBinding = serde_json::from_slice(&binding_extensions[0].extension_data)
        .map_err(|err| operation_error("group.e2ee.did_binding_invalid", err, request_id))?;
    Ok((
        binding,
        V2LeafBindingEvidence {
            credential_identity: leaf.credential().serialized_content().to_vec(),
            leaf_signature_key_b64u: URL_SAFE_NO_PAD.encode(leaf.signature_key().as_slice()),
            extensions,
            leaf_capability_extensions: leaf
                .capabilities()
                .extensions()
                .iter()
                .copied()
                .map(u16::from)
                .collect(),
        },
    ))
}

fn parse_and_validate_key_package(
    provider: &super::super::storage::SqliteMlsProvider,
    package: &V2GroupKeyPackage,
    did_document: &Value,
    now: &str,
    draft_extension_negotiated: bool,
    request_id: &str,
) -> GroupMlsOperationResult<(KeyPackage, V2KeyPackageBindingEvidence)> {
    let bytes = URL_SAFE_NO_PAD
        .decode(&package.mls_key_package_b64u)
        .map_err(|err| operation_error("group.e2ee.invalid_key_package", err, request_id))?;
    let mut reader = bytes.as_slice();
    let package_in = KeyPackageIn::tls_deserialize(&mut reader)
        .map_err(|err| mls_operation_error("group.e2ee.invalid_key_package", err, request_id))?;
    if !reader.is_empty() {
        return Err(operation_error(
            "group.e2ee.invalid_key_package",
            "trailing bytes after MLS KeyPackage",
            request_id,
        ));
    }
    let package_value = package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|err| mls_operation_error("group.e2ee.invalid_key_package", err, request_id))?;
    let (_, leaf) = leaf_binding_evidence(package_value.leaf_node(), request_id)?;
    let evidence = V2KeyPackageBindingEvidence {
        tls_serialized_key_package: bytes,
        leaf,
    };
    validate_group_key_package_binding_v2(
        package,
        did_document,
        &evidence,
        &[DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2],
        now,
        draft_extension_negotiated,
    )
    .map_err(|err| v2_error("group.e2ee.did_binding_invalid", err, request_id))?;
    Ok((package_value, evidence))
}

fn binding_extensions(
    binding: &V2DidWbaBinding,
    request_id: &str,
) -> GroupMlsOperationResult<Extensions<LeafNode>> {
    let bytes = serde_json_canonicalizer::to_vec(binding)
        .map_err(|err| operation_error("group.e2ee.did_binding_invalid", err, request_id))?;
    Extensions::single(Extension::Unknown(
        DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2,
        UnknownExtension(bytes),
    ))
    .map_err(|err| mls_operation_error("group.e2ee.did_binding_invalid", err, request_id))
}

fn v2_capabilities() -> Capabilities {
    Capabilities::builder()
        .extensions(vec![ExtensionType::Unknown(
            DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2,
        )])
        .credentials(vec![CredentialType::Basic])
        .build()
}

fn v2_group_create_config(
    binding: &V2DidWbaBinding,
    request_id: &str,
) -> GroupMlsOperationResult<MlsGroupCreateConfig> {
    let extension_type = ExtensionType::Unknown(DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2);
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite())
        .wire_format_policy(P6_V2_WIRE_FORMAT_POLICY)
        .capabilities(v2_capabilities())
        .with_leaf_node_extensions(binding_extensions(binding, request_id)?)
        .map_err(|err| mls_operation_error("group.e2ee.did_binding_invalid", err, request_id))?
        .with_group_context_extensions(
            Extensions::single(Extension::RequiredCapabilities(
                RequiredCapabilitiesExtension::new(&[extension_type], &[], &[]),
            ))
            .map_err(|err| mls_operation_error("group.e2ee.state_not_ready", err, request_id))?,
        )
        .use_ratchet_tree_extension(true)
        .build();
    Ok(config)
}

fn v2_group_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(P6_V2_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build()
}

fn required_extension_ids(group: &MlsGroup) -> Vec<u16> {
    group
        .extensions()
        .required_capabilities()
        .map(|required| {
            required
                .extension_types()
                .iter()
                .copied()
                .map(u16::from)
                .collect()
        })
        .unwrap_or_default()
}

#[allow(clippy::too_many_arguments)]
fn membership_aad(
    method: &str,
    meta: &V2GroupControlMetadata,
    state_ref: &V2GroupStateRef,
    crypto_group_id_b64u: &str,
    epoch: u64,
    member_did: &str,
    member_device_id: &str,
    request_id: &str,
) -> GroupMlsOperationResult<Vec<u8>> {
    crate::canonical_json::canonicalize_json(&json!({
        "group_did": meta.target.did,
        "crypto_group_id_b64u": crypto_group_id_b64u,
        "group_state_ref": state_ref,
        "subject_method": method,
        "member_did": member_did,
        "member_device_id": member_device_id,
        "epoch": epoch.to_string(),
        "security_profile": crate::group_e2ee::GROUP_E2EE_SECURITY_PROFILE_V2,
        "sender_did": meta.sender_did,
        "sender_device_id": meta.sender_device_id,
        "operation_id": meta.operation_id,
    }))
    .map_err(|err| operation_error("group.e2ee.commit_invalid", err, request_id))
}

fn validate_control_meta(
    meta: &V2GroupControlMetadata,
    state_ref: &V2GroupStateRef,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    meta.validate()
        .map_err(|err| v2_error("group.e2ee.state_not_ready", err, request_id))?;
    state_ref
        .validate()
        .map_err(|err| v2_error("group.e2ee.state_not_ready", err, request_id))?;
    if meta.target.did != state_ref.group_did {
        return Err(operation_error(
            "group.e2ee.state_not_ready",
            "control target must equal group_state_ref.group_did",
            request_id,
        ));
    }
    Ok(())
}

fn ensure_group_head(
    group: &MlsGroup,
    local_binding: &super::Binding,
    group_did: &str,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    if local_binding.group_did != group_did
        || local_binding.openmls_group_id != *group.group_id()
        || local_binding.epoch != group.epoch().as_u64()
    {
        return Err(operation_error(
            "group.e2ee.epoch_conflict",
            "local group binding does not match persisted OpenMLS state",
            request_id,
        ));
    }
    let required = required_extension_ids(group);
    if required != vec![DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2] {
        return Err(operation_error(
            "group.e2ee.did_binding_invalid",
            "group does not require the negotiated P6 v2 device-binding extension",
            request_id,
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn persist_pending_membership<T: Serialize>(
    scope: &GroupMlsOperationScope,
    pending_commit_id: &str,
    commit_b64u: &str,
    ratchet_tree_b64u: Option<&str>,
    response: &T,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    mark_v2_prepared(
        &scope.app_conn,
        pending_commit_id,
        commit_b64u,
        ratchet_tree_b64u,
        None,
        None,
        response,
        request_id,
    )
}

#[allow(clippy::too_many_arguments)]
fn insert_v2_preparing(
    conn: &rusqlite::Connection,
    pending_commit_id: &str,
    operation_id: &str,
    command: &str,
    actor_did: &str,
    actor_device_id: &str,
    group_did: &str,
    crypto_group_id_b64u: &str,
    subject_did: &str,
    subject_status: &str,
    from_epoch: u64,
    to_epoch: u64,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    let journal = V2PrepareJournalResponse::<Value> {
        journal_version: "p6-v2-prepare-journal-v1".to_owned(),
        prepared_response: None,
    };
    conn.execute(
        "INSERT INTO pending_commits(
            pending_commit_id, operation_id, command, agent_did, device_id, group_did,
            crypto_group_id_b64u, subject_did, subject_status, from_epoch, to_epoch,
            commit_b64u, ratchet_tree_b64u, group_info_b64u,
            epoch_authenticator_b64u, status, response_json, updated_at
         )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                 '', NULL, NULL, NULL, 'preparing', ?12, CURRENT_TIMESTAMP)",
        params![
            pending_commit_id,
            operation_id,
            command,
            actor_did,
            actor_device_id,
            group_did,
            crypto_group_id_b64u,
            subject_did,
            subject_status,
            from_epoch as i64,
            to_epoch as i64,
            serde_json::to_string(&journal).map_err(|err| operation_error(
                "group.e2ee.state_not_ready",
                err,
                request_id,
            ))?,
        ],
    )
    .map_err(|err| sqlite_operation_error(err, request_id))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn mark_v2_prepared<T: Serialize>(
    conn: &rusqlite::Connection,
    pending_commit_id: &str,
    commit_b64u: &str,
    ratchet_tree_b64u: Option<&str>,
    group_info_b64u: Option<&str>,
    epoch_authenticator_b64u: Option<&str>,
    response: &T,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    let journal = V2PrepareJournalResponse {
        journal_version: "p6-v2-prepare-journal-v1".to_owned(),
        prepared_response: Some(response),
    };
    conn.execute(
        "UPDATE pending_commits
             SET commit_b64u = ?2,
                 ratchet_tree_b64u = ?3,
                 group_info_b64u = ?4,
                 epoch_authenticator_b64u = ?5,
                 status = 'prepared',
                 response_json = ?6,
                 updated_at = CURRENT_TIMESTAMP
             WHERE pending_commit_id = ?1 AND status = 'preparing'",
        params![
            pending_commit_id,
            commit_b64u,
            ratchet_tree_b64u,
            group_info_b64u,
            epoch_authenticator_b64u,
            serde_json::to_string(&journal).map_err(|err| operation_error(
                "group.e2ee.state_not_ready",
                err,
                request_id,
            ))?,
        ],
    )
    .map_err(|err| sqlite_operation_error(err, request_id))?;
    let status: Option<String> = conn
        .query_row(
            "SELECT status FROM pending_commits WHERE pending_commit_id = ?1",
            params![pending_commit_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    if status.as_deref() != Some("prepared") {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "prepare journal is not in preparing state",
            request_id,
        ));
    }
    Ok(())
}

fn pending_prepared_response(
    conn: &rusqlite::Connection,
    pending_commit_id: &str,
    request_id: &str,
) -> GroupMlsOperationResult<Option<Value>> {
    let response_json: String = conn
        .query_row(
            "SELECT response_json FROM pending_commits WHERE pending_commit_id = ?1",
            params![pending_commit_id],
            |row| row.get(0),
        )
        .map_err(|err| sqlite_operation_error(err, request_id))?;
    let value: Value = serde_json::from_str(&response_json)
        .map_err(|err| operation_error("group.e2ee.state_not_ready", err, request_id))?;
    if value.get("journal_version").is_some() {
        serde_json::from_value::<V2PrepareJournalResponse<Value>>(value)
            .map(|journal| journal.prepared_response)
            .map_err(|err| operation_error("group.e2ee.state_not_ready", err, request_id))
    } else {
        Ok(Some(value))
    }
}

fn load_public_group(
    scope: &GroupMlsOperationScope,
    group: &MlsGroup,
    request_id: &str,
) -> GroupMlsOperationResult<PublicGroup> {
    PublicGroup::load(scope.provider.storage(), group.group_id())
        .map_err(|err| mls_operation_error("group.e2ee.state_not_ready", err, request_id))?
        .ok_or_else(|| {
            operation_error(
                "group.e2ee.state_not_ready",
                "OpenMLS public group is missing from local storage",
                request_id,
            )
        })
}

fn key_package_id_exists(
    scope: &GroupMlsOperationScope,
    key_package_id: &str,
    request_id: &str,
) -> GroupMlsOperationResult<bool> {
    scope
        .app_conn
        .query_row(
            "SELECT 1 FROM key_packages WHERE key_package_id = ?1 LIMIT 1",
            params![key_package_id],
            |_| Ok(()),
        )
        .optional()
        .map(|value| value.is_some())
        .map_err(|err| sqlite_operation_error(err, request_id))
}

fn open_scope<S: GroupMlsStore>(
    store: &S,
    request_id: &str,
) -> GroupMlsOperationResult<GroupMlsOperationScope> {
    store
        .open_operation()
        .map_err(|err| operation_error(err.code(), err, request_id))
}

fn validate_store_scope(
    scope: Option<&GroupMlsOwnerScope>,
    did: &str,
    device_id: &str,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    require_non_empty("owner_did", did, request_id)?;
    require_non_empty("device_id", device_id, request_id)?;
    if let Some(scope) = scope {
        if scope.owner_did != did || scope.device_id != device_id {
            return Err(operation_error(
                "owner_scope_mismatch",
                "operation DID/device is outside this MLS store owner scope",
                request_id,
            ));
        }
    }
    Ok(())
}

fn require_non_empty(field: &str, value: &str, request_id: &str) -> GroupMlsOperationResult<()> {
    if value.trim().is_empty() {
        Err(operation_error(
            "invalid_field",
            format!("{field} is required"),
            request_id,
        ))
    } else {
        Ok(())
    }
}

fn parse_epoch(value: &str, request_id: &str) -> GroupMlsOperationResult<u64> {
    value.parse::<u64>().map_err(|_| {
        operation_error(
            "group.e2ee.epoch_conflict",
            "epoch must be a non-negative decimal string",
            request_id,
        )
    })
}

fn encode_tls<T: TlsSerialize>(
    value: &T,
    code: &str,
    request_id: &str,
) -> GroupMlsOperationResult<String> {
    value
        .tls_serialize_detached()
        .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        .map_err(|err| mls_operation_error(code, err, request_id))
}

fn v2_error(code: &str, error: impl std::fmt::Display, request_id: &str) -> GroupMlsOperationError {
    operation_error(code, error, request_id)
}

fn mls_operation_error(
    code: &str,
    error: impl std::fmt::Debug,
    request_id: &str,
) -> GroupMlsOperationError {
    operation_error(code, format!("{error:?}"), request_id)
}

fn sqlite_operation_error(error: rusqlite::Error, request_id: &str) -> GroupMlsOperationError {
    GroupMlsOperationError::from(sqlite_error("state_write_failed", error, request_id))
}

fn operation_error(
    code: impl Into<String>,
    message: impl std::fmt::Display,
    request_id: &str,
) -> GroupMlsOperationError {
    GroupMlsOperationError {
        code: code.into(),
        message: message.to_string(),
        request_id: Some(request_id.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p6_v2_handshake_policy_requires_public_messages() {
        assert_eq!(
            P6_V2_WIRE_FORMAT_POLICY.outgoing(),
            OutgoingWireFormatPolicy::AlwaysPlaintext
        );
        assert_eq!(
            P6_V2_WIRE_FORMAT_POLICY.incoming(),
            IncomingWireFormatPolicy::AlwaysPlaintext
        );
        assert_eq!(
            v2_group_join_config().wire_format_policy(),
            P6_V2_WIRE_FORMAT_POLICY
        );
    }
}
