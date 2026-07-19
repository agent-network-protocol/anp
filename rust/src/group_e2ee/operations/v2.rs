//! Persistent P6 v2 OpenMLS operations.
//!
//! This module deliberately does not reinterpret the legacy typed runtime as
//! v2.  It uses the same device-scoped [`GroupMlsStore`] boundary while
//! enforcing the v2 LeafNode device binding, exact-device membership changes,
//! and RFC 8785 authenticated data.

use super::{
    active_binding, binding, binding_status, ciphersuite, decode_b64u, delete_binding,
    delete_openmls_group_state, encode_b64u, ensure_agent, insert_pending_commit, load_group,
    load_signer, mark_binding_inactive, pending_commit, set_binding_epoch_status, sqlite_error,
    update_pending_commit_status, upsert_binding, upsert_binding_status,
};
use crate::group_e2ee::storage::{GroupMlsOperationScope, GroupMlsOwnerScope, GroupMlsStore};
use crate::group_e2ee::{
    canonical_group_application_plaintext_v2, generate_did_wba_binding_v2,
    group_add_submission_binding_v2, group_remove_submission_binding_v2,
    group_send_authenticated_data_v2, parse_group_application_plaintext_v2,
    validate_group_key_package_binding_v2, validate_leaf_identity_set_v2,
    verify_did_wba_binding_v2, V2DidWbaBinding, V2DidWbaBindingUnsigned, V2GroupAddBody,
    V2GroupApplicationPlaintext, V2GroupCipherObject, V2GroupControlMetadata, V2GroupCreateBody,
    V2GroupKeyPackage, V2GroupRemoveBody, V2GroupSendMetadata, V2GroupStateRef,
    V2KeyPackageBindingEvidence, V2LeafBindingEvidence, V2LeafExtension, V2LeafIdentity,
    DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2, GROUP_E2EE_MTI_SUITE_V2, METHOD_GROUP_ADD_V2,
    METHOD_GROUP_REMOVE_V2,
};
use crate::PrivateKeyMaterial;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use openmls::prelude::{
    tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize},
    *,
};
use openmls_traits::OpenMlsProvider;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::typed::{GroupMlsOperationError, GroupMlsOperationResult};

const CRYPTO_GROUP_ID_LEN: usize = 32;

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
            verification_method: input.verification_method,
            leaf_signature_key_b64u: URL_SAFE_NO_PAD.encode(signer.to_public_vec()),
            issued_at: input.issued_at.clone(),
            expires_at: input.expires_at.clone(),
        },
        device_signing_private_key,
        Some(input.issued_at),
    )
    .map_err(|err| v2_error("group.e2ee.did_binding_invalid", err, &input.request_id))?;
    let bundle = KeyPackage::builder()
        .leaf_node_capabilities(v2_capabilities())
        .leaf_node_extensions(binding_extensions(&binding, &input.request_id)?)
        .build(ciphersuite(), &scope.provider, &signer, credential)
        .map_err(|err| {
            mls_operation_error("group.e2ee.invalid_key_package", err, &input.request_id)
        })?;
    let bytes = bundle
        .key_package()
        .tls_serialize_detached()
        .map_err(|err| {
            mls_operation_error("group.e2ee.invalid_key_package", err, &input.request_id)
        })?;
    let package = V2GroupKeyPackage {
        key_package_id: input.key_package_id,
        owner_did: input.owner_did,
        owner_device_id: input.owner_device_id,
        suite: GROUP_E2EE_MTI_SUITE_V2.to_owned(),
        mls_key_package_b64u: URL_SAFE_NO_PAD.encode(&bytes),
        did_wba_binding: binding,
        expires_at: Some(input.expires_at),
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
                package.owner_did,
                package.owner_device_id,
                package.key_package_id,
                serde_json::to_string(&package).map_err(|err| operation_error(
                    "group.e2ee.invalid_key_package",
                    err,
                    &input.request_id,
                ))?
            ],
        )
        .map_err(|err| sqlite_operation_error(err, &input.request_id))?;
    Ok(package)
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
    let group = MlsGroup::new_with_group_id(
        &scope.provider,
        &signer,
        &v2_group_create_config(
            &input.creator_key_package.did_wba_binding,
            &input.request_id,
        )?,
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
        &input.group_state_ref.group_did,
        &group_id,
        0,
        "creator",
        "pending_create",
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
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
    let local_artifact = encode_b64u(b"p6-v2-local-create");
    insert_pending_commit(
        &scope.app_conn,
        &input.pending_commit_id,
        &input.meta.operation_id,
        "group create",
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &body.group_did,
        &input.meta.sender_did,
        "active",
        0,
        0,
        &local_artifact,
        None,
        None,
        Some(&encode_b64u(group.epoch_authenticator().as_slice())),
        &serde_json::to_value(&body)
            .map_err(|err| operation_error("group.e2ee.state_not_ready", err, &input.request_id))?,
        &input.request_id,
    )
    .map_err(GroupMlsOperationError::from)?;
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
        &input.meta.operation_id,
        "group add-member",
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &body.group_state_ref.group_did,
        &body.member_did,
        "active",
        local_binding.epoch,
        next_epoch,
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
    let leaf = find_exact_leaf(
        &scope,
        &group,
        &input.member_did,
        &input.member_device_id,
        &input.member_did_document,
        &input.now,
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
    let (commit, welcome, _) = group
        .remove_members(
            &scope.provider,
            &load_signer(
                &scope.provider,
                &scope.app_conn,
                &input.meta.sender_did,
                &input.meta.sender_device_id,
                &input.request_id,
            )
            .map_err(GroupMlsOperationError::from)?,
            &[leaf.index],
        )
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
        &input.meta.operation_id,
        "group remove-member",
        &input.meta.sender_did,
        &input.meta.sender_device_id,
        &body.group_state_ref.group_did,
        &body.member_did,
        "removed",
        local_binding.epoch,
        next_epoch,
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
    if pending.status != "finalized" {
        if pending.command == "group create" {
            let group = load_group(
                &scope.provider,
                &GroupId::from_slice(
                    &decode_b64u(&pending.crypto_group_id_b64u, &input.request_id)
                        .map_err(GroupMlsOperationError::from)?,
                ),
                &input.request_id,
            )
            .map_err(GroupMlsOperationError::from)?;
            if group.epoch().as_u64() != pending.to_epoch {
                return Err(operation_error(
                    "group.e2ee.epoch_conflict",
                    "created group epoch changed before service acceptance",
                    &input.request_id,
                ));
            }
        } else {
            let mut group = load_group(
                &scope.provider,
                &GroupId::from_slice(
                    &decode_b64u(&pending.crypto_group_id_b64u, &input.request_id)
                        .map_err(GroupMlsOperationError::from)?,
                ),
                &input.request_id,
            )
            .map_err(GroupMlsOperationError::from)?;
            let staged = group.pending_commit().ok_or_else(|| {
                operation_error(
                    "group.e2ee.commit_invalid",
                    "OpenMLS pending commit is missing",
                    &input.request_id,
                )
            })?;
            if staged.epoch().as_u64() != pending.to_epoch {
                return Err(operation_error(
                    "group.e2ee.epoch_conflict",
                    "OpenMLS pending epoch changed before service acceptance",
                    &input.request_id,
                ));
            }
            group.merge_pending_commit(&scope.provider).map_err(|err| {
                mls_operation_error("group.e2ee.commit_invalid", err, &input.request_id)
            })?;
        }
        // P6 v2 changes one exact leaf.  A sibling leaf can share the local
        // controller DID, so DID equality must never deactivate this device.
        set_binding_epoch_status(
            &scope.app_conn,
            &pending.agent_did,
            &pending.device_id,
            &pending.group_did,
            pending.to_epoch,
            "active",
            &input.request_id,
        )
        .map_err(GroupMlsOperationError::from)?;
        update_pending_commit_status(
            &scope.app_conn,
            &pending.pending_commit_id,
            "finalized",
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
    if pending.status == "finalized" {
        return Err(operation_error(
            "group.e2ee.commit_invalid",
            "finalized pending commit cannot be aborted",
            &input.request_id,
        ));
    }
    if pending.status != "aborted" {
        if pending.command == "group create" {
            let group_id = GroupId::from_slice(
                &decode_b64u(&pending.crypto_group_id_b64u, &input.request_id)
                    .map_err(GroupMlsOperationError::from)?,
            );
            delete_openmls_group_state(&scope.app_conn, &group_id, &input.request_id)
                .map_err(GroupMlsOperationError::from)?;
            delete_binding(
                &scope.app_conn,
                &pending.agent_did,
                &pending.device_id,
                &pending.group_did,
                &input.request_id,
            )
            .map_err(GroupMlsOperationError::from)?;
        } else {
            let mut group = load_group(
                &scope.provider,
                &GroupId::from_slice(
                    &decode_b64u(&pending.crypto_group_id_b64u, &input.request_id)
                        .map_err(GroupMlsOperationError::from)?,
                ),
                &input.request_id,
            )
            .map_err(GroupMlsOperationError::from)?;
            group
                .clear_pending_commit(scope.provider.storage())
                .map_err(|err| {
                    mls_operation_error("group.e2ee.commit_invalid", err, &input.request_id)
                })?;
        }
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
    if input.group_state_ref.group_did != input.group_did {
        return Err(operation_error(
            "group.e2ee.welcome_invalid",
            "Welcome group_state_ref does not match group_did",
            &input.request_id,
        ));
    }
    let target_epoch = parse_epoch(&input.epoch, &input.request_id)?;
    let scope = open_scope(store, &input.request_id)?;
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
        if existing.epoch >= target_epoch
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
                from_epoch: existing.epoch.to_string(),
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
        &scope,
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
    body.private_message_b64u = encode_tls(
        &message,
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
    let message = MlsMessageIn::tls_deserialize_exact(
        decode_b64u(
            &input.group_cipher_object.private_message_b64u,
            &input.request_id,
        )
        .map_err(GroupMlsOperationError::from)?,
    )
    .map_err(|err| {
        mls_operation_error("group.e2ee.private_message_invalid", err, &input.request_id)
    })?;
    let protocol = message.try_into_protocol_message().map_err(|_| {
        operation_error(
            "group.e2ee.private_message_invalid",
            "group cipher is not an MLS protocol message",
            &input.request_id,
        )
    })?;
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
            let exact = find_exact_leaf(
                scope,
                group,
                member_did,
                member_device_id,
                member_document,
                now,
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

#[allow(clippy::too_many_arguments)]
fn find_exact_leaf(
    scope: &GroupMlsOperationScope,
    group: &MlsGroup,
    did: &str,
    device_id: &str,
    did_document: &Value,
    now: &str,
    draft_extension_negotiated: bool,
    request_id: &str,
) -> GroupMlsOperationResult<Member> {
    let public_group = load_public_group(scope, group, request_id)?;
    let required = required_extension_ids(group);
    let mut matches = Vec::new();
    for member in group.members() {
        let leaf = public_group.leaf(member.index).ok_or_else(|| {
            operation_error(
                "group.e2ee.did_binding_invalid",
                "member leaf is missing from the public group",
                request_id,
            )
        })?;
        let (binding, _) = leaf_binding_evidence(leaf, request_id)?;
        if binding.agent_did == did && binding.device_id == device_id {
            validate_leaf_exact(
                leaf,
                did,
                device_id,
                did_document,
                required.clone(),
                now,
                draft_extension_negotiated,
                request_id,
            )?;
            matches.push(member);
        }
    }
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
    operation_id: &str,
    command: &str,
    actor_did: &str,
    actor_device_id: &str,
    group_did: &str,
    subject_did: &str,
    subject_status: &str,
    from_epoch: u64,
    to_epoch: u64,
    commit_b64u: &str,
    ratchet_tree_b64u: Option<&str>,
    response: &T,
    request_id: &str,
) -> GroupMlsOperationResult<()> {
    insert_pending_commit(
        &scope.app_conn,
        pending_commit_id,
        operation_id,
        command,
        actor_did,
        actor_device_id,
        group_did,
        subject_did,
        subject_status,
        from_epoch,
        to_epoch,
        commit_b64u,
        ratchet_tree_b64u,
        None,
        None,
        &serde_json::to_value(response)
            .map_err(|err| operation_error("group.e2ee.commit_invalid", err, request_id))?,
        request_id,
    )
    .map_err(GroupMlsOperationError::from)
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
