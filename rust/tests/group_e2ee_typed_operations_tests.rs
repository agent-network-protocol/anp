#![cfg(feature = "mls")]

mod common;

use anp::group_e2ee::operations::{
    add_member_prepare, create_group_prepare, decrypt, encrypt, finalize_commit,
    generate_key_package, process_notice, process_welcome, remove_member_prepare, status,
    AddMemberInput, CreateGroupInput, DecryptInput, EncryptInput, FinalizeCommitInput,
    GenerateKeyPackageInput, ProcessNoticeInput, ProcessWelcomeInput, RemoveMemberInput,
    StatusInput,
};
use anp::group_e2ee::storage::{CompatDataDirStore, ImCoreSqliteGroupMlsStore};
use anp::group_e2ee::{GroupApplicationPlaintext, GroupStateRef};
use common::tempdir;
use rusqlite::{params, Connection};
use serde_json::json;

fn alice() -> &'static str {
    "did:wba:example.com:users:alice:e1"
}

fn bob() -> &'static str {
    "did:wba:example.com:users:bob:e1"
}

#[test]
fn typed_operations_create_finalize_add_finalize_without_binary_exec() {
    let alice_dir = tempdir("anp-group-typed-alice").expect("alice state");
    let bob_dir = tempdir("anp-group-typed-bob").expect("bob state");
    let alice_store = CompatDataDirStore::new(alice_dir.path());
    let bob_store = CompatDataDirStore::new(bob_dir.path());
    let group_did = "did:wba:example.com:groups:typed-ops:e1";

    let bob_kp = generate_key_package(
        &bob_store,
        GenerateKeyPackageInput {
            owner_did: bob().to_owned(),
            device_id: "phone".to_owned(),
            operation_id: "op-typed-bob-kp".to_owned(),
            request_id: "req-typed-bob-kp".to_owned(),
            key_package_id: None,
            purpose: None,
            group_did: None,
        },
    )
    .expect("generate bob key package");
    assert_eq!(bob_kp.group_key_package.owner_did, bob());

    let create = create_group_prepare(
        &alice_store,
        CreateGroupInput {
            creator_did: alice().to_owned(),
            device_id: "phone".to_owned(),
            group_did: group_did.to_owned(),
            operation_id: "op-typed-create".to_owned(),
            request_id: "req-typed-create".to_owned(),
            pending_commit_id: Some("pc-typed-create".to_owned()),
        },
    )
    .expect("create group prepare");
    assert_eq!(create.status, "pending");
    assert_eq!(create.pending_commit_id, "pc-typed-create");
    assert_eq!(create.local_epoch, "0");

    let pending_status = status(
        &alice_store,
        StatusInput {
            request_id: "req-typed-status-pending-create".to_owned(),
            device_id: "phone".to_owned(),
            agent_did: Some(alice().to_owned()),
            group_did: Some(group_did.to_owned()),
        },
    )
    .expect("pending create status");
    assert_eq!(pending_status.status, "pending_create");
    assert_eq!(pending_status.pending_commits.len(), 1);

    let create_finalized = finalize_commit(
        &alice_store,
        FinalizeCommitInput {
            pending_commit_id: create.pending_commit_id.clone(),
            request_id: "req-typed-create-finalize".to_owned(),
        },
    )
    .expect("finalize create");
    assert_eq!(create_finalized.status, "finalized");
    assert_eq!(create_finalized.epoch, "0");

    let add = add_member_prepare(
        &alice_store,
        AddMemberInput {
            actor_did: alice().to_owned(),
            device_id: "phone".to_owned(),
            group_did: group_did.to_owned(),
            member_did: bob().to_owned(),
            group_key_package: bob_kp.group_key_package,
            operation_id: "op-typed-add".to_owned(),
            request_id: "req-typed-add".to_owned(),
            pending_commit_id: Some("pc-typed-add".to_owned()),
        },
    )
    .expect("add member prepare");
    assert_eq!(add.status, "pending");
    assert_eq!(add.pending_commit_id, "pc-typed-add");
    assert_eq!(add.from_epoch, "0");
    assert_eq!(add.epoch, "1");
    assert_eq!(add.local_epoch, "0");
    assert!(add.welcome_b64u.as_deref().unwrap_or_default().len() > 64);
    assert!(add.ratchet_tree_b64u.as_deref().unwrap_or_default().len() > 64);

    let add_pending_status = status(
        &alice_store,
        StatusInput {
            request_id: "req-typed-status-pending-add".to_owned(),
            device_id: "phone".to_owned(),
            agent_did: Some(alice().to_owned()),
            group_did: Some(group_did.to_owned()),
        },
    )
    .expect("pending add status");
    assert_eq!(add_pending_status.status, "active");
    assert_eq!(add_pending_status.local_epoch.as_deref(), Some("0"));
    assert_eq!(add_pending_status.pending_commits.len(), 1);

    let add_finalized = finalize_commit(
        &alice_store,
        FinalizeCommitInput {
            pending_commit_id: add.pending_commit_id,
            request_id: "req-typed-add-finalize".to_owned(),
        },
    )
    .expect("finalize add");
    assert_eq!(add_finalized.status, "finalized");
    assert_eq!(add_finalized.epoch, "1");

    let bob_welcome = process_welcome(
        &bob_store,
        ProcessWelcomeInput {
            agent_did: bob().to_owned(),
            device_id: "phone".to_owned(),
            group_did: group_did.to_owned(),
            welcome_b64u: add.welcome_b64u.clone().expect("welcome"),
            ratchet_tree_b64u: add.ratchet_tree_b64u.clone().expect("ratchet tree"),
            group_state_ref: GroupStateRef {
                group_did: group_did.to_owned(),
                group_state_version: "1".to_owned(),
                policy_hash: None,
            },
            crypto_group_id_b64u: add.crypto_group_id_b64u.clone(),
            epoch: add.epoch.clone(),
            request_id: "req-typed-bob-welcome".to_owned(),
        },
    )
    .expect("process bob welcome");
    assert_eq!(bob_welcome.status, "active");
    assert_eq!(bob_welcome.epoch, "1");

    let encrypted = encrypt(
        &alice_store,
        EncryptInput {
            sender_did: alice().to_owned(),
            device_id: "phone".to_owned(),
            group_state_ref: GroupStateRef {
                group_did: group_did.to_owned(),
                group_state_version: "1".to_owned(),
                policy_hash: None,
            },
            message_id: "msg-typed-alice".to_owned(),
            operation_id: "op-typed-alice-encrypt".to_owned(),
            application_plaintext: GroupApplicationPlaintext {
                application_content_type: "text/plain".to_owned(),
                thread_id: None,
                reply_to_message_id: None,
                annotations: Default::default(),
                text: Some("typed hello".to_owned()),
                payload: None,
                payload_b64u: None,
            },
            request_id: "req-typed-alice-encrypt".to_owned(),
        },
    )
    .expect("typed encrypt");
    assert_eq!(encrypted.group_cipher_object.epoch, "1");
    assert_eq!(
        encrypted.group_cipher_object.group_state_ref.group_did,
        group_did
    );

    let decrypted = decrypt(
        &bob_store,
        DecryptInput {
            recipient_did: bob().to_owned(),
            device_id: "phone".to_owned(),
            group_did: group_did.to_owned(),
            sender_did: alice().to_owned(),
            message_id: "msg-typed-alice".to_owned(),
            operation_id: "op-typed-alice-encrypt".to_owned(),
            group_cipher_object: encrypted.group_cipher_object,
            request_id: "req-typed-bob-decrypt".to_owned(),
        },
    )
    .expect("typed decrypt");
    assert_eq!(
        decrypted.application_plaintext.text.as_deref(),
        Some("typed hello")
    );

    let attachment_manifest = json!({
        "attachments": [{
            "attachment_id": "att-typed-group",
            "size": "48",
            "digest": {
                "alg": "sha-256",
                "value_b64u": "digest"
            },
            "mime_type": "text/plain",
            "encryption_info": {
                "mode": "object-e2ee",
                "object_cipher": "chacha20-poly1305",
                "object_key_b64u": "OBJECT-KEY",
                "nonce_b64u": "NONCE",
                "plaintext_size": "31"
            }
        }],
        "caption": "secure attachment",
        "primary_attachment_id": "att-typed-group"
    });
    let encrypted_payload = encrypt(
        &alice_store,
        EncryptInput {
            sender_did: alice().to_owned(),
            device_id: "phone".to_owned(),
            group_state_ref: GroupStateRef {
                group_did: group_did.to_owned(),
                group_state_version: "1".to_owned(),
                policy_hash: None,
            },
            message_id: "msg-typed-attachment".to_owned(),
            operation_id: "op-typed-attachment-encrypt".to_owned(),
            application_plaintext: GroupApplicationPlaintext {
                application_content_type: "application/anp-attachment-manifest+json".to_owned(),
                thread_id: Some(group_did.to_owned()),
                reply_to_message_id: None,
                annotations: Default::default(),
                text: None,
                payload: Some(attachment_manifest.clone()),
                payload_b64u: None,
            },
            request_id: "req-typed-attachment-encrypt".to_owned(),
        },
    )
    .expect("typed payload encrypt");
    let decrypted_payload = decrypt(
        &bob_store,
        DecryptInput {
            recipient_did: bob().to_owned(),
            device_id: "phone".to_owned(),
            group_did: group_did.to_owned(),
            sender_did: alice().to_owned(),
            message_id: "msg-typed-attachment".to_owned(),
            operation_id: "op-typed-attachment-encrypt".to_owned(),
            group_cipher_object: encrypted_payload.group_cipher_object,
            request_id: "req-typed-attachment-decrypt".to_owned(),
        },
    )
    .expect("typed payload decrypt");
    assert_eq!(
        decrypted_payload
            .application_plaintext
            .application_content_type,
        "application/anp-attachment-manifest+json"
    );
    assert_eq!(
        decrypted_payload.application_plaintext.payload,
        Some(attachment_manifest)
    );
    assert_eq!(decrypted_payload.application_plaintext.text, None);

    let active_status = status(
        &alice_store,
        StatusInput {
            request_id: "req-typed-status-active".to_owned(),
            device_id: "phone".to_owned(),
            agent_did: Some(alice().to_owned()),
            group_did: Some(group_did.to_owned()),
        },
    )
    .expect("active status");
    assert_eq!(active_status.status, "active");
    assert_eq!(active_status.local_epoch.as_deref(), Some("1"));
    assert!(active_status.pending_commits.is_empty());

    let remove = remove_member_prepare(
        &alice_store,
        RemoveMemberInput {
            actor_did: alice().to_owned(),
            device_id: "phone".to_owned(),
            group_did: group_did.to_owned(),
            member_did: bob().to_owned(),
            group_state_ref: Some(GroupStateRef {
                group_did: group_did.to_owned(),
                group_state_version: "1".to_owned(),
                policy_hash: None,
            }),
            operation_id: "op-typed-remove".to_owned(),
            request_id: "req-typed-remove".to_owned(),
            pending_commit_id: Some("pc-typed-remove".to_owned()),
        },
    )
    .expect("typed remove prepare");
    assert_eq!(remove.status, "pending");
    assert_eq!(remove.from_epoch, "1");
    assert_eq!(remove.epoch, "2");

    let remove_finalized = finalize_commit(
        &alice_store,
        FinalizeCommitInput {
            pending_commit_id: remove.pending_commit_id,
            request_id: "req-typed-remove-finalize".to_owned(),
        },
    )
    .expect("typed remove finalize");
    assert_eq!(remove_finalized.epoch, "2");

    let bob_notice = process_notice(
        &bob_store,
        ProcessNoticeInput {
            recipient_did: bob().to_owned(),
            device_id: "phone".to_owned(),
            group_did: group_did.to_owned(),
            commit_b64u: remove.commit_b64u,
            from_epoch: "1".to_owned(),
            subject_did: Some(bob().to_owned()),
            subject_status: Some("removed".to_owned()),
            request_id: "req-typed-bob-remove-notice".to_owned(),
        },
    )
    .expect("typed process remove notice");
    assert_eq!(bob_notice.status, "inactive");
    assert!(bob_notice.self_removed);
    assert_eq!(bob_notice.subject_status, "removed");
}

#[test]
fn typed_operations_im_core_store_uses_owner_device_scoped_group_mls_tables() {
    let root = tempdir("anp-group-typed-im-core").expect("state");
    let local_state = root.path().join("local_state.sqlite");
    let alice_store = ImCoreSqliteGroupMlsStore::from_local_state_sqlite_path(
        &local_state,
        "identity-alice",
        alice(),
        "phone",
    )
    .expect("alice im-core store");
    let bob_store = ImCoreSqliteGroupMlsStore::from_local_state_sqlite_path(
        &local_state,
        "identity-bob",
        bob(),
        "phone",
    )
    .expect("bob im-core store");
    assert_ne!(alice_store.state_db_path(), bob_store.state_db_path());
    assert!(alice_store.state_db_path().ends_with("mls_state.sqlite"));
    let group_did = "did:wba:example.com:groups:typed-im-core-store:e1";

    let bob_kp = generate_key_package(
        &bob_store,
        GenerateKeyPackageInput {
            owner_did: bob().to_owned(),
            device_id: "phone".to_owned(),
            operation_id: "op-im-core-bob-kp".to_owned(),
            request_id: "req-im-core-bob-kp".to_owned(),
            key_package_id: Some("kp-im-core-bob".to_owned()),
            purpose: None,
            group_did: Some(group_did.to_owned()),
        },
    )
    .expect("bob key package");

    let wrong_owner = generate_key_package(
        &alice_store,
        GenerateKeyPackageInput {
            owner_did: bob().to_owned(),
            device_id: "phone".to_owned(),
            operation_id: "op-im-core-wrong-owner".to_owned(),
            request_id: "req-im-core-wrong-owner".to_owned(),
            key_package_id: None,
            purpose: None,
            group_did: None,
        },
    )
    .expect_err("wrong owner should fail before writing local MLS state");
    assert_eq!(wrong_owner.code, "owner_scope_mismatch");

    let create = create_group_prepare(
        &alice_store,
        CreateGroupInput {
            creator_did: alice().to_owned(),
            device_id: "phone".to_owned(),
            group_did: group_did.to_owned(),
            operation_id: "op-im-core-create".to_owned(),
            request_id: "req-im-core-create".to_owned(),
            pending_commit_id: Some("pc-im-core-create".to_owned()),
        },
    )
    .expect("create");
    finalize_commit(
        &alice_store,
        FinalizeCommitInput {
            pending_commit_id: create.pending_commit_id,
            request_id: "req-im-core-create-finalize".to_owned(),
        },
    )
    .expect("finalize create");

    let add = add_member_prepare(
        &alice_store,
        AddMemberInput {
            actor_did: alice().to_owned(),
            device_id: "phone".to_owned(),
            group_did: group_did.to_owned(),
            member_did: bob().to_owned(),
            group_key_package: bob_kp.group_key_package,
            operation_id: "op-im-core-add".to_owned(),
            request_id: "req-im-core-add".to_owned(),
            pending_commit_id: Some("pc-im-core-add".to_owned()),
        },
    )
    .expect("add prepare");
    finalize_commit(
        &alice_store,
        FinalizeCommitInput {
            pending_commit_id: add.pending_commit_id,
            request_id: "req-im-core-add-finalize".to_owned(),
        },
    )
    .expect("finalize add");

    process_welcome(
        &bob_store,
        ProcessWelcomeInput {
            agent_did: bob().to_owned(),
            device_id: "phone".to_owned(),
            group_did: group_did.to_owned(),
            welcome_b64u: add.welcome_b64u.expect("welcome"),
            ratchet_tree_b64u: add.ratchet_tree_b64u.expect("ratchet tree"),
            group_state_ref: GroupStateRef {
                group_did: group_did.to_owned(),
                group_state_version: "1".to_owned(),
                policy_hash: None,
            },
            crypto_group_id_b64u: add.crypto_group_id_b64u,
            epoch: add.epoch,
            request_id: "req-im-core-bob-welcome".to_owned(),
        },
    )
    .expect("bob welcome");

    assert_im_core_store_owner_rows(
        alice_store.state_db_path(),
        "identity-alice",
        alice(),
        group_did,
    );
    assert_im_core_store_owner_rows(bob_store.state_db_path(), "identity-bob", bob(), group_did);
}

fn assert_im_core_store_owner_rows(
    db_path: &std::path::Path,
    owner_identity_id: &str,
    owner_did: &str,
    group_did: &str,
) {
    let conn = Connection::open(db_path).expect("open im-core group mls state");
    let binding_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM group_mls_bindings
             WHERE owner_identity_id = ?1 AND owner_did = ?2 AND device_id = 'phone' AND group_did = ?3",
            params![owner_identity_id, owner_did, group_did],
            |row| row.get(0),
        )
        .expect("binding count");
    assert_eq!(binding_count, 1);
    let legacy_binding_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'group_bindings'",
            [],
            |row| row.get(0),
        )
        .expect("legacy table count");
    assert_eq!(legacy_binding_count, 0);
    let openmls_table_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name LIKE 'openmls_%'",
            [],
            |row| row.get(0),
        )
        .expect("openmls table count");
    assert!(openmls_table_count > 0);
}
