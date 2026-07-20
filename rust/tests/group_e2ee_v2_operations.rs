#![cfg(feature = "mls")]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anp::authentication::{
    create_did_wba_document, validate_device_manifest, DidDocumentOptions, DidProfile,
};
use anp::group_e2ee::operations::v2::{
    abort_commit_v2, add_member_prepare_v2, create_group_prepare_v2, decrypt_v2, encrypt_v2,
    finalize_commit_v2, generate_key_package_v2, inspect_local_group_v2,
    list_local_group_member_endpoints_v2, process_commit_v2, process_notice_v2, process_welcome_v2,
    reconcile_pending_v2, remove_member_prepare_v2, V2AddMemberInput, V2CreateGroupInput,
    V2DecryptInput, V2DidDocument, V2EncryptInput, V2FinalizeInput, V2GenerateKeyPackageInput,
    V2InspectLocalGroupInput, V2LocalGroupMemberEndpoint, V2LocalGroupReadiness,
    V2MembershipCommitMethod, V2ProcessCommitInput, V2ProcessNoticeInput, V2ProcessWelcomeInput,
    V2ReconcilePendingInput, V2RemoveMemberInput,
};
use anp::group_e2ee::storage::ImCoreSqliteGroupMlsStore;
use anp::group_e2ee::{
    V2E2eeNotice, V2GroupApplicationPlaintext, V2GroupControlMetadata, V2GroupNoticeMetadata,
    V2GroupSendMetadata, V2GroupStateRef, V2ServiceMetadata, V2Target,
    GROUP_CIPHER_CONTENT_TYPE_V2, GROUP_E2EE_PROFILE_V2, GROUP_E2EE_SECURITY_PROFILE_V2,
    GROUP_E2EE_TRANSPORT_PROFILE_V2,
};
use anp::proof::{
    generate_w3c_proof, ProofGenerationOptions, CRYPTOSUITE_EDDSA_JCS_2022,
    PROOF_TYPE_DATA_INTEGRITY,
};
use anp::PrivateKeyMaterial;
use rusqlite::{params, Connection};
use serde_json::{json, Value};

const NOW: &str = "2026-07-20T00:00:00Z";
const ISSUED_AT: &str = "2026-07-19T00:00:00Z";
const EXPIRES_AT: &str = "2026-08-19T00:00:00Z";
const GROUP_DID: &str = "did:wba:p6-runtime.example:groups:operations";

#[derive(Debug)]
struct DeviceFixture {
    device_id: String,
    signing_key_id: String,
    signing_private_pem: String,
}

#[derive(Debug)]
struct DidFixture {
    did: String,
    document: Value,
    devices: Vec<DeviceFixture>,
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "anp-p6-v2-operations-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn p6_profiles() -> Value {
    json!([
        "anp.core.binding.v2",
        "anp.identity.discovery.v2",
        "anp.group.base.v2",
        "anp.group.e2ee.v2"
    ])
}

fn make_did_fixture(label: &str, device_ids: &[&str]) -> DidFixture {
    assert!(!device_ids.is_empty());
    let primary = create_did_wba_document(
        "p6-runtime.example",
        DidDocumentOptions {
            path_segments: vec!["agents".to_owned(), label.to_owned()],
            did_profile: DidProfile::E1,
            created: Some(ISSUED_AT.to_owned()),
            ..Default::default()
        },
    )
    .expect("primary DID document");
    let did = primary.did().expect("primary DID").to_owned();
    let root_key = PrivateKeyMaterial::from_pem(&primary.keys["key-1"].private_key_pem)
        .expect("primary signing key");
    let mut document = primary.did_document.clone();
    document
        .as_object_mut()
        .expect("DID object")
        .remove("proof");

    let mut devices = vec![DeviceFixture {
        device_id: device_ids[0].to_owned(),
        signing_key_id: format!("{did}#key-1"),
        signing_private_pem: primary.keys["key-1"].private_key_pem.clone(),
    }];

    for (index, device_id) in device_ids.iter().enumerate().skip(1) {
        let scratch = create_did_wba_document(
            "p6-runtime.example",
            DidDocumentOptions {
                path_segments: vec!["scratch".to_owned(), label.to_owned(), index.to_string()],
                did_profile: DidProfile::E1,
                created: Some(ISSUED_AT.to_owned()),
                ..Default::default()
            },
        )
        .expect("additional device keys");
        let signing_key_id = format!("{did}#device-{index}-sign");
        let e2ee_key_id = format!("{did}#device-{index}-e2ee");
        let mut signing_method = scratch.did_document["verificationMethod"]
            .as_array()
            .expect("scratch verification methods")
            .iter()
            .find(|method| {
                method
                    .get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| id.ends_with("#key-1"))
            })
            .expect("scratch signing method")
            .clone();
        signing_method["id"] = json!(signing_key_id);
        signing_method["controller"] = json!(did);
        let mut e2ee_method = scratch.did_document["verificationMethod"]
            .as_array()
            .expect("scratch verification methods")
            .iter()
            .find(|method| {
                method
                    .get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| id.ends_with("#key-3"))
            })
            .expect("scratch E2EE method")
            .clone();
        e2ee_method["id"] = json!(e2ee_key_id);
        e2ee_method["controller"] = json!(did);

        document["verificationMethod"]
            .as_array_mut()
            .expect("verification methods")
            .extend([signing_method, e2ee_method]);
        document["authentication"]
            .as_array_mut()
            .expect("authentication")
            .push(json!(signing_key_id));
        document["assertionMethod"]
            .as_array_mut()
            .expect("assertionMethod")
            .push(json!(signing_key_id));
        document["keyAgreement"]
            .as_array_mut()
            .expect("keyAgreement")
            .push(json!(e2ee_key_id));
        devices.push(DeviceFixture {
            device_id: (*device_id).to_owned(),
            signing_key_id,
            signing_private_pem: scratch.keys["key-1"].private_key_pem.clone(),
        });
    }

    document["deviceManifest"] = json!({
        "type": "ANPDeviceManifest",
        "devices": devices.iter().enumerate().map(|(index, device)| {
            let e2ee_key_id = if index == 0 {
                format!("{did}#key-3")
            } else {
                format!("{did}#device-{index}-e2ee")
            };
            json!({
                "device_id": device.device_id,
                "signing_key_id": device.signing_key_id,
                "e2ee_key_id": e2ee_key_id,
                "profiles": p6_profiles()
            })
        }).collect::<Vec<_>>()
    });
    document = generate_w3c_proof(
        &document,
        &root_key,
        &format!("{did}#key-1"),
        ProofGenerationOptions {
            proof_purpose: Some("assertionMethod".to_owned()),
            proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_owned()),
            cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.to_owned()),
            created: Some(ISSUED_AT.to_owned()),
            ..Default::default()
        },
    )
    .expect("signed DID document");
    validate_device_manifest(&document).expect("valid device Manifest");

    DidFixture {
        did,
        document,
        devices,
    }
}

fn store(root: &Path, did: &str, device_id: &str) -> ImCoreSqliteGroupMlsStore {
    ImCoreSqliteGroupMlsStore::from_local_state_sqlite_path(
        root.join(device_id).join("local_state.sqlite"),
        format!("identity-{device_id}"),
        did.to_owned(),
        device_id.to_owned(),
    )
    .expect("device-scoped MLS store")
}

fn signing_key(device: &DeviceFixture) -> PrivateKeyMaterial {
    PrivateKeyMaterial::from_pem(&device.signing_private_pem).expect("device signing key")
}

fn state_ref(version: u64) -> V2GroupStateRef {
    V2GroupStateRef {
        group_did: GROUP_DID.to_owned(),
        group_state_version: version.to_string(),
        policy_hash: None,
        roster_hash: None,
    }
}

fn service_meta(did: &str, device_id: &str, operation_id: &str) -> V2ServiceMetadata {
    V2ServiceMetadata {
        anp_version: Some("2.0".to_owned()),
        profile: GROUP_E2EE_PROFILE_V2.to_owned(),
        security_profile: GROUP_E2EE_SECURITY_PROFILE_V2.to_owned(),
        sender_did: did.to_owned(),
        sender_device_id: device_id.to_owned(),
        target: V2Target {
            kind: "service".to_owned(),
            did: "did:wba:p6-runtime.example:services:message".to_owned(),
        },
        operation_id: operation_id.to_owned(),
        created_at: Some(NOW.to_owned()),
    }
}

fn control_meta(did: &str, device_id: &str, operation_id: &str) -> V2GroupControlMetadata {
    V2GroupControlMetadata {
        anp_version: Some("2.0".to_owned()),
        profile: GROUP_E2EE_PROFILE_V2.to_owned(),
        security_profile: GROUP_E2EE_SECURITY_PROFILE_V2.to_owned(),
        sender_did: did.to_owned(),
        sender_device_id: device_id.to_owned(),
        target: V2Target {
            kind: "group".to_owned(),
            did: GROUP_DID.to_owned(),
        },
        operation_id: operation_id.to_owned(),
        created_at: Some(NOW.to_owned()),
    }
}

fn send_meta(did: &str, device_id: &str, suffix: &str) -> V2GroupSendMetadata {
    V2GroupSendMetadata {
        anp_version: Some("2.0".to_owned()),
        profile: GROUP_E2EE_PROFILE_V2.to_owned(),
        security_profile: GROUP_E2EE_SECURITY_PROFILE_V2.to_owned(),
        sender_did: did.to_owned(),
        sender_device_id: device_id.to_owned(),
        target: V2Target {
            kind: "group".to_owned(),
            did: GROUP_DID.to_owned(),
        },
        operation_id: format!("op-send-{suffix}"),
        message_id: format!("msg-{suffix}"),
        content_type: GROUP_CIPHER_CONTENT_TYPE_V2.to_owned(),
        created_at: Some(NOW.to_owned()),
    }
}

fn notice_meta(
    recipient_did: &str,
    recipient_device_id: &str,
    operation_id: &str,
) -> V2GroupNoticeMetadata {
    V2GroupNoticeMetadata {
        anp_version: Some("2.0".to_owned()),
        profile: GROUP_E2EE_PROFILE_V2.to_owned(),
        security_profile: GROUP_E2EE_TRANSPORT_PROFILE_V2.to_owned(),
        sender_did: GROUP_DID.to_owned(),
        target: V2Target {
            kind: "agent".to_owned(),
            did: recipient_did.to_owned(),
        },
        recipient_device_id: recipient_device_id.to_owned(),
        operation_id: operation_id.to_owned(),
        created_at: Some(NOW.to_owned()),
    }
}

fn member_documents(owner: &DidFixture, member: &DidFixture) -> Vec<V2DidDocument> {
    vec![
        V2DidDocument {
            did: owner.did.clone(),
            document: owner.document.clone(),
        },
        V2DidDocument {
            did: member.did.clone(),
            document: member.document.clone(),
        },
    ]
}

fn force_pending_status(store: &ImCoreSqliteGroupMlsStore, pending_commit_id: &str, status: &str) {
    let conn = Connection::open(store.state_db_path()).expect("open MLS test database");
    assert_eq!(
        conn.execute(
            "UPDATE group_mls_pending_commits SET status = ?2 WHERE pending_commit_id = ?1",
            params![pending_commit_id, status],
        )
        .expect("set simulated crash journal state"),
        1
    );
}

#[test]
fn persistent_v2_operations_keep_same_did_devices_independent() {
    let directory = TestDirectory::new();
    let owner = make_did_fixture("owner-operations", &["owner-device"]);
    let alice = make_did_fixture("alice-operations", &["alice-a1", "alice-a2"]);
    let owner_device = &owner.devices[0];
    let a1_device = &alice.devices[0];
    let a2_device = &alice.devices[1];
    let owner_store = store(directory.path(), &owner.did, &owner_device.device_id);
    let a1_store = store(directory.path(), &alice.did, &a1_device.device_id);
    let a2_store = store(directory.path(), &alice.did, &a2_device.device_id);

    let a2_missing = inspect_local_group_v2(
        &a2_store,
        V2InspectLocalGroupInput {
            owner_did: alice.did.clone(),
            owner_device_id: a2_device.device_id.clone(),
            group_did: GROUP_DID.to_owned(),
            request_id: "req-inspect-a2-before-welcome".to_owned(),
        },
    )
    .expect("secret-free local inspect before Welcome");
    assert_eq!(a2_missing.readiness, V2LocalGroupReadiness::Missing);
    assert_eq!(a2_missing.auto_reconcile_pending_count, 0);
    assert_eq!(a2_missing.host_recheck_pending_count, 0);
    assert_eq!(
        list_local_group_member_endpoints_v2(
            &a2_store,
            V2InspectLocalGroupInput {
                owner_did: alice.did.clone(),
                owner_device_id: a2_device.device_id.clone(),
                group_did: GROUP_DID.to_owned(),
                request_id: "req-list-a2-before-welcome".to_owned(),
            },
        )
        .expect_err("missing local MLS state has no current endpoint inventory")
        .code,
        "group.e2ee.state_not_ready"
    );
    assert!(inspect_local_group_v2(
        &a2_store,
        V2InspectLocalGroupInput {
            owner_did: alice.did.clone(),
            owner_device_id: a1_device.device_id.clone(),
            group_did: GROUP_DID.to_owned(),
            request_id: "req-inspect-wrong-device-scope".to_owned(),
        },
    )
    .is_err());

    let owner_package = generate_key_package_v2(
        &owner_store,
        V2GenerateKeyPackageInput {
            owner_did: owner.did.clone(),
            owner_device_id: owner_device.device_id.clone(),
            verification_method: owner_device.signing_key_id.clone(),
            key_package_id: "kp-owner".to_owned(),
            issued_at: ISSUED_AT.to_owned(),
            expires_at: EXPIRES_AT.to_owned(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            request_id: "req-kp-owner".to_owned(),
        },
        &owner.document,
        &signing_key(owner_device),
    )
    .expect("owner KeyPackage");
    let a1_package = generate_key_package_v2(
        &a1_store,
        V2GenerateKeyPackageInput {
            owner_did: alice.did.clone(),
            owner_device_id: a1_device.device_id.clone(),
            verification_method: a1_device.signing_key_id.clone(),
            key_package_id: "kp-a1".to_owned(),
            issued_at: ISSUED_AT.to_owned(),
            expires_at: EXPIRES_AT.to_owned(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            request_id: "req-kp-a1".to_owned(),
        },
        &alice.document,
        &signing_key(a1_device),
    )
    .expect("A1 KeyPackage");
    let a2_package = generate_key_package_v2(
        &a2_store,
        V2GenerateKeyPackageInput {
            owner_did: alice.did.clone(),
            owner_device_id: a2_device.device_id.clone(),
            verification_method: a2_device.signing_key_id.clone(),
            key_package_id: "kp-a2".to_owned(),
            issued_at: ISSUED_AT.to_owned(),
            expires_at: EXPIRES_AT.to_owned(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            request_id: "req-kp-a2".to_owned(),
        },
        &alice.document,
        &signing_key(a2_device),
    )
    .expect("A2 KeyPackage");

    assert_ne!(a1_store.state_db_path(), a2_store.state_db_path());
    assert_ne!(
        a1_package.mls_key_package_b64u,
        a2_package.mls_key_package_b64u
    );
    assert_ne!(
        a1_package.did_wba_binding.leaf_signature_key_b64u,
        a2_package.did_wba_binding.leaf_signature_key_b64u
    );

    let created = create_group_prepare_v2(
        &owner_store,
        V2CreateGroupInput {
            meta: service_meta(&owner.did, &owner_device.device_id, "op-create"),
            group_state_ref: state_ref(1),
            creator_key_package: owner_package,
            creator_did_document: owner.document.clone(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            pending_commit_id: "pending-create".to_owned(),
            request_id: "req-create".to_owned(),
        },
    )
    .expect("prepare group create");
    assert_eq!(created.body.epoch, "0");
    let prepared_status = inspect_local_group_v2(
        &owner_store,
        V2InspectLocalGroupInput {
            owner_did: owner.did.clone(),
            owner_device_id: owner_device.device_id.clone(),
            group_did: GROUP_DID.to_owned(),
            request_id: "req-inspect-prepared-create".to_owned(),
        },
    )
    .expect("secret-free inspect reports durable prepared WAL");
    assert_eq!(prepared_status.readiness, V2LocalGroupReadiness::Missing);
    assert_eq!(prepared_status.host_recheck_pending_count, 1);
    force_pending_status(&owner_store, &created.pending_commit_id, "corrupt-status");
    assert!(inspect_local_group_v2(
        &owner_store,
        V2InspectLocalGroupInput {
            owner_did: owner.did.clone(),
            owner_device_id: owner_device.device_id.clone(),
            group_did: GROUP_DID.to_owned(),
            request_id: "req-inspect-corrupt-wal".to_owned(),
        },
    )
    .is_err());
    force_pending_status(&owner_store, &created.pending_commit_id, "prepared");
    let prepared = reconcile_pending_v2(
        &owner_store,
        V2ReconcilePendingInput {
            request_id: "req-reconcile-prepared-create".to_owned(),
        },
    )
    .expect("prepared create survives restart reconciliation");
    assert_eq!(prepared.pending_commits[0].status, "prepared");
    assert_eq!(
        prepared.pending_commits[0]
            .prepared_response
            .as_ref()
            .and_then(|value| value.get("group_did"))
            .and_then(Value::as_str),
        Some(GROUP_DID)
    );
    assert_eq!(
        prepared.pending_commits[0].action,
        "awaiting-service-decision"
    );
    force_pending_status(&owner_store, &created.pending_commit_id, "accepted");
    let restarted_owner_store = store(directory.path(), &owner.did, &owner_device.device_id);
    let reconciled = reconcile_pending_v2(
        &restarted_owner_store,
        V2ReconcilePendingInput {
            request_id: "req-reconcile-accepted-create".to_owned(),
        },
    )
    .expect("accepted create finalizes after restart");
    assert_eq!(reconciled.pending_commits[0].status, "finalized");
    let active_status = inspect_local_group_v2(
        &owner_store,
        V2InspectLocalGroupInput {
            owner_did: owner.did.clone(),
            owner_device_id: owner_device.device_id.clone(),
            group_did: GROUP_DID.to_owned(),
            request_id: "req-inspect-finalized-create".to_owned(),
        },
    )
    .expect("secret-free inspect reports active local MLS state");
    assert_eq!(active_status.readiness, V2LocalGroupReadiness::Active);
    assert_eq!(active_status.host_recheck_pending_count, 0);
    assert_eq!(
        list_local_group_member_endpoints_v2(
            &owner_store,
            V2InspectLocalGroupInput {
                owner_did: owner.did.clone(),
                owner_device_id: owner_device.device_id.clone(),
                group_did: GROUP_DID.to_owned(),
                request_id: "req-list-finalized-create".to_owned(),
            },
        )
        .expect("created owner group exposes one secret-free endpoint")
        .member_endpoints,
        vec![V2LocalGroupMemberEndpoint {
            member_did: owner.did.clone(),
            member_device_id: owner_device.device_id.clone(),
        }]
    );
    assert_eq!(
        finalize_commit_v2(
            &owner_store,
            V2FinalizeInput {
                pending_commit_id: created.pending_commit_id,
                request_id: "req-finalize-create-repeat".to_owned(),
            },
        )
        .expect("finalize is idempotent after restart reconciliation")
        .status,
        "finalized"
    );
    assert!(reconcile_pending_v2(
        &owner_store,
        V2ReconcilePendingInput {
            request_id: "req-reconcile-finalized-create-repeat".to_owned(),
        },
    )
    .expect("reconcile is idempotent after finalize")
    .pending_commits
    .is_empty());

    let add_a1_meta = control_meta(&owner.did, &owner_device.device_id, "op-add-a1");
    let add_a1 = add_member_prepare_v2(
        &owner_store,
        V2AddMemberInput {
            meta: add_a1_meta.clone(),
            group_state_ref: state_ref(2),
            group_key_package: a1_package.clone(),
            member_did_document: alice.document.clone(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            pending_commit_id: "pending-add-a1".to_owned(),
            request_id: "req-add-a1".to_owned(),
        },
    )
    .expect("prepare A1 Add");
    force_pending_status(&owner_store, &add_a1.pending_commit_id, "accepted");
    let restarted_owner_store = store(directory.path(), &owner.did, &owner_device.device_id);
    let reconciled = reconcile_pending_v2(
        &restarted_owner_store,
        V2ReconcilePendingInput {
            request_id: "req-reconcile-accepted-add-a1".to_owned(),
        },
    )
    .expect("accepted membership Commit merges after restart");
    assert_eq!(
        reconciled.pending_commits[0].action,
        "completed-accepted-commit"
    );
    // Simulate a second crash after the OpenMLS merge but before the final
    // journal marker. Reconciliation must not attempt to merge twice.
    force_pending_status(&owner_store, &add_a1.pending_commit_id, "accepted");
    let post_merge_reconciled = reconcile_pending_v2(
        &restarted_owner_store,
        V2ReconcilePendingInput {
            request_id: "req-reconcile-post-merge-add-a1".to_owned(),
        },
    )
    .expect("already merged accepted Commit finalizes idempotently");
    assert_eq!(post_merge_reconciled.pending_commits[0].status, "finalized");
    assert_eq!(
        finalize_commit_v2(
            &owner_store,
            V2FinalizeInput {
                pending_commit_id: add_a1.pending_commit_id.clone(),
                request_id: "req-finalize-add-a1-repeat".to_owned(),
            },
        )
        .expect("membership finalize is idempotent after restart")
        .status,
        "finalized"
    );
    let welcome_a1 = V2ProcessWelcomeInput {
        recipient_did: alice.did.clone(),
        recipient_device_id: a1_device.device_id.clone(),
        group_did: GROUP_DID.to_owned(),
        group_state_ref: add_a1.body.group_state_ref.clone(),
        crypto_group_id_b64u: add_a1.body.crypto_group_id_b64u.clone(),
        epoch: add_a1.body.epoch.clone(),
        welcome_b64u: add_a1.body.welcome_b64u.clone(),
        ratchet_tree_b64u: add_a1.body.ratchet_tree_b64u.clone(),
        member_documents: vec![
            V2DidDocument {
                did: owner.did.clone(),
                document: owner.document.clone(),
            },
            V2DidDocument {
                did: alice.did.clone(),
                document: alice.document.clone(),
            },
        ],
        now: NOW.to_owned(),
        draft_extension_negotiated: true,
        request_id: "req-welcome-a1".to_owned(),
    };
    process_welcome_v2(&a1_store, welcome_a1.clone()).expect("A1 processes Welcome");
    let mut repeated_welcome_a1 = welcome_a1;
    repeated_welcome_a1.request_id = "req-welcome-a1-repeat".to_owned();
    assert_eq!(
        process_welcome_v2(&a1_store, repeated_welcome_a1)
            .expect("repeated Welcome is idempotent")
            .epoch,
        "1"
    );

    let history_meta = send_meta(&owner.did, &owner_device.device_id, "history");
    let history = encrypt_v2(
        &owner_store,
        V2EncryptInput {
            meta: history_meta.clone(),
            group_state_ref: state_ref(2),
            application_plaintext: V2GroupApplicationPlaintext {
                application_content_type: "text/plain".to_owned(),
                thread_id: None,
                reply_to_message_id: None,
                annotations: None,
                text: Some("before A2".to_owned()),
                payload: None,
                payload_b64u: None,
            },
            sender_did_document: owner.document.clone(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            request_id: "req-encrypt-history".to_owned(),
        },
    )
    .expect("encrypt pre-A2 history");
    assert_eq!(
        decrypt_v2(
            &a1_store,
            V2DecryptInput {
                recipient_did: alice.did.clone(),
                recipient_device_id: a1_device.device_id.clone(),
                originating_meta: history_meta.clone(),
                group_cipher_object: history.clone(),
                sender_did_document: owner.document.clone(),
                now: NOW.to_owned(),
                draft_extension_negotiated: true,
                request_id: "req-decrypt-history-a1".to_owned(),
            },
        )
        .expect("A1 decrypts pre-A2 history")
        .application_plaintext
        .text
        .as_deref(),
        Some("before A2")
    );

    let mut wrong_device_package = a2_package.clone();
    wrong_device_package.owner_device_id = a1_device.device_id.clone();
    wrong_device_package.did_wba_binding = a1_package.did_wba_binding.clone();
    let error = add_member_prepare_v2(
        &owner_store,
        V2AddMemberInput {
            meta: control_meta(&owner.did, &owner_device.device_id, "op-add-wrong"),
            group_state_ref: state_ref(3),
            group_key_package: wrong_device_package,
            member_did_document: alice.document.clone(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            pending_commit_id: "pending-add-wrong".to_owned(),
            request_id: "req-add-wrong".to_owned(),
        },
    )
    .expect_err("wrong device binding must fail");
    assert_eq!(error.code, "group.e2ee.did_binding_invalid");

    let interrupted_add = add_member_prepare_v2(
        &owner_store,
        V2AddMemberInput {
            meta: control_meta(&owner.did, &owner_device.device_id, "op-add-a2-crash"),
            group_state_ref: state_ref(3),
            group_key_package: a2_package.clone(),
            member_did_document: alice.document.clone(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            pending_commit_id: "pending-add-a2-crash".to_owned(),
            request_id: "req-add-a2-crash".to_owned(),
        },
    )
    .expect("prepare A2 Add before simulated process crash");
    // Simulate a crash after OpenMLS persisted its pending Commit but before
    // the write-ahead journal advanced from preparing to prepared.
    force_pending_status(
        &owner_store,
        &interrupted_add.pending_commit_id,
        "preparing",
    );
    let restarted_owner_store = store(directory.path(), &owner.did, &owner_device.device_id);
    let reconciled = reconcile_pending_v2(
        &restarted_owner_store,
        V2ReconcilePendingInput {
            request_id: "req-reconcile-interrupted-add".to_owned(),
        },
    )
    .expect("restart rolls back interrupted Add");
    assert_eq!(reconciled.pending_commits[0].previous_status, "preparing");
    assert_eq!(reconciled.pending_commits[0].status, "aborted");
    assert_eq!(
        abort_commit_v2(
            &owner_store,
            V2FinalizeInput {
                pending_commit_id: interrupted_add.pending_commit_id,
                request_id: "req-abort-interrupted-add-repeat".to_owned(),
            },
        )
        .expect("abort remains idempotent after restart")
        .status,
        "aborted"
    );
    assert!(reconcile_pending_v2(
        &owner_store,
        V2ReconcilePendingInput {
            request_id: "req-reconcile-interrupted-add-repeat".to_owned(),
        },
    )
    .expect("reconcile is idempotent after abort")
    .pending_commits
    .is_empty());

    let add_a2_meta = control_meta(&owner.did, &owner_device.device_id, "op-add-a2");
    let add_a2 = add_member_prepare_v2(
        &owner_store,
        V2AddMemberInput {
            meta: add_a2_meta.clone(),
            group_state_ref: state_ref(3),
            group_key_package: a2_package.clone(),
            member_did_document: alice.document.clone(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            pending_commit_id: "pending-add-a2".to_owned(),
            request_id: "req-add-a2".to_owned(),
        },
    )
    .expect("prepare A2 Add");
    let add_a2_commit_notice = V2ProcessNoticeInput {
        recipient_did: alice.did.clone(),
        recipient_device_id: a1_device.device_id.clone(),
        meta: notice_meta(&alice.did, &a1_device.device_id, "notice-add-a2-a1"),
        notice: V2E2eeNotice {
            notice_id: Some("notice-add-a2-a1".to_owned()),
            notice_type: "commit-delivery".to_owned(),
            group_did: GROUP_DID.to_owned(),
            group_state_ref: add_a2.body.group_state_ref.clone(),
            crypto_group_id_b64u: add_a2.body.crypto_group_id_b64u.clone(),
            epoch: add_a2.body.epoch.clone(),
            subject_did: alice.did.clone(),
            subject_device_id: a2_device.device_id.clone(),
            subject_status: "active".to_owned(),
            commit_b64u: Some(add_a2.body.commit_b64u.clone()),
            welcome_b64u: None,
            ratchet_tree_b64u: None,
            epoch_authenticator: None,
            group_receipt: None,
        },
        member_documents: member_documents(&owner, &alice),
        now: NOW.to_owned(),
        draft_extension_negotiated: true,
        request_id: "req-notice-add-a2-a1".to_owned(),
    };
    let notice_output = process_notice_v2(&a1_store, add_a2_commit_notice.clone())
        .expect("A1 processes A2 Add from the standard notice");
    assert_eq!(
        notice_output.source_operation_id.as_deref(),
        Some("op-add-a2")
    );
    let mut repeated_notice = add_a2_commit_notice.clone();
    repeated_notice.request_id = "req-notice-add-a2-a1-repeat".to_owned();
    assert_eq!(
        process_notice_v2(
            &store(directory.path(), &alice.did, &a1_device.device_id),
            repeated_notice,
        )
        .expect("exact Commit notice replay is idempotent"),
        notice_output
    );
    let mut non_actor_same_epoch = add_a2_commit_notice.clone();
    non_actor_same_epoch.meta.operation_id = "notice-add-a2-a1-new-delivery".to_owned();
    non_actor_same_epoch.notice.notice_id = Some("notice-add-a2-a1-new-delivery".to_owned());
    non_actor_same_epoch.request_id = "req-notice-add-a2-a1-new-delivery".to_owned();
    assert_eq!(
        process_notice_v2(&a1_store, non_actor_same_epoch)
            .expect_err("a non-actor cannot use the finalized-actor same-epoch path")
            .code,
        "group.e2ee.commit_invalid"
    );
    let mut conflicting_notice = add_a2_commit_notice;
    conflicting_notice.notice.subject_device_id = a1_device.device_id.clone();
    conflicting_notice.request_id = "req-notice-add-a2-a1-conflict".to_owned();
    assert_eq!(
        process_notice_v2(&a1_store, conflicting_notice)
            .expect_err("same notice operation with different binding must fail")
            .code,
        "group.e2ee.commit_invalid"
    );
    finalize_commit_v2(
        &owner_store,
        V2FinalizeInput {
            pending_commit_id: add_a2.pending_commit_id.clone(),
            request_id: "req-finalize-add-a2".to_owned(),
        },
    )
    .expect("finalize A2 Add");
    let add_a2_self_echo = V2ProcessNoticeInput {
        recipient_did: owner.did.clone(),
        recipient_device_id: owner_device.device_id.clone(),
        meta: notice_meta(
            &owner.did,
            &owner_device.device_id,
            "notice-add-a2-owner-echo",
        ),
        notice: V2E2eeNotice {
            notice_id: Some("notice-add-a2-owner-echo".to_owned()),
            notice_type: "commit-delivery".to_owned(),
            group_did: GROUP_DID.to_owned(),
            group_state_ref: add_a2.body.group_state_ref.clone(),
            crypto_group_id_b64u: add_a2.body.crypto_group_id_b64u.clone(),
            epoch: add_a2.body.epoch.clone(),
            subject_did: alice.did.clone(),
            subject_device_id: a2_device.device_id.clone(),
            subject_status: "active".to_owned(),
            commit_b64u: Some(add_a2.body.commit_b64u.clone()),
            welcome_b64u: None,
            ratchet_tree_b64u: None,
            epoch_authenticator: None,
            group_receipt: None,
        },
        member_documents: member_documents(&owner, &alice),
        now: NOW.to_owned(),
        draft_extension_negotiated: true,
        request_id: "req-notice-add-a2-owner-echo".to_owned(),
    };
    let self_echo_output = process_notice_v2(
        &store(directory.path(), &owner.did, &owner_device.device_id),
        add_a2_self_echo.clone(),
    )
    .expect("finalized Add actor accepts its exact Commit echo after restart");
    assert_eq!(
        self_echo_output.source_operation_id.as_deref(),
        Some("op-add-a2")
    );
    assert_eq!(self_echo_output.from_epoch, "1");
    assert_eq!(self_echo_output.epoch, "2");
    let mut repeated_self_echo = add_a2_self_echo.clone();
    repeated_self_echo.request_id = "req-notice-add-a2-owner-echo-repeat".to_owned();
    assert_eq!(
        process_notice_v2(
            &store(directory.path(), &owner.did, &owner_device.device_id),
            repeated_self_echo,
        )
        .expect("finalized Add actor echo replay is receipt-idempotent"),
        self_echo_output
    );
    let mut conflicting_self_echo = add_a2_self_echo.clone();
    conflicting_self_echo.notice.subject_device_id = a1_device.device_id.clone();
    conflicting_self_echo.request_id = "req-notice-add-a2-owner-echo-conflict".to_owned();
    assert_eq!(
        process_notice_v2(&owner_store, conflicting_self_echo)
            .expect_err("reusing the self-echo notice operation with changed content must fail")
            .code,
        "group.e2ee.commit_invalid"
    );
    let mut wrong_commit_self_echo = add_a2_self_echo;
    wrong_commit_self_echo.meta.operation_id = "notice-add-a2-owner-wrong-commit".to_owned();
    wrong_commit_self_echo.notice.notice_id = Some("notice-add-a2-owner-wrong-commit".to_owned());
    wrong_commit_self_echo.notice.commit_b64u = Some(add_a1.body.commit_b64u.clone());
    wrong_commit_self_echo.request_id = "req-notice-add-a2-owner-wrong-commit".to_owned();
    assert_eq!(
        process_notice_v2(&owner_store, wrong_commit_self_echo)
            .expect_err("same-epoch echo with a different Commit must fail")
            .code,
        "group.e2ee.commit_invalid"
    );
    let welcome_a2_notice = V2ProcessNoticeInput {
        recipient_did: alice.did.clone(),
        recipient_device_id: a2_device.device_id.clone(),
        meta: notice_meta(&alice.did, &a2_device.device_id, "notice-welcome-a2"),
        notice: V2E2eeNotice {
            notice_id: Some("notice-welcome-a2".to_owned()),
            notice_type: "welcome-delivery".to_owned(),
            group_did: GROUP_DID.to_owned(),
            group_state_ref: add_a2.body.group_state_ref.clone(),
            crypto_group_id_b64u: add_a2.body.crypto_group_id_b64u.clone(),
            epoch: add_a2.body.epoch.clone(),
            subject_did: alice.did.clone(),
            subject_device_id: a2_device.device_id.clone(),
            subject_status: "active".to_owned(),
            commit_b64u: None,
            welcome_b64u: Some(add_a2.body.welcome_b64u.clone()),
            ratchet_tree_b64u: Some(add_a2.body.ratchet_tree_b64u.clone()),
            epoch_authenticator: None,
            group_receipt: None,
        },
        member_documents: member_documents(&owner, &alice),
        now: NOW.to_owned(),
        draft_extension_negotiated: true,
        request_id: "req-notice-welcome-a2".to_owned(),
    };
    let mut wrong_welcome_target = welcome_a2_notice.clone();
    wrong_welcome_target.recipient_device_id = a1_device.device_id.clone();
    wrong_welcome_target.request_id = "req-notice-welcome-a2-wrong-target".to_owned();
    assert_eq!(
        process_notice_v2(&a2_store, wrong_welcome_target)
            .expect_err("Welcome cannot target a sibling device")
            .code,
        "group.e2ee.did_binding_invalid"
    );
    let welcome_output = process_notice_v2(&a2_store, welcome_a2_notice.clone())
        .expect("A2 processes its own standard Welcome notice");
    let mut repeated_welcome_notice = welcome_a2_notice;
    repeated_welcome_notice.request_id = "req-notice-welcome-a2-repeat".to_owned();
    assert_eq!(
        process_notice_v2(
            &store(directory.path(), &alice.did, &a2_device.device_id),
            repeated_welcome_notice,
        )
        .expect("exact Welcome notice replay is idempotent"),
        welcome_output
    );

    assert_eq!(
        list_local_group_member_endpoints_v2(
            &owner_store,
            V2InspectLocalGroupInput {
                owner_did: owner.did.clone(),
                owner_device_id: owner_device.device_id.clone(),
                group_did: GROUP_DID.to_owned(),
                request_id: "req-list-after-a2-add".to_owned(),
            },
        )
        .expect("current tree exposes each same-DID device endpoint once")
        .member_endpoints,
        vec![
            V2LocalGroupMemberEndpoint {
                member_did: alice.did.clone(),
                member_device_id: a1_device.device_id.clone(),
            },
            V2LocalGroupMemberEndpoint {
                member_did: alice.did.clone(),
                member_device_id: a2_device.device_id.clone(),
            },
            V2LocalGroupMemberEndpoint {
                member_did: owner.did.clone(),
                member_device_id: owner_device.device_id.clone(),
            },
        ]
    );

    assert!(decrypt_v2(
        &a2_store,
        V2DecryptInput {
            recipient_did: alice.did.clone(),
            recipient_device_id: a2_device.device_id.clone(),
            originating_meta: history_meta,
            group_cipher_object: history,
            sender_did_document: owner.document.clone(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            request_id: "req-decrypt-history-a2".to_owned(),
        },
    )
    .is_err());

    let replay_error = add_member_prepare_v2(
        &owner_store,
        V2AddMemberInput {
            meta: control_meta(&owner.did, &owner_device.device_id, "op-add-a2-replay"),
            group_state_ref: state_ref(4),
            group_key_package: a2_package,
            member_did_document: alice.document.clone(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            pending_commit_id: "pending-add-a2-replay".to_owned(),
            request_id: "req-add-a2-replay".to_owned(),
        },
    )
    .expect_err("same device KeyPackage cannot add another leaf");
    assert_eq!(replay_error.code, "group.e2ee.key_package_consumed");

    let attachment_manifest = V2GroupApplicationPlaintext {
        application_content_type: "application/anp-attachment-manifest+json".to_owned(),
        thread_id: Some("thread-1".to_owned()),
        reply_to_message_id: None,
        annotations: None,
        text: None,
        payload: Some(json!({
            "object_id": "object-1",
            "object_uri": "https://objects.example/ciphertext-1",
            "object_key_b64u": "AQIDBA",
            "nonce_b64u": "BQYHCA"
        })),
        payload_b64u: None,
    };
    let attachment_meta = send_meta(&owner.did, &owner_device.device_id, "attachment");
    let attachment_cipher = encrypt_v2(
        &owner_store,
        V2EncryptInput {
            meta: attachment_meta.clone(),
            group_state_ref: state_ref(3),
            application_plaintext: attachment_manifest.clone(),
            sender_did_document: owner.document.clone(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            request_id: "req-encrypt-attachment".to_owned(),
        },
    )
    .expect("one MLS encryption for one attachment Manifest");
    for (store, device) in [(&a1_store, a1_device), (&a2_store, a2_device)] {
        let output = decrypt_v2(
            store,
            V2DecryptInput {
                recipient_did: alice.did.clone(),
                recipient_device_id: device.device_id.clone(),
                originating_meta: attachment_meta.clone(),
                group_cipher_object: attachment_cipher.clone(),
                sender_did_document: owner.document.clone(),
                now: NOW.to_owned(),
                draft_extension_negotiated: true,
                request_id: format!("req-decrypt-attachment-{}", device.device_id),
            },
        )
        .expect("current Leaf decrypts the one attachment Manifest cipher");
        assert_eq!(output.application_plaintext, attachment_manifest);
    }

    let remove_meta = control_meta(&owner.did, &owner_device.device_id, "op-remove-a2");
    let remove_a2 = remove_member_prepare_v2(
        &owner_store,
        V2RemoveMemberInput {
            meta: remove_meta.clone(),
            group_state_ref: state_ref(4),
            member_did: alice.did.clone(),
            member_device_id: a2_device.device_id.clone(),
            member_did_document: alice.document.clone(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            pending_commit_id: "pending-remove-a2".to_owned(),
            request_id: "req-remove-a2".to_owned(),
        },
    )
    .expect("prepare exact A2 Remove");
    for (store, device) in [(&a1_store, a1_device), (&a2_store, a2_device)] {
        process_commit_v2(
            store,
            V2ProcessCommitInput {
                recipient_did: alice.did.clone(),
                recipient_device_id: device.device_id.clone(),
                meta: remove_meta.clone(),
                group_state_ref: remove_a2.body.group_state_ref.clone(),
                crypto_group_id_b64u: remove_a2.body.crypto_group_id_b64u.clone(),
                epoch: remove_a2.body.epoch.clone(),
                member_did: alice.did.clone(),
                member_device_id: a2_device.device_id.clone(),
                commit_b64u: remove_a2.body.commit_b64u.clone(),
                method: V2MembershipCommitMethod::Remove,
                sender_did_document: owner.document.clone(),
                member_did_document: alice.document.clone(),
                now: NOW.to_owned(),
                draft_extension_negotiated: true,
                request_id: format!("req-commit-remove-a2-{}", device.device_id),
            },
        )
        .expect("existing Leaf processes exact A2 Remove");
    }
    finalize_commit_v2(
        &owner_store,
        V2FinalizeInput {
            pending_commit_id: remove_a2.pending_commit_id.clone(),
            request_id: "req-finalize-remove-a2".to_owned(),
        },
    )
    .expect("finalize A2 Remove");
    let remove_a2_self_echo = V2ProcessNoticeInput {
        recipient_did: owner.did.clone(),
        recipient_device_id: owner_device.device_id.clone(),
        meta: notice_meta(
            &owner.did,
            &owner_device.device_id,
            "notice-remove-a2-owner-echo",
        ),
        notice: V2E2eeNotice {
            notice_id: Some("notice-remove-a2-owner-echo".to_owned()),
            notice_type: "commit-delivery".to_owned(),
            group_did: GROUP_DID.to_owned(),
            group_state_ref: remove_a2.body.group_state_ref.clone(),
            crypto_group_id_b64u: remove_a2.body.crypto_group_id_b64u.clone(),
            epoch: remove_a2.body.epoch.clone(),
            subject_did: alice.did.clone(),
            subject_device_id: a2_device.device_id.clone(),
            subject_status: "removed".to_owned(),
            commit_b64u: Some(remove_a2.body.commit_b64u.clone()),
            welcome_b64u: None,
            ratchet_tree_b64u: None,
            epoch_authenticator: None,
            group_receipt: None,
        },
        member_documents: member_documents(&owner, &alice),
        now: NOW.to_owned(),
        draft_extension_negotiated: true,
        request_id: "req-notice-remove-a2-owner-echo".to_owned(),
    };
    let remove_echo_output = process_notice_v2(&owner_store, remove_a2_self_echo)
        .expect("finalized Remove actor accepts its exact Commit echo");
    assert_eq!(
        remove_echo_output.source_operation_id.as_deref(),
        Some("op-remove-a2")
    );
    assert_eq!(remove_echo_output.from_epoch, "2");
    assert_eq!(remove_echo_output.epoch, "3");
    assert_eq!(
        list_local_group_member_endpoints_v2(
            &owner_store,
            V2InspectLocalGroupInput {
                owner_did: owner.did.clone(),
                owner_device_id: owner_device.device_id.clone(),
                group_did: GROUP_DID.to_owned(),
                request_id: "req-list-after-a2-remove".to_owned(),
            },
        )
        .expect("exact-device Remove updates the local public endpoint projection")
        .member_endpoints,
        vec![
            V2LocalGroupMemberEndpoint {
                member_did: alice.did.clone(),
                member_device_id: a1_device.device_id.clone(),
            },
            V2LocalGroupMemberEndpoint {
                member_did: owner.did.clone(),
                member_device_id: owner_device.device_id.clone(),
            },
        ]
    );

    let future_meta = send_meta(&owner.did, &owner_device.device_id, "future");
    let future = encrypt_v2(
        &owner_store,
        V2EncryptInput {
            meta: future_meta.clone(),
            group_state_ref: state_ref(4),
            application_plaintext: V2GroupApplicationPlaintext {
                application_content_type: "text/plain".to_owned(),
                thread_id: None,
                reply_to_message_id: None,
                annotations: None,
                text: Some("after A2 removal".to_owned()),
                payload: None,
                payload_b64u: None,
            },
            sender_did_document: owner.document.clone(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            request_id: "req-encrypt-future".to_owned(),
        },
    )
    .expect("encrypt after exact A2 Remove");
    assert!(decrypt_v2(
        &a1_store,
        V2DecryptInput {
            recipient_did: alice.did.clone(),
            recipient_device_id: a1_device.device_id.clone(),
            originating_meta: future_meta.clone(),
            group_cipher_object: future.clone(),
            sender_did_document: owner.document.clone(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            request_id: "req-decrypt-future-a1".to_owned(),
        },
    )
    .is_ok());
    assert!(decrypt_v2(
        &a2_store,
        V2DecryptInput {
            recipient_did: alice.did,
            recipient_device_id: a2_device.device_id.clone(),
            originating_meta: future_meta,
            group_cipher_object: future,
            sender_did_document: owner.document,
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            request_id: "req-decrypt-future-a2".to_owned(),
        },
    )
    .is_err());
}
