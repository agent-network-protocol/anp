#![cfg(feature = "mls")]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anp::authentication::{
    create_did_wba_document, validate_device_manifest, DidDocumentOptions, DidProfile,
};
use anp::group_e2ee::operations::v2::{
    add_member_prepare_v2, create_group_prepare_v2, decrypt_v2, encrypt_v2, finalize_commit_v2,
    generate_key_package_v2, process_commit_v2, process_welcome_v2, remove_member_prepare_v2,
    V2AddMemberInput, V2CreateGroupInput, V2DecryptInput, V2DidDocument, V2EncryptInput,
    V2FinalizeInput, V2GenerateKeyPackageInput, V2MembershipCommitMethod, V2ProcessCommitInput,
    V2ProcessWelcomeInput, V2RemoveMemberInput,
};
use anp::group_e2ee::storage::ImCoreSqliteGroupMlsStore;
use anp::group_e2ee::{
    V2GroupApplicationPlaintext, V2GroupControlMetadata, V2GroupSendMetadata, V2GroupStateRef,
    V2ServiceMetadata, V2Target, GROUP_CIPHER_CONTENT_TYPE_V2, GROUP_E2EE_PROFILE_V2,
    GROUP_E2EE_SECURITY_PROFILE_V2,
};
use anp::proof::{
    generate_w3c_proof, ProofGenerationOptions, CRYPTOSUITE_EDDSA_JCS_2022,
    PROOF_TYPE_DATA_INTEGRITY,
};
use anp::PrivateKeyMaterial;
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
    finalize_commit_v2(
        &owner_store,
        V2FinalizeInput {
            pending_commit_id: created.pending_commit_id,
            request_id: "req-finalize-create".to_owned(),
        },
    )
    .expect("finalize group create");

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
    finalize_commit_v2(
        &owner_store,
        V2FinalizeInput {
            pending_commit_id: add_a1.pending_commit_id,
            request_id: "req-finalize-add-a1".to_owned(),
        },
    )
    .expect("finalize A1 Add");
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
    process_commit_v2(
        &a1_store,
        V2ProcessCommitInput {
            recipient_did: alice.did.clone(),
            recipient_device_id: a1_device.device_id.clone(),
            meta: add_a2_meta,
            group_state_ref: add_a2.body.group_state_ref.clone(),
            crypto_group_id_b64u: add_a2.body.crypto_group_id_b64u.clone(),
            epoch: add_a2.body.epoch.clone(),
            member_did: alice.did.clone(),
            member_device_id: a2_device.device_id.clone(),
            commit_b64u: add_a2.body.commit_b64u.clone(),
            method: V2MembershipCommitMethod::Add,
            sender_did_document: owner.document.clone(),
            member_did_document: alice.document.clone(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            request_id: "req-commit-add-a2-a1".to_owned(),
        },
    )
    .expect("A1 processes A2 Add");
    finalize_commit_v2(
        &owner_store,
        V2FinalizeInput {
            pending_commit_id: add_a2.pending_commit_id,
            request_id: "req-finalize-add-a2".to_owned(),
        },
    )
    .expect("finalize A2 Add");
    process_welcome_v2(
        &a2_store,
        V2ProcessWelcomeInput {
            recipient_did: alice.did.clone(),
            recipient_device_id: a2_device.device_id.clone(),
            group_did: GROUP_DID.to_owned(),
            group_state_ref: add_a2.body.group_state_ref.clone(),
            crypto_group_id_b64u: add_a2.body.crypto_group_id_b64u.clone(),
            epoch: add_a2.body.epoch.clone(),
            welcome_b64u: add_a2.body.welcome_b64u.clone(),
            ratchet_tree_b64u: add_a2.body.ratchet_tree_b64u.clone(),
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
            request_id: "req-welcome-a2".to_owned(),
        },
    )
    .expect("A2 processes its own Welcome");

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
            pending_commit_id: remove_a2.pending_commit_id,
            request_id: "req-finalize-remove-a2".to_owned(),
        },
    )
    .expect("finalize A2 Remove");

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
