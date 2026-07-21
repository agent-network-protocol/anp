#![cfg(feature = "mls")]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anp::authentication::{
    create_did_wba_document, validate_device_manifest, DidDocumentOptions, DidProfile,
};
use anp::group_e2ee::operations::v2::{
    abort_commit_v2, accept_key_package_publish_v2, add_member_prepare_v2, create_group_prepare_v2,
    decrypt_v2, encrypt_v2, finalize_commit_v2, generate_key_package_v2, inspect_local_group_v2,
    list_local_group_member_endpoints_v2, prepare_or_resume_key_package_publish_v2,
    process_commit_v2, process_notice_v2, process_welcome_v2, reconcile_pending_v2,
    remove_member_prepare_v2, V2AcceptKeyPackagePublishInput, V2AddMemberInput, V2CreateGroupInput,
    V2DecryptInput, V2DidDocument, V2EncryptInput, V2FinalizeInput, V2GenerateKeyPackageInput,
    V2InspectLocalGroupInput, V2KeyPackagePublishStatus, V2LocalGroupMemberEndpoint,
    V2LocalGroupReadiness, V2MembershipCommitMethod, V2PrepareKeyPackagePublishInput,
    V2ProcessCommitInput, V2ProcessNoticeInput, V2ProcessWelcomeInput, V2ReconcilePendingInput,
    V2RemoveMemberInput,
};
use anp::group_e2ee::storage::{CompatDataDirStore, ImCoreSqliteGroupMlsStore};
use anp::group_e2ee::{
    V2E2eeNotice, V2GroupApplicationPlaintext, V2GroupControlMetadata, V2GroupNoticeMetadata,
    V2GroupSendMetadata, V2GroupStateRef, V2PublishKeyPackageResult, V2ServiceMetadata, V2Target,
    GROUP_CIPHER_CONTENT_TYPE_V2, GROUP_E2EE_PROFILE_V2, GROUP_E2EE_SECURITY_PROFILE_V2,
    GROUP_E2EE_TRANSPORT_PROFILE_V2,
};
use anp::proof::{
    generate_w3c_proof, ProofGenerationOptions, CRYPTOSUITE_EDDSA_JCS_2022,
    PROOF_TYPE_DATA_INTEGRITY,
};
use anp::PrivateKeyMaterial;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use openmls::prelude::{tls_codec::Deserialize as TlsDeserialize, MlsMessageIn, PrivateMessageIn};
use rusqlite::{params, Connection};
use serde_json::{json, Value};

const NOW: &str = "2026-07-20T00:00:00Z";
const ISSUED_AT: &str = "2026-07-19T00:00:00Z";
const EXPIRES_AT: &str = "2026-08-19T00:00:00Z";
const GROUP_DID: &str = "did:wba:p6-runtime.example:groups:operations";
static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
            "anp-p6-v2-operations-{}-{nonce}-{}",
            std::process::id(),
            TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
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

fn document_without_manifest_device(fixture: &DidFixture, device_id: &str) -> Value {
    let mut document = fixture.document.clone();
    document
        .as_object_mut()
        .expect("DID document object")
        .remove("proof");
    document["deviceManifest"]["devices"]
        .as_array_mut()
        .expect("Manifest devices")
        .retain(|device| device["device_id"].as_str() != Some(device_id));
    validate_device_manifest(&document).expect("updated device Manifest remains valid");
    let document = generate_w3c_proof(
        &document,
        &signing_key(&fixture.devices[0]),
        &format!("{}#key-1", fixture.did),
        ProofGenerationOptions {
            proof_purpose: Some("assertionMethod".to_owned()),
            proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_owned()),
            cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.to_owned()),
            created: Some(NOW.to_owned()),
            ..Default::default()
        },
    )
    .expect("sign current DID document after device removal");
    assert!(document["deviceManifest"]["devices"]
        .as_array()
        .expect("Manifest devices")
        .iter()
        .all(|device| device["device_id"].as_str() != Some(device_id)));
    document
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
fn key_package_publish_wal_resumes_exactly_and_caches_typed_acceptance() {
    let directory = TestDirectory::new();
    let owner = make_did_fixture("publish-wal", &["publish-device"]);
    let device = &owner.devices[0];
    let operation_id = "join-kp-publish-operation";
    let key_package_id = "join-kp-publish-package";
    let mut meta = service_meta(&owner.did, &device.device_id, operation_id);
    meta.security_profile = GROUP_E2EE_TRANSPORT_PROFILE_V2.to_owned();
    meta.created_at = None;
    let first_input = V2PrepareKeyPackagePublishInput {
        meta,
        owner_did: owner.did.clone(),
        owner_device_id: device.device_id.clone(),
        verification_method: device.signing_key_id.clone(),
        key_package_id: key_package_id.to_owned(),
        issued_at: ISSUED_AT.to_owned(),
        expires_at: EXPIRES_AT.to_owned(),
        now: NOW.to_owned(),
        draft_extension_negotiated: true,
        request_id: "req-publish-prepare-first".to_owned(),
    };
    let first_store = store(directory.path(), &owner.did, &device.device_id);
    let first = prepare_or_resume_key_package_publish_v2(
        &first_store,
        first_input.clone(),
        &owner.document,
        &signing_key(device),
    )
    .expect("prepare persisted KeyPackage publish");
    assert_eq!(first.status, V2KeyPackagePublishStatus::Prepared);
    assert!(first.accepted_result.is_none());
    drop(first_store);

    let mut retry_input = first_input.clone();
    retry_input.issued_at = "2026-07-19T01:00:00Z".to_owned();
    retry_input.expires_at = "2026-08-20T00:00:00Z".to_owned();
    retry_input.now = "2026-07-20T00:01:00Z".to_owned();
    retry_input.request_id = "req-publish-prepare-after-restart".to_owned();
    let restarted_store = store(directory.path(), &owner.did, &device.device_id);
    let resumed = prepare_or_resume_key_package_publish_v2(
        &restarted_store,
        retry_input.clone(),
        &owner.document,
        &signing_key(device),
    )
    .expect("resume exact persisted KeyPackage publish");
    assert_eq!(resumed, first);
    assert_eq!(
        serde_json::to_vec(&resumed).expect("serialize resumed publish"),
        serde_json::to_vec(&first).expect("serialize first publish")
    );

    let conn = Connection::open(restarted_store.state_db_path()).expect("open SDK state database");
    let package_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM group_mls_key_packages\n             WHERE owner_identity_id = ?1 AND device_id = ?2 AND key_package_id = ?3",
            params![
                format!("identity-{}", device.device_id),
                device.device_id,
                key_package_id
            ],
            |row| row.get(0),
        )
        .expect("count persisted public KeyPackages");
    assert_eq!(package_count, 1);
    let openmls_package_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM openmls_key_packages", [], |row| {
            row.get(0)
        })
        .expect("count persisted private OpenMLS KeyPackages");
    assert_eq!(openmls_package_count, 1);
    let (journal_status, response_json, contains_sensitive): (String, String, i64) = conn
        .query_row(
            "SELECT status, response_json, contains_sensitive FROM group_mls_operations\n             WHERE owner_identity_id = ?1 AND device_id = ?2 AND operation_id = ?3",
            params![
                format!("identity-{}", device.device_id),
                device.device_id,
                operation_id
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("load public publish journal");
    assert_eq!(journal_status, "prepared");
    assert_eq!(contains_sensitive, 0);
    assert!(!response_json.contains("private_key"));
    assert!(!response_json.contains("private_ref"));
    assert!(!response_json.contains("private_init_key"));
    assert!(!response_json.contains("private_encryption_key"));
    drop(conn);

    let result = V2PublishKeyPackageResult {
        published: true,
        owner_did: owner.did.clone(),
        owner_device_id: device.device_id.clone(),
        key_package_id: key_package_id.to_owned(),
        published_at: NOW.to_owned(),
    };
    let accepted = accept_key_package_publish_v2(
        &restarted_store,
        V2AcceptKeyPackagePublishInput {
            owner_did: owner.did.clone(),
            owner_device_id: device.device_id.clone(),
            operation_id: operation_id.to_owned(),
            result: result.clone(),
            request_id: "req-publish-accept".to_owned(),
        },
    )
    .expect("persist typed host acceptance");
    assert_eq!(accepted.status, V2KeyPackagePublishStatus::Accepted);
    assert_eq!(accepted.accepted_result.as_ref(), Some(&result));
    drop(restarted_store);

    let replay_store = store(directory.path(), &owner.did, &device.device_id);
    let replay = prepare_or_resume_key_package_publish_v2(
        &replay_store,
        retry_input.clone(),
        &owner.document,
        &signing_key(device),
    )
    .expect("accepted publish replay returns cached result");
    assert_eq!(replay.status, V2KeyPackagePublishStatus::Accepted);
    assert_eq!(replay.meta, first.meta);
    assert_eq!(replay.body, first.body);
    assert_eq!(replay.accepted_result.as_ref(), Some(&result));

    let mut expired_retry = retry_input.clone();
    expired_retry.now = "2026-08-21T00:00:00Z".to_owned();
    expired_retry.request_id = "req-publish-accepted-after-expiry".to_owned();
    let expired_replay = prepare_or_resume_key_package_publish_v2(
        &replay_store,
        expired_retry,
        &owner.document,
        &signing_key(device),
    )
    .expect("terminal accepted publish remains replayable after package expiry");
    assert_eq!(expired_replay, replay);

    let accepted_replay = accept_key_package_publish_v2(
        &replay_store,
        V2AcceptKeyPackagePublishInput {
            owner_did: owner.did.clone(),
            owner_device_id: device.device_id.clone(),
            operation_id: operation_id.to_owned(),
            result: result.clone(),
            request_id: "req-publish-accept-replay".to_owned(),
        },
    )
    .expect("same typed acceptance is idempotent");
    assert_eq!(accepted_replay, replay);

    let mut conflict = retry_input;
    conflict.key_package_id = "different-key-package".to_owned();
    conflict.request_id = "req-publish-conflict".to_owned();
    let error = prepare_or_resume_key_package_publish_v2(
        &replay_store,
        conflict,
        &owner.document,
        &signing_key(device),
    )
    .expect_err("same operation ID with another stable input must fail closed");
    assert_eq!(error.code, "group.e2ee.commit_invalid");

    let mut equivalent_result = result;
    equivalent_result.published_at = "2026-07-20T00:02:00Z".to_owned();
    let equivalent_replay = accept_key_package_publish_v2(
        &replay_store,
        V2AcceptKeyPackagePublishInput {
            owner_did: owner.did.clone(),
            owner_device_id: device.device_id.clone(),
            operation_id: operation_id.to_owned(),
            result: equivalent_result,
            request_id: "req-publish-accept-equivalent".to_owned(),
        },
    )
    .expect("equivalent Host acceptance returns the first cached result");
    assert_eq!(equivalent_replay, replay);
}

#[test]
fn expired_prepared_publish_rotates_once_and_accepts_the_new_wire_attempt() {
    let directory = TestDirectory::new();
    let owner = make_did_fixture("publish-expired-rotate", &["publish-rotate-device"]);
    let device = &owner.devices[0];
    let operation_id = "join-kp-expired-rotate-operation";
    let key_package_id = "join-kp-expired-rotate-package";
    let mut meta = service_meta(&owner.did, &device.device_id, operation_id);
    meta.security_profile = GROUP_E2EE_TRANSPORT_PROFILE_V2.to_owned();
    meta.created_at = None;
    let input = V2PrepareKeyPackagePublishInput {
        meta,
        owner_did: owner.did.clone(),
        owner_device_id: device.device_id.clone(),
        verification_method: device.signing_key_id.clone(),
        key_package_id: key_package_id.to_owned(),
        issued_at: ISSUED_AT.to_owned(),
        expires_at: EXPIRES_AT.to_owned(),
        now: NOW.to_owned(),
        draft_extension_negotiated: true,
        request_id: "req-publish-expired-initial".to_owned(),
    };
    let initial_store = store(directory.path(), &owner.did, &device.device_id);
    let first = prepare_or_resume_key_package_publish_v2(
        &initial_store,
        input.clone(),
        &owner.document,
        &signing_key(device),
    )
    .expect("prepare the attempt whose Host response is lost");
    drop(initial_store);

    let mut changed_route = input.clone();
    changed_route.meta.target.did = "did:wba:p6-rotated.example:services:message".to_owned();
    changed_route.request_id = "req-publish-route-change-before-expiry".to_owned();
    let unexpired_store = store(directory.path(), &owner.did, &device.device_id);
    let error = prepare_or_resume_key_package_publish_v2(
        &unexpired_store,
        changed_route.clone(),
        &owner.document,
        &signing_key(device),
    )
    .expect_err("an unexpired attempt cannot be rebound to another route");
    assert_eq!(error.code, "group.e2ee.commit_invalid");
    drop(unexpired_store);

    changed_route.issued_at = "2026-08-21T00:00:00Z".to_owned();
    changed_route.expires_at = "2026-09-21T00:00:00Z".to_owned();
    changed_route.now = "2026-08-21T00:00:00Z".to_owned();
    changed_route.request_id = "req-publish-route-change-after-expiry".to_owned();
    let rotated_store = store(directory.path(), &owner.did, &device.device_id);
    let error = prepare_or_resume_key_package_publish_v2(
        &rotated_store,
        changed_route,
        &owner.document,
        &signing_key(device),
    )
    .expect_err("expiry must not permit rebinding the publish family route");
    assert_eq!(error.code, "group.e2ee.commit_invalid");

    let mut rotation_retry = input.clone();
    rotation_retry.issued_at = "2026-08-21T00:00:00Z".to_owned();
    rotation_retry.expires_at = "2026-09-21T00:00:00Z".to_owned();
    rotation_retry.now = "2026-08-21T00:00:00Z".to_owned();
    rotation_retry.request_id = "req-publish-rotate-after-expiry".to_owned();
    let rotated = prepare_or_resume_key_package_publish_v2(
        &rotated_store,
        rotation_retry.clone(),
        &owner.document,
        &signing_key(device),
    )
    .expect("expired response-loss attempt rotates exactly once");
    assert_eq!(rotated.status, V2KeyPackagePublishStatus::Prepared);
    assert_ne!(rotated.meta.operation_id, first.meta.operation_id);
    assert_ne!(
        rotated.body.group_key_package.key_package_id,
        first.body.group_key_package.key_package_id
    );
    assert!(rotated.meta.operation_id.starts_with("kp-op-attempt-"));
    assert!(rotated
        .body
        .group_key_package
        .key_package_id
        .starts_with("kp-attempt-"));
    assert_eq!(rotated.meta.target, rotation_retry.meta.target);

    let mut exact_retry = rotation_retry.clone();
    exact_retry.issued_at = "2026-08-22T00:00:00Z".to_owned();
    exact_retry.expires_at = "2026-09-22T00:00:00Z".to_owned();
    exact_retry.now = "2026-08-22T00:00:00Z".to_owned();
    exact_retry.request_id = "req-publish-rotated-exact-retry".to_owned();
    let replay = prepare_or_resume_key_package_publish_v2(
        &rotated_store,
        exact_retry,
        &owner.document,
        &signing_key(device),
    )
    .expect("the new attempt retries byte-for-byte");
    assert_eq!(replay, rotated);

    let conn = Connection::open(rotated_store.state_db_path()).expect("inspect rotated WAL");
    assert_eq!(
        conn.execute(
            "INSERT INTO group_mls_operations(\n                 owner_identity_id, device_id, operation_id, command, input_digest,\n                 response_json, redaction_version, contains_sensitive, status, created_at, updated_at\n             )\n             SELECT owner_identity_id, device_id, 'legacy-superseded-accept-duplicate', command, input_digest,\n                    response_json, redaction_version, contains_sensitive, 'superseded', created_at, updated_at\n             FROM group_mls_operations WHERE operation_id = ?1",
            params![operation_id],
        )
        .unwrap(),
        1
    );

    let accepted_result = V2PublishKeyPackageResult {
        published: true,
        owner_did: owner.did.clone(),
        owner_device_id: device.device_id.clone(),
        key_package_id: rotated.body.group_key_package.key_package_id.clone(),
        published_at: "2026-08-22T00:00:00Z".to_owned(),
    };
    let accepted = accept_key_package_publish_v2(
        &rotated_store,
        V2AcceptKeyPackagePublishInput {
            owner_did: owner.did.clone(),
            owner_device_id: device.device_id.clone(),
            operation_id: rotated.meta.operation_id.clone(),
            result: accepted_result,
            request_id: "req-publish-rotated-accept".to_owned(),
        },
    )
    .expect("a terminal duplicate cannot make the active wire ID ambiguous");
    assert_eq!(accepted.status, V2KeyPackagePublishStatus::Accepted);
    assert_eq!(
        conn.execute(
            "DELETE FROM group_mls_operations WHERE operation_id = 'legacy-superseded-accept-duplicate'",
            [],
        )
        .unwrap(),
        1
    );
    drop(conn);

    let mut accepted_after_expiry = rotation_retry;
    accepted_after_expiry.now = "2026-10-01T00:00:00Z".to_owned();
    accepted_after_expiry.request_id = "req-publish-accepted-after-expiry".to_owned();
    let terminal = prepare_or_resume_key_package_publish_v2(
        &rotated_store,
        accepted_after_expiry,
        &owner.document,
        &signing_key(device),
    )
    .expect("accepted attempt never rotates after expiry");
    assert_eq!(terminal, accepted);

    let conn = Connection::open(rotated_store.state_db_path()).expect("inspect rotated WAL");
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM group_mls_operations", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM group_mls_key_packages", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM openmls_key_packages", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    let (status, response_json, contains_sensitive): (String, String, i64) = conn
        .query_row(
            "SELECT status, response_json, contains_sensitive FROM group_mls_operations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(status, "accepted");
    assert_eq!(contains_sensitive, 0);
    assert!(response_json.contains("superseded_attempts"));
    for forbidden in [
        "private_key",
        "private_ref",
        "private_init_key",
        "private_encryption_key",
    ] {
        assert!(!response_json.contains(forbidden));
    }
}

#[test]
fn expired_publish_rotation_rejects_missing_or_tampered_public_rows() {
    let directory = TestDirectory::new();
    let owner = make_did_fixture("publish-public-row-guard", &["publish-public-row-device"]);
    let device = &owner.devices[0];
    for mutation in ["missing", "tampered"] {
        let operation_id = format!("join-kp-public-{mutation}-operation");
        let key_package_id = format!("join-kp-public-{mutation}-package");
        let mut meta = service_meta(&owner.did, &device.device_id, &operation_id);
        meta.security_profile = GROUP_E2EE_TRANSPORT_PROFILE_V2.to_owned();
        meta.created_at = None;
        let input = V2PrepareKeyPackagePublishInput {
            meta,
            owner_did: owner.did.clone(),
            owner_device_id: device.device_id.clone(),
            verification_method: device.signing_key_id.clone(),
            key_package_id: key_package_id.clone(),
            issued_at: ISSUED_AT.to_owned(),
            expires_at: EXPIRES_AT.to_owned(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            request_id: format!("req-publish-public-{mutation}-prepare"),
        };
        let case_root = directory.path().join(mutation);
        let case_store = store(&case_root, &owner.did, &device.device_id);
        prepare_or_resume_key_package_publish_v2(
            &case_store,
            input.clone(),
            &owner.document,
            &signing_key(device),
        )
        .expect("prepare public-row guard fixture");
        let conn = Connection::open(case_store.state_db_path()).unwrap();
        let original_journal: String = conn
            .query_row(
                "SELECT response_json FROM group_mls_operations WHERE operation_id = ?1",
                params![operation_id],
                |row| row.get(0),
            )
            .unwrap();
        if mutation == "missing" {
            assert_eq!(
                conn.execute(
                    "DELETE FROM group_mls_key_packages WHERE key_package_id = ?1",
                    params![key_package_id],
                )
                .unwrap(),
                1
            );
        } else {
            let public_json: String = conn
                .query_row(
                    "SELECT public_json FROM group_mls_key_packages WHERE key_package_id = ?1",
                    params![key_package_id],
                    |row| row.get(0),
                )
                .unwrap();
            let mut public: Value = serde_json::from_str(&public_json).unwrap();
            public["expires_at"] = json!("2026-08-18T00:00:00Z");
            assert_eq!(
                conn.execute(
                    "UPDATE group_mls_key_packages SET public_json = ?2 WHERE key_package_id = ?1",
                    params![key_package_id, public.to_string()],
                )
                .unwrap(),
                1
            );
        }
        drop(conn);

        let mut expired = input;
        expired.issued_at = "2026-08-20T00:00:00Z".to_owned();
        expired.expires_at = "2026-09-20T00:00:00Z".to_owned();
        expired.now = "2026-08-20T00:00:00Z".to_owned();
        expired.request_id = format!("req-publish-public-{mutation}-rotate");
        let error = prepare_or_resume_key_package_publish_v2(
            &case_store,
            expired,
            &owner.document,
            &signing_key(device),
        )
        .expect_err("rotation requires the exact journal public object");
        assert_eq!(error.code, "group.e2ee.state_not_ready");

        let conn = Connection::open(case_store.state_db_path()).unwrap();
        let (journal, status): (String, String) = conn
            .query_row(
                "SELECT response_json, status FROM group_mls_operations WHERE operation_id = ?1",
                params![operation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(journal, original_journal);
        assert_eq!(status, "prepared");
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM openmls_key_packages", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            1
        );
    }
}

#[test]
fn publish_wire_ids_are_unique_across_current_and_historical_families() {
    let directory = TestDirectory::new();
    let owner = make_did_fixture("publish-family-uniqueness", &["publish-family-device"]);
    let device = &owner.devices[0];
    let make_input = |operation_id: &str, key_package_id: &str, request_id: &str| {
        let mut meta = service_meta(&owner.did, &device.device_id, operation_id);
        meta.security_profile = GROUP_E2EE_TRANSPORT_PROFILE_V2.to_owned();
        meta.created_at = None;
        V2PrepareKeyPackagePublishInput {
            meta,
            owner_did: owner.did.clone(),
            owner_device_id: device.device_id.clone(),
            verification_method: device.signing_key_id.clone(),
            key_package_id: key_package_id.to_owned(),
            issued_at: ISSUED_AT.to_owned(),
            expires_at: EXPIRES_AT.to_owned(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            request_id: request_id.to_owned(),
        }
    };

    let probe_root = directory.path().join("probe");
    let probe_store = store(&probe_root, &owner.did, &device.device_id);
    let base_operation_id = "family-a-operation";
    let base_key_package_id = "family-a-package";
    let base_input = make_input(
        base_operation_id,
        base_key_package_id,
        "req-family-a-prepare",
    );
    prepare_or_resume_key_package_publish_v2(
        &probe_store,
        base_input.clone(),
        &owner.document,
        &signing_key(device),
    )
    .unwrap();
    let mut first_expired = base_input.clone();
    first_expired.issued_at = "2026-08-20T00:00:00Z".to_owned();
    first_expired.expires_at = "2026-09-20T00:00:00Z".to_owned();
    first_expired.now = "2026-08-20T00:00:00Z".to_owned();
    first_expired.request_id = "req-family-a-rotate-one".to_owned();
    let generation_one = prepare_or_resume_key_package_publish_v2(
        &probe_store,
        first_expired.clone(),
        &owner.document,
        &signing_key(device),
    )
    .unwrap();
    let mut second_expired = first_expired;
    second_expired.issued_at = "2026-09-21T00:00:00Z".to_owned();
    second_expired.expires_at = "2026-10-21T00:00:00Z".to_owned();
    second_expired.now = "2026-09-21T00:00:00Z".to_owned();
    second_expired.request_id = "req-family-a-rotate-two".to_owned();
    let generation_two = prepare_or_resume_key_package_publish_v2(
        &probe_store,
        second_expired,
        &owner.document,
        &signing_key(device),
    )
    .unwrap();

    let conflicting_new_families = [
        (
            "current-operation",
            generation_two.meta.operation_id.as_str(),
            "unique-current-operation-package",
        ),
        (
            "current-key",
            "unique-current-key-operation",
            generation_two
                .body
                .group_key_package
                .key_package_id
                .as_str(),
        ),
        (
            "history-operation",
            generation_one.meta.operation_id.as_str(),
            "unique-history-operation-package",
        ),
        (
            "history-key",
            "unique-history-key-operation",
            generation_one
                .body
                .group_key_package
                .key_package_id
                .as_str(),
        ),
    ];
    for (label, operation_id, key_package_id) in conflicting_new_families {
        let error = prepare_or_resume_key_package_publish_v2(
            &probe_store,
            make_input(
                operation_id,
                key_package_id,
                &format!("req-family-conflict-{label}"),
            ),
            &owner.document,
            &signing_key(device),
        )
        .expect_err("a new family cannot reuse current or historical wire IDs");
        assert_eq!(error.code, "group.e2ee.commit_invalid");
    }
    let conn = Connection::open(probe_store.state_db_path()).unwrap();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM group_mls_operations", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    drop(conn);

    let conn = Connection::open(probe_store.state_db_path()).unwrap();
    assert_eq!(
        conn.execute(
            "UPDATE group_mls_operations SET status = 'superseded' WHERE operation_id = ?1",
            params![base_operation_id],
        )
        .unwrap(),
        1
    );
    drop(conn);
    let superseded_family_conflicts = [
        (
            "superseded-current-operation",
            generation_two.meta.operation_id.as_str(),
            "unique-superseded-current-operation-package",
        ),
        (
            "superseded-current-key",
            "unique-superseded-current-key-operation",
            generation_two
                .body
                .group_key_package
                .key_package_id
                .as_str(),
        ),
        (
            "superseded-history-operation",
            generation_one.meta.operation_id.as_str(),
            "unique-superseded-history-operation-package",
        ),
        (
            "superseded-history-key",
            "unique-superseded-history-key-operation",
            generation_one
                .body
                .group_key_package
                .key_package_id
                .as_str(),
        ),
    ];
    for (label, operation_id, key_package_id) in superseded_family_conflicts {
        let error = prepare_or_resume_key_package_publish_v2(
            &probe_store,
            make_input(
                operation_id,
                key_package_id,
                &format!("req-family-conflict-{label}"),
            ),
            &owner.document,
            &signing_key(device),
        )
        .expect_err("a superseded family must keep all current and historical wire IDs reserved");
        assert_eq!(error.code, "group.e2ee.commit_invalid");
    }

    for (label, other_operation_id, other_key_package_id) in [
        (
            "operation",
            generation_one.meta.operation_id.as_str(),
            "unrelated-family-package",
        ),
        (
            "key",
            "unrelated-family-operation",
            generation_one
                .body
                .group_key_package
                .key_package_id
                .as_str(),
        ),
    ] {
        let case_root = directory.path().join(format!("rotate-{label}"));
        let case_store = store(&case_root, &owner.did, &device.device_id);
        prepare_or_resume_key_package_publish_v2(
            &case_store,
            base_input.clone(),
            &owner.document,
            &signing_key(device),
        )
        .unwrap();
        prepare_or_resume_key_package_publish_v2(
            &case_store,
            make_input(
                other_operation_id,
                other_key_package_id,
                &format!("req-other-family-{label}"),
            ),
            &owner.document,
            &signing_key(device),
        )
        .expect("the other family does not collide with generation zero");
        let conn = Connection::open(case_store.state_db_path()).unwrap();
        assert_eq!(
            conn.execute(
                "UPDATE group_mls_operations SET status = 'superseded' WHERE operation_id = ?1",
                params![other_operation_id],
            )
            .unwrap(),
            1
        );
        drop(conn);
        let mut expired = base_input.clone();
        expired.issued_at = "2026-08-20T00:00:00Z".to_owned();
        expired.expires_at = "2026-09-20T00:00:00Z".to_owned();
        expired.now = "2026-08-20T00:00:00Z".to_owned();
        expired.request_id = format!("req-family-a-rotate-{label}-conflict");
        let error = prepare_or_resume_key_package_publish_v2(
            &case_store,
            expired,
            &owner.document,
            &signing_key(device),
        )
        .expect_err("rotation cannot claim a superseded family's current wire ID");
        assert_eq!(error.code, "group.e2ee.commit_invalid");
        let conn = Connection::open(case_store.state_db_path()).unwrap();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM group_mls_operations", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            2
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM group_mls_key_packages", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            2
        );
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM openmls_key_packages", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            2
        );
        let journal: String = conn
            .query_row(
                "SELECT response_json FROM group_mls_operations WHERE operation_id = ?1",
                params![base_operation_id],
                |row| row.get(0),
            )
            .unwrap();
        let journal: Value = serde_json::from_str(&journal).unwrap();
        assert_eq!(journal["generation"], json!(0));
        assert!(journal["superseded_attempts"]
            .as_array()
            .is_none_or(Vec::is_empty));
    }
}

#[test]
fn rotated_publish_recovers_after_atomic_switch_and_rejects_ambiguous_bindings() {
    let directory = TestDirectory::new();
    let owner = make_did_fixture("publish-rotate-crash", &["publish-rotate-crash-device"]);
    let device = &owner.devices[0];
    let operation_id = "join-kp-rotate-crash-operation";
    let key_package_id = "join-kp-rotate-crash-package";
    let mut meta = service_meta(&owner.did, &device.device_id, operation_id);
    meta.security_profile = GROUP_E2EE_TRANSPORT_PROFILE_V2.to_owned();
    meta.created_at = None;
    let input = V2PrepareKeyPackagePublishInput {
        meta,
        owner_did: owner.did.clone(),
        owner_device_id: device.device_id.clone(),
        verification_method: device.signing_key_id.clone(),
        key_package_id: key_package_id.to_owned(),
        issued_at: ISSUED_AT.to_owned(),
        expires_at: EXPIRES_AT.to_owned(),
        now: NOW.to_owned(),
        draft_extension_negotiated: true,
        request_id: "req-publish-rotate-crash-initial".to_owned(),
    };
    let initial_store = store(directory.path(), &owner.did, &device.device_id);
    prepare_or_resume_key_package_publish_v2(
        &initial_store,
        input.clone(),
        &owner.document,
        &signing_key(device),
    )
    .unwrap();
    drop(initial_store);

    let mut retry = input;
    retry.issued_at = "2026-08-21T00:00:00Z".to_owned();
    retry.expires_at = "2026-09-21T00:00:00Z".to_owned();
    retry.now = "2026-08-21T00:00:00Z".to_owned();
    retry.request_id = "req-publish-rotate-crash-switch".to_owned();
    let rotated_store = store(directory.path(), &owner.did, &device.device_id);
    let rotated = prepare_or_resume_key_package_publish_v2(
        &rotated_store,
        retry.clone(),
        &owner.document,
        &signing_key(device),
    )
    .unwrap();
    let conn = Connection::open(rotated_store.state_db_path()).unwrap();
    assert_eq!(
        conn.execute(
            "INSERT INTO group_mls_operations(\n                 owner_identity_id, device_id, operation_id, command, input_digest,\n                 response_json, redaction_version, contains_sensitive, status, created_at, updated_at\n             )\n             SELECT owner_identity_id, device_id, 'ambiguous-family', command, input_digest,\n                    response_json, redaction_version, contains_sensitive, status, created_at, updated_at\n             FROM group_mls_operations WHERE operation_id = ?1",
            params![operation_id],
        )
        .unwrap(),
        1
    );
    let ambiguous = accept_key_package_publish_v2(
        &rotated_store,
        V2AcceptKeyPackagePublishInput {
            owner_did: owner.did.clone(),
            owner_device_id: device.device_id.clone(),
            operation_id: rotated.meta.operation_id.clone(),
            result: V2PublishKeyPackageResult {
                published: true,
                owner_did: owner.did.clone(),
                owner_device_id: device.device_id.clone(),
                key_package_id: rotated.body.group_key_package.key_package_id.clone(),
                published_at: "2026-08-21T00:00:01Z".to_owned(),
            },
            request_id: "req-publish-ambiguous-wire-id".to_owned(),
        },
    )
    .expect_err("wire IDs must resolve to exactly one family");
    assert_eq!(ambiguous.code, "group.e2ee.commit_invalid");
    conn.execute(
        "DELETE FROM group_mls_operations WHERE operation_id = 'ambiguous-family'",
        [],
    )
    .unwrap();

    let response_json: String = conn
        .query_row(
            "SELECT response_json FROM group_mls_operations WHERE operation_id = ?1",
            params![operation_id],
            |row| row.get(0),
        )
        .unwrap();
    let mut preparing: Value = serde_json::from_str(&response_json).unwrap();
    preparing.as_object_mut().unwrap().remove("body");
    preparing.as_object_mut().unwrap().remove("accepted_result");
    conn.execute(
        "UPDATE group_mls_operations SET response_json = ?2, status = 'preparing'\n         WHERE operation_id = ?1",
        params![operation_id, preparing.to_string()],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM group_mls_key_packages WHERE key_package_id = ?1",
        params![rotated.body.group_key_package.key_package_id],
    )
    .unwrap();
    conn.execute("DELETE FROM openmls_key_packages", [])
        .unwrap();
    drop(conn);
    drop(rotated_store);

    retry.now = "2026-08-22T00:00:00Z".to_owned();
    retry.request_id = "req-publish-rotate-crash-resume".to_owned();
    let recovered_store = store(directory.path(), &owner.did, &device.device_id);
    let recovered = prepare_or_resume_key_package_publish_v2(
        &recovered_store,
        retry.clone(),
        &owner.document,
        &signing_key(device),
    )
    .expect("preparing journal after the atomic switch regenerates its current attempt");
    assert_eq!(recovered.meta.operation_id, rotated.meta.operation_id);
    assert_eq!(
        recovered.body.group_key_package.key_package_id,
        rotated.body.group_key_package.key_package_id
    );

    let conn = Connection::open(recovered_store.state_db_path()).unwrap();
    let response_json: String = conn
        .query_row(
            "SELECT response_json FROM group_mls_operations WHERE operation_id = ?1",
            params![operation_id],
            |row| row.get(0),
        )
        .unwrap();
    let mut collision: Value = serde_json::from_str(&response_json).unwrap();
    collision["superseded_attempts"][0]["operation_id"] =
        Value::String(recovered.meta.operation_id.clone());
    conn.execute(
        "UPDATE group_mls_operations SET response_json = ?2 WHERE operation_id = ?1",
        params![operation_id, collision.to_string()],
    )
    .unwrap();
    drop(conn);
    drop(recovered_store);
    retry.request_id = "req-publish-rotate-collision".to_owned();
    let collision_store = store(directory.path(), &owner.did, &device.device_id);
    let error = accept_key_package_publish_v2(
        &collision_store,
        V2AcceptKeyPackagePublishInput {
            owner_did: owner.did.clone(),
            owner_device_id: device.device_id.clone(),
            operation_id: recovered.meta.operation_id.clone(),
            result: V2PublishKeyPackageResult {
                published: true,
                owner_did: owner.did.clone(),
                owner_device_id: device.device_id.clone(),
                key_package_id: recovered.body.group_key_package.key_package_id.clone(),
                published_at: "2026-08-22T00:00:00Z".to_owned(),
            },
            request_id: "req-publish-accept-collision".to_owned(),
        },
    )
    .expect_err("acceptance must reject a history/current wire ID collision");
    assert_eq!(error.code, "group.e2ee.commit_invalid");
    let error = prepare_or_resume_key_package_publish_v2(
        &collision_store,
        retry,
        &owner.document,
        &signing_key(device),
    )
    .expect_err("history/current wire ID collision must fail closed");
    assert_eq!(error.code, "group.e2ee.commit_invalid");
}

#[test]
fn unscoped_publish_acceptance_still_binds_the_exact_owner_device() {
    let directory = TestDirectory::new();
    let owner = make_did_fixture("publish-unscoped-owner", &["publish-owner-device"]);
    let device = &owner.devices[0];
    let operation_id = "join-kp-unscoped-owner-operation";
    let key_package_id = "join-kp-unscoped-owner-package";
    let mut meta = service_meta(&owner.did, &device.device_id, operation_id);
    meta.security_profile = GROUP_E2EE_TRANSPORT_PROFILE_V2.to_owned();
    meta.created_at = None;
    let input = V2PrepareKeyPackagePublishInput {
        meta,
        owner_did: owner.did.clone(),
        owner_device_id: device.device_id.clone(),
        verification_method: device.signing_key_id.clone(),
        key_package_id: key_package_id.to_owned(),
        issued_at: ISSUED_AT.to_owned(),
        expires_at: EXPIRES_AT.to_owned(),
        now: NOW.to_owned(),
        draft_extension_negotiated: true,
        request_id: "req-publish-unscoped-prepare".to_owned(),
    };
    let store = CompatDataDirStore::new(directory.path().join("compat-store"));
    prepare_or_resume_key_package_publish_v2(
        &store,
        input.clone(),
        &owner.document,
        &signing_key(device),
    )
    .expect("prepare publish in an unscoped compatibility store");

    let result = V2PublishKeyPackageResult {
        published: true,
        owner_did: owner.did.clone(),
        owner_device_id: device.device_id.clone(),
        key_package_id: key_package_id.to_owned(),
        published_at: NOW.to_owned(),
    };
    let error = accept_key_package_publish_v2(
        &store,
        V2AcceptKeyPackagePublishInput {
            owner_did: "did:wba:p6-runtime.example:users:other".to_owned(),
            owner_device_id: "other-device".to_owned(),
            operation_id: operation_id.to_owned(),
            result,
            request_id: "req-publish-unscoped-wrong-owner".to_owned(),
        },
    )
    .expect_err("unscoped stores must not weaken exact owner/device binding");
    assert_eq!(error.code, "group.e2ee.did_binding_invalid");

    let unchanged = prepare_or_resume_key_package_publish_v2(
        &store,
        V2PrepareKeyPackagePublishInput {
            request_id: "req-publish-unscoped-after-rejection".to_owned(),
            ..input
        },
        &owner.document,
        &signing_key(device),
    )
    .expect("rejected acceptance leaves the prepared journal unchanged");
    assert_eq!(unchanged.status, V2KeyPackagePublishStatus::Prepared);
    assert!(unchanged.accepted_result.is_none());
}

#[test]
fn key_package_publish_preparing_recovery_removes_orphan_private_bundles() {
    let directory = TestDirectory::new();
    let owner = make_did_fixture("publish-preparing-crash", &["publish-crash-device"]);
    let device = &owner.devices[0];
    let operation_id = "join-kp-preparing-crash-operation";
    let key_package_id = "join-kp-preparing-crash-package";
    let mut meta = service_meta(&owner.did, &device.device_id, operation_id);
    meta.security_profile = GROUP_E2EE_TRANSPORT_PROFILE_V2.to_owned();
    meta.created_at = None;
    let input = V2PrepareKeyPackagePublishInput {
        meta,
        owner_did: owner.did.clone(),
        owner_device_id: device.device_id.clone(),
        verification_method: device.signing_key_id.clone(),
        key_package_id: key_package_id.to_owned(),
        issued_at: ISSUED_AT.to_owned(),
        expires_at: EXPIRES_AT.to_owned(),
        now: NOW.to_owned(),
        draft_extension_negotiated: true,
        request_id: "req-publish-before-simulated-crash".to_owned(),
    };
    let first_store = store(directory.path(), &owner.did, &device.device_id);
    prepare_or_resume_key_package_publish_v2(
        &first_store,
        input.clone(),
        &owner.document,
        &signing_key(device),
    )
    .expect("prepare initial KeyPackage");

    let conn = Connection::open(first_store.state_db_path()).expect("open SDK state database");
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM openmls_key_packages", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    assert_eq!(
        conn.execute(
            "DELETE FROM group_mls_key_packages\n             WHERE owner_identity_id = ?1 AND device_id = ?2 AND key_package_id = ?3",
            params![
                format!("identity-{}", device.device_id),
                device.device_id,
                key_package_id
            ],
        )
        .unwrap(),
        1
    );
    let preparing_journal = json!({
        "journal_version": "v1",
        "meta": input.meta,
    });
    assert_eq!(
        conn.execute(
            "UPDATE group_mls_operations\n             SET response_json = ?4, status = 'preparing'\n             WHERE owner_identity_id = ?1 AND device_id = ?2 AND operation_id = ?3",
            params![
                format!("identity-{}", device.device_id),
                device.device_id,
                operation_id,
                preparing_journal.to_string()
            ],
        )
        .unwrap(),
        1
    );
    drop(conn);
    drop(first_store);

    let mut colliding_family = input.clone();
    colliding_family.meta.operation_id = "join-kp-legacy-colliding-operation".to_owned();
    colliding_family.request_id = "req-publish-legacy-colliding-family".to_owned();
    let blocked_store = store(directory.path(), &owner.did, &device.device_id);
    let error = prepare_or_resume_key_package_publish_v2(
        &blocked_store,
        colliding_family,
        &owner.document,
        &signing_key(device),
    )
    .expect_err("an unknown legacy preparing key binding blocks a new family");
    assert_eq!(error.code, "group.e2ee.state_not_ready");
    let conn = Connection::open(blocked_store.state_db_path()).expect("inspect blocked family");
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM group_mls_operations", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1,
        "the rejected family must not create a second WAL row"
    );
    drop(conn);
    drop(blocked_store);

    let mut retry_input = input;
    retry_input.request_id = "req-publish-after-simulated-crash".to_owned();
    let restarted_store = store(directory.path(), &owner.did, &device.device_id);
    let resumed = prepare_or_resume_key_package_publish_v2(
        &restarted_store,
        retry_input,
        &owner.document,
        &signing_key(device),
    )
    .expect("remove orphan private bundle and prepare one replacement");
    assert_eq!(resumed.status, V2KeyPackagePublishStatus::Prepared);
    let conn = Connection::open(restarted_store.state_db_path()).expect("reopen SDK state");
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM openmls_key_packages", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM group_mls_key_packages\n             WHERE owner_identity_id = ?1 AND device_id = ?2 AND key_package_id = ?3",
            params![
                format!("identity-{}", device.device_id),
                device.device_id,
                key_package_id
            ],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        1
    );
    let response_json: String = conn
        .query_row(
            "SELECT response_json FROM group_mls_operations WHERE operation_id = ?1",
            params![operation_id],
            |row| row.get(0),
        )
        .unwrap();
    let recovered_journal: Value = serde_json::from_str(&response_json).unwrap();
    assert_eq!(
        recovered_journal["base_key_package_id"],
        json!(key_package_id)
    );
    assert!(recovered_journal["body"].is_object());
}

#[test]
fn legacy_publish_recovery_serializes_conflicting_family_ownership() {
    let directory = TestDirectory::new();
    let owner = make_did_fixture("legacy-family-recovery", &["legacy-family-device"]);
    let device = &owner.devices[0];
    let shared_key_package_id = "legacy-shared-package";
    let make_input = |operation_id: &str, request_id: &str| {
        let mut meta = service_meta(&owner.did, &device.device_id, operation_id);
        meta.security_profile = GROUP_E2EE_TRANSPORT_PROFILE_V2.to_owned();
        meta.created_at = None;
        V2PrepareKeyPackagePublishInput {
            meta,
            owner_did: owner.did.clone(),
            owner_device_id: device.device_id.clone(),
            verification_method: device.signing_key_id.clone(),
            key_package_id: shared_key_package_id.to_owned(),
            issued_at: ISSUED_AT.to_owned(),
            expires_at: EXPIRES_AT.to_owned(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            request_id: request_id.to_owned(),
        }
    };
    let owner_input = make_input("legacy-owner-operation", "req-legacy-owner-prepare");
    let loser_input = make_input("legacy-loser-operation", "req-legacy-loser-probe");

    let probe_store = store(
        &directory.path().join("probe"),
        &owner.did,
        &device.device_id,
    );
    let loser_probe = prepare_or_resume_key_package_publish_v2(
        &probe_store,
        loser_input.clone(),
        &owner.document,
        &signing_key(device),
    )
    .unwrap();
    let conn = Connection::open(probe_store.state_db_path()).unwrap();
    let loser_digest: String = conn
        .query_row(
            "SELECT input_digest FROM group_mls_operations WHERE operation_id = ?1",
            params![loser_input.meta.operation_id],
            |row| row.get(0),
        )
        .unwrap();
    drop(conn);
    let loser_legacy_json = json!({
        "journal_version": "v1",
        "meta": loser_probe.meta,
    })
    .to_string();
    let insert_legacy_loser = |conn: &Connection| {
        conn.execute(
            "INSERT INTO group_mls_operations(\n                 owner_identity_id, device_id, operation_id, command, input_digest,\n                 response_json, status\n             ) VALUES (?1, ?2, ?3, 'group.e2ee.publish-key-package.v2', ?4, ?5, 'preparing')",
            params![
                format!("identity-{}", device.device_id),
                device.device_id,
                loser_input.meta.operation_id,
                loser_digest,
                loser_legacy_json,
            ],
        )
        .unwrap();
    };

    let two_unknown_store = store(
        &directory.path().join("two-unknown"),
        &owner.did,
        &device.device_id,
    );
    let owner_prepared = prepare_or_resume_key_package_publish_v2(
        &two_unknown_store,
        owner_input.clone(),
        &owner.document,
        &signing_key(device),
    )
    .unwrap();
    let conn = Connection::open(two_unknown_store.state_db_path()).unwrap();
    let owner_legacy_json = json!({
        "journal_version": "v1",
        "meta": owner_prepared.meta,
    })
    .to_string();
    conn.execute(
        "UPDATE group_mls_operations SET response_json = ?2, status = 'preparing'\n         WHERE operation_id = ?1",
        params![owner_input.meta.operation_id, owner_legacy_json],
    )
    .unwrap();
    insert_legacy_loser(&conn);
    drop(conn);

    let mut owner_retry = owner_input.clone();
    owner_retry.request_id = "req-legacy-owner-recover".to_owned();
    let recovered_owner = prepare_or_resume_key_package_publish_v2(
        &two_unknown_store,
        owner_retry,
        &owner.document,
        &signing_key(device),
    )
    .expect("the first serialized valid legacy retry claims and recovers the package");
    let mut loser_retry = loser_input.clone();
    loser_retry.request_id = "req-legacy-loser-after-owner".to_owned();
    let error = prepare_or_resume_key_package_publish_v2(
        &two_unknown_store,
        loser_retry,
        &owner.document,
        &signing_key(device),
    )
    .expect_err("the second conflicting legacy family cannot bind the same package");
    assert_eq!(error.code, "group.e2ee.commit_invalid");
    let conn = Connection::open(two_unknown_store.state_db_path()).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT status FROM group_mls_operations WHERE operation_id = ?1",
            params![loser_input.meta.operation_id],
            |row| row.get::<_, String>(0),
        )
        .unwrap(),
        "superseded"
    );
    let owner_journal: String = conn
        .query_row(
            "SELECT response_json FROM group_mls_operations WHERE operation_id = ?1",
            params![owner_input.meta.operation_id],
            |row| row.get(0),
        )
        .unwrap();
    let loser_journal: String = conn
        .query_row(
            "SELECT response_json FROM group_mls_operations WHERE operation_id = ?1",
            params![loser_input.meta.operation_id],
            |row| row.get(0),
        )
        .unwrap();
    assert!(serde_json::from_str::<Value>(&owner_journal).unwrap()["body"].is_object());
    let loser_journal: Value = serde_json::from_str(&loser_journal).unwrap();
    assert!(loser_journal["body"].is_null());
    assert_eq!(
        loser_journal["base_key_package_id"],
        json!(shared_key_package_id)
    );
    assert_eq!(
        loser_journal["base_operation_id"],
        json!(loser_input.meta.operation_id)
    );
    assert!(loser_journal["family_digest"]
        .as_str()
        .is_some_and(|digest| !digest.is_empty()));
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM group_mls_key_packages", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM openmls_key_packages", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    drop(conn);
    accept_key_package_publish_v2(
        &two_unknown_store,
        V2AcceptKeyPackagePublishInput {
            owner_did: owner.did.clone(),
            owner_device_id: device.device_id.clone(),
            operation_id: recovered_owner.meta.operation_id.clone(),
            result: V2PublishKeyPackageResult {
                published: true,
                owner_did: owner.did.clone(),
                owner_device_id: device.device_id.clone(),
                key_package_id: recovered_owner
                    .body
                    .group_key_package
                    .key_package_id
                    .clone(),
                published_at: NOW.to_owned(),
            },
            request_id: "req-legacy-owner-accept".to_owned(),
        },
    )
    .expect("the claimed owner family remains exactly acceptable");

    let completed_store = store(
        &directory.path().join("completed-owner"),
        &owner.did,
        &device.device_id,
    );
    let completed = prepare_or_resume_key_package_publish_v2(
        &completed_store,
        owner_input.clone(),
        &owner.document,
        &signing_key(device),
    )
    .unwrap();
    let completed_result = V2PublishKeyPackageResult {
        published: true,
        owner_did: owner.did.clone(),
        owner_device_id: device.device_id.clone(),
        key_package_id: completed.body.group_key_package.key_package_id.clone(),
        published_at: NOW.to_owned(),
    };
    accept_key_package_publish_v2(
        &completed_store,
        V2AcceptKeyPackagePublishInput {
            owner_did: owner.did.clone(),
            owner_device_id: device.device_id.clone(),
            operation_id: completed.meta.operation_id.clone(),
            result: completed_result.clone(),
            request_id: "req-completed-owner-accept".to_owned(),
        },
    )
    .unwrap();
    let conn = Connection::open(completed_store.state_db_path()).unwrap();
    insert_legacy_loser(&conn);
    conn.execute(
        "UPDATE group_mls_operations SET status = 'superseded' WHERE operation_id = ?1",
        params![loser_input.meta.operation_id],
    )
    .unwrap();
    drop(conn);
    let unrelated_before_hydration = make_input(
        "unrelated-before-terminal-hydration",
        "req-unrelated-before-terminal-hydration",
    );
    let mut unrelated_before_hydration = unrelated_before_hydration;
    unrelated_before_hydration.key_package_id = "unrelated-before-package".to_owned();
    let error = prepare_or_resume_key_package_publish_v2(
        &completed_store,
        unrelated_before_hydration,
        &owner.document,
        &signing_key(device),
    )
    .expect_err("an unresolved superseded legacy reservation fails closed");
    assert_eq!(error.code, "group.e2ee.state_not_ready");

    let mut loser_again = loser_input.clone();
    loser_again.request_id = "req-legacy-loser-against-completed".to_owned();
    let error = prepare_or_resume_key_package_publish_v2(
        &completed_store,
        loser_again,
        &owner.document,
        &signing_key(device),
    )
    .expect_err("the original base retry hydrates but cannot revive a superseded family");
    assert_eq!(error.code, "group.e2ee.state_not_ready");
    let conn = Connection::open(completed_store.state_db_path()).unwrap();
    let (loser_status, loser_response): (String, String) = conn
        .query_row(
            "SELECT status, response_json FROM group_mls_operations WHERE operation_id = ?1",
            params![loser_input.meta.operation_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(loser_status, "superseded");
    let loser_response: Value = serde_json::from_str(&loser_response).unwrap();
    assert_eq!(
        loser_response["base_key_package_id"],
        json!(shared_key_package_id)
    );
    assert_eq!(
        loser_response["base_operation_id"],
        json!(loser_input.meta.operation_id)
    );
    assert!(loser_response["family_digest"]
        .as_str()
        .is_some_and(|digest| !digest.is_empty()));
    assert!(loser_response["body"].is_null());
    drop(conn);
    let mut unrelated_after_hydration = make_input(
        "unrelated-after-terminal-hydration",
        "req-unrelated-after-terminal-hydration",
    );
    unrelated_after_hydration.key_package_id = "unrelated-after-package".to_owned();
    prepare_or_resume_key_package_publish_v2(
        &completed_store,
        unrelated_after_hydration,
        &owner.document,
        &signing_key(device),
    )
    .expect("hydrating the terminal reservation unblocks unrelated families");
    let mut completed_retry = owner_input;
    completed_retry.request_id = "req-completed-owner-retry".to_owned();
    let cached = prepare_or_resume_key_package_publish_v2(
        &completed_store,
        completed_retry,
        &owner.document,
        &signing_key(device),
    )
    .expect("the completed owner family remains intact");
    assert_eq!(cached.accepted_result, Some(completed_result));
}

#[test]
fn key_package_publish_validation_failure_does_not_retain_private_orphan() {
    let directory = TestDirectory::new();
    let owner = make_did_fixture("publish-validation-cleanup", &["publish-invalid-device"]);
    let device = &owner.devices[0];
    let operation_id = "join-kp-validation-cleanup-operation";
    let mut meta = service_meta(&owner.did, &device.device_id, operation_id);
    meta.security_profile = GROUP_E2EE_TRANSPORT_PROFILE_V2.to_owned();
    meta.created_at = None;
    let mut input = V2PrepareKeyPackagePublishInput {
        meta,
        owner_did: owner.did.clone(),
        owner_device_id: device.device_id.clone(),
        verification_method: device.signing_key_id.clone(),
        key_package_id: "join-kp-validation-cleanup-package".to_owned(),
        issued_at: ISSUED_AT.to_owned(),
        expires_at: EXPIRES_AT.to_owned(),
        now: EXPIRES_AT.to_owned(),
        draft_extension_negotiated: true,
        request_id: "req-publish-invalid-time".to_owned(),
    };
    let first_store = store(directory.path(), &owner.did, &device.device_id);
    assert!(prepare_or_resume_key_package_publish_v2(
        &first_store,
        input.clone(),
        &owner.document,
        &signing_key(device),
    )
    .is_err());
    let conn = Connection::open(first_store.state_db_path()).expect("open SDK state database");
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM openmls_key_packages", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        0
    );
    drop(conn);
    drop(first_store);

    input.now = NOW.to_owned();
    input.request_id = "req-publish-valid-time-retry".to_owned();
    let retry_store = store(directory.path(), &owner.did, &device.device_id);
    prepare_or_resume_key_package_publish_v2(
        &retry_store,
        input,
        &owner.document,
        &signing_key(device),
    )
    .expect("retry after validation failure creates exactly one private bundle");
    let conn = Connection::open(retry_store.state_db_path()).expect("reopen SDK state");
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM openmls_key_packages", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
}

#[test]
fn concurrent_expired_publish_rotation_converges_on_one_attempt() {
    let directory = TestDirectory::new();
    let owner = make_did_fixture("publish-concurrent-rotate", &["publish-rotate-device"]);
    let device = &owner.devices[0];
    let operation_id = "join-kp-concurrent-rotate-operation";
    let key_package_id = "join-kp-concurrent-rotate-package";
    let mut meta = service_meta(&owner.did, &device.device_id, operation_id);
    meta.security_profile = GROUP_E2EE_TRANSPORT_PROFILE_V2.to_owned();
    meta.created_at = None;
    let input = V2PrepareKeyPackagePublishInput {
        meta,
        owner_did: owner.did.clone(),
        owner_device_id: device.device_id.clone(),
        verification_method: device.signing_key_id.clone(),
        key_package_id: key_package_id.to_owned(),
        issued_at: ISSUED_AT.to_owned(),
        expires_at: EXPIRES_AT.to_owned(),
        now: NOW.to_owned(),
        draft_extension_negotiated: true,
        request_id: "req-publish-concurrent-rotate-initial".to_owned(),
    };
    let initial_store = store(directory.path(), &owner.did, &device.device_id);
    prepare_or_resume_key_package_publish_v2(
        &initial_store,
        input.clone(),
        &owner.document,
        &signing_key(device),
    )
    .unwrap();
    drop(initial_store);

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for index in 0..2 {
        let root = directory.path().to_path_buf();
        let did = owner.did.clone();
        let device_id = device.device_id.clone();
        let document = owner.document.clone();
        let key = signing_key(device);
        let barrier = barrier.clone();
        let mut retry = input.clone();
        retry.issued_at = "2026-08-21T00:00:00Z".to_owned();
        retry.expires_at = "2026-09-21T00:00:00Z".to_owned();
        retry.now = "2026-08-21T00:00:00Z".to_owned();
        retry.request_id = format!("req-publish-concurrent-rotate-{index}");
        handles.push(std::thread::spawn(move || {
            let store = store(&root, &did, &device_id);
            barrier.wait();
            for _ in 0..100 {
                match prepare_or_resume_key_package_publish_v2(
                    &store,
                    retry.clone(),
                    &document,
                    &key,
                ) {
                    Ok(output) => return output,
                    Err(error) if error.code == "state_locked" => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(error) => panic!("unexpected concurrent rotate error: {error:?}"),
                }
            }
            panic!("concurrent rotate did not acquire the device store lock")
        }));
    }
    let first = handles.remove(0).join().expect("first rotate thread");
    let second = handles.remove(0).join().expect("second rotate thread");
    assert_eq!(first, second);
    assert_ne!(first.meta.operation_id, operation_id);
    assert_ne!(first.body.group_key_package.key_package_id, key_package_id);

    let store = store(directory.path(), &owner.did, &device.device_id);
    let conn = Connection::open(store.state_db_path()).unwrap();
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM group_mls_operations", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM group_mls_key_packages", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM openmls_key_packages", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
}

#[test]
fn concurrent_equivalent_key_package_acceptances_share_first_cached_result() {
    let directory = TestDirectory::new();
    let owner = make_did_fixture("publish-concurrent-accept", &["publish-concurrent-device"]);
    let device = &owner.devices[0];
    let operation_id = "join-kp-concurrent-accept-operation";
    let key_package_id = "join-kp-concurrent-accept-package";
    let mut meta = service_meta(&owner.did, &device.device_id, operation_id);
    meta.security_profile = GROUP_E2EE_TRANSPORT_PROFILE_V2.to_owned();
    meta.created_at = None;
    let initial_store = store(directory.path(), &owner.did, &device.device_id);
    prepare_or_resume_key_package_publish_v2(
        &initial_store,
        V2PrepareKeyPackagePublishInput {
            meta,
            owner_did: owner.did.clone(),
            owner_device_id: device.device_id.clone(),
            verification_method: device.signing_key_id.clone(),
            key_package_id: key_package_id.to_owned(),
            issued_at: ISSUED_AT.to_owned(),
            expires_at: EXPIRES_AT.to_owned(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            request_id: "req-publish-concurrent-prepare".to_owned(),
        },
        &owner.document,
        &signing_key(device),
    )
    .expect("prepare concurrent acceptance fixture");
    drop(initial_store);

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut handles = Vec::new();
    for (index, published_at) in [NOW, "2026-07-20T00:00:01Z"].into_iter().enumerate() {
        let root = directory.path().to_path_buf();
        let did = owner.did.clone();
        let device_id = device.device_id.clone();
        let barrier = barrier.clone();
        handles.push(std::thread::spawn(move || {
            let store = store(&root, &did, &device_id);
            let input = V2AcceptKeyPackagePublishInput {
                owner_did: did.clone(),
                owner_device_id: device_id.clone(),
                operation_id: operation_id.to_owned(),
                result: V2PublishKeyPackageResult {
                    published: true,
                    owner_did: did,
                    owner_device_id: device_id,
                    key_package_id: key_package_id.to_owned(),
                    published_at: published_at.to_owned(),
                },
                request_id: format!("req-publish-concurrent-accept-{index}"),
            };
            barrier.wait();
            for _ in 0..100 {
                match accept_key_package_publish_v2(&store, input.clone()) {
                    Ok(output) => return output,
                    Err(error) if error.code == "state_locked" => {
                        std::thread::sleep(std::time::Duration::from_millis(2));
                    }
                    Err(error) => panic!("unexpected concurrent accept error: {}", error.code),
                }
            }
            panic!("concurrent accept did not acquire the device store lock")
        }));
    }
    let first = handles.remove(0).join().expect("first accept thread");
    let second = handles.remove(0).join().expect("second accept thread");
    assert_eq!(first, second);
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
    let mut a1_publish_meta = service_meta(&alice.did, &a1_device.device_id, "op-publish-a1");
    a1_publish_meta.security_profile = GROUP_E2EE_TRANSPORT_PROFILE_V2.to_owned();
    a1_publish_meta.created_at = None;
    let a1_publish_input = V2PrepareKeyPackagePublishInput {
        meta: a1_publish_meta,
        owner_did: alice.did.clone(),
        owner_device_id: a1_device.device_id.clone(),
        verification_method: a1_device.signing_key_id.clone(),
        key_package_id: "kp-a1".to_owned(),
        issued_at: ISSUED_AT.to_owned(),
        expires_at: EXPIRES_AT.to_owned(),
        now: NOW.to_owned(),
        draft_extension_negotiated: true,
        request_id: "req-publish-a1".to_owned(),
    };
    let a1_prepared = prepare_or_resume_key_package_publish_v2(
        &a1_store,
        a1_publish_input.clone(),
        &alice.document,
        &signing_key(a1_device),
    )
    .expect("prepare A1 KeyPackage without Host acceptance");
    let a1_package = a1_prepared.body.group_key_package;
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
    let conn = Connection::open(a1_store.state_db_path()).expect("inspect consumed A1 package");
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM group_mls_key_packages", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1,
        "Welcome keeps the public package row used by the prepared publish WAL"
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM openmls_key_packages", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        0,
        "OpenMLS consumes the private KeyPackage bundle while processing Welcome"
    );
    assert_eq!(
        conn.query_row(
            "SELECT status FROM group_mls_operations WHERE operation_id = 'op-publish-a1'",
            [],
            |row| row.get::<_, String>(0),
        )
        .unwrap(),
        "prepared"
    );
    drop(conn);

    let mut a1_rotation_input = a1_publish_input.clone();
    a1_rotation_input.issued_at = "2026-08-20T00:00:00Z".to_owned();
    a1_rotation_input.expires_at = "2026-09-20T00:00:00Z".to_owned();
    a1_rotation_input.now = "2026-08-20T00:00:00Z".to_owned();
    a1_rotation_input.request_id = "req-publish-a1-after-welcome-ttl".to_owned();
    let a1_rotated = prepare_or_resume_key_package_publish_v2(
        &a1_store,
        a1_rotation_input,
        &alice.document,
        &signing_key(a1_device),
    )
    .expect("consumed private bundle does not wedge an expired prepared publish");
    assert_ne!(a1_rotated.meta.operation_id, "op-publish-a1");
    assert_ne!(
        a1_rotated.body.group_key_package.key_package_id,
        a1_package.key_package_id
    );
    let conn = Connection::open(a1_store.state_db_path()).expect("inspect rotated A1 package");
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM group_mls_key_packages", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM openmls_key_packages", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap(),
        1
    );
    let response_json: String = conn
        .query_row(
            "SELECT response_json FROM group_mls_operations WHERE operation_id = 'op-publish-a1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let journal: Value = serde_json::from_str(&response_json).unwrap();
    assert_eq!(journal["generation"], json!(1));
    assert_eq!(
        journal["superseded_attempts"]
            .as_array()
            .expect("superseded attempt history")
            .len(),
        1
    );
    drop(conn);
    let accepted_a1_rotation = accept_key_package_publish_v2(
        &a1_store,
        V2AcceptKeyPackagePublishInput {
            owner_did: alice.did.clone(),
            owner_device_id: a1_device.device_id.clone(),
            operation_id: a1_rotated.meta.operation_id.clone(),
            result: V2PublishKeyPackageResult {
                published: true,
                owner_did: alice.did.clone(),
                owner_device_id: a1_device.device_id.clone(),
                key_package_id: a1_rotated.body.group_key_package.key_package_id.clone(),
                published_at: "2026-08-20T00:00:01Z".to_owned(),
            },
            request_id: "req-accept-a1-after-welcome-ttl".to_owned(),
        },
    )
    .expect("rotated post-Welcome package remains acceptable");
    assert_eq!(
        accepted_a1_rotation.status,
        V2KeyPackagePublishStatus::Accepted
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
    let raw_private_message = URL_SAFE_NO_PAD
        .decode(&history.private_message_b64u)
        .expect("decode raw MLS PrivateMessage");
    PrivateMessageIn::tls_deserialize_exact(raw_private_message.clone())
        .expect("P6 private_message_b64u is an exact raw MLS PrivateMessage");
    assert!(MlsMessageIn::tls_deserialize_exact(raw_private_message).is_err());
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

    let alice_after_a2_revoke = document_without_manifest_device(&alice, &a2_device.device_id);

    let wrong_endpoint_error = remove_member_prepare_v2(
        &owner_store,
        V2RemoveMemberInput {
            meta: control_meta(
                &owner.did,
                &owner_device.device_id,
                "op-remove-wrong-endpoint",
            ),
            group_state_ref: state_ref(4),
            member_did: alice.did.clone(),
            member_device_id: "alice-not-a-current-leaf".to_owned(),
            member_did_document: alice_after_a2_revoke.clone(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            pending_commit_id: "pending-remove-wrong-endpoint".to_owned(),
            request_id: "req-remove-wrong-endpoint".to_owned(),
        },
    )
    .expect_err("Remove cannot substitute another or unknown endpoint");
    assert_eq!(wrong_endpoint_error.code, "group.e2ee.did_binding_invalid");
    assert!(list_local_group_member_endpoints_v2(
        &owner_store,
        V2InspectLocalGroupInput {
            owner_did: owner.did.clone(),
            owner_device_id: owner_device.device_id.clone(),
            group_did: GROUP_DID.to_owned(),
            request_id: "req-list-after-wrong-remove".to_owned(),
        },
    )
    .expect("failed Remove leaves the accepted tree unchanged")
    .member_endpoints
    .iter()
    .any(|endpoint| endpoint.member_device_id == a2_device.device_id));

    let remove_meta = control_meta(&owner.did, &owner_device.device_id, "op-remove-a2");
    let remove_a2 = remove_member_prepare_v2(
        &owner_store,
        V2RemoveMemberInput {
            meta: remove_meta.clone(),
            group_state_ref: state_ref(4),
            member_did: alice.did.clone(),
            member_device_id: a2_device.device_id.clone(),
            member_did_document: alice_after_a2_revoke.clone(),
            now: NOW.to_owned(),
            draft_extension_negotiated: true,
            pending_commit_id: "pending-remove-a2".to_owned(),
            request_id: "req-remove-a2".to_owned(),
        },
    )
    .expect("prepare exact A2 Remove after A2 loses current Manifest eligibility");
    let restarted_remove_owner_store = store(directory.path(), &owner.did, &owner_device.device_id);
    let remove_after_restart = reconcile_pending_v2(
        &restarted_remove_owner_store,
        V2ReconcilePendingInput {
            request_id: "req-reconcile-prepared-remove-after-restart".to_owned(),
        },
    )
    .expect("prepared exact-device Remove survives restart");
    assert_eq!(remove_after_restart.pending_commits.len(), 1);
    assert_eq!(remove_after_restart.pending_commits[0].status, "prepared");
    assert_eq!(
        remove_after_restart.pending_commits[0].pending_commit_id,
        remove_a2.pending_commit_id
    );
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
                member_did_document: alice_after_a2_revoke.clone(),
                now: NOW.to_owned(),
                draft_extension_negotiated: true,
                request_id: format!("req-commit-remove-a2-{}", device.device_id),
            },
        )
        .expect("existing Leaf processes exact A2 Remove");
    }
    finalize_commit_v2(
        &restarted_remove_owner_store,
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
    let remove_echo_output =
        process_notice_v2(&restarted_remove_owner_store, remove_a2_self_echo.clone())
            .expect("finalized Remove actor accepts its exact Commit echo");
    assert_eq!(
        remove_echo_output.source_operation_id.as_deref(),
        Some("op-remove-a2")
    );
    assert_eq!(remove_echo_output.from_epoch, "2");
    assert_eq!(remove_echo_output.epoch, "3");
    let mut remove_a2_self_echo_replay = remove_a2_self_echo;
    remove_a2_self_echo_replay.request_id = "req-notice-remove-a2-owner-echo-replay".to_owned();
    assert_eq!(
        process_notice_v2(
            &store(directory.path(), &owner.did, &owner_device.device_id),
            remove_a2_self_echo_replay,
        )
        .expect("exact Remove actor echo replays after restart"),
        remove_echo_output
    );
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
