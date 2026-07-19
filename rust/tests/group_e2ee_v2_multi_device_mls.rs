#![cfg(feature = "mls")]

use std::collections::BTreeSet;

use anp::authentication::{
    create_did_wba_document, validate_device_manifest, DidDocumentOptions, DidProfile,
};
use anp::group_e2ee::{
    generate_did_wba_binding_v2, validate_group_key_package_binding_v2,
    validate_leaf_identity_set_v2, verify_did_wba_binding_v2, V2DidWbaBinding,
    V2DidWbaBindingUnsigned, V2GroupKeyPackage, V2KeyPackageBindingEvidence, V2LeafBindingEvidence,
    V2LeafExtension, V2LeafIdentity, DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2,
    GROUP_E2EE_MTI_SUITE_V2,
};
use anp::proof::{
    generate_w3c_proof, ProofGenerationOptions, CRYPTOSUITE_EDDSA_JCS_2022,
    PROOF_TYPE_DATA_INTEGRITY,
};
use anp::PrivateKeyMaterial;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use openmls::prelude::{
    tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize},
    *,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde_json::{json, Value};

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const NOW: &str = "2026-07-20T00:00:00Z";
const ISSUED_AT: &str = "2026-07-19T00:00:00Z";
const EXPIRES_AT: &str = "2026-08-19T00:00:00Z";

#[derive(Debug)]
struct DidDeviceFixture {
    device_id: String,
    signing_key_id: String,
    signing_private_pem: String,
    e2ee_private_pem: String,
}

#[derive(Debug)]
struct DidFixture {
    did: String,
    document: Value,
    devices: Vec<DidDeviceFixture>,
}

struct MlsDeviceFixture {
    device_id: String,
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    binding: V2DidWbaBinding,
    key_package: KeyPackageBundle,
    wire_key_package: V2GroupKeyPackage,
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

    let mut devices = vec![DidDeviceFixture {
        device_id: device_ids[0].to_owned(),
        signing_key_id: format!("{did}#key-1"),
        signing_private_pem: primary.keys["key-1"].private_key_pem.clone(),
        e2ee_private_pem: primary.keys["key-3"].private_key_pem.clone(),
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
        devices.push(DidDeviceFixture {
            device_id: (*device_id).to_owned(),
            signing_key_id,
            signing_private_pem: scratch.keys["key-1"].private_key_pem.clone(),
            e2ee_private_pem: scratch.keys["key-3"].private_key_pem.clone(),
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
    validate_device_manifest(&document).expect("valid multi-device Manifest");

    DidFixture {
        did,
        document,
        devices,
    }
}

fn binding_extension(binding: &V2DidWbaBinding) -> Extensions<LeafNode> {
    Extensions::single(Extension::Unknown(
        DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2,
        UnknownExtension(serde_json_canonicalizer::to_vec(binding).expect("binding JCS")),
    ))
    .expect("valid leaf binding extension")
}

fn p6_capabilities() -> Capabilities {
    Capabilities::builder()
        .extensions(vec![ExtensionType::Unknown(
            DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2,
        )])
        .credentials(vec![CredentialType::Basic])
        .build()
}

fn make_mls_device(did: &DidFixture, index: usize) -> MlsDeviceFixture {
    let device = &did.devices[index];
    let provider = OpenMlsRustCrypto::default();
    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).expect("MLS signer");
    signer
        .store(provider.storage())
        .expect("store MLS signer in device provider");
    let credential = CredentialWithKey {
        credential: BasicCredential::new(did.did.as_bytes().to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    };
    let device_signing_key =
        PrivateKeyMaterial::from_pem(&device.signing_private_pem).expect("device signing key");
    let binding = generate_did_wba_binding_v2(
        V2DidWbaBindingUnsigned {
            agent_did: did.did.clone(),
            device_id: device.device_id.clone(),
            verification_method: device.signing_key_id.clone(),
            leaf_signature_key_b64u: URL_SAFE_NO_PAD.encode(signer.to_public_vec()),
            issued_at: ISSUED_AT.to_owned(),
            expires_at: EXPIRES_AT.to_owned(),
        },
        &device_signing_key,
        Some(ISSUED_AT.to_owned()),
    )
    .expect("device binding");
    let key_package = KeyPackage::builder()
        .leaf_node_capabilities(p6_capabilities())
        .leaf_node_extensions(binding_extension(&binding))
        .build(CIPHERSUITE, &provider, &signer, credential.clone())
        .expect("P6 v2 KeyPackage");
    let key_package_bytes = key_package
        .key_package()
        .tls_serialize_detached()
        .expect("serialize KeyPackage");
    let wire_key_package = V2GroupKeyPackage {
        key_package_id: format!("kp-{}", device.device_id),
        owner_did: did.did.clone(),
        owner_device_id: device.device_id.clone(),
        suite: GROUP_E2EE_MTI_SUITE_V2.to_owned(),
        mls_key_package_b64u: URL_SAFE_NO_PAD.encode(key_package_bytes),
        did_wba_binding: binding.clone(),
        expires_at: Some(EXPIRES_AT.to_owned()),
    };

    MlsDeviceFixture {
        device_id: device.device_id.clone(),
        provider,
        signer,
        credential,
        binding,
        key_package,
        wire_key_package,
    }
}

fn leaf_evidence(leaf: &LeafNode) -> V2LeafBindingEvidence {
    V2LeafBindingEvidence {
        credential_identity: leaf.credential().serialized_content().to_vec(),
        leaf_signature_key_b64u: URL_SAFE_NO_PAD.encode(leaf.signature_key().as_slice()),
        extensions: leaf
            .extensions()
            .iter()
            .filter_map(|extension| match extension {
                Extension::Unknown(extension_type, value) => Some(V2LeafExtension {
                    extension_type: *extension_type,
                    extension_data: value.0.clone(),
                }),
                _ => None,
            })
            .collect(),
        leaf_capability_extensions: leaf
            .capabilities()
            .extensions()
            .iter()
            .copied()
            .map(u16::from)
            .collect(),
    }
}

fn parse_and_validate_key_package(
    verifier: &OpenMlsRustCrypto,
    package: &V2GroupKeyPackage,
) -> (KeyPackage, V2KeyPackageBindingEvidence) {
    let bytes = URL_SAFE_NO_PAD
        .decode(&package.mls_key_package_b64u)
        .expect("KeyPackage base64url");
    let mut reader = bytes.as_slice();
    let package_in = KeyPackageIn::tls_deserialize(&mut reader).expect("TLS KeyPackage");
    assert!(reader.is_empty(), "no trailing KeyPackage bytes");
    let package = package_in
        .validate(verifier.crypto(), ProtocolVersion::Mls10)
        .expect("cryptographically valid KeyPackage");
    let evidence = V2KeyPackageBindingEvidence {
        tls_serialized_key_package: bytes,
        leaf: leaf_evidence(package.leaf_node()),
    };
    (package, evidence)
}

fn required_extension_ids(group: &MlsGroup) -> Vec<u16> {
    group
        .extensions()
        .required_capabilities()
        .expect("P6 required capabilities")
        .extension_types()
        .iter()
        .copied()
        .map(u16::from)
        .collect()
}

fn merge_commit(group: &mut MlsGroup, provider: &OpenMlsRustCrypto, commit: MlsMessageOut) {
    let commit = MlsMessageIn::tls_deserialize_exact(
        commit.tls_serialize_detached().expect("serialize commit"),
    )
    .expect("deserialize commit")
    .try_into_protocol_message()
    .expect("commit protocol message");
    let processed = group
        .process_message(provider, commit)
        .expect("process commit");
    match processed.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged) => group
            .merge_staged_commit(provider, *staged)
            .expect("merge staged commit"),
        _ => panic!("expected staged commit"),
    }
}

fn decrypt_application(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    message: MlsMessageOut,
) -> Result<Vec<u8>, String> {
    let protocol = MlsMessageIn::tls_deserialize_exact(
        message
            .tls_serialize_detached()
            .map_err(|error| format!("serialize message: {error:?}"))?,
    )
    .map_err(|error| format!("deserialize message: {error:?}"))?
    .try_into_protocol_message()
    .map_err(|error| format!("protocol message: {error:?}"))?;
    let processed = group
        .process_message(provider, protocol)
        .map_err(|error| format!("process application: {error:?}"))?;
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(application) => Ok(application.into_bytes()),
        other => Err(format!("unexpected processed content: {other:?}")),
    }
}

fn business_did_count(group: &MlsGroup) -> usize {
    group
        .members()
        .map(|member| member.credential.serialized_content().to_vec())
        .collect::<BTreeSet<_>>()
        .len()
}

#[test]
fn real_openmls_same_did_multi_device_lifecycle_gate() {
    let owner_did = make_did_fixture("owner", &["owner-device"]);
    let member_did = make_did_fixture("alice", &["alice-a1", "alice-a2"]);
    let owner = make_mls_device(&owner_did, 0);
    let a1 = make_mls_device(&member_did, 0);
    let a2 = make_mls_device(&member_did, 1);

    // Device signing keys, E2EE keys, MLS signing keys, KeyPackages and providers are all
    // device-local; no private material or ratchet state is copied from A1 to A2.
    assert_ne!(
        member_did.devices[0].signing_private_pem,
        member_did.devices[1].signing_private_pem
    );
    assert_ne!(
        member_did.devices[0].e2ee_private_pem,
        member_did.devices[1].e2ee_private_pem
    );
    assert_ne!(a1.signer.to_public_vec(), a2.signer.to_public_vec());
    assert_ne!(
        a1.key_package.key_package().hpke_init_key(),
        a2.key_package.key_package().hpke_init_key()
    );
    assert_ne!(
        a1.wire_key_package.mls_key_package_b64u,
        a2.wire_key_package.mls_key_package_b64u
    );
    assert!(!std::ptr::eq(&a1.provider, &a2.provider));

    let extension_type = ExtensionType::Unknown(DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2);
    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .capabilities(p6_capabilities())
        .with_leaf_node_extensions(binding_extension(&owner.binding))
        .expect("owner binding extension")
        .with_group_context_extensions(
            Extensions::single(Extension::RequiredCapabilities(
                RequiredCapabilitiesExtension::new(&[extension_type], &[], &[]),
            ))
            .expect("P6 required capabilities"),
        )
        .use_ratchet_tree_extension(true)
        .build();
    let join_config = create_config.join_config().clone();
    let mut owner_group = MlsGroup::new_with_group_id(
        &owner.provider,
        &owner.signer,
        &create_config,
        GroupId::from_slice(b"anp-p6-v2-multi-device-gate"),
        owner.credential.clone(),
    )
    .expect("owner creates MLS group");
    let required_extensions = required_extension_ids(&owner_group);
    assert_eq!(
        required_extensions,
        vec![DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2]
    );
    verify_did_wba_binding_v2(
        &owner.binding,
        &owner_did.document,
        &leaf_evidence(owner_group.own_leaf_node().expect("owner leaf")),
        &required_extensions,
        NOW,
        true,
    )
    .expect("owner leaf is bound to an eligible owner device");

    let (a1_package, a1_evidence) =
        parse_and_validate_key_package(&owner.provider, &a1.wire_key_package);
    validate_group_key_package_binding_v2(
        &a1.wire_key_package,
        &member_did.document,
        &a1_evidence,
        &required_extensions,
        NOW,
        true,
    )
    .expect("owner verifies A1 KeyPackage binding");
    let (_add_a1_commit, add_a1_welcome, _) = owner_group
        .add_members(&owner.provider, &owner.signer, &[a1_package])
        .expect("owner adds A1");
    owner_group
        .merge_pending_commit(&owner.provider)
        .expect("owner merges A1 Add");
    let a1_tree = owner_group.export_ratchet_tree();
    let a1_welcome = match add_a1_welcome.body() {
        MlsMessageBodyOut::Welcome(welcome) => welcome.clone(),
        _ => panic!("expected A1 Welcome"),
    };
    let mut a1_group = StagedWelcome::new_from_welcome(
        &a1.provider,
        &join_config,
        a1_welcome,
        Some(a1_tree.into()),
    )
    .expect("A1 stages Welcome")
    .into_group(&a1.provider)
    .expect("A1 joins group");
    assert_eq!(owner_group.epoch().as_u64(), 1);
    assert_eq!(a1_group.epoch().as_u64(), 1);
    assert_eq!(owner_group.members().count(), 2);
    assert_eq!(business_did_count(&owner_group), 2);
    let history = owner_group
        .create_message(&owner.provider, &owner.signer, b"before A2")
        .expect("pre-A2 application");
    assert_eq!(
        decrypt_application(&mut a1_group, &a1.provider, history.clone())
            .expect("A1 decrypts pre-A2 history"),
        b"before A2"
    );

    let (a2_package, a2_evidence) =
        parse_and_validate_key_package(&owner.provider, &a2.wire_key_package);
    validate_group_key_package_binding_v2(
        &a2.wire_key_package,
        &member_did.document,
        &a2_evidence,
        &required_extensions,
        NOW,
        true,
    )
    .expect("eligible owner verifies A2 KeyPackage binding");
    validate_leaf_identity_set_v2(&[
        V2LeafIdentity {
            agent_did: member_did.did.clone(),
            device_id: a1.device_id.clone(),
            leaf_signature_key_b64u: a1_evidence.leaf.leaf_signature_key_b64u.clone(),
        },
        V2LeafIdentity {
            agent_did: member_did.did.clone(),
            device_id: a2.device_id.clone(),
            leaf_signature_key_b64u: a2_evidence.leaf.leaf_signature_key_b64u.clone(),
        },
    ])
    .expect("same DID has two distinct device leaves");

    // A valid A1 binding cannot be substituted around A2's authenticated TLS KeyPackage.
    let mut wrong_device_binding = a2.wire_key_package.clone();
    wrong_device_binding.owner_device_id = a1.device_id.clone();
    wrong_device_binding.did_wba_binding = a1.binding.clone();
    assert!(validate_group_key_package_binding_v2(
        &wrong_device_binding,
        &member_did.document,
        &a2_evidence,
        &required_extensions,
        NOW,
        true,
    )
    .is_err());

    let before_a2_business_members = business_did_count(&owner_group);
    let (add_a2_commit, add_a2_welcome, _) = owner_group
        .add_members(&owner.provider, &owner.signer, &[a2_package.clone()])
        .expect("owner adds A2");
    merge_commit(&mut a1_group, &a1.provider, add_a2_commit.clone());
    owner_group
        .merge_pending_commit(&owner.provider)
        .expect("owner merges A2 Add");
    let a2_tree = owner_group.export_ratchet_tree();
    let a2_welcome = match add_a2_welcome.body() {
        MlsMessageBodyOut::Welcome(welcome) => welcome.clone(),
        _ => panic!("expected A2 Welcome"),
    };

    // A1's independent storage has no private init key for A2's KeyPackage.
    assert!(StagedWelcome::new_from_welcome(
        &a1.provider,
        &join_config,
        a2_welcome.clone(),
        Some(a2_tree.clone().into()),
    )
    .is_err());
    let mut a2_group = StagedWelcome::new_from_welcome(
        &a2.provider,
        &join_config,
        a2_welcome,
        Some(a2_tree.into()),
    )
    .expect("A2 stages its own Welcome")
    .into_group(&a2.provider)
    .expect("A2 joins with its own private state");

    assert_eq!(owner_group.epoch().as_u64(), 2);
    assert_eq!(a1_group.epoch().as_u64(), 2);
    assert_eq!(a2_group.epoch().as_u64(), 2);
    assert_eq!(owner_group.members().count(), 3);
    assert_eq!(
        business_did_count(&owner_group),
        before_a2_business_members,
        "adding A2 adds a cryptographic Leaf, not a P4 business member"
    );
    assert_ne!(a1_group.own_leaf_index(), a2_group.own_leaf_index());

    let after_join = owner_group
        .create_message(&owner.provider, &owner.signer, b"after A2")
        .expect("post-A2 application");
    assert_eq!(
        decrypt_application(&mut a1_group, &a1.provider, after_join.clone())
            .expect("A1 decrypts post-join application"),
        b"after A2"
    );
    assert_eq!(
        decrypt_application(&mut a2_group, &a2.provider, after_join)
            .expect("A2 decrypts post-join application"),
        b"after A2"
    );
    assert!(
        decrypt_application(&mut a2_group, &a2.provider, history).is_err(),
        "A2 must not decrypt an application from before its Welcome epoch"
    );

    // The same KeyPackage cannot add a second leaf or be replayed after consumption.
    assert!(owner_group
        .add_members(&owner.provider, &owner.signer, &[a2_package])
        .is_err());

    let a1_leaf_key = URL_SAFE_NO_PAD
        .decode(&a1_evidence.leaf.leaf_signature_key_b64u)
        .expect("A1 leaf key");
    let a2_leaf_key = URL_SAFE_NO_PAD
        .decode(&a2_evidence.leaf.leaf_signature_key_b64u)
        .expect("A2 leaf key");
    let a1_leaf = owner_group
        .members()
        .find(|member| {
            member.credential.serialized_content() == member_did.did.as_bytes()
                && member.signature_key == a1_leaf_key
        })
        .expect("A1 exact leaf");
    let a2_leaf = owner_group
        .members()
        .find(|member| {
            member.credential.serialized_content() == member_did.did.as_bytes()
                && member.signature_key == a2_leaf_key
        })
        .expect("A2 exact leaf");
    assert_ne!(a1_leaf.index, a2_leaf.index);

    let remove_from_epoch = owner_group.epoch().as_u64();
    let (remove_a2_commit, welcome, _) = owner_group
        .remove_members(&owner.provider, &owner.signer, &[a2_leaf.index])
        .expect("remove only A2 leaf");
    assert!(welcome.is_none());
    merge_commit(&mut a1_group, &a1.provider, remove_a2_commit.clone());
    merge_commit(&mut a2_group, &a2.provider, remove_a2_commit);
    owner_group
        .merge_pending_commit(&owner.provider)
        .expect("owner merges A2 Remove");

    assert_eq!(owner_group.epoch().as_u64(), remove_from_epoch + 1);
    assert!(a1_group.is_active());
    assert!(!a2_group.is_active());
    assert_eq!(owner_group.members().count(), 2);
    assert_eq!(business_did_count(&owner_group), 2);
    assert!(owner_group.members().any(|member| {
        member.credential.serialized_content() == member_did.did.as_bytes()
            && member.signature_key == a1_leaf_key
    }));
    assert!(!owner_group.members().any(|member| {
        member.credential.serialized_content() == member_did.did.as_bytes()
            && member.signature_key == a2_leaf_key
    }));

    let future = owner_group
        .create_message(&owner.provider, &owner.signer, b"after A2 removal")
        .expect("current member sends after Remove");
    assert_eq!(
        decrypt_application(&mut a1_group, &a1.provider, future.clone())
            .expect("A1 continues after sibling removal"),
        b"after A2 removal"
    );
    assert!(
        decrypt_application(&mut a2_group, &a2.provider, future).is_err(),
        "removed A2 cannot decrypt a future epoch application"
    );
}
