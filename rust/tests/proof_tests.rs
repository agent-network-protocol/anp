use anp::authentication::{create_did_wba_document, DidDocumentOptions, DidProfile};
use anp::proof::{
    complete_object_proof, complete_rfc9421_origin_proof, complete_w3c_proof,
    generate_did_wba_binding, generate_group_receipt_proof, generate_object_proof,
    generate_rfc9421_origin_proof, generate_w3c_proof, prepare_object_proof,
    prepare_rfc9421_origin_proof, prepare_w3c_proof, verify_did_wba_binding,
    verify_group_receipt_proof, verify_object_proof, verify_rfc9421_origin_proof, verify_w3c_proof,
    DidWbaBindingVerificationOptions, ProofGenerationOptions, ProofVerificationOptions,
    Rfc9421OriginProofGenerationOptions, Rfc9421OriginProofVerificationOptions,
    CRYPTOSUITE_EDDSA_JCS_2022, PROOF_TYPE_DATA_INTEGRITY,
};
use anp::PrivateKeyMaterial;
use serde_json::json;

#[test]
fn test_generate_and_verify_secp256k1_proof() {
    let private_key =
        PrivateKeyMaterial::Secp256k1(k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng));
    let public_key = private_key.public_key();
    let document = json!({
        "id": "did:wba:example.com:alice",
        "claim": "test-data",
    });
    let signed = generate_w3c_proof(
        &document,
        &private_key,
        "did:wba:example.com:alice#key-1",
        ProofGenerationOptions::default(),
    )
    .expect("proof generation should succeed");
    assert!(verify_w3c_proof(
        &signed,
        &public_key,
        ProofVerificationOptions::default(),
    ));
}

#[test]
fn test_generate_and_verify_ed25519_data_integrity_proof() {
    let private_key =
        PrivateKeyMaterial::Ed25519(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng));
    let public_key = private_key.public_key();
    let document = json!({
        "id": "did:wba:example.com:bob",
        "type": "VerifiableCredential",
    });
    let signed = generate_w3c_proof(
        &document,
        &private_key,
        "did:wba:example.com:bob#key-1",
        ProofGenerationOptions {
            proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_string()),
            cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.to_string()),
            ..ProofGenerationOptions::default()
        },
    )
    .expect("proof generation should succeed");
    assert!(verify_w3c_proof(
        &signed,
        &public_key,
        ProofVerificationOptions::default(),
    ));
}

#[test]
fn test_external_signer_uses_the_same_proof_input_as_the_private_key_api() {
    let private_key =
        PrivateKeyMaterial::Ed25519(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng));
    let public_key = private_key.public_key();
    let document = json!({
        "id": "did:wba:example.com:agents:alice:e1_test",
        "assertionMethod": ["did:wba:example.com:agents:alice:e1_test#root"],
    });
    let options = ProofGenerationOptions {
        proof_type: Some(PROOF_TYPE_DATA_INTEGRITY.to_string()),
        cryptosuite: Some(CRYPTOSUITE_EDDSA_JCS_2022.to_string()),
        created: Some("2026-08-18T10:00:00Z".to_string()),
        ..ProofGenerationOptions::default()
    };
    let prepared = prepare_w3c_proof(
        &document,
        &public_key,
        "did:wba:example.com:agents:alice:e1_test#root",
        options.clone(),
    )
    .expect("proof preparation should succeed");
    let signature = private_key
        .sign_message(prepared.signing_input())
        .expect("external signer should sign the prepared bytes");
    let externally_signed =
        complete_w3c_proof(prepared, &signature).expect("proof completion should succeed");
    let privately_signed = generate_w3c_proof(
        &document,
        &private_key,
        "did:wba:example.com:agents:alice:e1_test#root",
        options,
    )
    .expect("legacy private-key API should succeed");

    assert_eq!(externally_signed, privately_signed);
    assert!(verify_w3c_proof(
        &externally_signed,
        &public_key,
        ProofVerificationOptions::default(),
    ));
}

#[test]
fn test_external_signer_matches_object_proof_private_key_api() {
    let bundle = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["agents".to_owned(), "alice".to_owned()],
            did_profile: DidProfile::E1,
            ..DidDocumentOptions::default()
        },
    )
    .expect("DID document should be created");
    let did = bundle.did().expect("DID should exist").to_owned();
    let verification_method = format!("{did}#key-1");
    let private_key =
        PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem).expect("private key");
    let public_key = private_key.public_key();
    let document = json!({
        "type": "anp.test.external-signer.v1",
        "issuer": did,
        "payload": {"message": "hello"},
    });
    let created = Some("2026-08-21T01:00:00Z".to_owned());
    let prepared = prepare_object_proof(
        &document,
        &public_key,
        &verification_method,
        &did,
        created.clone(),
    )
    .expect("object proof should prepare");
    let signature = private_key
        .sign_message(prepared.signing_input())
        .expect("prepared object proof should sign");
    let external =
        complete_object_proof(prepared, &signature).expect("object proof should complete");
    let direct =
        generate_object_proof(&document, &private_key, &verification_method, &did, created)
            .expect("object proof should generate");

    assert_eq!(external, direct);
    verify_object_proof(&external, &did, &bundle.did_document)
        .expect("external object proof should verify");
}

#[test]
fn test_external_signer_matches_origin_proof_private_key_api() {
    let bundle = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["agents".to_owned(), "alice".to_owned()],
            did_profile: DidProfile::E1,
            ..DidDocumentOptions::default()
        },
    )
    .expect("DID document should be created");
    let did = bundle.did().expect("DID should exist").to_owned();
    let keyid = format!("{did}#key-1");
    let private_key =
        PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem).expect("private key");
    let public_key = private_key.public_key();
    let meta = json!({
        "anp_version": "1.0",
        "profile": "anp.direct.base.v1",
        "security_profile": "transport-protected",
        "sender_did": did,
        "target": {"kind": "agent", "did": "did:wba:example.com:agents:bob:e1_bob"},
        "operation_id": "op-external-proof",
        "message_id": "msg-external-proof",
        "content_type": "text/plain",
    });
    let body = json!({"text": "hello"});
    let options = Rfc9421OriginProofGenerationOptions {
        created: Some(1_777_000_000),
        expires: Some(1_777_000_300),
        nonce: Some("external-proof-nonce".to_owned()),
        ..Rfc9421OriginProofGenerationOptions::default()
    };
    let prepared = prepare_rfc9421_origin_proof(
        "direct.send",
        &meta,
        &body,
        &public_key,
        &keyid,
        options.clone(),
    )
    .expect("origin proof should prepare");
    let signature = private_key
        .sign_message(prepared.signing_input())
        .expect("prepared origin proof should sign");
    let external =
        complete_rfc9421_origin_proof(prepared, &signature).expect("origin proof should complete");
    let direct =
        generate_rfc9421_origin_proof("direct.send", &meta, &body, &private_key, &keyid, options)
            .expect("origin proof should generate");

    assert_eq!(external, direct);
    verify_rfc9421_origin_proof(
        &external,
        "direct.send",
        &meta,
        &body,
        Rfc9421OriginProofVerificationOptions {
            did_document: Some(bundle.did_document),
            expected_signer_did: Some(did),
            ..Rfc9421OriginProofVerificationOptions::default()
        },
    )
    .expect("external origin proof should verify");
}

#[test]
fn test_tampered_document_fails_proof_verification() {
    let private_key =
        PrivateKeyMaterial::Secp256k1(k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng));
    let public_key = private_key.public_key();
    let document = json!({
        "id": "did:wba:example.com:alice",
        "claim": "test-data",
    });
    let mut signed = generate_w3c_proof(
        &document,
        &private_key,
        "did:wba:example.com:alice#key-1",
        ProofGenerationOptions::default(),
    )
    .expect("proof generation should succeed");
    signed["claim"] = json!("tampered-data");
    assert!(!verify_w3c_proof(
        &signed,
        &public_key,
        ProofVerificationOptions::default(),
    ));
}

#[test]
fn test_generate_and_verify_group_receipt_proof() {
    let bundle = create_did_wba_document(
        "groups.example",
        DidDocumentOptions {
            path_segments: vec!["team".to_owned(), "dev".to_owned()],
            did_profile: DidProfile::E1,
            ..Default::default()
        },
    )
    .expect("group did document");
    let did = bundle.did().expect("group did").to_string();
    let private_key =
        PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem).expect("private key");
    let receipt = json!({
        "receipt_type": "anp.group_receipt.v1",
        "group_did": did,
        "group_state_version": "43",
        "group_event_seq": "128",
        "subject_method": "group.send",
        "operation_id": "op-group-send-001",
        "message_id": "msg-group-send-001",
        "actor_did": "did:wba:a.example:agents:alice:e1_alice",
        "accepted_at": "2026-03-29T15:10:01Z",
        "payload_digest": "sha-256=:stub:",
    });
    let signed = generate_group_receipt_proof(&receipt, &private_key, &format!("{did}#key-1"))
        .expect("group receipt proof generation should succeed");
    assert_eq!(signed["proof"]["cryptosuite"], json!("eddsa-jcs-2022"));
    assert!(signed["proof"]["proofValue"]
        .as_str()
        .expect("proof value")
        .starts_with('z'));
    assert!(verify_group_receipt_proof(&signed, &bundle.did_document).is_ok());
}

#[test]
fn test_tampered_group_receipt_fails_verification() {
    let bundle = create_did_wba_document(
        "groups.example",
        DidDocumentOptions {
            path_segments: vec!["team".to_owned(), "dev".to_owned()],
            did_profile: DidProfile::E1,
            ..Default::default()
        },
    )
    .expect("group did document");
    let did = bundle.did().expect("group did").to_string();
    let private_key =
        PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem).expect("private key");
    let receipt = json!({
        "receipt_type": "anp.group_receipt.v1",
        "group_did": did,
        "group_state_version": "43",
        "group_event_seq": "128",
        "subject_method": "group.send",
        "operation_id": "op-group-send-001",
        "message_id": "msg-group-send-001",
        "actor_did": "did:wba:a.example:agents:alice:e1_alice",
        "accepted_at": "2026-03-29T15:10:01Z",
        "payload_digest": "sha-256=:stub:",
    });
    let mut signed = generate_group_receipt_proof(
        &receipt,
        &private_key,
        &format!("{}#key-1", receipt["group_did"].as_str().unwrap()),
    )
    .expect("group receipt proof generation should succeed");
    signed["group_event_seq"] = json!("129");
    assert!(verify_group_receipt_proof(&signed, &bundle.did_document).is_err());
}

#[test]
fn test_generate_and_verify_did_wba_binding() {
    let bundle = create_did_wba_document(
        "a.example",
        DidDocumentOptions {
            path_segments: vec!["agents".to_owned(), "alice".to_owned()],
            did_profile: DidProfile::E1,
            ..Default::default()
        },
    )
    .expect("agent did document");
    let did = bundle.did().expect("agent did").to_string();
    let private_key =
        PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem).expect("private key");
    let binding = generate_did_wba_binding(
        &did,
        &format!("{did}#key-1"),
        "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
        &private_key,
        "2026-03-29T12:00:00Z",
        "2026-04-29T12:00:00Z",
        Some("2026-03-29T12:00:00Z".to_string()),
    )
    .expect("binding proof generation should succeed");
    assert!(binding["proof"]["proofValue"]
        .as_str()
        .expect("proof value")
        .starts_with('z'));
    assert!(verify_did_wba_binding(
        &binding,
        &bundle.did_document,
        DidWbaBindingVerificationOptions {
            now: Some("2026-03-30T12:00:00Z".to_string()),
            expected_credential_identity: Some(did.clone()),
            ..DidWbaBindingVerificationOptions::default()
        },
    )
    .is_ok());
}

#[test]
fn test_did_wba_binding_golden_vector_verifies_and_tamper_fails() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../testdata/group_e2ee/did_wba_binding_golden.json"
    ))
    .expect("golden vector should decode");
    let issuer_did = vector["issuer_did"]
        .as_str()
        .expect("issuer DID should be present");
    let binding = vector
        .get("did_wba_binding")
        .expect("binding should be present");
    let did_document = vector
        .get("did_document")
        .expect("issuer DID document should be present");
    let now = vector["now"].as_str().expect("now should be present");

    verify_did_wba_binding(
        binding,
        did_document,
        DidWbaBindingVerificationOptions {
            now: Some(now.to_string()),
            expected_leaf_signature_key_b64u: Some(
                vector["leaf_signature_key_b64u"]
                    .as_str()
                    .expect("leaf key should be present")
                    .to_string(),
            ),
            expected_credential_identity: Some(issuer_did.to_string()),
        },
    )
    .expect("golden DID WBA binding should verify");

    let mut tampered = binding.clone();
    tampered["leaf_signature_key_b64u"] = json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert!(verify_did_wba_binding(
        &tampered,
        did_document,
        DidWbaBindingVerificationOptions {
            now: Some(now.to_string()),
            expected_credential_identity: Some(issuer_did.to_string()),
            ..DidWbaBindingVerificationOptions::default()
        },
    )
    .is_err());
}

#[test]
fn test_expired_did_wba_binding_fails() {
    let bundle = create_did_wba_document(
        "a.example",
        DidDocumentOptions {
            path_segments: vec!["agents".to_owned(), "alice".to_owned()],
            did_profile: DidProfile::E1,
            ..Default::default()
        },
    )
    .expect("agent did document");
    let did = bundle.did().expect("agent did").to_string();
    let private_key =
        PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem).expect("private key");
    let binding = generate_did_wba_binding(
        &did,
        &format!("{did}#key-1"),
        "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
        &private_key,
        "2026-03-29T12:00:00Z",
        "2026-04-29T12:00:00Z",
        Some("2026-03-29T12:00:00Z".to_string()),
    )
    .expect("binding proof generation should succeed");
    assert!(verify_did_wba_binding(
        &binding,
        &bundle.did_document,
        DidWbaBindingVerificationOptions {
            now: Some("2026-05-01T00:00:00Z".to_string()),
            ..DidWbaBindingVerificationOptions::default()
        },
    )
    .is_err());
}
