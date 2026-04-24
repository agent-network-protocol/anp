use std::fs;
use std::path::PathBuf;

use anp::direct_e2ee::aad::{build_init_aad, build_message_aad};
use anp::direct_e2ee::models::{DirectCipherBody, DirectEnvelopeMetadata, DirectInitBody};
use anp::direct_e2ee::ratchet::{derive_chain_step, derive_root_step};
use anp::direct_e2ee::x3dh::{
    derive_initial_material_for_initiator_with_opk, derive_initial_material_for_responder_with_opk,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

#[derive(Debug, Deserialize)]
struct SharedP5Vectors {
    version: String,
    x3dh: Vec<X3DHVector>,
    kdf_ck: Vec<KDFCKVector>,
    kdf_rk: Vec<KDFRKVector>,
    aad: Vec<AADVector>,
}

#[derive(Debug, Deserialize)]
struct X3DHVector {
    name: String,
    sender_static_private_b64u: String,
    sender_ephemeral_private_b64u: String,
    recipient_static_private_b64u: String,
    recipient_signed_prekey_private_b64u: String,
    #[serde(default)]
    recipient_one_time_prekey_private_b64u: String,
    recipient_static_public_b64u: String,
    recipient_signed_prekey_public_b64u: String,
    #[serde(default)]
    recipient_one_time_prekey_public_b64u: String,
    initial_secret_b64u: String,
    root_key_b64u: String,
    chain_key_b64u: String,
    session_id: String,
}

#[derive(Debug, Deserialize)]
struct KDFCKVector {
    name: String,
    chain_key_b64u: String,
    next_chain_key_b64u: String,
    message_key_b64u: String,
    nonce_b64u: String,
}

#[derive(Debug, Deserialize)]
struct KDFRKVector {
    name: String,
    root_key_b64u: String,
    dh_out_b64u: String,
    next_root_key_b64u: String,
    chain_key_b64u: String,
}

#[derive(Debug, Deserialize)]
struct AADVector {
    name: String,
    metadata: DirectEnvelopeMetadata,
    #[serde(default)]
    init_body: Option<DirectInitBody>,
    #[serde(default)]
    cipher_body: Option<DirectCipherBody>,
    expected_aad: String,
}

#[test]
fn direct_e2ee_rust_sdk_passes_shared_p5_vectors() {
    let vectors = load_vectors();
    assert_eq!(vectors.version, "anp-direct-e2ee-p5-shared-vectors-v1");
    for vector in &vectors.x3dh {
        let sender_static = secret_from_b64u(&vector.sender_static_private_b64u);
        let sender_ephemeral = secret_from_b64u(&vector.sender_ephemeral_private_b64u);
        let recipient_static_public = bytes32_from_b64u(&vector.recipient_static_public_b64u);
        let recipient_signed_prekey_public =
            bytes32_from_b64u(&vector.recipient_signed_prekey_public_b64u);
        let recipient_opk_public = if vector.recipient_one_time_prekey_public_b64u.is_empty() {
            None
        } else {
            Some(bytes32_from_b64u(
                &vector.recipient_one_time_prekey_public_b64u,
            ))
        };
        let initiator = derive_initial_material_for_initiator_with_opk(
            &sender_static,
            &sender_ephemeral,
            &recipient_static_public,
            &recipient_signed_prekey_public,
            recipient_opk_public.as_ref(),
        )
        .unwrap_or_else(|err| panic!("{} initiator material failed: {err}", vector.name));

        assert_eq!(
            encode_b64u(&initiator.initial_secret),
            vector.initial_secret_b64u,
            "{} initial_secret",
            vector.name
        );
        assert_eq!(
            encode_b64u(&initiator.root_key),
            vector.root_key_b64u,
            "{} root_key",
            vector.name
        );
        assert_eq!(
            encode_b64u(&initiator.chain_key),
            vector.chain_key_b64u,
            "{} chain_key",
            vector.name
        );
        assert_eq!(initiator.session_id, vector.session_id, "{}", vector.name);

        let recipient_static = secret_from_b64u(&vector.recipient_static_private_b64u);
        let recipient_signed_prekey =
            secret_from_b64u(&vector.recipient_signed_prekey_private_b64u);
        let recipient_opk = if vector.recipient_one_time_prekey_private_b64u.is_empty() {
            None
        } else {
            Some(secret_from_b64u(
                &vector.recipient_one_time_prekey_private_b64u,
            ))
        };
        let responder = derive_initial_material_for_responder_with_opk(
            &recipient_static,
            &recipient_signed_prekey,
            recipient_opk.as_ref(),
            &X25519PublicKey::from(&sender_static).to_bytes(),
            &X25519PublicKey::from(&sender_ephemeral).to_bytes(),
        )
        .unwrap_or_else(|err| panic!("{} responder material failed: {err}", vector.name));
        assert_eq!(responder, initiator, "{} responder parity", vector.name);
    }

    for vector in &vectors.kdf_ck {
        let step = derive_chain_step(&bytes32_from_b64u(&vector.chain_key_b64u));
        assert_eq!(
            encode_b64u(&step.next_chain_key),
            vector.next_chain_key_b64u,
            "{} next_chain_key",
            vector.name
        );
        assert_eq!(
            encode_b64u(&step.message_key),
            vector.message_key_b64u,
            "{} message_key",
            vector.name
        );
        assert_eq!(
            encode_b64u(&step.nonce),
            vector.nonce_b64u,
            "{} nonce",
            vector.name
        );
    }

    for vector in &vectors.kdf_rk {
        let step = derive_root_step(
            &bytes32_from_b64u(&vector.root_key_b64u),
            &decode_b64u(&vector.dh_out_b64u),
        )
        .unwrap_or_else(|err| panic!("{} root step failed: {err}", vector.name));
        assert_eq!(
            encode_b64u(&step.root_key),
            vector.next_root_key_b64u,
            "{} root_key",
            vector.name
        );
        assert_eq!(
            encode_b64u(&step.chain_key),
            vector.chain_key_b64u,
            "{} chain_key",
            vector.name
        );
    }

    for vector in &vectors.aad {
        let aad = if let Some(body) = &vector.init_body {
            build_init_aad(&vector.metadata, body)
        } else if let Some(body) = &vector.cipher_body {
            build_message_aad(&vector.metadata, body)
        } else {
            panic!("{} missing body", vector.name);
        }
        .unwrap_or_else(|err| panic!("{} aad failed: {err}", vector.name));
        assert_eq!(
            String::from_utf8(aad).expect("aad must be utf8"),
            vector.expected_aad,
            "{} aad",
            vector.name
        );
    }
}

#[test]
fn direct_e2ee_init_serialization_omits_absent_opk_and_legacy_static_field() {
    let vectors = load_vectors();
    let init = vectors
        .aad
        .iter()
        .find(|vector| vector.name == "p5_aad_init_no_opk")
        .and_then(|vector| vector.init_body.as_ref())
        .expect("p5_aad_init_no_opk vector should exist");
    let encoded = serde_json::to_string(init).expect("init serializes");
    assert!(
        !encoded.contains("recipient_static_key_agreement_id"),
        "legacy recipient static field must not serialize: {encoded}"
    );
    assert!(
        !encoded.contains("recipient_one_time_prekey_id") && !encoded.contains(":null"),
        "absent OPK must be omitted rather than null: {encoded}"
    );
}

fn load_vectors() -> SharedP5Vectors {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("testdata")
        .join("direct_e2ee")
        .join("p5_shared_vectors.json");
    serde_json::from_str(&fs::read_to_string(path).expect("shared vectors should be readable"))
        .expect("shared vectors must be valid JSON")
}

fn decode_b64u(value: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD
        .decode(value)
        .expect("value must be base64url")
}

fn bytes32_from_b64u(value: &str) -> [u8; 32] {
    decode_b64u(value)
        .try_into()
        .expect("value must decode to 32 bytes")
}

fn secret_from_b64u(value: &str) -> X25519StaticSecret {
    X25519StaticSecret::from(bytes32_from_b64u(value))
}

fn encode_b64u(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}
