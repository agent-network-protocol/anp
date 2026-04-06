use std::fs;
use std::path::PathBuf;

use anp::direct_e2ee::{
    extract_x25519_public_key, ApplicationPlaintext, DirectCipherBody, DirectE2eeSession,
    DirectEnvelopeMetadata, DirectInitBody,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use serde_json::{json, Value};
use x25519_dalek::StaticSecret as X25519StaticSecret;

#[derive(Debug, Deserialize)]
struct Fixture {
    alice_did_document: Value,
    bob_did_document: Value,
    bob_static_private_key_b64u: String,
    bob_signed_prekey_private_key_b64u: String,
    init_metadata: DirectEnvelopeMetadata,
    follow_up_metadata: DirectEnvelopeMetadata,
    init_body: DirectInitBody,
    cipher_body: DirectCipherBody,
    init_plaintext: Value,
    follow_up_plaintext: Value,
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<String>>();
    if args.first().map(String::as_str) != Some("fixture") || args.get(1).is_none() {
        eprintln!("Usage: cargo run --example direct_e2ee_verify_fixture -- fixture <path>");
        std::process::exit(1);
    }

    let fixture_path = PathBuf::from(&args[1]);
    let fixture: Fixture = serde_json::from_str(
        &fs::read_to_string(&fixture_path).expect("fixture file should be readable"),
    )
    .expect("fixture must be valid json");

    let bob_did = fixture.bob_did_document["id"]
        .as_str()
        .expect("bob did should exist");
    let sender_static_key = extract_x25519_public_key(
        &fixture.alice_did_document,
        fixture.init_body.sender_static_key_agreement_id.as_str(),
    )
    .expect("sender static key should exist");

    let bob_static = decode_secret(&fixture.bob_static_private_key_b64u);
    let bob_spk = decode_secret(&fixture.bob_signed_prekey_private_key_b64u);

    let (mut session, plaintext) = DirectE2eeSession::accept_incoming_init(
        &fixture.init_metadata,
        &format!("{bob_did}#key-3"),
        &bob_static,
        &bob_spk,
        &sender_static_key,
        &fixture.init_body,
    )
    .expect("init should decrypt");

    let expected_init_text = fixture.init_plaintext["text"]
        .as_str()
        .expect("init text should exist");
    assert_eq!(plaintext.text.as_deref(), Some(expected_init_text));

    let decrypted = DirectE2eeSession::decrypt_follow_up(
        &mut session,
        &fixture.follow_up_metadata,
        &fixture.cipher_body,
        fixture.follow_up_plaintext["application_content_type"]
            .as_str()
            .unwrap_or("application/json"),
    )
    .expect("follow-up should decrypt");

    let expected_payload = fixture.follow_up_plaintext["payload"].clone();
    assert_eq!(decrypted.payload, Some(expected_payload.clone()));

    println!(
        "{}",
        serde_json::to_string(&json!({
            "verified": true,
            "init_text": plaintext.text,
            "follow_up_payload": expected_payload,
        }))
        .expect("output json")
    );
}

fn decode_secret(value: &str) -> X25519StaticSecret {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .expect("secret must be base64url");
    let bytes: [u8; 32] = bytes.try_into().expect("secret must be 32 bytes");
    X25519StaticSecret::from(bytes)
}
