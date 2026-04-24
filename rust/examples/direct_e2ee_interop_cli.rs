use anp::authentication::{create_did_wba_document, DidDocumentOptions, DidProfile};
use anp::direct_e2ee::{
    build_prekey_bundle, signed_prekey_from_private_key, ApplicationPlaintext, DirectE2eeSession,
    DirectEnvelopeMetadata,
};
use anp::PrivateKeyMaterial;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::json;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<String>>();
    if args.first().map(String::as_str) != Some("fixture") {
        eprintln!("Usage: cargo run --example direct_e2ee_interop_cli -- fixture");
        std::process::exit(1);
    }

    let alice = create_did_wba_document(
        "a.example",
        DidDocumentOptions::default()
            .with_profile(DidProfile::E1)
            .with_path_segments(["agents", "alice"]),
    )
    .expect("alice did");
    let bob = create_did_wba_document(
        "b.example",
        DidDocumentOptions::default()
            .with_profile(DidProfile::E1)
            .with_path_segments(["agents", "bob"]),
    )
    .expect("bob did");

    let alice_did = alice.did_document["id"].as_str().unwrap().to_string();
    let bob_did = bob.did_document["id"].as_str().unwrap().to_string();

    let alice_static = load_x25519_secret(&alice.keys["key-3"].private_key_pem);
    let bob_static = load_x25519_secret(&bob.keys["key-3"].private_key_pem);
    let bob_spk = X25519StaticSecret::from([55u8; 32]);

    let bob_signing_key =
        PrivateKeyMaterial::from_pem(&bob.keys["key-1"].private_key_pem).expect("bob signing key");
    let bundle = build_prekey_bundle(
        "bundle-001",
        &bob_did,
        &format!("{bob_did}#key-3"),
        signed_prekey_from_private_key("spk-001", &bob_spk, "2026-04-07T00:00:00Z"),
        &bob_signing_key,
        &format!("{bob_did}#key-1"),
        Some("2026-03-31T09:58:58Z"),
    )
    .expect("bundle");

    let init_metadata = metadata(&alice_did, &bob_did, "msg-init");
    let (mut alice_session, _pending, init_body) = DirectE2eeSession::initiate_session(
        &init_metadata,
        "op-init",
        &format!("{alice_did}#key-3"),
        &alice_static,
        &bundle,
        &X25519PublicKey::from(&bob_static).to_bytes(),
        &X25519PublicKey::from(&bob_spk).to_bytes(),
        &ApplicationPlaintext::new_text("text/plain", "hello bob"),
    )
    .expect("initiate");

    let follow_up_metadata = metadata(&alice_did, &bob_did, "msg-2");
    let (_pending, cipher_body) = DirectE2eeSession::encrypt_follow_up(
        &mut alice_session,
        &follow_up_metadata,
        "op-2",
        &ApplicationPlaintext::new_json("application/json", json!({"event": "wave"})),
    )
    .expect("follow up");

    println!(
        "{}",
        serde_json::to_string(&json!({
            "alice_did_document": alice.did_document,
            "bob_did_document": bob.did_document,
            "bundle": serde_json::to_value(&bundle).expect("bundle json"),
            "bob_static_private_key_b64u": encode_secret(&bob_static),
            "bob_signed_prekey_private_key_b64u": encode_secret(&bob_spk),
            "init_metadata": serde_json::to_value(&init_metadata).expect("metadata json"),
            "follow_up_metadata": serde_json::to_value(&follow_up_metadata).expect("metadata json"),
            "init_body": serde_json::to_value(&init_body).expect("init json"),
            "cipher_body": serde_json::to_value(&cipher_body).expect("cipher json"),
            "init_plaintext": json!({"application_content_type": "text/plain", "text": "hello bob"}),
            "follow_up_plaintext": json!({"application_content_type": "application/json", "payload": {"event": "wave"}}),
        }))
        .expect("fixture json")
    );
}

fn metadata(sender: &str, recipient: &str, message_id: &str) -> DirectEnvelopeMetadata {
    DirectEnvelopeMetadata {
        sender_did: sender.to_owned(),
        recipient_did: recipient.to_owned(),
        message_id: message_id.to_owned(),
        profile: "anp.direct.e2ee.v1".to_owned(),
        security_profile: "direct-e2ee".to_owned(),
    }
}

fn load_x25519_secret(pem: &str) -> X25519StaticSecret {
    match PrivateKeyMaterial::from_pem(pem).expect("private key") {
        PrivateKeyMaterial::X25519(secret) => secret,
        _ => panic!("expected X25519 private key"),
    }
}

fn encode_secret(secret: &X25519StaticSecret) -> String {
    URL_SAFE_NO_PAD.encode(secret.to_bytes())
}
