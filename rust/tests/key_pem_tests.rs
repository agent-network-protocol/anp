use anp::authentication::{create_did_wba_document, DidDocumentOptions, DidProfile};
use anp::{PrivateKeyMaterial, PublicKeyMaterial};

#[test]
fn test_generated_did_keys_use_standard_pkcs8_and_spki_pem() {
    let e1 = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["user".to_string(), "rust-pem".to_string()],
            ..DidDocumentOptions::default()
        },
    )
    .expect("e1 DID should generate");
    assert_standard_key_bundle(&e1, &["key-1", "key-2", "key-3"]);

    let k1 = create_did_wba_document(
        "example.com",
        DidDocumentOptions {
            path_segments: vec!["user".to_string(), "rust-pem-k1".to_string()],
            did_profile: DidProfile::K1,
            enable_e2ee: false,
            ..DidDocumentOptions::default()
        },
    )
    .expect("k1 DID should generate");
    assert_standard_key_bundle(&k1, &["key-1"]);
}

#[test]
fn test_legacy_anp_pem_rejected_by_runtime_parsers() {
    let legacy_private = "-----BEGIN ANP ED25519 PRIVATE KEY-----\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n-----END ANP ED25519 PRIVATE KEY-----\n";
    assert!(
        PrivateKeyMaterial::from_pem(legacy_private).is_err(),
        "runtime parser must reject legacy ANP private labels"
    );

    let legacy_public = "-----BEGIN ANP ED25519 PUBLIC KEY-----\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n-----END ANP ED25519 PUBLIC KEY-----\n";
    assert!(
        PublicKeyMaterial::from_pem(legacy_public).is_err(),
        "runtime parser must reject legacy ANP public labels"
    );
}

fn assert_standard_key_bundle(bundle: &anp::authentication::DidDocumentBundle, fragments: &[&str]) {
    for fragment in fragments {
        let key_pair = bundle
            .keys
            .get(*fragment)
            .expect("key fragment should exist");
        assert_eq!(
            first_line(&key_pair.private_key_pem),
            "-----BEGIN PRIVATE KEY-----"
        );
        assert_eq!(
            first_line(&key_pair.public_key_pem),
            "-----BEGIN PUBLIC KEY-----"
        );
        assert!(!key_pair.private_key_pem.contains("ANP "));
        assert!(!key_pair.public_key_pem.contains("ANP "));

        let private_key =
            PrivateKeyMaterial::from_pem(&key_pair.private_key_pem).expect("private key parses");
        let public_key =
            PublicKeyMaterial::from_pem(&key_pair.public_key_pem).expect("public key parses");
        if !matches!(public_key, PublicKeyMaterial::X25519(_)) {
            let signature = private_key
                .sign_message(b"standard pem")
                .expect("signature should be created");
            public_key
                .verify_message(b"standard pem", &signature)
                .expect("signature should verify");
        }
    }
}

fn first_line(value: &str) -> &str {
    value.lines().next().unwrap_or_default()
}
