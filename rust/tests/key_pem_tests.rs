use anp::authentication::{create_did_wba_document, DidDocumentOptions, DidProfile};
use anp::{PrivateKeyMaterial, PublicKeyMaterial};
use base64::{engine::general_purpose::STANDARD, Engine as _};

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

#[test]
fn test_compatible_private_pem_converts_legacy_anp_labels_to_pkcs8() {
    let cases: &[(&str, &[u8], fn(&PrivateKeyMaterial) -> bool)] = &[
        ("ANP ED25519 PRIVATE KEY", &[7; 32], |key| {
            matches!(key, PrivateKeyMaterial::Ed25519(_))
        }),
        ("ANP X25519 PRIVATE KEY", &[9; 32], |key| {
            matches!(key, PrivateKeyMaterial::X25519(_))
        }),
        ("ANP SECP256R1 PRIVATE KEY", &[1], |key| {
            matches!(key, PrivateKeyMaterial::Secp256r1(_))
        }),
        ("ANP SECP256K1 PRIVATE KEY", &[1], |key| {
            matches!(key, PrivateKeyMaterial::Secp256k1(_))
        }),
    ];

    for (label, raw, matches_variant) in cases {
        let legacy_pem = pem(label, raw);
        assert!(
            PrivateKeyMaterial::from_pem(&legacy_pem).is_err(),
            "runtime parser must keep rejecting {label}"
        );

        let key = PrivateKeyMaterial::from_compatible_private_pem(&legacy_pem)
            .expect("legacy private key should parse through compatibility API");
        assert!(matches_variant(&key));

        let standard_pem = key.to_pem();
        assert_eq!(first_line(&standard_pem), "-----BEGIN PRIVATE KEY-----");
        assert!(!standard_pem.contains("ANP "));

        let reparsed =
            PrivateKeyMaterial::from_pem(&standard_pem).expect("standard PKCS#8 should parse");
        assert!(matches_variant(&reparsed));
    }
}

#[test]
fn test_compatible_private_pem_supports_sec1_ec_private_keys() {
    let cases: &[(&str, Vec<u8>, fn(&PrivateKeyMaterial) -> bool)] = &[
        ("P-256 SEC1", sec1_private_key_der(&[1], P256_OID), |key| {
            matches!(key, PrivateKeyMaterial::Secp256r1(_))
        }),
        (
            "secp256k1 SEC1",
            sec1_private_key_der(&[1], SECP256K1_OID),
            |key| matches!(key, PrivateKeyMaterial::Secp256k1(_)),
        ),
    ];

    for (name, der, matches_variant) in cases {
        let sec1_pem = pem("EC PRIVATE KEY", der);
        assert!(
            PrivateKeyMaterial::from_pem(&sec1_pem).is_err(),
            "runtime parser must reject {name}"
        );

        let key = PrivateKeyMaterial::from_compatible_private_pem(&sec1_pem)
            .expect("SEC1 private key should parse through compatibility API");
        assert!(matches_variant(&key), "{name} parsed as wrong key type");

        let standard_pem = key.to_pem();
        assert_eq!(first_line(&standard_pem), "-----BEGIN PRIVATE KEY-----");
        let reparsed =
            PrivateKeyMaterial::from_pem(&standard_pem).expect("standard PKCS#8 should parse");
        assert!(matches_variant(&reparsed));
    }
}

#[test]
fn test_compatible_private_pem_rejects_invalid_secp256k1_scalars() {
    for raw in [&[0][..], SECP256K1_ORDER] {
        let legacy_pem = pem("ANP SECP256K1 PRIVATE KEY", raw);
        assert!(
            PrivateKeyMaterial::from_compatible_private_pem(&legacy_pem).is_err(),
            "invalid secp256k1 scalar should be rejected"
        );
    }
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

fn pem(label: &str, contents: impl AsRef<[u8]>) -> String {
    let encoded = STANDARD.encode(contents);
    let mut wrapped = String::new();
    for chunk in encoded.as_bytes().chunks(64) {
        wrapped.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        wrapped.push('\n');
    }
    format!("-----BEGIN {label}-----\n{wrapped}-----END {label}-----\n")
}

fn sec1_private_key_der(raw_scalar: &[u8], curve_oid: &[u8]) -> Vec<u8> {
    let mut scalar = [0u8; 32];
    scalar[32 - raw_scalar.len()..].copy_from_slice(raw_scalar);

    let mut body = vec![0x02, 0x01, 0x01, 0x04, 0x20];
    body.extend_from_slice(&scalar);
    body.push(0xa0);
    body.push((2 + curve_oid.len()) as u8);
    body.push(0x06);
    body.push(curve_oid.len() as u8);
    body.extend_from_slice(curve_oid);

    let mut der = vec![0x30, body.len() as u8];
    der.extend_from_slice(&body);
    der
}

const P256_OID: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const SECP256K1_OID: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x0a];
const SECP256K1_ORDER: &[u8] = &[
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
