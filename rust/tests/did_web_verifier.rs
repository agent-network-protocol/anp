use anp::authentication::{generate_http_signature_headers, DidWbaVerifier, DidWbaVerifierConfig};
use anp::PrivateKeyMaterial;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::json;
use std::collections::BTreeMap;

#[tokio::test]
async fn web_http_auth_bearer_and_negative_boundaries() {
    let did = "did:web:example.com:users:e1_web-path";
    let keyid = format!("{did}#request");
    let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let public = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
    let private = PrivateKeyMaterial::Ed25519(key);
    let document = json!({"id":did, "verificationMethod":[{"id":keyid,"controller":did,
        "type":"JsonWebKey2020","publicKeyJwk":{"kty":"OKP","crv":"Ed25519","x":public}}],
        "authentication":[keyid],"assertionMethod":[keyid]});
    let url = "https://api.example.com/orders";
    let body = br#"{"item":"book"}"#;
    let headers = generate_http_signature_headers(
        &document,
        url,
        "POST",
        &private,
        None,
        Some(body),
        Default::default(),
    )
    .unwrap();
    let mut verifier = DidWbaVerifier::new(DidWbaVerifierConfig {
        jwt_algorithm: "HS256".to_owned(),
        jwt_private_key: Some("unit-test-secret-32-bytes-minimum".to_owned()),
        jwt_public_key: Some("unit-test-secret-32-bytes-minimum".to_owned()),
        ..Default::default()
    });
    for (wrong_url, wrong_body) in [
        ("https://api.example.com/other", body.as_slice()),
        (url, br#"{"item":"music"}"#.as_slice()),
    ] {
        assert!(verifier
            .verify_request_with_did_document(
                "POST",
                wrong_url,
                &headers,
                Some(wrong_body),
                None,
                &document
            )
            .await
            .is_err());
    }
    let first = verifier
        .verify_request_with_did_document("POST", url, &headers, Some(body), None, &document)
        .await
        .unwrap();
    assert_eq!(first.did, did);
    assert!(verifier
        .verify_request_with_did_document("POST", url, &headers, Some(body), None, &document)
        .await
        .is_err());
    let bearer = BTreeMap::from([(
        "Authorization".to_owned(),
        format!("Bearer {}", first.access_token.unwrap()),
    )]);
    assert_eq!(
        verifier
            .verify_request("POST", url, &bearer, Some(body), None)
            .await
            .unwrap()
            .did,
        did
    );
    let mut assertion_only = document;
    assertion_only
        .as_object_mut()
        .unwrap()
        .remove("authentication");
    let mut group_object = anp::proof::generate_object_proof(
        &json!({"group_did":did,"epoch":3}),
        &private,
        &keyid,
        did,
        None,
    )
    .unwrap();
    anp::proof::verify_object_proof(&group_object, did, &assertion_only).unwrap();
    group_object["epoch"] = json!(4);
    assert!(anp::proof::verify_object_proof(&group_object, did, &assertion_only).is_err());
    assert_eq!(
        verifier
            .verify_request_with_did_document(
                "POST",
                url,
                &headers,
                Some(body),
                None,
                &assertion_only
            )
            .await
            .unwrap_err()
            .status_code,
        403
    );
}
