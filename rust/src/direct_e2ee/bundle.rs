use super::errors::DirectE2eeError;
use super::models::{PrekeyBundle, SignedPrekey, MTI_DIRECT_E2EE_SUITE};
use crate::authentication::{
    create_verification_method, find_verification_method, validate_did_document_binding,
};
use crate::keys::base64url_encode;
use crate::proof::{generate_object_proof, verify_object_proof};
use crate::PrivateKeyMaterial;
use serde_json::{json, Value};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

pub fn signed_prekey_from_private_key(
    key_id: &str,
    private_key: &X25519StaticSecret,
    expires_at: &str,
) -> SignedPrekey {
    let public_key = X25519PublicKey::from(private_key);
    SignedPrekey {
        key_id: key_id.to_owned(),
        public_key_b64u: base64url_encode(&public_key.to_bytes()),
        expires_at: expires_at.to_owned(),
    }
}

pub fn build_prekey_bundle(
    bundle_id: &str,
    owner_did: &str,
    static_key_agreement_id: &str,
    signed_prekey: SignedPrekey,
    signing_private_key: &PrivateKeyMaterial,
    verification_method: &str,
    created: Option<&str>,
) -> Result<PrekeyBundle, DirectE2eeError> {
    let unsigned = json!({
        "bundle_id": bundle_id,
        "owner_did": owner_did,
        "suite": MTI_DIRECT_E2EE_SUITE,
        "static_key_agreement_id": static_key_agreement_id,
        "signed_prekey": signed_prekey,
    });
    let signed = generate_object_proof(
        &unsigned,
        signing_private_key,
        verification_method,
        owner_did,
        created.map(ToOwned::to_owned),
    )?;
    let proof = signed
        .get("proof")
        .cloned()
        .ok_or(DirectE2eeError::MissingField("proof"))?;
    Ok(PrekeyBundle {
        bundle_id: bundle_id.to_owned(),
        owner_did: owner_did.to_owned(),
        suite: MTI_DIRECT_E2EE_SUITE.to_owned(),
        static_key_agreement_id: static_key_agreement_id.to_owned(),
        signed_prekey,
        proof,
    })
}

pub fn verify_prekey_bundle(
    bundle: &PrekeyBundle,
    did_document: &Value,
) -> Result<(), DirectE2eeError> {
    if bundle.suite != MTI_DIRECT_E2EE_SUITE {
        return Err(DirectE2eeError::UnsupportedSuite(bundle.suite.clone()));
    }
    if did_document.get("id").and_then(Value::as_str) != Some(bundle.owner_did.as_str()) {
        return Err(DirectE2eeError::invalid_field(
            "owner_did must match the issuer DID document",
        ));
    }
    if bundle.owner_did.starts_with("did:wba:")
        && !validate_did_document_binding(did_document, false)
    {
        return Err(DirectE2eeError::invalid_field(
            "owner DID document binding validation failed",
        ));
    }
    let key_agreement = did_document
        .get("keyAgreement")
        .and_then(Value::as_array)
        .ok_or(DirectE2eeError::MissingField("keyAgreement"))?;
    let static_key_found = key_agreement
        .iter()
        .any(|entry| entry.as_str() == Some(&bundle.static_key_agreement_id));
    if !static_key_found {
        return Err(DirectE2eeError::invalid_field(
            "static_key_agreement_id must appear in did_document.keyAgreement",
        ));
    }
    let signed_bundle = serde_json::to_value(bundle).map_err(|error| {
        DirectE2eeError::invalid_field(format!("invalid bundle serialization: {error}"))
    })?;
    verify_object_proof(&signed_bundle, &bundle.owner_did, did_document)?;
    Ok(())
}

pub fn extract_x25519_public_key(
    did_document: &Value,
    key_id: &str,
) -> Result<[u8; 32], DirectE2eeError> {
    let method = find_verification_method(did_document, key_id).ok_or_else(|| {
        DirectE2eeError::invalid_field(format!("verification method not found: {key_id}"))
    })?;
    let verification_method = create_verification_method(&method).map_err(|error| {
        DirectE2eeError::invalid_field(format!("invalid verification method: {error}"))
    })?;
    match verification_method.public_key {
        crate::PublicKeyMaterial::X25519(bytes) => Ok(bytes),
        _ => Err(DirectE2eeError::invalid_field(format!(
            "verification method is not X25519: {key_id}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{build_prekey_bundle, signed_prekey_from_private_key, verify_prekey_bundle};
    use crate::authentication::{create_did_wba_document, DidDocumentOptions, DidProfile};
    use crate::PrivateKeyMaterial;
    use x25519_dalek::StaticSecret as X25519StaticSecret;

    #[test]
    fn bundle_round_trip_verifies_against_did_document() {
        let bundle = create_did_wba_document(
            "bundle.example",
            DidDocumentOptions {
                path_segments: vec!["agents".to_owned(), "alice".to_owned()],
                did_profile: DidProfile::E1,
                ..Default::default()
            },
        )
        .expect("did document");
        let did = bundle.did().expect("did");
        let signing_key = PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
            .expect("private key");
        let spk_private = X25519StaticSecret::from([7u8; 32]);
        let signed_prekey =
            signed_prekey_from_private_key("spk-001", &spk_private, "2026-04-07T00:00:00Z");
        let built = build_prekey_bundle(
            "bundle-001",
            did,
            &format!("{did}#key-3"),
            signed_prekey,
            &signing_key,
            &format!("{did}#key-1"),
            Some("2026-03-31T09:58:58Z"),
        )
        .expect("bundle");

        verify_prekey_bundle(&built, &bundle.did_document).expect("bundle should verify");
    }
}
