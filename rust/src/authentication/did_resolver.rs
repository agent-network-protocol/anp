pub use super::did_web::build_did_web_resolution_url;
use serde_json::Value;

/// Validate method rules after trusted resolution; this does not grant key purposes.
pub fn validate_did_document_method(document: &Value, verify_proof: bool) -> bool {
    let Some(did) = document.get("id").and_then(Value::as_str) else {
        return false;
    };
    if did.starts_with("did:wba:") {
        super::did_wba::validate_did_document_binding(document, verify_proof)
    } else if did.starts_with("did:web:") {
        build_did_web_resolution_url(did).is_ok()
    } else {
        false
    }
}

#[cfg(feature = "network")]
use crate::proof::{verify_w3c_proof, ProofVerificationOptions};

#[cfg(feature = "network")]
use super::did_wba::find_verification_method;
use super::did_wba::{
    resolve_did_wba_document_sync, resolve_did_wba_document_with_options, AuthenticationError,
    DidResolutionOptions,
};
#[cfg(feature = "network")]
use super::verification_methods::extract_public_key;

pub async fn resolve_did_document(
    did: &str,
    verify_proof: bool,
) -> Result<Value, AuthenticationError> {
    resolve_did_document_with_options(did, verify_proof, &DidResolutionOptions::default()).await
}

pub async fn resolve_did_document_with_options(
    did: &str,
    verify_proof: bool,
    options: &DidResolutionOptions,
) -> Result<Value, AuthenticationError> {
    if did.starts_with("did:wba:") {
        return resolve_did_wba_document_with_options(did, verify_proof, options).await;
    }
    if !did.starts_with("did:web:") {
        return Err(AuthenticationError::InvalidDid);
    }

    #[cfg(not(feature = "network"))]
    {
        build_did_web_resolution_url(did)?;
        return Err(AuthenticationError::NetworkFailure);
    }

    #[cfg(feature = "network")]
    {
        let document = super::did_web::fetch_document(did, options).await?;
        if verify_proof {
            if let Some(proof) = document.get("proof") {
                let verification_method = proof
                    .get("verificationMethod")
                    .and_then(Value::as_str)
                    .ok_or(AuthenticationError::InvalidDidDocument)?;
                let method = find_verification_method(&document, verification_method)
                    .ok_or(AuthenticationError::VerificationMethodNotFound)?;
                let public_key = extract_public_key(&method)
                    .map_err(|err| AuthenticationError::VerificationMethod(err.to_string()))?;
                if !verify_w3c_proof(&document, &public_key, ProofVerificationOptions::default()) {
                    return Err(AuthenticationError::VerificationFailed);
                }
            }
        }

        Ok(document)
    }
}

pub fn resolve_did_document_sync(
    did: &str,
    verify_proof: bool,
) -> Result<Value, AuthenticationError> {
    if did.starts_with("did:wba:") {
        return resolve_did_wba_document_sync(did, verify_proof);
    }
    let runtime =
        tokio::runtime::Runtime::new().map_err(|_| AuthenticationError::NetworkFailure)?;
    runtime.block_on(resolve_did_document(did, verify_proof))
}
