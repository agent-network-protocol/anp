use percent_encoding::percent_decode_str;
use reqwest::Client;
use serde_json::Value;

use crate::proof::{verify_w3c_proof, ProofVerificationOptions};

use super::did_wba::{
    find_verification_method, resolve_did_wba_document_sync, resolve_did_wba_document_with_options,
    validate_did_document_binding, AuthenticationError, DidResolutionOptions,
};
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

    let parts: Vec<&str> = did.split(':').collect();
    if parts.len() < 3 {
        return Err(AuthenticationError::InvalidDid);
    }
    let domain = percent_decode_str(parts[2]).decode_utf8_lossy().to_string();
    let path_segments = if parts.len() > 3 {
        &parts[3..]
    } else {
        &[][..]
    };
    let base_url = options
        .base_url_override
        .clone()
        .unwrap_or_else(|| format!("https://{domain}"));
    let url = if path_segments.is_empty() {
        format!("{}/.well-known/did.json", base_url.trim_end_matches('/'))
    } else {
        format!(
            "{}/{}/did.json",
            base_url.trim_end_matches('/'),
            path_segments
                .iter()
                .map(|segment| percent_decode_str(segment).decode_utf8_lossy().to_string())
                .collect::<Vec<String>>()
                .join("/")
        )
    };

    let client = Client::builder()
        .danger_accept_invalid_certs(!options.verify_ssl)
        .timeout(std::time::Duration::from_secs_f64(options.timeout_seconds))
        .build()
        .map_err(|_| AuthenticationError::NetworkFailure)?;
    let document: Value = client
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|_| AuthenticationError::NetworkFailure)?
        .error_for_status()
        .map_err(|_| AuthenticationError::NetworkFailure)?
        .json()
        .await
        .map_err(|_| AuthenticationError::JsonFailure)?;

    if document.get("id").and_then(Value::as_str) != Some(did) {
        return Err(AuthenticationError::InvalidDidDocument);
    }
    if did.starts_with("did:wba:") && !validate_did_document_binding(&document, verify_proof) {
        return Err(AuthenticationError::InvalidDidBinding);
    }
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
