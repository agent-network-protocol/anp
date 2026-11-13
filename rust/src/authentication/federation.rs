use std::collections::BTreeMap;
use std::sync::LazyLock;

use super::http_auth_security::{
    authentication_origin, HttpReplayStore, HttpSignaturePolicy, MemoryHttpReplayStore,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use super::did_resolver::resolve_did_document_with_options;
use super::did_wba::{
    is_authentication_authorized, DidResolutionOptions, ANP_MESSAGE_SERVICE_TYPE,
};
use super::http_signatures::{
    extract_signature_metadata, http_signature_replay_context,
    verify_http_message_signature_with_policy, HttpSignatureError, SignatureMetadata,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedVerificationOptions {
    pub sender_did_document: Option<Value>,
    pub service_did_document: Option<Value>,
    pub service_id: Option<String>,
    pub service_endpoint: Option<String>,
    pub verify_sender_did_proof: bool,
    pub verify_service_did_proof: bool,
    pub did_resolution_options: DidResolutionOptions,
}

impl Default for FederatedVerificationOptions {
    fn default() -> Self {
        Self {
            sender_did_document: None,
            service_did_document: None,
            service_id: None,
            service_endpoint: None,
            verify_sender_did_proof: false,
            verify_service_did_proof: false,
            did_resolution_options: DidResolutionOptions::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedVerificationResult {
    pub sender_did: String,
    pub service_did: String,
    pub service_id: String,
    pub signature_metadata: SignatureMetadata,
}

#[derive(Debug, Error)]
pub enum FederatedVerificationError {
    #[error("Sender DID document ID mismatch")]
    SenderDidMismatch,
    #[error("serviceDid document ID mismatch")]
    ServiceDidMismatch,
    #[error("No ANPMessageService found in DID document")]
    MissingAnpMessageService,
    #[error("Selected ANPMessageService is missing serviceDid")]
    MissingServiceDid,
    #[error("ANPMessageService not found for service_id={0}")]
    ServiceIdNotFound(String),
    #[error("ANPMessageService not found for serviceEndpoint")]
    ServiceEndpointNotFound,
    #[error(
        "Multiple ANPMessageService entries found; service_id or service_endpoint is required"
    )]
    AmbiguousAnpMessageService,
    #[error("Signature keyid DID does not match serviceDid")]
    KeyidDidMismatch,
    #[error("Verification method is not authorized for authentication")]
    UnauthorizedVerificationMethod,
    #[error(transparent)]
    Signature(#[from] HttpSignatureError),
    #[error("DID resolution error: {0}")]
    DidResolution(String),
}

impl FederatedVerificationError {
    /// Distinguish replay-store outages without changing the public error enum.
    /// Hosts must reject these requests, not fall back to weaker authentication.
    pub fn is_replay_store_unavailable(&self) -> bool {
        matches!(self, Self::DidResolution(message) if message == "HTTP replay protection unavailable")
    }
}

/// Explicit dependencies for full federated authentication.
/// The receiver scope and supplied documents must be host-trusted, not peer assertions.
pub struct FederatedHttpSecurity<'a> {
    pub policy: HttpSignaturePolicy,
    pub now: i64,
    pub verifier_scope: &'a str,
    pub replay_store: &'a dyn HttpReplayStore,
}

pub async fn verify_federated_http_request(
    sender_did: &str,
    request_method: &str,
    request_url: &str,
    headers: &BTreeMap<String, String>,
    body: Option<&[u8]>,
    options: FederatedVerificationOptions,
) -> Result<FederatedVerificationResult, FederatedVerificationError> {
    static REPLAY_STORE: LazyLock<MemoryHttpReplayStore> =
        LazyLock::new(MemoryHttpReplayStore::default);
    let scope = authentication_origin(request_url)?;
    verify_federated_http_request_with_security(
        sender_did,
        request_method,
        request_url,
        headers,
        body,
        options,
        FederatedHttpSecurity {
            policy: HttpSignaturePolicy::default(),
            now: chrono::Utc::now().timestamp(),
            verifier_scope: &scope,
            replay_store: &*REPLAY_STORE,
        },
    )
    .await
}

/// Verify identity, signature, time and atomic replay state.
/// Clustered hosts must supply their shared store, never the default memory store.
pub async fn verify_federated_http_request_with_security(
    sender_did: &str,
    request_method: &str,
    request_url: &str,
    headers: &BTreeMap<String, String>,
    body: Option<&[u8]>,
    options: FederatedVerificationOptions,
    security: FederatedHttpSecurity<'_>,
) -> Result<FederatedVerificationResult, FederatedVerificationError> {
    if !security.policy.check_time {
        return Err(HttpSignatureError::InvalidSignatureInput.into());
    }
    let metadata = extract_signature_metadata(headers)?;
    security
        .policy
        .validate(metadata.created, metadata.expires, security.now)?;
    let sender_document = if let Some(document) = options.sender_did_document.clone() {
        document
    } else {
        resolve_did_document_with_options(
            sender_did,
            options.verify_sender_did_proof,
            &options.did_resolution_options,
        )
        .await
        .map_err(|err| FederatedVerificationError::DidResolution(err.to_string()))?
    };
    if sender_document.get("id").and_then(Value::as_str) != Some(sender_did) {
        return Err(FederatedVerificationError::SenderDidMismatch);
    }

    let service = select_anp_message_service(
        &sender_document,
        options.service_id.as_deref(),
        options.service_endpoint.as_deref(),
    )?;
    let service_did = service
        .get("serviceDid")
        .and_then(Value::as_str)
        .ok_or(FederatedVerificationError::MissingServiceDid)?
        .to_string();

    let keyid_did = metadata.keyid.split('#').next().unwrap_or_default();
    if keyid_did != service_did {
        return Err(FederatedVerificationError::KeyidDidMismatch);
    }

    let service_document = if let Some(document) = options.service_did_document.clone() {
        document
    } else {
        resolve_did_document_with_options(
            &service_did,
            options.verify_service_did_proof,
            &options.did_resolution_options,
        )
        .await
        .map_err(|err| FederatedVerificationError::DidResolution(err.to_string()))?
    };
    if service_document.get("id").and_then(Value::as_str) != Some(service_did.as_str()) {
        return Err(FederatedVerificationError::ServiceDidMismatch);
    }
    if !is_authentication_authorized(&service_document, &metadata.keyid) {
        return Err(FederatedVerificationError::UnauthorizedVerificationMethod);
    }

    let verified_metadata = verify_http_message_signature_with_policy(
        &service_document,
        request_method,
        request_url,
        headers,
        body,
        security.policy,
        security.now,
    )?;
    let context = http_signature_replay_context(
        &verified_metadata,
        request_method,
        request_url,
        headers,
        security.verifier_scope,
        security.policy,
    )?;
    let first_use = security
        .replay_store
        .consume_once(&context)
        .await
        .map_err(|_| {
            FederatedVerificationError::DidResolution("HTTP replay protection unavailable".into())
        })?;
    if !first_use {
        return Err(HttpSignatureError::InvalidSignatureInput.into());
    }

    Ok(FederatedVerificationResult {
        sender_did: sender_did.to_string(),
        service_did,
        service_id: service
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        signature_metadata: verified_metadata,
    })
}

fn select_anp_message_service(
    did_document: &Value,
    service_id: Option<&str>,
    service_endpoint: Option<&str>,
) -> Result<Value, FederatedVerificationError> {
    let services = did_document
        .get("service")
        .and_then(Value::as_array)
        .ok_or(FederatedVerificationError::MissingAnpMessageService)?;

    let candidates: Vec<Value> = services
        .iter()
        .filter(|service| {
            service.get("type").and_then(Value::as_str) == Some(ANP_MESSAGE_SERVICE_TYPE)
        })
        .cloned()
        .collect();
    if candidates.is_empty() {
        return Err(FederatedVerificationError::MissingAnpMessageService);
    }

    if let Some(target_id) = service_id {
        return candidates
            .into_iter()
            .find(|service| service.get("id").and_then(Value::as_str) == Some(target_id))
            .ok_or_else(|| FederatedVerificationError::ServiceIdNotFound(target_id.to_string()));
    }

    if let Some(target_endpoint) = service_endpoint {
        return candidates
            .into_iter()
            .find(|service| {
                service.get("serviceEndpoint").and_then(Value::as_str) == Some(target_endpoint)
            })
            .ok_or(FederatedVerificationError::ServiceEndpointNotFound);
    }

    if candidates.len() == 1 {
        return Ok(candidates.into_iter().next().expect("candidate exists"));
    }

    Err(FederatedVerificationError::AmbiguousAnpMessageService)
}
