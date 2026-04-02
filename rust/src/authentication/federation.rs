use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use super::did_resolver::resolve_did_document_with_options;
use super::did_wba::{
    is_authentication_authorized, DidResolutionOptions, ANP_MESSAGE_SERVICE_TYPE,
};
use super::http_signatures::{
    extract_signature_metadata, verify_http_message_signature, HttpSignatureError,
    SignatureMetadata,
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

pub async fn verify_federated_http_request(
    sender_did: &str,
    request_method: &str,
    request_url: &str,
    headers: &BTreeMap<String, String>,
    body: Option<&[u8]>,
    options: FederatedVerificationOptions,
) -> Result<FederatedVerificationResult, FederatedVerificationError> {
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

    let metadata = extract_signature_metadata(headers)?;
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

    let verified_metadata = verify_http_message_signature(
        &service_document,
        request_method,
        request_url,
        headers,
        body,
    )?;

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
