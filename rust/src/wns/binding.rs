use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

use crate::authentication::{resolve_did_wba_document_with_options, DidResolutionOptions};

use super::models::{HandleStatus, ANP_HANDLE_SERVICE_TYPE};
use super::resolver::{resolve_handle_with_options, ResolveHandleOptions};
use super::validator::{build_resolution_url, validate_handle};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BindingVerificationResult {
    pub is_valid: bool,
    pub handle: String,
    pub did: String,
    pub forward_verified: bool,
    pub reverse_verified: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BindingVerificationOptions {
    pub did_document: Option<Value>,
    pub resolution_options: ResolveHandleOptions,
    pub did_resolution_options: DidResolutionOptions,
}

impl Default for BindingVerificationOptions {
    fn default() -> Self {
        Self {
            did_document: None,
            resolution_options: ResolveHandleOptions::default(),
            did_resolution_options: DidResolutionOptions::default(),
        }
    }
}

pub async fn verify_handle_binding(handle: &str) -> BindingVerificationResult {
    verify_handle_binding_with_options(handle, BindingVerificationOptions::default()).await
}

pub async fn verify_handle_binding_with_options(
    handle: &str,
    options: BindingVerificationOptions,
) -> BindingVerificationResult {
    let bare_handle = handle.strip_prefix("wba://").unwrap_or(handle);
    let (local_part, domain) = match validate_handle(bare_handle) {
        Ok(value) => value,
        Err(err) => {
            return BindingVerificationResult {
                is_valid: false,
                handle: bare_handle.to_string(),
                did: String::new(),
                forward_verified: false,
                reverse_verified: false,
                error_message: Some(err.message),
            };
        }
    };
    let normalized_handle = format!("{}.{}", local_part, domain);

    let resolution =
        match resolve_handle_with_options(&normalized_handle, &options.resolution_options).await {
            Ok(value) => value,
            Err(err) => {
                return BindingVerificationResult {
                    is_valid: false,
                    handle: normalized_handle,
                    did: String::new(),
                    forward_verified: false,
                    reverse_verified: false,
                    error_message: Some(format!("Forward resolution failed: {}", err.message)),
                };
            }
        };
    if resolution.status != HandleStatus::Active {
        return BindingVerificationResult {
            is_valid: false,
            handle: normalized_handle,
            did: resolution.did.clone(),
            forward_verified: false,
            reverse_verified: false,
            error_message: Some(
                format!(
                    "Handle status is '{:?}', expected 'active'",
                    resolution.status
                )
                .to_ascii_lowercase(),
            ),
        };
    }
    let did_value = resolution.did.clone();
    if !did_value.starts_with("did:wba:") {
        return BindingVerificationResult {
            is_valid: false,
            handle: normalized_handle,
            did: did_value.clone(),
            forward_verified: true,
            reverse_verified: false,
            error_message: Some("DID does not use did:wba method".to_string()),
        };
    }
    let did_domain = did_value.split(':').nth(2).unwrap_or_default().to_string();
    if did_domain.to_ascii_lowercase() != domain {
        return BindingVerificationResult {
            is_valid: false,
            handle: normalized_handle,
            did: resolution.did,
            forward_verified: true,
            reverse_verified: false,
            error_message: Some(format!(
                "Domain mismatch: handle domain '{}' != DID domain '{}'",
                domain, did_domain
            )),
        };
    }

    let did_document = if let Some(value) = options.did_document {
        value
    } else {
        match resolve_did_wba_document_with_options(
            &resolution.did,
            false,
            &options.did_resolution_options,
        )
        .await
        {
            Ok(value) => value,
            Err(err) => {
                return BindingVerificationResult {
                    is_valid: false,
                    handle: normalized_handle,
                    did: resolution.did,
                    forward_verified: true,
                    reverse_verified: false,
                    error_message: Some(format!("Failed to resolve DID Document: {}", err)),
                };
            }
        }
    };

    let handle_services = extract_handle_service_from_did_document(&did_document);
    let reverse_verified = handle_services.iter().any(|service| {
        service
            .get("serviceEndpoint")
            .and_then(Value::as_str)
            .map(|value| matches_handle_service_domain(value, &domain))
            .unwrap_or(false)
    });
    if !reverse_verified {
        return BindingVerificationResult {
            is_valid: false,
            handle: normalized_handle,
            did: resolution.did,
            forward_verified: true,
            reverse_verified: false,
            error_message: Some(format!(
                "DID Document does not contain an {} entry whose HTTPS domain matches '{}'",
                ANP_HANDLE_SERVICE_TYPE, domain
            )),
        };
    }

    BindingVerificationResult {
        is_valid: true,
        handle: normalized_handle,
        did: resolution.did,
        forward_verified: true,
        reverse_verified: true,
        error_message: None,
    }
}

pub fn build_handle_service_entry(did: &str, local_part: &str, domain: &str) -> Value {
    json!({
        "id": format!("{did}#handle"),
        "type": ANP_HANDLE_SERVICE_TYPE,
        "serviceEndpoint": build_resolution_url(local_part, domain),
    })
}

pub fn extract_handle_service_from_did_document(did_document: &Value) -> Vec<Value> {
    did_document
        .get("service")
        .and_then(Value::as_array)
        .map(|services| {
            services
                .iter()
                .filter(|service| {
                    service.get("type").and_then(Value::as_str) == Some(ANP_HANDLE_SERVICE_TYPE)
                })
                .cloned()
                .collect::<Vec<Value>>()
        })
        .unwrap_or_default()
}

fn matches_handle_service_domain(service_endpoint: &str, expected_domain: &str) -> bool {
    Url::parse(service_endpoint)
        .ok()
        .and_then(|url| {
            url.host_str().map(|host| {
                url.scheme().eq_ignore_ascii_case("https")
                    && host.eq_ignore_ascii_case(expected_domain)
            })
        })
        .unwrap_or(false)
}
