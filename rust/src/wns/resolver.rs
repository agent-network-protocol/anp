use reqwest::Client;
use serde_json::Value;

use super::errors::{
    HandleGoneError, HandleMovedError, HandleNotFoundError, HandleResolutionError,
};
use super::models::HandleResolutionDocument;
use super::validator::{build_resolution_url, parse_wba_uri, validate_handle};

#[derive(Debug, Clone)]
pub struct ResolveHandleOptions {
    pub timeout_seconds: f64,
    pub verify_ssl: bool,
    pub base_url_override: Option<String>,
}

impl Default for ResolveHandleOptions {
    fn default() -> Self {
        Self {
            timeout_seconds: 10.0,
            verify_ssl: true,
            base_url_override: None,
        }
    }
}

pub async fn resolve_handle(
    handle: &str,
) -> Result<HandleResolutionDocument, HandleResolutionError> {
    resolve_handle_with_options(handle, &ResolveHandleOptions::default()).await
}

pub async fn resolve_handle_with_options(
    handle: &str,
    options: &ResolveHandleOptions,
) -> Result<HandleResolutionDocument, HandleResolutionError> {
    let bare_handle = strip_wba_scheme(handle);
    let (local_part, domain) =
        validate_handle(bare_handle).map_err(|err| HandleResolutionError {
            message: err.message,
            status_code: 400,
        })?;
    let url = options
        .base_url_override
        .as_ref()
        .map(|base| {
            format!(
                "{}/.well-known/handle/{}",
                base.trim_end_matches('/'),
                local_part
            )
        })
        .unwrap_or_else(|| build_resolution_url(&local_part, &domain));
    let normalized = format!("{}.{}", local_part, domain);
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs_f64(options.timeout_seconds))
        .build()
        .map_err(|_| HandleResolutionError {
            message: format!("Unexpected error resolving handle '{}'", normalized),
            status_code: 502,
        })?;
    let response = client
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|err| HandleResolutionError {
            message: format!("Network error resolving handle '{}': {}", normalized, err),
            status_code: 502,
        })?;

    let status = response.status();
    if status.as_u16() == 301 {
        let redirect_url = response
            .headers()
            .get("Location")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string();
        return Err(HandleResolutionError {
            message: HandleMovedError {
                message: format!("Handle '{}' has been migrated", normalized),
                status_code: 301,
                redirect_url,
            }
            .message,
            status_code: 301,
        });
    }
    if status.as_u16() == 404 {
        return Err(HandleResolutionError {
            message: HandleNotFoundError {
                message: format!("Handle '{}' does not exist", normalized),
                status_code: 404,
            }
            .message,
            status_code: 404,
        });
    }
    if status.as_u16() == 410 {
        return Err(HandleResolutionError {
            message: HandleGoneError {
                message: format!("Handle '{}' has been permanently revoked", normalized),
                status_code: 410,
            }
            .message,
            status_code: 410,
        });
    }
    if status.as_u16() != 200 {
        let text = response.text().await.unwrap_or_default();
        return Err(HandleResolutionError {
            message: format!(
                "Unexpected status {} resolving '{}': {}",
                status.as_u16(),
                normalized,
                text
            ),
            status_code: 502,
        });
    }

    let data: Value = response.json().await.map_err(|err| HandleResolutionError {
        message: format!(
            "Unexpected error resolving handle '{}': {}",
            normalized, err
        ),
        status_code: 502,
    })?;
    let document: HandleResolutionDocument =
        serde_json::from_value(data).map_err(|err| HandleResolutionError {
            message: format!(
                "Unexpected error resolving handle '{}': {}",
                normalized, err
            ),
            status_code: 502,
        })?;
    if document.handle.to_ascii_lowercase() != normalized {
        return Err(HandleResolutionError {
            message: format!(
                "Handle mismatch: requested '{}', got '{}'",
                normalized, document.handle
            ),
            status_code: 502,
        });
    }
    Ok(document)
}

pub fn resolve_handle_sync(
    handle: &str,
) -> Result<HandleResolutionDocument, HandleResolutionError> {
    let runtime = tokio::runtime::Runtime::new().map_err(|_| HandleResolutionError {
        message: "Unable to start runtime".to_string(),
        status_code: 502,
    })?;
    runtime.block_on(resolve_handle(handle))
}

pub async fn resolve_handle_from_uri(
    wba_uri: &str,
) -> Result<HandleResolutionDocument, HandleResolutionError> {
    let parsed = parse_wba_uri(wba_uri).map_err(|err| HandleResolutionError {
        message: err.message,
        status_code: 400,
    })?;
    resolve_handle(&parsed.handle).await
}

fn strip_wba_scheme(handle_or_uri: &str) -> &str {
    handle_or_uri
        .strip_prefix("wba://")
        .unwrap_or(handle_or_uri)
}
