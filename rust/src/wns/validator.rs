use regex::Regex;

use super::errors::{HandleValidationError, WbaUriParseError};
use super::models::ParsedWbaUri;

pub fn validate_local_part(local_part: &str) -> bool {
    let normalized = local_part.to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 63 {
        return false;
    }
    if normalized.starts_with('-') || normalized.ends_with('-') {
        return false;
    }
    if normalized.contains("--") {
        return false;
    }
    normalized
        .chars()
        .all(|value| value.is_ascii_lowercase() || value.is_ascii_digit() || value == '-')
}

pub fn validate_handle(handle: &str) -> Result<(String, String), HandleValidationError> {
    let normalized = handle.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Err(HandleValidationError {
            message: "Handle must not be empty".to_string(),
            status_code: 400,
        });
    }
    let dot_index = normalized.find('.').ok_or(HandleValidationError {
        message: format!("Handle must contain at least one dot: '{}'", handle),
        status_code: 400,
    })?;
    let local_part = normalized[..dot_index].to_string();
    let domain = normalized[dot_index + 1..].to_string();
    if local_part.is_empty() {
        return Err(HandleValidationError {
            message: format!("Handle local-part is empty: '{}'", handle),
            status_code: 400,
        });
    }
    if domain.is_empty() {
        return Err(HandleValidationError {
            message: format!("Handle domain is empty: '{}'", handle),
            status_code: 400,
        });
    }
    if !validate_local_part(&local_part) {
        return Err(HandleValidationError {
            message: format!(
                "Invalid local-part '{}': must be 1-63 chars of a-z, 0-9, hyphen; must start/end with alnum; no consecutive hyphens",
                local_part
            ),
            status_code: 400,
        });
    }
    if !is_valid_domain(&domain) {
        return Err(HandleValidationError {
            message: format!("Invalid domain '{}'", domain),
            status_code: 400,
        });
    }
    Ok((local_part, domain))
}

pub fn normalize_handle(handle: &str) -> Result<String, HandleValidationError> {
    let (local_part, domain) = validate_handle(handle)?;
    Ok(format!("{}.{}", local_part, domain))
}

pub fn parse_wba_uri(uri: &str) -> Result<ParsedWbaUri, WbaUriParseError> {
    if !uri.starts_with("wba://") {
        return Err(WbaUriParseError {
            message: format!("URI must start with 'wba://': '{}'", uri),
            status_code: 400,
        });
    }
    let handle_part = &uri[6..];
    if handle_part.is_empty() {
        return Err(WbaUriParseError {
            message: format!("URI contains no handle after 'wba://': '{}'", uri),
            status_code: 400,
        });
    }
    let (local_part, domain) = validate_handle(handle_part).map_err(|err| WbaUriParseError {
        message: format!("Invalid handle in URI '{}': {}", uri, err.message),
        status_code: 400,
    })?;
    Ok(ParsedWbaUri {
        local_part: local_part.clone(),
        domain: domain.clone(),
        handle: format!("{}.{}", local_part, domain),
        original_uri: uri.to_string(),
    })
}

pub fn build_resolution_url(local_part: &str, domain: &str) -> String {
    format!("https://{}/.well-known/handle/{}", domain, local_part)
}

pub fn build_wba_uri(local_part: &str, domain: &str) -> String {
    format!("wba://{}.{}", local_part, domain)
}

fn is_valid_domain(domain: &str) -> bool {
    let label_re =
        Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$").expect("domain regex must compile");
    let labels = domain.split('.').collect::<Vec<&str>>();
    if labels.len() < 2 {
        return false;
    }
    labels.iter().all(|label| label_re.is_match(label))
}
