use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::keys::base64url_encode;
use crate::PrivateKeyMaterial;

use super::did_wba::find_verification_method;
use super::verification_methods::extract_public_key;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpSignatureOptions {
    pub keyid: Option<String>,
    pub nonce: Option<String>,
    pub created: Option<i64>,
    pub expires: Option<i64>,
    pub covered_components: Option<Vec<String>>,
}

impl Default for HttpSignatureOptions {
    fn default() -> Self {
        Self {
            keyid: None,
            nonce: None,
            created: None,
            expires: None,
            covered_components: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMetadata {
    pub label: String,
    pub components: Vec<String>,
    pub keyid: String,
    pub nonce: Option<String>,
    pub created: i64,
    pub expires: Option<i64>,
}

#[derive(Debug, Error)]
pub enum HttpSignatureError {
    #[error("Missing Signature-Input or Signature header")]
    MissingSignatureHeaders,
    #[error("Invalid signature header format")]
    InvalidSignatureFormat,
    #[error("Invalid signature input")]
    InvalidSignatureInput,
    #[error("Missing Content-Digest header")]
    MissingContentDigest,
    #[error("Content-Digest verification failed")]
    InvalidContentDigest,
    #[error("Verification method not found")]
    VerificationMethodNotFound,
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Signing failed")]
    SigningFailed,
}

pub fn build_content_digest(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!("sha-256=:{}:", STANDARD.encode(digest))
}

pub fn verify_content_digest(body: &[u8], content_digest: &str) -> bool {
    build_content_digest(body) == content_digest.trim()
}

pub fn generate_http_signature_headers(
    did_document: &serde_json::Value,
    request_url: &str,
    request_method: &str,
    private_key: &PrivateKeyMaterial,
    headers: Option<&BTreeMap<String, String>>,
    body: Option<&[u8]>,
    options: HttpSignatureOptions,
) -> Result<BTreeMap<String, String>, HttpSignatureError> {
    let keyid = if let Some(value) = options.keyid.clone() {
        value
    } else {
        select_default_keyid(did_document)?
    };
    let components = options.covered_components.unwrap_or_else(|| {
        vec![
            "@method".to_string(),
            "@target-uri".to_string(),
            "@authority".to_string(),
        ]
    });
    let mut headers_to_sign = headers.cloned().unwrap_or_default();
    let body_bytes = body.unwrap_or_default();
    let mut covered = components.clone();
    if !body_bytes.is_empty() {
        headers_to_sign
            .entry("Content-Digest".to_string())
            .or_insert_with(|| build_content_digest(body_bytes));
        headers_to_sign
            .entry("Content-Length".to_string())
            .or_insert_with(|| body_bytes.len().to_string());
        if !covered.iter().any(|value| value.eq_ignore_ascii_case("content-digest")) {
            covered.push("content-digest".to_string());
        }
    }
    let created = options
        .created
        .unwrap_or_else(|| Utc::now().timestamp());
    let expires = options.expires.or(Some(created + 300));
    let nonce = options
        .nonce
        .or_else(|| Some(base64url_encode(&rand::random::<[u8; 16]>())));
    let signature_base = build_signature_base(
        &covered,
        request_method,
        request_url,
        &headers_to_sign,
        created,
        expires,
        nonce.as_deref(),
        &keyid,
    )
    .map_err(|_| HttpSignatureError::InvalidSignatureInput)?;
    let signature = private_key
        .sign_message(signature_base.as_bytes())
        .map_err(|_| HttpSignatureError::SigningFailed)?;
    let signature_input = format!(
        "sig1={}",
        serialize_signature_params(&covered, created, expires, nonce.as_deref(), &keyid)
    );
    let signature_header = format!("sig1=:{}:", STANDARD.encode(signature));
    let mut result = BTreeMap::new();
    result.insert("Signature-Input".to_string(), signature_input);
    result.insert("Signature".to_string(), signature_header);
    if let Some(value) = headers_to_sign.get("Content-Digest") {
        result.insert("Content-Digest".to_string(), value.clone());
    }
    Ok(result)
}

pub fn extract_signature_metadata(
    headers: &BTreeMap<String, String>,
) -> Result<SignatureMetadata, HttpSignatureError> {
    let signature_input = get_header_case_insensitive(headers, "Signature-Input")
        .ok_or(HttpSignatureError::MissingSignatureHeaders)?;
    let signature_header = get_header_case_insensitive(headers, "Signature")
        .ok_or(HttpSignatureError::MissingSignatureHeaders)?;
    let (label_input, components, params) = parse_signature_input(signature_input)?;
    let (label_signature, _) = parse_signature_header(signature_header)?;
    if label_input != label_signature {
        return Err(HttpSignatureError::InvalidSignatureInput);
    }
    let keyid = params
        .get("keyid")
        .cloned()
        .ok_or(HttpSignatureError::InvalidSignatureInput)?;
    let created = params
        .get("created")
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or(HttpSignatureError::InvalidSignatureInput)?;
    let expires = params.get("expires").and_then(|value| value.parse::<i64>().ok());
    let nonce = params.get("nonce").cloned();
    Ok(SignatureMetadata {
        label: label_input,
        components,
        keyid,
        nonce,
        created,
        expires,
    })
}

pub fn verify_http_message_signature(
    did_document: &serde_json::Value,
    request_method: &str,
    request_url: &str,
    headers: &BTreeMap<String, String>,
    body: Option<&[u8]>,
) -> Result<SignatureMetadata, HttpSignatureError> {
    let signature_input = get_header_case_insensitive(headers, "Signature-Input")
        .ok_or(HttpSignatureError::MissingSignatureHeaders)?;
    let signature_header = get_header_case_insensitive(headers, "Signature")
        .ok_or(HttpSignatureError::MissingSignatureHeaders)?;
    let (label_input, components, params) = parse_signature_input(signature_input)?;
    let (label_signature, signature_bytes) = parse_signature_header(signature_header)?;
    if label_input != label_signature {
        return Err(HttpSignatureError::InvalidSignatureInput);
    }
    let keyid = params
        .get("keyid")
        .cloned()
        .ok_or(HttpSignatureError::InvalidSignatureInput)?;
    let created = params
        .get("created")
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or(HttpSignatureError::InvalidSignatureInput)?;
    let expires = params.get("expires").and_then(|value| value.parse::<i64>().ok());
    let nonce = params.get("nonce").cloned();

    let body_bytes = body.unwrap_or_default();
    if !body_bytes.is_empty()
        || components.iter().any(|value| value.eq_ignore_ascii_case("content-digest"))
    {
        let digest = get_header_case_insensitive(headers, "Content-Digest")
            .ok_or(HttpSignatureError::MissingContentDigest)?;
        if !verify_content_digest(body_bytes, digest) {
            return Err(HttpSignatureError::InvalidContentDigest);
        }
    }

    let method = find_verification_method(did_document, &keyid)
        .ok_or(HttpSignatureError::VerificationMethodNotFound)?;
    let public_key = extract_public_key(&method)
        .map_err(|_| HttpSignatureError::VerificationMethodNotFound)?;
    let signature_base = build_signature_base(
        &components,
        request_method,
        request_url,
        headers,
        created,
        expires,
        nonce.as_deref(),
        &keyid,
    )
    .map_err(|_| HttpSignatureError::InvalidSignatureInput)?;
    public_key
        .verify_message(signature_base.as_bytes(), &signature_bytes)
        .map_err(|_| HttpSignatureError::VerificationFailed)?;
    Ok(SignatureMetadata {
        label: label_input,
        components,
        keyid,
        nonce,
        created,
        expires,
    })
}

fn get_header_case_insensitive<'a>(
    headers: &'a BTreeMap<String, String>,
    name: &str,
) -> Option<&'a String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn build_signature_base(
    components: &[String],
    method: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
    created: i64,
    expires: Option<i64>,
    nonce: Option<&str>,
    keyid: &str,
) -> Result<String, HttpSignatureError> {
    let mut lines = Vec::new();
    for component in components {
        let value = component_value(component, method, url, headers)?;
        lines.push(format!("\"{}\": {}", component, value));
    }
    lines.push(format!(
        "\"@signature-params\": {}",
        serialize_signature_params(components, created, expires, nonce, keyid)
    ));
    Ok(lines.join("\n"))
}

fn component_value(
    component: &str,
    method: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
) -> Result<String, HttpSignatureError> {
    match component {
        "@method" => Ok(method.to_uppercase()),
        "@target-uri" => Ok(url.to_string()),
        "@authority" => {
            let parsed = Url::parse(url).map_err(|_| HttpSignatureError::InvalidSignatureInput)?;
            let host = parsed.host_str().unwrap_or_default();
            if let Some(port) = parsed.port() {
                Ok(format!("{}:{}", host, port))
            } else {
                Ok(host.to_string())
            }
        }
        other => get_header_case_insensitive(headers, other)
            .cloned()
            .ok_or(HttpSignatureError::InvalidSignatureInput),
    }
}

fn serialize_signature_params(
    components: &[String],
    created: i64,
    expires: Option<i64>,
    nonce: Option<&str>,
    keyid: &str,
) -> String {
    let quoted = components
        .iter()
        .map(|value| format!("\"{}\"", value))
        .collect::<Vec<String>>()
        .join(" ");
    let mut params = vec![format!("created={created}")];
    if let Some(value) = expires {
        params.push(format!("expires={value}"));
    }
    if let Some(value) = nonce {
        params.push(format!("nonce=\"{}\"", value));
    }
    params.push(format!("keyid=\"{}\"", keyid));
    format!("({quoted});{}", params.join(";"))
}

fn parse_signature_input(
    signature_input: &str,
) -> Result<(String, Vec<String>, BTreeMap<String, String>), HttpSignatureError> {
    let (label, remainder) = signature_input
        .split_once('=')
        .ok_or(HttpSignatureError::InvalidSignatureInput)?;
    let open_index = remainder.find('(').ok_or(HttpSignatureError::InvalidSignatureInput)?;
    let close_index = remainder.find(')').ok_or(HttpSignatureError::InvalidSignatureInput)?;
    let components_raw = &remainder[open_index + 1..close_index];
    let params_raw = remainder[close_index + 1..].trim_start_matches(';');
    let components = components_raw
        .split_whitespace()
        .map(|value| value.trim_matches('"').to_string())
        .collect::<Vec<String>>();
    if components.is_empty() {
        return Err(HttpSignatureError::InvalidSignatureInput);
    }
    let mut params = BTreeMap::new();
    for raw in params_raw.split(';') {
        if raw.trim().is_empty() {
            continue;
        }
        let (name, value) = raw
            .split_once('=')
            .ok_or(HttpSignatureError::InvalidSignatureInput)?;
        params.insert(name.to_string(), value.trim_matches('"').to_string());
    }
    Ok((label.to_string(), components, params))
}

fn parse_signature_header(
    signature_header: &str,
) -> Result<(String, Vec<u8>), HttpSignatureError> {
    let (label, remainder) = signature_header
        .split_once('=')
        .ok_or(HttpSignatureError::InvalidSignatureFormat)?;
    let value = remainder
        .strip_prefix(':')
        .and_then(|item| item.strip_suffix(':'))
        .ok_or(HttpSignatureError::InvalidSignatureFormat)?;
    let bytes = STANDARD
        .decode(value.as_bytes())
        .map_err(|_| HttpSignatureError::InvalidSignatureFormat)?;
    Ok((label.to_string(), bytes))
}

fn select_default_keyid(did_document: &serde_json::Value) -> Result<String, HttpSignatureError> {
    let authentication = did_document
        .get("authentication")
        .and_then(serde_json::Value::as_array)
        .ok_or(HttpSignatureError::VerificationMethodNotFound)?;
    let first = authentication
        .first()
        .ok_or(HttpSignatureError::VerificationMethodNotFound)?;
    if let Some(value) = first.as_str() {
        return Ok(value.to_string());
    }
    first
        .get("id")
        .and_then(serde_json::Value::as_str)
        .map(|value| value.to_string())
        .ok_or(HttpSignatureError::VerificationMethodNotFound)
}
