use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use super::http_auth_security::{HttpReplayContext, HttpSignaturePolicy};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
#[cfg(feature = "network")]
use url::Url;

use crate::keys::base64url_encode;
use crate::PrivateKeyMaterial;

use super::did_wba::{
    find_verification_method, is_authentication_authorized, normalize_authentication_kid,
};
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
    #[error("Invalid or foreign verification method KID")]
    InvalidKeyId,
    #[error("Verification method is not authorized for authentication")]
    UnauthorizedVerificationMethod,
    #[error("Signature verification failed")]
    VerificationFailed,
    #[error("Signing failed")]
    SigningFailed,
}

/// HTTP Message Signature data prepared for an external signer.
pub struct PreparedHttpSignature {
    headers: BTreeMap<String, String>,
    signing_input: Vec<u8>,
    public_key: crate::PublicKeyMaterial,
}

impl PreparedHttpSignature {
    /// Returns the exact HTTP signature base bytes to sign.
    pub fn signing_input(&self) -> &[u8] {
        &self.signing_input
    }
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
    let prepared = prepare_http_signature_headers(
        did_document,
        request_url,
        request_method,
        headers,
        body,
        options,
    )?;
    let signature = private_key
        .sign_message(prepared.signing_input())
        .map_err(|_| HttpSignatureError::SigningFailed)?;
    Ok(complete_http_signature_headers_unchecked(
        prepared, &signature,
    ))
}

/// Generates HTTP Message Signature headers with an explicit authentication KID.
pub fn generate_http_signature_headers_with_kid(
    did_document: &serde_json::Value,
    request_url: &str,
    request_method: &str,
    private_key: &PrivateKeyMaterial,
    headers: Option<&BTreeMap<String, String>>,
    body: Option<&[u8]>,
    kid: &str,
    mut options: HttpSignatureOptions,
) -> Result<BTreeMap<String, String>, HttpSignatureError> {
    options.keyid = Some(kid.to_string());
    let prepared = prepare_http_signature_headers(
        did_document,
        request_url,
        request_method,
        headers,
        body,
        options,
    )?;
    let signature = private_key
        .sign_message(prepared.signing_input())
        .map_err(|_| HttpSignatureError::SigningFailed)?;
    complete_http_signature_headers(prepared, &signature)
}

/// Prepares HTTP Message Signature headers for an external signer.
pub fn prepare_http_signature_headers(
    did_document: &serde_json::Value,
    request_url: &str,
    request_method: &str,
    headers: Option<&BTreeMap<String, String>>,
    body: Option<&[u8]>,
    options: HttpSignatureOptions,
) -> Result<PreparedHttpSignature, HttpSignatureError> {
    let did = did_document
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or(HttpSignatureError::InvalidKeyId)?;
    let requested_keyid = if let Some(value) = options.keyid.clone() {
        value
    } else {
        select_default_keyid(did_document)?
    };
    let keyid = normalize_authentication_kid(did, &requested_keyid)
        .map_err(|_| HttpSignatureError::InvalidKeyId)?;
    if !is_authentication_authorized(did_document, &keyid) {
        return Err(HttpSignatureError::UnauthorizedVerificationMethod);
    }
    let method = find_verification_method(did_document, &keyid)
        .ok_or(HttpSignatureError::VerificationMethodNotFound)?;
    let public_key =
        extract_public_key(&method).map_err(|_| HttpSignatureError::VerificationMethodNotFound)?;
    let components = options.covered_components.unwrap_or_else(|| {
        vec![
            "@method".to_string(),
            "@target-uri".to_string(),
            "@authority".to_string(),
        ]
    });
    let mut headers_to_sign = headers.cloned().unwrap_or_default();
    let body_present = body.is_some();
    let body_bytes = body.unwrap_or_default();
    let mut covered = components.clone();
    if body_present {
        headers_to_sign
            .entry("Content-Digest".to_string())
            .or_insert_with(|| build_content_digest(body_bytes));
        headers_to_sign
            .entry("Content-Length".to_string())
            .or_insert_with(|| body_bytes.len().to_string());
        if !covered
            .iter()
            .any(|value| value.eq_ignore_ascii_case("content-digest"))
        {
            covered.push("content-digest".to_string());
        }
    }
    if !covered.iter().any(|c| c == "@method") || !covered.iter().any(|c| c == "@target-uri") {
        return Err(HttpSignatureError::InvalidSignatureInput);
    }
    let created = options.created.unwrap_or_else(|| Utc::now().timestamp());
    let expires = options.expires.or_else(|| created.checked_add(300));
    HttpSignaturePolicy {
        check_time: false,
        ..Default::default()
    }
    .validate(created, expires, created)?;
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
    let signature_input = format!(
        "sig1={}",
        serialize_signature_params(&covered, created, expires, nonce.as_deref(), &keyid)
    );
    let mut result = BTreeMap::new();
    result.insert("Signature-Input".to_string(), signature_input);
    if let Some(value) = headers_to_sign.get("Content-Digest") {
        result.insert("Content-Digest".to_string(), value.clone());
    }
    Ok(PreparedHttpSignature {
        headers: result,
        signing_input: signature_base.into_bytes(),
        public_key,
    })
}

/// Completes prepared HTTP Message Signature headers with an external signature.
pub fn complete_http_signature_headers(
    prepared: PreparedHttpSignature,
    signature: &[u8],
) -> Result<BTreeMap<String, String>, HttpSignatureError> {
    prepared
        .public_key
        .verify_message(&prepared.signing_input, signature)
        .map_err(|_| HttpSignatureError::SigningFailed)?;
    Ok(complete_http_signature_headers_unchecked(
        prepared, signature,
    ))
}

fn complete_http_signature_headers_unchecked(
    mut prepared: PreparedHttpSignature,
    signature: &[u8],
) -> BTreeMap<String, String> {
    prepared.headers.insert(
        "Signature".to_string(),
        format!("sig1=:{}:", STANDARD.encode(signature)),
    );
    prepared.headers
}

pub fn extract_signature_metadata(
    headers: &BTreeMap<String, String>,
) -> Result<SignatureMetadata, HttpSignatureError> {
    let signature_input = get_header_case_insensitive(headers, "Signature-Input")
        .ok_or(HttpSignatureError::MissingSignatureHeaders)?;
    let signature_header = get_header_case_insensitive(headers, "Signature")
        .ok_or(HttpSignatureError::MissingSignatureHeaders)?;
    let (label_input, components, params, _) = parse_signature_input(signature_input)?;
    let (label_signature, _) = parse_signature_header(signature_header)?;
    if label_input != label_signature {
        return Err(HttpSignatureError::InvalidSignatureInput);
    }
    let keyid = required_signature_param(&params, "keyid")?;
    if !keyid.starts_with("did:") || keyid.matches('#').count() != 1 || keyid.ends_with('#') {
        return Err(HttpSignatureError::InvalidKeyId);
    }
    let created = params
        .get("created")
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or(HttpSignatureError::InvalidSignatureInput)?;
    let expires = parse_optional_i64_param(&params, "expires")?;
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
    verify_http_message_signature_with_policy(
        did_document,
        request_method,
        request_url,
        headers,
        body,
        HttpSignaturePolicy::default(),
        Utc::now().timestamp(),
    )
}

/// Verify coverage, time and cryptographic validity without replay I/O.
/// Offline callers must explicitly select check_time=false. Full authentication
/// additionally requires a trusted Document/receiver and atomic replay consumption.
pub fn verify_http_message_signature_with_policy(
    did_document: &serde_json::Value,
    request_method: &str,
    request_url: &str,
    headers: &BTreeMap<String, String>,
    body: Option<&[u8]>,
    policy: HttpSignaturePolicy,
    now: i64,
) -> Result<SignatureMetadata, HttpSignatureError> {
    let signature_input = get_header_case_insensitive(headers, "Signature-Input")
        .ok_or(HttpSignatureError::MissingSignatureHeaders)?;
    let signature_header = get_header_case_insensitive(headers, "Signature")
        .ok_or(HttpSignatureError::MissingSignatureHeaders)?;
    let (label_input, components, params, serialized_params) =
        parse_signature_input(signature_input)?;
    let (label_signature, signature_bytes) = parse_signature_header(signature_header)?;
    if label_input != label_signature {
        return Err(HttpSignatureError::InvalidSignatureInput);
    }
    let keyid = required_signature_param(&params, "keyid")?;
    if !keyid.starts_with("did:") || keyid.matches('#').count() != 1 || keyid.ends_with('#') {
        return Err(HttpSignatureError::InvalidKeyId);
    }
    let created = params
        .get("created")
        .and_then(|value| value.parse::<i64>().ok())
        .ok_or(HttpSignatureError::InvalidSignatureInput)?;
    let expires = parse_optional_i64_param(&params, "expires")?;
    let nonce = params.get("nonce").cloned();

    policy.validate(created, expires, now)?;
    if nonce
        .as_ref()
        .is_some_and(|n| n.is_empty() || n.len() > 1024)
        || !components.iter().any(|c| c == "@method")
        || !components.iter().any(|c| c == "@target-uri")
    {
        return Err(HttpSignatureError::InvalidSignatureInput);
    }
    let body_bytes = body.unwrap_or_default();
    if !body_bytes.is_empty() && !components.iter().any(|c| c == "content-digest") {
        return Err(HttpSignatureError::InvalidSignatureInput);
    }
    if !body_bytes.is_empty()
        || components
            .iter()
            .any(|value| value.eq_ignore_ascii_case("content-digest"))
    {
        let digest = get_header_case_insensitive(headers, "Content-Digest")
            .ok_or(HttpSignatureError::MissingContentDigest)?;
        if !verify_content_digest(body_bytes, digest) {
            return Err(HttpSignatureError::InvalidContentDigest);
        }
    }

    let did = did_document
        .get("id")
        .and_then(serde_json::Value::as_str)
        .ok_or(HttpSignatureError::InvalidKeyId)?;
    let normalized_keyid =
        normalize_authentication_kid(did, &keyid).map_err(|_| HttpSignatureError::InvalidKeyId)?;
    if !is_authentication_authorized(did_document, &normalized_keyid) {
        return Err(HttpSignatureError::UnauthorizedVerificationMethod);
    }
    let method = find_verification_method(did_document, &normalized_keyid)
        .ok_or(HttpSignatureError::VerificationMethodNotFound)?;
    let public_key =
        extract_public_key(&method).map_err(|_| HttpSignatureError::VerificationMethodNotFound)?;
    let signature_base = build_signature_base_with_params(
        &components,
        request_method,
        request_url,
        headers,
        &serialized_params,
    )
    .map_err(|_| HttpSignatureError::InvalidSignatureInput)?;
    let candidates = authority_candidates(request_url)?;
    let mut bases = vec![signature_base.clone()];
    if components.iter().any(|c| c == "@authority") {
        bases.extend(
            candidates
                .iter()
                .map(|authority| replace_authority(&signature_base, authority)),
        );
    }
    if !bases.iter().any(|base| {
        public_key
            .verify_message(base.as_bytes(), &signature_bytes)
            .is_ok()
    }) {
        return Err(HttpSignatureError::VerificationFailed);
    }
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
    let mut matches = headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name));
    let (_, value) = matches.next()?;
    if matches.next().is_some()
        || value.len() > 16384
        || value.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0 | 127))
    {
        return None;
    }
    Some(value)
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

fn build_signature_base_with_params(
    components: &[String],
    method: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
    serialized_params: &str,
) -> Result<String, HttpSignatureError> {
    let mut lines = Vec::new();
    for component in components {
        lines.push(format!(
            "\"{}\": {}",
            component,
            component_value(component, method, url, headers)?
        ));
    }
    lines.push(format!("\"@signature-params\": {}", serialized_params));
    Ok(lines.join("\n"))
}

/// Derive replay facts only AFTER a successful signature/identity/target check.
/// The scope must be the host-configured logical receiving service, shared by replicas.
pub fn http_signature_replay_context(
    metadata: &SignatureMetadata,
    method: &str,
    url: &str,
    headers: &BTreeMap<String, String>,
    scope: &str,
    policy: HttpSignaturePolicy,
) -> Result<HttpReplayContext, HttpSignatureError> {
    if scope.is_empty() || scope.contains('\0') {
        return Err(HttpSignatureError::InvalidSignatureInput);
    }
    let input = get_header_case_insensitive(headers, "Signature-Input")
        .ok_or(HttpSignatureError::MissingSignatureHeaders)?;
    let (_, components, _, params) = parse_signature_input(input)?;
    let base = build_signature_base_with_params(&components, method, url, headers, &params)?;
    let origin = super::http_auth_security::authentication_origin(url)?;
    let base = replace_authority(
        &base,
        origin
            .split_once("://")
            .ok_or(HttpSignatureError::InvalidSignatureInput)?
            .1,
    );
    let did = metadata
        .keyid
        .split_once('#')
        .ok_or(HttpSignatureError::InvalidKeyId)?
        .0;
    let material = match &metadata.nonce {
        Some(nonce) => format!("nonce:{nonce}"),
        None => format!("base:{:x}", Sha256::digest(base.as_bytes())),
    };
    let key = format!("anp.http-auth.replay.v1\0{scope}\0{did}\0{material}");
    let deadline = policy.validate(metadata.created, metadata.expires, metadata.created)?;
    Ok(HttpReplayContext {
        signer_did: did.to_owned(),
        verifier_scope: scope.to_owned(),
        replay_key: format!("{:x}", Sha256::digest(key.as_bytes())),
        valid_until: deadline.saturating_add(policy.future_skew_seconds),
    })
}

fn replace_authority(base: &str, authority: &str) -> String {
    base.lines()
        .map(|line| {
            if line.starts_with("\"@authority\": ") {
                format!("\"@authority\": {authority}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}
fn authority_candidates(url: &str) -> Result<Vec<String>, HttpSignatureError> {
    let origin = super::http_auth_security::authentication_origin(url)?;
    let raw = url
        .split_once("://")
        .ok_or(HttpSignatureError::InvalidSignatureInput)?
        .1
        .split(['/', '?'])
        .next()
        .unwrap_or_default();
    let normalized = origin
        .split_once("://")
        .ok_or(HttpSignatureError::InvalidSignatureInput)?
        .1;
    let default = if url.starts_with("https://") {
        ":443"
    } else {
        ":80"
    };
    let mut result = Vec::new();
    for authority in [raw, normalized] {
        for value in [
            authority,
            authority.strip_suffix(default).unwrap_or(authority),
        ] {
            result.push(value.to_owned());
            result.push(value.replace(['[', ']'], ""));
        }
    }
    result.sort();
    result.dedup();
    Ok(result)
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
        "@authority" => extract_url_authority(url).ok_or(HttpSignatureError::InvalidSignatureInput),
        other => get_header_case_insensitive(headers, other)
            .cloned()
            .ok_or(HttpSignatureError::InvalidSignatureInput),
    }
}

fn extract_url_authority(url: &str) -> Option<String> {
    #[cfg(feature = "network")]
    {
        let parsed = Url::parse(url).ok()?;
        let host = parsed.host_str()?;
        return if let Some(port) = parsed.port() {
            Some(format!("{host}:{port}"))
        } else {
            Some(host.to_string())
        };
    }

    #[cfg(not(feature = "network"))]
    {
        let (_, rest) = url.split_once("://")?;
        let authority = rest
            .split(['/', '?', '#'])
            .next()
            .unwrap_or_default()
            .trim();
        if authority.is_empty() || authority.contains('@') {
            return None;
        }
        Some(authority.to_string())
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
        params.push(format!(
            "nonce=\"{}\"",
            value.replace('\\', "\\\\").replace('"', "\\\"")
        ));
    }
    params.push(format!(
        "keyid=\"{}\"",
        keyid.replace('\\', "\\\\").replace('"', "\\\"")
    ));
    format!("({quoted});{}", params.join(";"))
}

fn parse_signature_input(
    signature_input: &str,
) -> Result<(String, Vec<String>, BTreeMap<String, String>, String), HttpSignatureError> {
    static COMPONENTS: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r#"^"[a-z0-9@!#$%&'*+.^_`|~-]+"(?: +"[a-z0-9@!#$%&'*+.^_`|~-]+")*$"#)
            .expect("constant component regex")
    });
    static PARAMETER: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
        r#"^;([a-z*][a-z0-9_.*-]*)(?:=("(?:[\x20-\x21\x23-\x5b\x5d-\x7e]|\\["\\])*"|-?[0-9]{1,15}|\?[01]|[A-Za-z*][A-Za-z0-9!#$%&\'*+.^_`|~:/-]*))?"#
    ).expect("constant parameter regex")
    });
    if signature_input.len() > 16384 {
        return Err(HttpSignatureError::InvalidSignatureInput);
    }
    let (label, remainder) = signature_input
        .trim()
        .split_once('=')
        .ok_or(HttpSignatureError::InvalidSignatureInput)?;
    if label.is_empty()
        || !label
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        || !remainder.starts_with('(')
    {
        return Err(HttpSignatureError::InvalidSignatureInput);
    }
    let close = remainder
        .find(')')
        .ok_or(HttpSignatureError::InvalidSignatureInput)?;
    let raw_components = &remainder[1..close];
    if !COMPONENTS.is_match(raw_components) {
        return Err(HttpSignatureError::InvalidSignatureInput);
    }
    let components: Vec<String> = raw_components
        .split_whitespace()
        .map(|c| c.trim_matches('"').to_owned())
        .collect();
    if components.len() > 32 || components.iter().collect::<BTreeSet<_>>().len() != components.len()
    {
        return Err(HttpSignatureError::InvalidSignatureInput);
    }
    let mut serialized = format!(
        "({})",
        components
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let mut rest = &remainder[close + 1..];
    let mut params = BTreeMap::new();
    while !rest.is_empty() {
        let captures = PARAMETER
            .captures(rest)
            .ok_or(HttpSignatureError::InvalidSignatureInput)?;
        let name = &captures[1];
        let raw = captures.get(2).map(|m| m.as_str());
        if params.contains_key(name) || params.len() >= 32 {
            return Err(HttpSignatureError::InvalidSignatureInput);
        }
        if matches!(name, "created" | "expires") && raw.is_none_or(|v| v.parse::<i64>().is_err()) {
            return Err(HttpSignatureError::InvalidSignatureInput);
        }
        if matches!(name, "keyid" | "nonce") && raw.is_none_or(|v| !v.starts_with('"')) {
            return Err(HttpSignatureError::InvalidSignatureInput);
        }
        let value = if let Some(quoted) = raw.filter(|v| v.starts_with('"')) {
            let mut value = String::new();
            let mut chars = quoted[1..quoted.len() - 1].chars();
            while let Some(c) = chars.next() {
                value.push(if c == '\\' {
                    chars
                        .next()
                        .ok_or(HttpSignatureError::InvalidSignatureInput)?
                } else {
                    c
                });
            }
            value
        } else {
            raw.unwrap_or("true").to_owned()
        };
        params.insert(name.to_owned(), value);
        serialized.push(';');
        serialized.push_str(name);
        if let Some(raw) = raw.filter(|v| *v != "?1") {
            serialized.push('=');
            serialized.push_str(raw);
        }
        rest = &rest[captures.get(0).expect("matched parameter").end()..];
    }
    Ok((label.to_owned(), components, params, serialized))
}

fn required_signature_param(
    params: &BTreeMap<String, String>,
    name: &str,
) -> Result<String, HttpSignatureError> {
    params
        .get(name)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or(HttpSignatureError::InvalidSignatureInput)
}

fn parse_optional_i64_param(
    params: &BTreeMap<String, String>,
    name: &str,
) -> Result<Option<i64>, HttpSignatureError> {
    params
        .get(name)
        .filter(|value| !value.is_empty())
        .map(|value| value.parse::<i64>())
        .transpose()
        .map_err(|_| HttpSignatureError::InvalidSignatureInput)
}

fn parse_signature_header(signature_header: &str) -> Result<(String, Vec<u8>), HttpSignatureError> {
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
