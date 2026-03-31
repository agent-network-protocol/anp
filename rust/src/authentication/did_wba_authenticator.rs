use std::collections::HashMap;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde_json::Value;

use crate::keys::PrivateKeyMaterial;

use super::did_wba::{generate_auth_header, generate_auth_header_with_overrides, AuthenticationError};
use super::http_signatures::{generate_http_signature_headers, HttpSignatureOptions};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    HttpSignatures,
    LegacyDidWba,
    Auto,
}

impl AuthMode {
    pub fn from_str(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "legacy_didwba" => Self::LegacyDidWba,
            "auto" => Self::Auto,
            _ => Self::HttpSignatures,
        }
    }
}

#[derive(Debug)]
pub struct DIDWbaAuthHeader {
    did_document_path: PathBuf,
    private_key_path: PathBuf,
    auth_mode: AuthMode,
    did_document_cache: Option<Value>,
    tokens: HashMap<String, String>,
}

impl DIDWbaAuthHeader {
    pub fn new(
        did_document_path: impl AsRef<Path>,
        private_key_path: impl AsRef<Path>,
        auth_mode: AuthMode,
    ) -> Self {
        Self {
            did_document_path: did_document_path.as_ref().to_path_buf(),
            private_key_path: private_key_path.as_ref().to_path_buf(),
            auth_mode,
            did_document_cache: None,
            tokens: HashMap::new(),
        }
    }

    pub fn get_auth_header(
        &mut self,
        server_url: &str,
        force_new: bool,
        method: &str,
        headers: Option<&std::collections::BTreeMap<String, String>>,
        body: Option<&[u8]>,
    ) -> Result<std::collections::BTreeMap<String, String>, AuthenticationError> {
        let domain = extract_domain(server_url);
        if !force_new {
            if let Some(token) = self.tokens.get(&domain) {
                let mut result = std::collections::BTreeMap::new();
                result.insert("Authorization".to_string(), format!("Bearer {}", token));
                return Ok(result);
            }
        }

        let did_document = self.load_did_document()?.clone();
        let private_key = self.load_private_key()?;
        match self.auth_mode {
            AuthMode::HttpSignatures | AuthMode::Auto => generate_http_signature_headers(
                &did_document,
                server_url,
                method,
                &private_key,
                headers,
                body,
                HttpSignatureOptions::default(),
            )
            .map_err(|_| AuthenticationError::SignatureGenerationFailed),
            AuthMode::LegacyDidWba => {
                let value = generate_auth_header(&did_document, &domain, &private_key, "1.1")?;
                let mut result = std::collections::BTreeMap::new();
                result.insert("Authorization".to_string(), value);
                Ok(result)
            }
        }
    }

    pub fn update_token(
        &mut self,
        server_url: &str,
        headers: &std::collections::BTreeMap<String, String>,
    ) -> Option<String> {
        let domain = extract_domain(server_url);
        if let Some(value) = get_header_case_insensitive(headers, "Authentication-Info") {
            let parsed = parse_authentication_info(value);
            if let Some(token) = parsed.get("access_token") {
                self.tokens.insert(domain, token.clone());
                return Some(token.clone());
            }
        }
        if let Some(value) = get_header_case_insensitive(headers, "Authorization") {
            if let Some(token) = value.strip_prefix("Bearer ") {
                let token = token.to_string();
                self.tokens.insert(domain, token.clone());
                return Some(token);
            }
        }
        None
    }

    pub fn clear_token(&mut self, server_url: &str) {
        let domain = extract_domain(server_url);
        self.tokens.remove(&domain);
    }

    pub fn clear_all_tokens(&mut self) {
        self.tokens.clear();
    }

    pub fn should_retry_after_401(
        &self,
        response_headers: &BTreeMap<String, String>,
    ) -> bool {
        let Some(www_authenticate) =
            get_header_case_insensitive(response_headers, "WWW-Authenticate")
        else {
            return false;
        };
        let challenge = parse_www_authenticate(www_authenticate);
        if challenge.get("nonce").is_some() {
            return true;
        }
        !matches!(
            challenge.get("error").map(|value| value.as_str()),
            Some("invalid_did") | Some("invalid_verification_method") | Some("forbidden_did")
        )
    }

    pub fn get_challenge_auth_header(
        &mut self,
        server_url: &str,
        response_headers: &BTreeMap<String, String>,
        method: &str,
        headers: Option<&BTreeMap<String, String>>,
        body: Option<&[u8]>,
    ) -> Result<BTreeMap<String, String>, AuthenticationError> {
        let www_authenticate =
            get_header_case_insensitive(response_headers, "WWW-Authenticate");
        let accept_signature =
            get_header_case_insensitive(response_headers, "Accept-Signature");
        let challenge = www_authenticate
            .map(|value| parse_www_authenticate(value))
            .unwrap_or_default();
        let covered_components = normalize_covered_components(
            accept_signature
                .map(|value| parse_accept_signature(value))
                .as_ref(),
            headers,
            body,
        );
        let nonce = challenge.get("nonce").map(String::as_str);

        let did_document = self.load_did_document()?.clone();
        let private_key = self.load_private_key()?;
        match self.auth_mode {
            AuthMode::HttpSignatures | AuthMode::Auto => generate_http_signature_headers(
                &did_document,
                server_url,
                method,
                &private_key,
                headers,
                body,
                HttpSignatureOptions {
                    nonce: nonce.map(ToOwned::to_owned),
                    covered_components,
                    ..HttpSignatureOptions::default()
                },
            )
            .map_err(|_| AuthenticationError::SignatureGenerationFailed),
            AuthMode::LegacyDidWba => {
                let value = generate_auth_header_with_overrides(
                    &did_document,
                    &extract_domain(server_url),
                    &private_key,
                    "1.1",
                    nonce,
                    None,
                )?;
                let mut result = BTreeMap::new();
                result.insert("Authorization".to_string(), value);
                Ok(result)
            }
        }
    }

    fn load_did_document(&mut self) -> Result<&Value, AuthenticationError> {
        if self.did_document_cache.is_none() {
            let content = fs::read_to_string(&self.did_document_path)
                .map_err(|_| AuthenticationError::IoFailure)?;
            let value = serde_json::from_str(&content).map_err(|_| AuthenticationError::JsonFailure)?;
            self.did_document_cache = Some(value);
        }
        self.did_document_cache
            .as_ref()
            .ok_or(AuthenticationError::InvalidDidDocument)
    }

    fn load_private_key(&self) -> Result<PrivateKeyMaterial, AuthenticationError> {
        let content = fs::read_to_string(&self.private_key_path)
            .map_err(|_| AuthenticationError::IoFailure)?;
        PrivateKeyMaterial::from_pem(&content).map_err(|_| AuthenticationError::InvalidDidDocument)
    }
}

fn extract_domain(server_url: &str) -> String {
    url::Url::parse(server_url)
        .ok()
        .and_then(|value| value.host_str().map(|host| host.to_string()))
        .unwrap_or_else(|| server_url.to_string())
}

fn get_header_case_insensitive<'a>(
    headers: &'a std::collections::BTreeMap<String, String>,
    name: &str,
) -> Option<&'a String> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn parse_authentication_info(value: &str) -> HashMap<String, String> {
    value
        .split(',')
        .filter_map(|item| item.trim().split_once('='))
        .map(|(key, raw)| (key.trim().to_string(), raw.trim().trim_matches('"').to_string()))
        .collect()
}

fn parse_www_authenticate(value: &str) -> HashMap<String, String> {
    let normalized = value
        .trim()
        .strip_prefix("DIDWba ")
        .or_else(|| value.trim().strip_prefix("didwba "))
        .unwrap_or(value.trim());
    let regex = Regex::new(r#"([\w-]+)=("[^"]*"|[^,]+)"#).expect("regex should compile");
    regex
        .captures_iter(normalized)
        .filter_map(|captures| {
            let key = captures.get(1)?.as_str().trim().to_string();
            let value = captures
                .get(2)?
                .as_str()
                .trim()
                .trim_matches('"')
                .to_string();
            Some((key, value))
        })
        .collect()
}

fn parse_accept_signature(value: &str) -> Vec<String> {
    let regex = Regex::new(r#""([^"]+)""#).expect("regex should compile");
    regex
        .captures_iter(value)
        .filter_map(|captures| captures.get(1).map(|matched| matched.as_str().to_string()))
        .collect()
}

fn normalize_covered_components(
    covered_components: Option<&Vec<String>>,
    headers: Option<&BTreeMap<String, String>>,
    body: Option<&[u8]>,
) -> Option<Vec<String>> {
    let covered_components = covered_components?;
    let body_present = body.map(|bytes| !bytes.is_empty()).unwrap_or(false);
    let normalized_headers = headers
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|(key, value)| (key.to_ascii_lowercase(), value))
        .collect::<BTreeMap<_, _>>();

    let mut result = Vec::new();
    for component in covered_components {
        let lower = component.to_ascii_lowercase();
        if lower == "content-digest" && !body_present {
            continue;
        }
        if lower == "content-length"
            && !body_present
            && !normalized_headers.contains_key("content-length")
        {
            continue;
        }
        if lower == "content-type" && !normalized_headers.contains_key("content-type") {
            continue;
        }
        if !lower.starts_with('@')
            && lower != "content-length"
            && lower != "content-digest"
            && !normalized_headers.contains_key(&lower)
        {
            continue;
        }
        result.push(component.clone());
    }
    Some(result)
}
