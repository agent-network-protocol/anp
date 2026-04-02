use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::did_wba::{
    extract_auth_header_parts, is_authentication_authorized, resolve_did_wba_document_with_options,
    validate_did_document_binding, verify_auth_header_signature, DidResolutionOptions,
};
use super::http_signatures::{extract_signature_metadata, verify_http_message_signature};

#[derive(Clone)]
pub struct DidWbaVerifierConfig {
    pub jwt_private_key: Option<String>,
    pub jwt_public_key: Option<String>,
    pub jwt_algorithm: String,
    pub access_token_expire_minutes: i64,
    pub nonce_expiration_minutes: i64,
    pub timestamp_expiration_minutes: i64,
    pub allowed_domains: Option<Vec<String>>,
    pub allow_http_signatures: bool,
    pub allow_legacy_didwba: bool,
    pub emit_authentication_info_header: bool,
    pub emit_legacy_authorization_header: bool,
    pub require_nonce_for_http_signatures: bool,
    pub did_resolution_options: DidResolutionOptions,
    pub external_nonce_validator: Option<Arc<dyn Fn(&str, &str) -> bool + Send + Sync>>,
}

impl Default for DidWbaVerifierConfig {
    fn default() -> Self {
        Self {
            jwt_private_key: None,
            jwt_public_key: None,
            jwt_algorithm: "RS256".to_string(),
            access_token_expire_minutes: 60,
            nonce_expiration_minutes: 6,
            timestamp_expiration_minutes: 5,
            allowed_domains: None,
            allow_http_signatures: true,
            allow_legacy_didwba: true,
            emit_authentication_info_header: true,
            emit_legacy_authorization_header: true,
            require_nonce_for_http_signatures: true,
            did_resolution_options: DidResolutionOptions::default(),
            external_nonce_validator: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationSuccess {
    pub did: String,
    pub auth_scheme: String,
    pub response_headers: BTreeMap<String, String>,
    pub access_token: Option<String>,
    pub token_type: Option<String>,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct DidWbaVerifierError {
    pub message: String,
    pub status_code: u16,
    pub headers: BTreeMap<String, String>,
}

pub struct DidWbaVerifier {
    config: DidWbaVerifierConfig,
    used_nonces: HashMap<String, chrono::DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iat: i64,
    exp: i64,
}

impl DidWbaVerifier {
    pub fn new(config: DidWbaVerifierConfig) -> Self {
        Self {
            config,
            used_nonces: HashMap::new(),
        }
    }

    pub async fn verify_request(
        &mut self,
        method: &str,
        url: &str,
        headers: &BTreeMap<String, String>,
        body: Option<&[u8]>,
        domain: Option<&str>,
    ) -> Result<VerificationSuccess, DidWbaVerifierError> {
        let request_domain = domain
            .map(|value| value.to_string())
            .unwrap_or_else(|| extract_domain(url));
        self.validate_allowed_domain(&request_domain)?;

        if let Some(auth_header) = get_header_case_insensitive(headers, "Authorization") {
            if auth_header.starts_with("Bearer ") {
                return self.handle_bearer_auth(auth_header);
            }
        }

        if get_header_case_insensitive(headers, "Signature-Input").is_some()
            || get_header_case_insensitive(headers, "Signature").is_some()
        {
            if !self.config.allow_http_signatures {
                return Err(self.challenge_error(
                    "HTTP Message Signatures authentication is disabled",
                    401,
                    &request_domain,
                    "invalid_request",
                ));
            }
            return self
                .handle_http_signature_auth(method, url, headers, body, &request_domain)
                .await;
        }

        if let Some(auth_header) = get_header_case_insensitive(headers, "Authorization") {
            if !self.config.allow_legacy_didwba {
                return Err(self.challenge_error(
                    "Legacy DIDWba authentication is disabled",
                    401,
                    &request_domain,
                    "invalid_request",
                ));
            }
            return self
                .handle_legacy_did_auth(auth_header, &request_domain)
                .await;
        }

        Err(DidWbaVerifierError {
            message: "Missing authentication headers".to_string(),
            status_code: 401,
            headers: BTreeMap::new(),
        })
    }

    pub async fn verify_request_with_did_document(
        &mut self,
        method: &str,
        url: &str,
        headers: &BTreeMap<String, String>,
        body: Option<&[u8]>,
        domain: Option<&str>,
        did_document: &serde_json::Value,
    ) -> Result<VerificationSuccess, DidWbaVerifierError> {
        let request_domain = domain
            .map(|value| value.to_string())
            .unwrap_or_else(|| extract_domain(url));
        self.validate_allowed_domain(&request_domain)?;

        if let Some(auth_header) = get_header_case_insensitive(headers, "Authorization") {
            if auth_header.starts_with("Bearer ") {
                return self.handle_bearer_auth(auth_header);
            }
        }

        if get_header_case_insensitive(headers, "Signature-Input").is_some()
            || get_header_case_insensitive(headers, "Signature").is_some()
        {
            if !self.config.allow_http_signatures {
                return Err(self.challenge_error(
                    "HTTP Message Signatures authentication is disabled",
                    401,
                    &request_domain,
                    "invalid_request",
                ));
            }
            return self.handle_http_signature_auth_with_document(
                method,
                url,
                headers,
                body,
                &request_domain,
                did_document,
            );
        }

        if let Some(auth_header) = get_header_case_insensitive(headers, "Authorization") {
            if !self.config.allow_legacy_didwba {
                return Err(self.challenge_error(
                    "Legacy DIDWba authentication is disabled",
                    401,
                    &request_domain,
                    "invalid_request",
                ));
            }
            return self.handle_legacy_did_auth_with_document(
                auth_header,
                &request_domain,
                did_document,
            );
        }

        Err(DidWbaVerifierError {
            message: "Missing authentication headers".to_string(),
            status_code: 401,
            headers: BTreeMap::new(),
        })
    }

    async fn handle_http_signature_auth(
        &mut self,
        method: &str,
        url: &str,
        headers: &BTreeMap<String, String>,
        body: Option<&[u8]>,
        domain: &str,
    ) -> Result<VerificationSuccess, DidWbaVerifierError> {
        let metadata = extract_signature_metadata(headers).map_err(|_| {
            self.challenge_error("Invalid signature metadata", 401, domain, "invalid_request")
        })?;
        let did = metadata
            .keyid
            .split('#')
            .next()
            .unwrap_or_default()
            .to_string();
        let did_document =
            resolve_did_wba_document_with_options(&did, false, &self.config.did_resolution_options)
                .await
                .map_err(|_| {
                    self.challenge_error(
                        "Failed to resolve DID document",
                        401,
                        domain,
                        "invalid_did",
                    )
                })?;
        self.handle_http_signature_auth_with_document(
            method,
            url,
            headers,
            body,
            domain,
            &did_document,
        )
    }

    fn handle_http_signature_auth_with_document(
        &mut self,
        method: &str,
        url: &str,
        headers: &BTreeMap<String, String>,
        body: Option<&[u8]>,
        domain: &str,
        did_document: &serde_json::Value,
    ) -> Result<VerificationSuccess, DidWbaVerifierError> {
        let metadata = extract_signature_metadata(headers).map_err(|_| {
            self.challenge_error("Invalid signature metadata", 401, domain, "invalid_request")
        })?;
        let did = metadata
            .keyid
            .split('#')
            .next()
            .unwrap_or_default()
            .to_string();

        self.validate_did_binding(did_document)?;
        if !is_authentication_authorized(did_document, &metadata.keyid) {
            return Err(DidWbaVerifierError {
                message: "Verification method is not authorized for authentication".to_string(),
                status_code: 403,
                headers: BTreeMap::new(),
            });
        }
        let verification = verify_http_message_signature(did_document, method, url, headers, body)
            .map_err(|_| {
                self.challenge_error("Invalid signature", 401, domain, "invalid_signature")
            })?;
        if !self.verify_http_signature_time_window(verification.created, verification.expires) {
            return Err(self.challenge_error(
                "HTTP signature timestamp is expired or invalid",
                401,
                domain,
                "invalid_timestamp",
            ));
        }
        if self.config.require_nonce_for_http_signatures && verification.nonce.is_none() {
            return Err(self.challenge_error(
                "HTTP signature nonce is required",
                401,
                domain,
                "invalid_nonce",
            ));
        }
        if let Some(nonce) = verification.nonce.as_deref() {
            if !self.is_valid_nonce(&did, nonce) {
                return Err(self.challenge_error(
                    "Nonce has already been used or expired",
                    401,
                    domain,
                    "invalid_nonce",
                ));
            }
        }
        let access_token = self.create_access_token(&did)?;
        Ok(self.build_success_result(&did, "http_signatures", Some(access_token)))
    }

    async fn handle_legacy_did_auth(
        &mut self,
        authorization: &str,
        domain: &str,
    ) -> Result<VerificationSuccess, DidWbaVerifierError> {
        let parsed = extract_auth_header_parts(authorization).map_err(|_| {
            self.challenge_error(
                "Invalid authorization header format",
                401,
                domain,
                "invalid_request",
            )
        })?;
        let did_document = resolve_did_wba_document_with_options(
            &parsed.did,
            false,
            &self.config.did_resolution_options,
        )
        .await
        .map_err(|_| {
            self.challenge_error("Failed to resolve DID document", 401, domain, "invalid_did")
        })?;
        self.handle_legacy_did_auth_with_document(authorization, domain, &did_document)
    }

    fn handle_legacy_did_auth_with_document(
        &mut self,
        authorization: &str,
        domain: &str,
        did_document: &serde_json::Value,
    ) -> Result<VerificationSuccess, DidWbaVerifierError> {
        let parsed = extract_auth_header_parts(authorization).map_err(|_| {
            self.challenge_error(
                "Invalid authorization header format",
                401,
                domain,
                "invalid_request",
            )
        })?;
        if !self.verify_legacy_timestamp(&parsed.timestamp) {
            return Err(self.challenge_error(
                "Legacy DIDWba timestamp is expired or invalid",
                401,
                domain,
                "invalid_timestamp",
            ));
        }
        if !self.is_valid_nonce(&parsed.did, &parsed.nonce) {
            return Err(self.challenge_error(
                "Legacy DIDWba nonce has already been used or expired",
                401,
                domain,
                "invalid_nonce",
            ));
        }
        self.validate_did_binding(did_document)?;
        let keyid = format!("{}#{}", parsed.did, parsed.verification_method);
        if !is_authentication_authorized(did_document, &keyid) {
            return Err(DidWbaVerifierError {
                message: "Verification method is not authorized for authentication".to_string(),
                status_code: 403,
                headers: BTreeMap::new(),
            });
        }
        verify_auth_header_signature(authorization, did_document, domain).map_err(|_| {
            self.challenge_error(
                "Legacy DIDWba signature verification failed",
                401,
                domain,
                "invalid_signature",
            )
        })?;
        let access_token = self.create_access_token(&parsed.did)?;
        Ok(self.build_success_result(&parsed.did, "legacy_didwba", Some(access_token)))
    }

    fn handle_bearer_auth(
        &self,
        token_header_value: &str,
    ) -> Result<VerificationSuccess, DidWbaVerifierError> {
        let token = token_header_value.trim_start_matches("Bearer ");
        let decoding_key = self.decoding_key()?;
        let algorithm = parse_algorithm(&self.config.jwt_algorithm)?;
        let mut validation = Validation::new(algorithm);
        validation.validate_exp = true;
        let token_data = decode::<Claims>(token, &decoding_key, &validation).map_err(|_| {
            DidWbaVerifierError {
                message: "Invalid token".to_string(),
                status_code: 401,
                headers: BTreeMap::new(),
            }
        })?;
        let claims = token_data.claims;
        let now = Utc::now().timestamp();
        if claims.iat > now + 5 {
            return Err(DidWbaVerifierError {
                message: "Token issued in the future".to_string(),
                status_code: 401,
                headers: BTreeMap::new(),
            });
        }
        if claims.exp <= now - 5 {
            return Err(DidWbaVerifierError {
                message: "Token has expired".to_string(),
                status_code: 401,
                headers: BTreeMap::new(),
            });
        }
        Ok(self.build_success_result(&claims.sub, "bearer", None))
    }

    fn build_success_result(
        &self,
        did: &str,
        auth_scheme: &str,
        access_token: Option<String>,
    ) -> VerificationSuccess {
        let mut response_headers = BTreeMap::new();
        if let Some(token) = access_token.as_ref() {
            let expires_in = self.config.access_token_expire_minutes * 60;
            if self.config.emit_authentication_info_header {
                response_headers.insert(
                    "Authentication-Info".to_string(),
                    format!(
                        "access_token=\"{}\", token_type=\"Bearer\", expires_in={}",
                        token, expires_in
                    ),
                );
            }
            if self.config.emit_legacy_authorization_header {
                response_headers.insert("Authorization".to_string(), format!("Bearer {}", token));
            }
        }
        VerificationSuccess {
            did: did.to_string(),
            auth_scheme: auth_scheme.to_string(),
            response_headers,
            access_token,
            token_type: Some("bearer".to_string()),
        }
    }

    fn validate_did_binding(
        &self,
        did_document: &serde_json::Value,
    ) -> Result<(), DidWbaVerifierError> {
        if validate_did_document_binding(did_document, false) {
            Ok(())
        } else {
            Err(DidWbaVerifierError {
                message: "DID binding verification failed".to_string(),
                status_code: 401,
                headers: BTreeMap::new(),
            })
        }
    }

    fn verify_legacy_timestamp(&self, timestamp: &str) -> bool {
        let parsed = chrono::DateTime::parse_from_rfc3339(&timestamp.replace('Z', "+00:00"));
        if let Ok(value) = parsed {
            let current = Utc::now();
            let request = value.with_timezone(&Utc);
            if request > current + Duration::minutes(1) {
                return false;
            }
            return current - request
                <= Duration::minutes(self.config.timestamp_expiration_minutes);
        }
        false
    }

    fn verify_http_signature_time_window(&self, created: i64, expires: Option<i64>) -> bool {
        let current = Utc::now().timestamp();
        if created > current + 60 {
            return false;
        }
        if current - created > self.config.timestamp_expiration_minutes * 60 {
            return false;
        }
        if let Some(value) = expires {
            if value < current {
                return false;
            }
        }
        true
    }

    fn is_valid_nonce(&mut self, did: &str, nonce: &str) -> bool {
        if let Some(validator) = self.config.external_nonce_validator.as_ref() {
            return validator(did, nonce);
        }
        let current = Utc::now();
        self.used_nonces.retain(|_, issued_at| {
            current.signed_duration_since(*issued_at)
                <= Duration::minutes(self.config.nonce_expiration_minutes)
        });
        let cache_key = format!("{}:{}", did, nonce);
        if self.used_nonces.contains_key(&cache_key) {
            return false;
        }
        self.used_nonces.insert(cache_key, current);
        true
    }

    fn create_access_token(&self, did: &str) -> Result<String, DidWbaVerifierError> {
        let now = Utc::now().timestamp();
        let claims = Claims {
            sub: did.to_string(),
            iat: now,
            exp: now + self.config.access_token_expire_minutes * 60,
        };
        let algorithm = parse_algorithm(&self.config.jwt_algorithm)?;
        let key = self.encoding_key()?;
        let mut header = Header::new(algorithm);
        header.typ = Some("JWT".to_string());
        encode(&header, &claims, &key).map_err(|_| DidWbaVerifierError {
            message: "Internal server error during token generation".to_string(),
            status_code: 500,
            headers: BTreeMap::new(),
        })
    }

    fn encoding_key(&self) -> Result<EncodingKey, DidWbaVerifierError> {
        let secret = self
            .config
            .jwt_private_key
            .as_ref()
            .ok_or(DidWbaVerifierError {
                message: "Missing JWT private key".to_string(),
                status_code: 500,
                headers: BTreeMap::new(),
            })?;
        match self.config.jwt_algorithm.as_str() {
            "HS256" | "HS384" | "HS512" => Ok(EncodingKey::from_secret(secret.as_bytes())),
            _ => EncodingKey::from_rsa_pem(secret.as_bytes()).map_err(|_| DidWbaVerifierError {
                message: "Invalid JWT private key".to_string(),
                status_code: 500,
                headers: BTreeMap::new(),
            }),
        }
    }

    fn decoding_key(&self) -> Result<DecodingKey, DidWbaVerifierError> {
        let secret = self
            .config
            .jwt_public_key
            .as_ref()
            .or(self.config.jwt_private_key.as_ref())
            .ok_or(DidWbaVerifierError {
                message: "Missing JWT public key".to_string(),
                status_code: 500,
                headers: BTreeMap::new(),
            })?;
        match self.config.jwt_algorithm.as_str() {
            "HS256" | "HS384" | "HS512" => Ok(DecodingKey::from_secret(secret.as_bytes())),
            _ => DecodingKey::from_rsa_pem(secret.as_bytes()).map_err(|_| DidWbaVerifierError {
                message: "Invalid JWT public key".to_string(),
                status_code: 500,
                headers: BTreeMap::new(),
            }),
        }
    }

    fn validate_allowed_domain(&self, domain: &str) -> Result<(), DidWbaVerifierError> {
        if let Some(allowed) = self.config.allowed_domains.as_ref() {
            if !allowed.iter().any(|item| item == domain) {
                return Err(DidWbaVerifierError {
                    message: "Domain is not allowed".to_string(),
                    status_code: 403,
                    headers: BTreeMap::new(),
                });
            }
        }
        Ok(())
    }

    fn challenge_error(
        &self,
        message: &str,
        status_code: u16,
        domain: &str,
        error: &str,
    ) -> DidWbaVerifierError {
        let mut headers = BTreeMap::new();
        headers.insert(
            "WWW-Authenticate".to_string(),
            format!(
                "DIDWba realm=\"{}\", error=\"{}\", error_description=\"{}\"",
                domain, error, message
            ),
        );
        if self.config.allow_http_signatures {
            headers.insert(
                "Accept-Signature".to_string(),
                "sig1=(\"@method\" \"@target-uri\" \"@authority\" \"content-digest\");created;expires;nonce;keyid".to_string(),
            );
        }
        DidWbaVerifierError {
            message: message.to_string(),
            status_code,
            headers,
        }
    }
}

fn parse_algorithm(value: &str) -> Result<Algorithm, DidWbaVerifierError> {
    match value {
        "HS256" => Ok(Algorithm::HS256),
        "HS384" => Ok(Algorithm::HS384),
        "HS512" => Ok(Algorithm::HS512),
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        _ => Err(DidWbaVerifierError {
            message: "Unsupported JWT algorithm".to_string(),
            status_code: 500,
            headers: BTreeMap::new(),
        }),
    }
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

fn extract_domain(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|value| value.host_str().map(|item| item.to_string()))
        .unwrap_or_else(|| url.to_string())
}
