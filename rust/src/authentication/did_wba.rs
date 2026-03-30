use std::collections::BTreeMap;

use chrono::Utc;
use percent_encoding::percent_decode_str;
use rand::rngs::OsRng;
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::canonical_json::canonicalize_json;
use crate::keys::{base64url_encode, GeneratedKeyPairPem};
use crate::proof::{
    generate_w3c_proof, verify_w3c_proof, ProofGenerationOptions,
    ProofVerificationOptions, CRYPTOSUITE_DIDWBA_SECP256K1_2025,
    CRYPTOSUITE_EDDSA_JCS_2022, PROOF_TYPE_DATA_INTEGRITY,
    PROOF_TYPE_SECP256K1,
};
use crate::{PrivateKeyMaterial, PublicKeyMaterial};

use super::verification_methods::{create_verification_method, extract_public_key};

pub const VM_KEY_AUTH: &str = "key-1";
pub const VM_KEY_E2EE_SIGNING: &str = "key-2";
pub const VM_KEY_E2EE_AGREEMENT: &str = "key-3";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DidProfile {
    #[serde(rename = "e1")]
    E1,
    #[serde(rename = "k1")]
    K1,
    #[serde(rename = "plain_legacy")]
    PlainLegacy,
}

impl Default for DidProfile {
    fn default() -> Self {
        Self::E1
    }
}

impl DidProfile {
    pub fn from_str(value: &str) -> Result<Self, AuthenticationError> {
        match value.to_ascii_lowercase().as_str() {
            "e1" => Ok(Self::E1),
            "k1" => Ok(Self::K1),
            "plain_legacy" => Ok(Self::PlainLegacy),
            _ => Err(AuthenticationError::UnsupportedProfile),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::E1 => "e1",
            Self::K1 => "k1",
            Self::PlainLegacy => "plain_legacy",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocumentOptions {
    pub port: Option<u16>,
    pub path_segments: Vec<String>,
    pub agent_description_url: Option<String>,
    pub services: Vec<Value>,
    pub proof_purpose: String,
    pub verification_method: Option<String>,
    pub domain: Option<String>,
    pub challenge: Option<String>,
    pub created: Option<String>,
    pub enable_e2ee: bool,
    pub did_profile: DidProfile,
}

impl Default for DidDocumentOptions {
    fn default() -> Self {
        Self {
            port: None,
            path_segments: Vec::new(),
            agent_description_url: None,
            services: Vec::new(),
            proof_purpose: "assertionMethod".to_string(),
            verification_method: None,
            domain: None,
            challenge: None,
            created: None,
            enable_e2ee: true,
            did_profile: DidProfile::E1,
        }
    }
}

impl DidDocumentOptions {
    pub fn with_profile(mut self, profile: DidProfile) -> Self {
        self.did_profile = profile;
        self
    }

    pub fn with_path_segments<I, S>(mut self, path_segments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.path_segments = path_segments.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_agent_description_url(mut self, value: impl Into<String>) -> Self {
        self.agent_description_url = Some(value.into());
        self
    }

    pub fn with_service(mut self, service: Value) -> Self {
        self.services.push(service);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocumentBundle {
    pub did_document: Value,
    pub keys: BTreeMap<String, GeneratedKeyPairPem>,
}

impl DidDocumentBundle {
    pub fn did(&self) -> Option<&str> {
        self.did_document.get("id").and_then(Value::as_str)
    }

    pub fn private_key_pem(&self, fragment: &str) -> Option<&str> {
        self.keys.get(fragment).map(|value| value.private_key_pem.as_str())
    }

    pub fn public_key_pem(&self, fragment: &str) -> Option<&str> {
        self.keys.get(fragment).map(|value| value.public_key_pem.as_str())
    }

    pub fn load_private_key(&self, fragment: &str) -> Result<PrivateKeyMaterial, AuthenticationError> {
        let pem = self.private_key_pem(fragment).ok_or(AuthenticationError::InvalidDidDocument)?;
        PrivateKeyMaterial::from_pem(pem).map_err(|_| AuthenticationError::InvalidDidDocument)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedAuthHeader {
    pub did: String,
    pub nonce: String,
    pub timestamp: String,
    pub verification_method: String,
    pub signature: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidResolutionOptions {
    pub timeout_seconds: f64,
    pub verify_ssl: bool,
    pub base_url_override: Option<String>,
}

impl Default for DidResolutionOptions {
    fn default() -> Self {
        Self {
            timeout_seconds: 10.0,
            verify_ssl: true,
            base_url_override: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum AuthenticationError {
    #[error("Hostname cannot be empty")]
    EmptyHostname,
    #[error("Hostname cannot be an IP address")]
    IpAddressNotAllowed,
    #[error("Invalid DID format")]
    InvalidDid,
    #[error("Invalid DID document")]
    InvalidDidDocument,
    #[error("DID binding verification failed")]
    InvalidDidBinding,
    #[error("Authentication header must start with DIDWba")]
    InvalidAuthorizationHeader,
    #[error("Missing field in authorization header: {0}")]
    MissingAuthorizationField(String),
    #[error("Verification method not found")]
    VerificationMethodNotFound,
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Signature generation failed")]
    SignatureGenerationFailed,
    #[error("Network failure")]
    NetworkFailure,
    #[error("I/O failure")]
    IoFailure,
    #[error("JSON failure")]
    JsonFailure,
    #[error("Regex failure")]
    RegexFailure,
    #[error("Unsupported profile")]
    UnsupportedProfile,
    #[error("Verification method error: {0}")]
    VerificationMethod(String),
    #[error("Proof error: {0}")]
    Proof(String),
}

pub fn create_did_wba_document(
    hostname: &str,
    options: DidDocumentOptions,
) -> Result<DidDocumentBundle, AuthenticationError> {
    if hostname.trim().is_empty() {
        return Err(AuthenticationError::EmptyHostname);
    }
    if is_ip_address(hostname) {
        return Err(AuthenticationError::IpAddressNotAllowed);
    }

    let did_base = build_did_base(hostname, options.port);
    let mut path_segments = options.path_segments.clone();
    let mut contexts = vec![Value::String(
        "https://www.w3.org/ns/did/v1".to_string(),
    )];
    let mut verification_methods: Vec<Value> = Vec::new();
    let mut authentication_entries: Vec<Value> = Vec::new();
    let mut assertion_method_entries: Vec<Value> = Vec::new();
    let mut key_agreement_entries: Vec<Value> = Vec::new();
    let mut keys = BTreeMap::new();

    let auth_private_key = match options.did_profile {
        DidProfile::E1 => {
            PrivateKeyMaterial::Ed25519(ed25519_dalek::SigningKey::generate(&mut OsRng))
        }
        DidProfile::K1 | DidProfile::PlainLegacy => {
            PrivateKeyMaterial::Secp256k1(k256::ecdsa::SigningKey::random(&mut OsRng))
        }
    };
    let auth_public_key = auth_private_key.public_key();

    let did = match options.did_profile {
        DidProfile::E1 => {
            if !path_segments.is_empty() {
                path_segments.push(format!(
                    "e1_{}",
                    compute_multikey_fingerprint(&auth_public_key)?
                ));
            }
            join_did(&did_base, &path_segments)
        }
        DidProfile::K1 => {
            if !path_segments.is_empty() {
                path_segments.push(format!(
                    "k1_{}",
                    compute_jwk_fingerprint(&auth_public_key)?
                ));
            }
            join_did(&did_base, &path_segments)
        }
        DidProfile::PlainLegacy => join_did(&did_base, &path_segments),
    };

    let auth_vm = match (&options.did_profile, &auth_public_key) {
        (DidProfile::E1, PublicKeyMaterial::Ed25519(key)) => {
            contexts.push(Value::String(
                "https://w3id.org/security/data-integrity/v2".to_string(),
            ));
            contexts.push(Value::String(
                "https://w3id.org/security/multikey/v1".to_string(),
            ));
            json!({
                "id": format!("{did}#{VM_KEY_AUTH}"),
                "type": "Multikey",
                "controller": did,
                "publicKeyMultibase": ed25519_public_key_to_multibase(key),
            })
        }
        (DidProfile::K1, PublicKeyMaterial::Secp256k1(key))
        | (DidProfile::PlainLegacy, PublicKeyMaterial::Secp256k1(key)) => {
            contexts.push(Value::String(
                "https://w3id.org/security/suites/jws-2020/v1".to_string(),
            ));
            contexts.push(Value::String(
                "https://w3id.org/security/suites/secp256k1-2019/v1".to_string(),
            ));
            if matches!(options.did_profile, DidProfile::K1) {
                contexts.push(Value::String(
                    "https://w3id.org/security/data-integrity/v2".to_string(),
                ));
            }
            json!({
                "id": format!("{did}#{VM_KEY_AUTH}"),
                "type": "EcdsaSecp256k1VerificationKey2019",
                "controller": did,
                "publicKeyJwk": secp256k1_public_key_to_jwk(key)?,
            })
        }
        _ => return Err(AuthenticationError::UnsupportedProfile),
    };

    verification_methods.push(auth_vm.clone());
    authentication_entries.push(Value::String(format!("{did}#{VM_KEY_AUTH}")));
    if matches!(options.did_profile, DidProfile::E1 | DidProfile::K1) {
        assertion_method_entries.push(Value::String(format!("{did}#{VM_KEY_AUTH}")));
    }
    keys.insert(
        VM_KEY_AUTH.to_string(),
        GeneratedKeyPairPem {
            private_key_pem: auth_private_key.to_pem(),
            public_key_pem: auth_public_key.to_pem(),
        },
    );

    if options.enable_e2ee {
        contexts.push(Value::String(
            "https://w3id.org/security/suites/x25519-2019/v1".to_string(),
        ));
        let signing_key =
            PrivateKeyMaterial::Secp256r1(p256::ecdsa::SigningKey::random(&mut OsRng));
        let agreement_key =
            PrivateKeyMaterial::X25519(x25519_dalek::StaticSecret::from(rand::random::<
                [u8; 32],
            >()));
        let signing_public = signing_key.public_key();
        let agreement_public = agreement_key.public_key();

        let signing_vm = match &signing_public {
            PublicKeyMaterial::Secp256r1(key) => json!({
                "id": format!("{did}#{VM_KEY_E2EE_SIGNING}"),
                "type": "EcdsaSecp256r1VerificationKey2019",
                "controller": did,
                "publicKeyJwk": secp256r1_public_key_to_jwk(key)?,
            }),
            _ => return Err(AuthenticationError::InvalidDidDocument),
        };
        let agreement_vm = match &agreement_public {
            PublicKeyMaterial::X25519(bytes) => json!({
                "id": format!("{did}#{VM_KEY_E2EE_AGREEMENT}"),
                "type": "X25519KeyAgreementKey2019",
                "controller": did,
                "publicKeyMultibase": x25519_public_key_to_multibase(bytes),
            }),
            _ => return Err(AuthenticationError::InvalidDidDocument),
        };

        verification_methods.push(signing_vm);
        verification_methods.push(agreement_vm);
        key_agreement_entries.push(Value::String(format!(
            "{did}#{VM_KEY_E2EE_AGREEMENT}"
        )));
        keys.insert(
            VM_KEY_E2EE_SIGNING.to_string(),
            GeneratedKeyPairPem {
                private_key_pem: signing_key.to_pem(),
                public_key_pem: signing_public.to_pem(),
            },
        );
        keys.insert(
            VM_KEY_E2EE_AGREEMENT.to_string(),
            GeneratedKeyPairPem {
                private_key_pem: agreement_key.to_pem(),
                public_key_pem: agreement_public.to_pem(),
            },
        );
    }

    let mut document = Map::new();
    document.insert("@context".to_string(), Value::Array(contexts));
    document.insert("id".to_string(), Value::String(did.clone()));
    document.insert(
        "verificationMethod".to_string(),
        Value::Array(verification_methods),
    );
    document.insert(
        "authentication".to_string(),
        Value::Array(authentication_entries),
    );
    if !assertion_method_entries.is_empty() {
        document.insert(
            "assertionMethod".to_string(),
            Value::Array(assertion_method_entries),
        );
    }
    if !key_agreement_entries.is_empty() {
        document.insert(
            "keyAgreement".to_string(),
            Value::Array(key_agreement_entries),
        );
    }
    let services = build_service_entries(
        &did,
        options.agent_description_url.as_deref(),
        &options.services,
    );
    if !services.is_empty() {
        document.insert("service".to_string(), Value::Array(services));
    }

    let proof_options = ProofGenerationOptions {
        proof_purpose: Some(options.proof_purpose.clone()),
        proof_type: Some(match options.did_profile {
            DidProfile::E1 | DidProfile::K1 => PROOF_TYPE_DATA_INTEGRITY.to_string(),
            DidProfile::PlainLegacy => PROOF_TYPE_SECP256K1.to_string(),
        }),
        cryptosuite: match options.did_profile {
            DidProfile::E1 => Some(CRYPTOSUITE_EDDSA_JCS_2022.to_string()),
            DidProfile::K1 => Some(CRYPTOSUITE_DIDWBA_SECP256K1_2025.to_string()),
            DidProfile::PlainLegacy => None,
        },
        created: options.created.clone(),
        domain: options.domain.clone(),
        challenge: options.challenge.clone(),
    };
    let verification_method = options
        .verification_method
        .clone()
        .unwrap_or_else(|| format!("{did}#{VM_KEY_AUTH}"));
    let signed_document = generate_w3c_proof(
        &Value::Object(document),
        &auth_private_key,
        &verification_method,
        proof_options,
    )
    .map_err(|err| AuthenticationError::Proof(err.to_string()))?;

    Ok(DidDocumentBundle {
        did_document: signed_document,
        keys,
    })
}

pub fn create_did_wba_document_with_key_binding(
    hostname: &str,
    mut options: DidDocumentOptions,
) -> Result<DidDocumentBundle, AuthenticationError> {
    if options.path_segments.is_empty() {
        options.path_segments = vec!["user".to_string()];
    }
    options.did_profile = DidProfile::K1;
    create_did_wba_document(hostname, options)
}

pub fn compute_jwk_fingerprint(
    public_key: &PublicKeyMaterial,
) -> Result<String, AuthenticationError> {
    match public_key {
        PublicKeyMaterial::Secp256k1(key) => jwk_thumbprint(&secp256k1_public_key_to_jwk(key)?),
        _ => Err(AuthenticationError::InvalidDidDocument),
    }
}

pub fn compute_multikey_fingerprint(
    public_key: &PublicKeyMaterial,
) -> Result<String, AuthenticationError> {
    match public_key {
        PublicKeyMaterial::Ed25519(key) => {
            let jwk = json!({
                "crv": "Ed25519",
                "kty": "OKP",
                "x": base64url_encode(&key.to_bytes()),
            });
            jwk_thumbprint(&jwk)
        }
        _ => Err(AuthenticationError::InvalidDidDocument),
    }
}

pub fn verify_did_key_binding(did: &str, binding_material: &Value) -> bool {
    let last_segment = did.rsplit(':').next().unwrap_or_default();
    if let Some(expected) = last_segment.strip_prefix("k1_") {
        if let Ok(public_key) = extract_public_key(binding_material) {
            return compute_jwk_fingerprint(&public_key)
                .map(|value| value == expected)
                .unwrap_or(false);
        }
        return false;
    }
    if let Some(expected) = last_segment.strip_prefix("e1_") {
        if let Ok(public_key) = extract_public_key(binding_material) {
            return compute_multikey_fingerprint(&public_key)
                .map(|value| value == expected)
                .unwrap_or(false);
        }
        return false;
    }
    true
}

pub fn validate_did_document_binding(did_document: &Value, verify_proof: bool) -> bool {
    let did = did_document.get("id").and_then(Value::as_str).unwrap_or_default();
    let last_segment = did.rsplit(':').next().unwrap_or_default();
    if let Some(expected) = last_segment.strip_prefix("e1_") {
        return validate_e1_binding(did_document, expected);
    }
    if let Some(expected) = last_segment.strip_prefix("k1_") {
        if verify_proof {
            return validate_k1_binding(did_document, expected);
        }
        if let Some(methods) = did_document
            .get("verificationMethod")
            .and_then(Value::as_array)
        {
            for method in methods {
                if let Some(method_id) = method.get("id").and_then(Value::as_str) {
                    if is_authentication_authorized(did_document, method_id)
                        && verify_did_key_binding(did, method)
                    {
                        return true;
                    }
                }
            }
        }
        return false;
    }
    true
}

pub async fn resolve_did_wba_document(
    did: &str,
    verify_proof: bool,
) -> Result<Value, AuthenticationError> {
    resolve_did_wba_document_with_options(did, verify_proof, &DidResolutionOptions::default())
        .await
}

pub async fn resolve_did_wba_document_with_options(
    did: &str,
    verify_proof: bool,
    options: &DidResolutionOptions,
) -> Result<Value, AuthenticationError> {
    if !did.starts_with("did:wba:") {
        return Err(AuthenticationError::InvalidDid);
    }
    let parts: Vec<&str> = did.split(':').collect();
    if parts.len() < 3 {
        return Err(AuthenticationError::InvalidDid);
    }
    let encoded_domain = parts[2];
    let domain = percent_decode_str(encoded_domain)
        .decode_utf8_lossy()
        .to_string();
    let path_segments = if parts.len() > 3 { &parts[3..] } else { &[][..] };

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
            path_segments.join("/")
        )
    };

    let client = Client::builder()
        .danger_accept_invalid_certs(!options.verify_ssl)
        .timeout(std::time::Duration::from_secs_f64(options.timeout_seconds))
        .build()
        .map_err(|_| AuthenticationError::NetworkFailure)?;

    let response = client
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|_| AuthenticationError::NetworkFailure)?
        .error_for_status()
        .map_err(|_| AuthenticationError::NetworkFailure)?;
    let document: Value = response
        .json()
        .await
        .map_err(|_| AuthenticationError::JsonFailure)?;

    if document.get("id").and_then(Value::as_str) != Some(did) {
        return Err(AuthenticationError::InvalidDidDocument);
    }
    if !validate_did_document_binding(&document, verify_proof) {
        return Err(AuthenticationError::InvalidDidBinding);
    }
    if verify_proof {
        let proof = document
            .get("proof")
            .ok_or(AuthenticationError::InvalidDidDocument)?;
        let verification_method = proof
            .get("verificationMethod")
            .and_then(Value::as_str)
            .ok_or(AuthenticationError::InvalidDidDocument)?;
        let method = find_verification_method(&document, verification_method)
            .ok_or(AuthenticationError::VerificationMethodNotFound)?;
        let public_key = extract_public_key(&method)
            .map_err(|err| AuthenticationError::VerificationMethod(err.to_string()))?;
        if !verify_w3c_proof(
            &document,
            &public_key,
            ProofVerificationOptions::default(),
        ) {
            return Err(AuthenticationError::VerificationFailed);
        }
    }

    Ok(document)
}

pub fn resolve_did_wba_document_sync(
    did: &str,
    verify_proof: bool,
) -> Result<Value, AuthenticationError> {
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|_| AuthenticationError::NetworkFailure)?;
    runtime.block_on(resolve_did_wba_document(did, verify_proof))
}

pub fn generate_auth_header(
    did_document: &Value,
    service_domain: &str,
    private_key: &PrivateKeyMaterial,
    version: &str,
) -> Result<String, AuthenticationError> {
    let parsed = generate_auth_payload(did_document, service_domain, private_key, version)?;
    Ok(format!(
        "DIDWba v=\"{}\", did=\"{}\", nonce=\"{}\", timestamp=\"{}\", verification_method=\"{}\", signature=\"{}\"",
        parsed.version,
        parsed.did,
        parsed.nonce,
        parsed.timestamp,
        parsed.verification_method,
        parsed.signature,
    ))
}

pub fn generate_auth_json(
    did_document: &Value,
    service_domain: &str,
    private_key: &PrivateKeyMaterial,
    version: &str,
) -> Result<String, AuthenticationError> {
    let parsed = generate_auth_payload(did_document, service_domain, private_key, version)?;
    serde_json::to_string(&json!({
        "v": parsed.version,
        "did": parsed.did,
        "nonce": parsed.nonce,
        "timestamp": parsed.timestamp,
        "verification_method": parsed.verification_method,
        "signature": parsed.signature,
    }))
    .map_err(|_| AuthenticationError::JsonFailure)
}

pub fn extract_auth_header_parts(
    auth_header: &str,
) -> Result<ParsedAuthHeader, AuthenticationError> {
    if !auth_header.trim_start().starts_with("DIDWba") {
        return Err(AuthenticationError::InvalidAuthorizationHeader);
    }

    let required_fields = [
        "did",
        "nonce",
        "timestamp",
        "verification_method",
        "signature",
    ];
    let mut values = BTreeMap::new();
    for field in required_fields {
        let pattern = format!(r#"(?i){field}=\"([^\"]+)\""#);
        let regex = Regex::new(&pattern).map_err(|_| AuthenticationError::RegexFailure)?;
        let capture = regex
            .captures(auth_header)
            .and_then(|caps| caps.get(1))
            .map(|matched| matched.as_str().to_string())
            .ok_or_else(|| {
                AuthenticationError::MissingAuthorizationField(field.to_string())
            })?;
        values.insert(field.to_string(), capture);
    }

    let version_regex = Regex::new(r#"(?i)v=\"([^\"]+)\""#)
        .map_err(|_| AuthenticationError::RegexFailure)?;
    let version = version_regex
        .captures(auth_header)
        .and_then(|caps| caps.get(1))
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| "1.1".to_string());

    Ok(ParsedAuthHeader {
        did: values.remove("did").unwrap_or_default(),
        nonce: values.remove("nonce").unwrap_or_default(),
        timestamp: values.remove("timestamp").unwrap_or_default(),
        verification_method: values.remove("verification_method").unwrap_or_default(),
        signature: values.remove("signature").unwrap_or_default(),
        version,
    })
}

pub fn verify_auth_header_signature(
    auth_header: &str,
    did_document: &Value,
    service_domain: &str,
) -> Result<(), AuthenticationError> {
    let parsed = extract_auth_header_parts(auth_header)?;
    verify_auth_payload(&parsed, did_document, service_domain)
}

pub fn verify_auth_json_signature(
    auth_json: &str,
    did_document: &Value,
    service_domain: &str,
) -> Result<(), AuthenticationError> {
    let value: Value =
        serde_json::from_str(auth_json).map_err(|_| AuthenticationError::JsonFailure)?;
    let parsed = ParsedAuthHeader {
        did: value
            .get("did")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        nonce: value
            .get("nonce")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        timestamp: value
            .get("timestamp")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        verification_method: value
            .get("verification_method")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        signature: value
            .get("signature")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        version: value
            .get("v")
            .and_then(Value::as_str)
            .unwrap_or("1.1")
            .to_string(),
    };
    verify_auth_payload(&parsed, did_document, service_domain)
}

pub fn find_verification_method(
    did_document: &Value,
    verification_method_id: &str,
) -> Option<Value> {
    if let Some(methods) = did_document
        .get("verificationMethod")
        .and_then(Value::as_array)
    {
        for method in methods {
            if method.get("id").and_then(Value::as_str)
                == Some(verification_method_id)
            {
                return Some(method.clone());
            }
        }
    }
    if let Some(authentication) = did_document
        .get("authentication")
        .and_then(Value::as_array)
    {
        for method in authentication {
            if method.get("id").and_then(Value::as_str)
                == Some(verification_method_id)
            {
                return Some(method.clone());
            }
        }
    }
    None
}

pub fn is_authentication_authorized(
    did_document: &Value,
    verification_method_id: &str,
) -> bool {
    did_document
        .get("authentication")
        .and_then(Value::as_array)
        .map(|entries| {
            entries.iter().any(|entry| {
                entry.as_str() == Some(verification_method_id)
                    || entry.get("id").and_then(Value::as_str)
                        == Some(verification_method_id)
            })
        })
        .unwrap_or(false)
}

fn validate_e1_binding(did_document: &Value, expected_fingerprint: &str) -> bool {
    let proof = match did_document.get("proof") {
        Some(value) => value,
        None => return false,
    };
    if proof.get("type").and_then(Value::as_str)
        != Some(PROOF_TYPE_DATA_INTEGRITY)
    {
        return false;
    }
    if proof.get("cryptosuite").and_then(Value::as_str)
        != Some(CRYPTOSUITE_EDDSA_JCS_2022)
    {
        return false;
    }
    let verification_method = match proof.get("verificationMethod").and_then(Value::as_str) {
        Some(value) => value,
        None => return false,
    };
    let method = match find_verification_method(did_document, verification_method) {
        Some(value) => value,
        None => return false,
    };
    let public_key = match extract_public_key(&method) {
        Ok(value) => value,
        Err(_) => return false,
    };
    verify_w3c_proof(
        did_document,
        &public_key,
        ProofVerificationOptions {
            expected_purpose: Some("assertionMethod".to_string()),
            expected_domain: None,
            expected_challenge: None,
        },
    ) && compute_multikey_fingerprint(&public_key)
        .map(|value| value == expected_fingerprint)
        .unwrap_or(false)
}

fn validate_k1_binding(did_document: &Value, expected_fingerprint: &str) -> bool {
    let proof = match did_document.get("proof") {
        Some(value) => value,
        None => return false,
    };
    let verification_method = match proof.get("verificationMethod").and_then(Value::as_str) {
        Some(value) => value,
        None => return false,
    };
    let method = match find_verification_method(did_document, verification_method) {
        Some(value) => value,
        None => return false,
    };
    let public_key = match extract_public_key(&method) {
        Ok(value) => value,
        Err(_) => return false,
    };
    verify_w3c_proof(
        did_document,
        &public_key,
        ProofVerificationOptions {
            expected_purpose: Some("assertionMethod".to_string()),
            expected_domain: None,
            expected_challenge: None,
        },
    ) && compute_jwk_fingerprint(&public_key)
        .map(|value| value == expected_fingerprint)
        .unwrap_or(false)
}

fn generate_auth_payload(
    did_document: &Value,
    service_domain: &str,
    private_key: &PrivateKeyMaterial,
    version: &str,
) -> Result<ParsedAuthHeader, AuthenticationError> {
    let did = did_document
        .get("id")
        .and_then(Value::as_str)
        .ok_or(AuthenticationError::InvalidDidDocument)?;
    let (method_dict, method_fragment) = select_authentication_method(did_document)?;
    let nonce = base64url_encode(&rand::random::<[u8; 16]>());
    let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let domain_field = domain_field_for_version(version);

    let payload = json!({
        "nonce": nonce,
        "timestamp": timestamp,
        domain_field: service_domain,
        "did": did,
    });
    let canonical = canonicalize_json(&payload)
        .map_err(|_| AuthenticationError::JsonFailure)?;
    let content_hash = Sha256::digest(canonical).to_vec();
    let signature_bytes = private_key
        .sign_message(&content_hash)
        .map_err(|_| AuthenticationError::SignatureGenerationFailed)?;
    let verifier = create_verification_method(&method_dict)
        .map_err(|err| AuthenticationError::VerificationMethod(err.to_string()))?;
    let signature = verifier
        .encode_signature(&signature_bytes)
        .map_err(|err| AuthenticationError::VerificationMethod(err.to_string()))?;

    Ok(ParsedAuthHeader {
        did: did.to_string(),
        nonce: payload
            .get("nonce")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        timestamp,
        verification_method: method_fragment,
        signature,
        version: version.to_string(),
    })
}

fn verify_auth_payload(
    parsed: &ParsedAuthHeader,
    did_document: &Value,
    service_domain: &str,
) -> Result<(), AuthenticationError> {
    if did_document
        .get("id")
        .and_then(Value::as_str)
        .map(|value| value.to_lowercase())
        != Some(parsed.did.to_lowercase())
    {
        return Err(AuthenticationError::VerificationFailed);
    }

    let domain_field = domain_field_for_version(&parsed.version);
    let payload = json!({
        "nonce": parsed.nonce,
        "timestamp": parsed.timestamp,
        domain_field: service_domain,
        "did": parsed.did,
    });
    let canonical = canonicalize_json(&payload)
        .map_err(|_| AuthenticationError::JsonFailure)?;
    let content_hash = Sha256::digest(canonical).to_vec();
    let verification_method_id = format!("{}#{}", parsed.did, parsed.verification_method);
    let method = find_verification_method(did_document, &verification_method_id)
        .ok_or(AuthenticationError::VerificationMethodNotFound)?;
    let verifier = create_verification_method(&method)
        .map_err(|err| AuthenticationError::VerificationMethod(err.to_string()))?;
    verifier
        .verify_signature(&content_hash, &parsed.signature)
        .map_err(|_| AuthenticationError::VerificationFailed)
}

fn select_authentication_method(
    did_document: &Value,
) -> Result<(Value, String), AuthenticationError> {
    let authentication = did_document
        .get("authentication")
        .and_then(Value::as_array)
        .ok_or(AuthenticationError::InvalidDidDocument)?;
    let first = authentication
        .first()
        .ok_or(AuthenticationError::InvalidDidDocument)?;
    if let Some(reference) = first.as_str() {
        let method = find_verification_method(did_document, reference)
            .ok_or(AuthenticationError::VerificationMethodNotFound)?;
        let fragment = reference
            .split('#')
            .last()
            .unwrap_or_default()
            .to_string();
        return Ok((method, fragment));
    }
    let id = first
        .get("id")
        .and_then(Value::as_str)
        .ok_or(AuthenticationError::InvalidDidDocument)?;
    Ok((
        first.clone(),
        id.split('#').last().unwrap_or_default().to_string(),
    ))
}

fn build_service_entries(
    did: &str,
    agent_description_url: Option<&str>,
    services: &[Value],
) -> Vec<Value> {
    let mut output = Vec::new();
    if let Some(url) = agent_description_url {
        output.push(json!({
            "id": format!("{did}#ad"),
            "type": "AgentDescription",
            "serviceEndpoint": url,
        }));
    }
    for service in services {
        let mut copy = service.clone();
        if let Some(object) = copy.as_object_mut() {
            if let Some(id_value) = object.get("id").and_then(Value::as_str) {
                if id_value.starts_with('#') {
                    object.insert(
                        "id".to_string(),
                        Value::String(format!("{did}{id_value}")),
                    );
                }
            }
        }
        output.push(copy);
    }
    output
}

fn build_did_base(hostname: &str, port: Option<u16>) -> String {
    match port {
        Some(value) => format!("did:wba:{hostname}%3A{value}"),
        None => format!("did:wba:{hostname}"),
    }
}

fn join_did(base: &str, path_segments: &[String]) -> String {
    if path_segments.is_empty() {
        base.to_string()
    } else {
        format!("{}:{}", base, path_segments.join(":"))
    }
}

fn jwk_thumbprint(jwk: &Value) -> Result<String, AuthenticationError> {
    let canonical = canonicalize_json(jwk)
        .map_err(|_| AuthenticationError::JsonFailure)?;
    Ok(base64url_encode(&Sha256::digest(canonical)))
}

fn secp256k1_public_key_to_jwk(
    key: &k256::ecdsa::VerifyingKey,
) -> Result<Value, AuthenticationError> {
    let point = key.to_encoded_point(false);
    let x = point.x().ok_or(AuthenticationError::InvalidDidDocument)?;
    let y = point.y().ok_or(AuthenticationError::InvalidDidDocument)?;
    Ok(json!({
        "crv": "secp256k1",
        "kty": "EC",
        "x": base64url_encode(x),
        "y": base64url_encode(y),
    }))
}

fn secp256r1_public_key_to_jwk(
    key: &p256::ecdsa::VerifyingKey,
) -> Result<Value, AuthenticationError> {
    let point = key.to_encoded_point(false);
    let x = point.x().ok_or(AuthenticationError::InvalidDidDocument)?;
    let y = point.y().ok_or(AuthenticationError::InvalidDidDocument)?;
    Ok(json!({
        "crv": "P-256",
        "kty": "EC",
        "x": base64url_encode(x),
        "y": base64url_encode(y),
    }))
}

fn ed25519_public_key_to_multibase(key: &ed25519_dalek::VerifyingKey) -> String {
    let mut bytes = vec![0xed, 0x01];
    bytes.extend_from_slice(&key.to_bytes());
    format!("z{}", bs58::encode(bytes).into_string())
}

fn x25519_public_key_to_multibase(bytes: &[u8; 32]) -> String {
    let mut prefixed = vec![0xec, 0x01];
    prefixed.extend_from_slice(bytes);
    format!("z{}", bs58::encode(prefixed).into_string())
}

fn domain_field_for_version(version: &str) -> &'static str {
    version
        .parse::<f64>()
        .map(|value| if value >= 1.1 { "aud" } else { "service" })
        .unwrap_or("service")
}

fn is_ip_address(hostname: &str) -> bool {
    hostname.parse::<std::net::IpAddr>().is_ok()
}
