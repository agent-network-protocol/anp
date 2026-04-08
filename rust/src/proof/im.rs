//! ANP IM business proof generation and verification.

use std::collections::BTreeMap;

use base64::{
    engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine as _,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::authentication::{
    build_content_digest, find_verification_method, is_assertion_method_authorized,
    is_authentication_authorized,
};
use crate::{PrivateKeyMaterial, PublicKeyMaterial};

pub const IM_PROOF_DEFAULT_COMPONENTS: [&str; 3] = ["@method", "@target-uri", "content-digest"];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImProof {
    #[serde(rename = "contentDigest")]
    pub content_digest: String,
    #[serde(rename = "signatureInput")]
    pub signature_input: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedImSignatureInput {
    pub label: String,
    pub components: Vec<String>,
    pub signature_params: String,
    pub keyid: String,
    pub nonce: Option<String>,
    pub created: Option<i64>,
    pub expires: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImProofGenerationOptions {
    pub label: String,
    pub components: Vec<String>,
    pub created: Option<i64>,
    pub expires: Option<i64>,
    pub nonce: Option<String>,
}

impl Default for ImProofGenerationOptions {
    fn default() -> Self {
        Self {
            label: "sig1".to_owned(),
            components: IM_PROOF_DEFAULT_COMPONENTS
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            created: None,
            expires: None,
            nonce: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImProofVerificationResult {
    pub parsed_signature_input: ParsedImSignatureInput,
    pub verification_method: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ImProofVerificationRelationship {
    #[default]
    Authentication,
    AssertionMethod,
}

impl ImProofVerificationRelationship {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::AssertionMethod => "assertionMethod",
        }
    }
}

#[derive(Debug, Error)]
pub enum ImProofError {
    #[error("missing proof field: {0}")]
    MissingField(&'static str),
    #[error("invalid proof.signatureInput format")]
    InvalidSignatureInput,
    #[error("proof.signatureInput must include covered components")]
    MissingCoveredComponents,
    #[error("proof.signatureInput must include keyid")]
    MissingKeyId,
    #[error("invalid proof.signature encoding")]
    InvalidSignatureEncoding,
    #[error("proof contentDigest does not match request payload")]
    InvalidContentDigest,
    #[error("verification method not found in DID document")]
    VerificationMethodNotFound,
    #[error("proof keyid must belong to expected signer DID")]
    InvalidSignerDid,
    #[error("verification method is not authorized for {0}")]
    UnauthorizedVerificationMethod(&'static str),
    #[error("signing error")]
    SigningError,
    #[error("signature verification failed")]
    VerificationFailed,
}

pub fn build_im_content_digest(payload: &[u8]) -> String {
    build_content_digest(payload)
}

pub fn verify_im_content_digest(payload: &[u8], content_digest: &str) -> bool {
    build_im_content_digest(payload) == content_digest.trim()
}

pub fn build_im_signature_input(
    keyid: &str,
    options: ImProofGenerationOptions,
) -> Result<String, ImProofError> {
    if options.components.is_empty() {
        return Err(ImProofError::MissingCoveredComponents);
    }
    let created = options.created.unwrap_or_else(|| Utc::now().timestamp());
    let nonce = options
        .nonce
        .unwrap_or_else(|| crate::keys::base64url_encode(&rand::random::<[u8; 16]>()));
    let quoted_components = options
        .components
        .iter()
        .map(|component| format!("\"{component}\""))
        .collect::<Vec<_>>()
        .join(" ");
    let mut params = vec![format!("created={created}")];
    if let Some(expires) = options.expires {
        params.push(format!("expires={expires}"));
    }
    params.push(format!("nonce=\"{nonce}\""));
    params.push(format!("keyid=\"{keyid}\""));
    Ok(format!(
        "{}=({quoted_components});{}",
        options.label,
        params.join(";")
    ))
}

pub fn parse_im_signature_input(
    signature_input: &str,
) -> Result<ParsedImSignatureInput, ImProofError> {
    let (label, remainder) = signature_input
        .split_once('=')
        .ok_or(ImProofError::InvalidSignatureInput)?;
    let remainder = remainder.trim();
    let open = remainder
        .find('(')
        .ok_or(ImProofError::InvalidSignatureInput)?;
    let close = remainder[open..]
        .find(')')
        .map(|index| open + index)
        .ok_or(ImProofError::InvalidSignatureInput)?;
    let components = remainder[open + 1..close]
        .split_whitespace()
        .map(|component| component.trim_matches('"').to_owned())
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    if components.is_empty() {
        return Err(ImProofError::MissingCoveredComponents);
    }

    let params_raw = remainder[close + 1..].trim_start_matches(';');
    let mut params = BTreeMap::new();
    for raw in params_raw.split(';') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let (name, value) = raw
            .split_once('=')
            .ok_or(ImProofError::InvalidSignatureInput)?;
        params.insert(
            name.trim().to_owned(),
            value.trim().trim_matches('"').to_owned(),
        );
    }
    let keyid = params
        .get("keyid")
        .cloned()
        .ok_or(ImProofError::MissingKeyId)?;

    Ok(ParsedImSignatureInput {
        label: label.trim().to_owned(),
        components,
        signature_params: remainder.to_owned(),
        keyid,
        nonce: params.get("nonce").cloned(),
        created: params
            .get("created")
            .and_then(|value| value.parse::<i64>().ok()),
        expires: params
            .get("expires")
            .and_then(|value| value.parse::<i64>().ok()),
    })
}

pub fn encode_im_signature(signature_bytes: &[u8], label: &str) -> String {
    format!("{label}=:{}:", STANDARD.encode(signature_bytes))
}

pub fn decode_im_signature(signature: &str) -> Result<(Option<String>, Vec<u8>), ImProofError> {
    let trimmed = signature.trim();
    let (label, encoded) = if let Some((label, value)) = trimmed.split_once("=:") {
        let encoded = value.trim_end_matches(':').trim();
        (Some(label.to_owned()), encoded.to_owned())
    } else {
        (
            None,
            trimmed
                .trim_start_matches(':')
                .trim_end_matches(':')
                .trim()
                .to_owned(),
        )
    };
    STANDARD
        .decode(encoded.as_bytes())
        .or_else(|_| URL_SAFE_NO_PAD.decode(encoded.as_bytes()))
        .map(|signature_bytes| (label, signature_bytes))
        .map_err(|_| ImProofError::InvalidSignatureEncoding)
}

pub fn generate_im_proof(
    payload: &[u8],
    signature_base: &[u8],
    private_key: &PrivateKeyMaterial,
    keyid: &str,
    options: ImProofGenerationOptions,
) -> Result<ImProof, ImProofError> {
    let signature_input = build_im_signature_input(keyid, options.clone())?;
    let signature_bytes = private_key
        .sign_message(signature_base)
        .map_err(|_| ImProofError::SigningError)?;
    Ok(ImProof {
        content_digest: build_im_content_digest(payload),
        signature_input,
        signature: encode_im_signature(&signature_bytes, &options.label),
    })
}

pub fn verify_im_proof_with_document(
    proof: &ImProof,
    payload: &[u8],
    signature_base: &[u8],
    did_document: &Value,
    expected_signer_did: Option<&str>,
) -> Result<ImProofVerificationResult, ImProofError> {
    verify_im_proof_with_document_for_relationship(
        proof,
        payload,
        signature_base,
        did_document,
        expected_signer_did,
        ImProofVerificationRelationship::Authentication,
    )
}

pub fn verify_im_proof_with_document_for_relationship(
    proof: &ImProof,
    payload: &[u8],
    signature_base: &[u8],
    did_document: &Value,
    expected_signer_did: Option<&str>,
    verification_relationship: ImProofVerificationRelationship,
) -> Result<ImProofVerificationResult, ImProofError> {
    let parsed = parse_im_signature_input(&proof.signature_input)?;
    if let Some(expected_signer_did) = expected_signer_did {
        if !keyid_belongs_to_expected_did(&parsed.keyid, expected_signer_did) {
            return Err(ImProofError::InvalidSignerDid);
        }
    }
    if !is_verification_method_authorized(did_document, &parsed.keyid, verification_relationship) {
        return Err(ImProofError::UnauthorizedVerificationMethod(
            verification_relationship.as_str(),
        ));
    }
    let verification_method = find_verification_method(did_document, &parsed.keyid)
        .ok_or(ImProofError::VerificationMethodNotFound)?;
    verify_im_proof_with_public_key(
        proof,
        payload,
        signature_base,
        &verification_method,
        expected_signer_did,
    )
}

pub fn verify_im_proof_with_public_key(
    proof: &ImProof,
    payload: &[u8],
    signature_base: &[u8],
    verification_method: &Value,
    expected_signer_did: Option<&str>,
) -> Result<ImProofVerificationResult, ImProofError> {
    let parsed = parse_im_signature_input(&proof.signature_input)?;
    if let Some(expected_signer_did) = expected_signer_did {
        if !keyid_belongs_to_expected_did(&parsed.keyid, expected_signer_did) {
            return Err(ImProofError::InvalidSignerDid);
        }
    }
    if !verify_im_content_digest(payload, &proof.content_digest) {
        return Err(ImProofError::InvalidContentDigest);
    }
    let (_label, signature_bytes) = decode_im_signature(&proof.signature)?;
    let public_key = crate::authentication::extract_public_key(verification_method)
        .map_err(|_| ImProofError::VerificationMethodNotFound)?;
    verify_im_signature_bytes(&public_key, signature_base, &signature_bytes)?;
    Ok(ImProofVerificationResult {
        parsed_signature_input: parsed,
        verification_method: verification_method.clone(),
    })
}

fn verify_im_signature_bytes(
    public_key: &PublicKeyMaterial,
    signature_base: &[u8],
    signature_bytes: &[u8],
) -> Result<(), ImProofError> {
    public_key
        .verify_message(signature_base, signature_bytes)
        .map_err(|_| ImProofError::VerificationFailed)
}

fn keyid_belongs_to_expected_did(keyid: &str, expected_signer_did: &str) -> bool {
    keyid
        .split('#')
        .next()
        .map(|did| did == expected_signer_did)
        .unwrap_or(false)
}

fn is_verification_method_authorized(
    did_document: &Value,
    verification_method_id: &str,
    verification_relationship: ImProofVerificationRelationship,
) -> bool {
    match verification_relationship {
        ImProofVerificationRelationship::Authentication => {
            is_authentication_authorized(did_document, verification_method_id)
        }
        ImProofVerificationRelationship::AssertionMethod => {
            is_assertion_method_authorized(did_document, verification_method_id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_im_content_digest, build_im_signature_input, decode_im_signature, generate_im_proof,
        parse_im_signature_input, verify_im_proof_with_document,
        verify_im_proof_with_document_for_relationship, ImProofGenerationOptions,
        ImProofVerificationRelationship,
    };
    use crate::authentication::{create_did_wba_document, DidDocumentOptions, DidProfile};
    use crate::PrivateKeyMaterial;
    use serde_json::json;

    fn business_signature_base(
        method: &str,
        target_uri: &str,
        content_digest: &str,
        signature_input: &str,
    ) -> Vec<u8> {
        let parsed =
            parse_im_signature_input(signature_input).expect("signature input should parse");
        let lines = parsed
            .components
            .iter()
            .map(|component| match component.as_str() {
                "@method" => format!("\"{component}\": {method}"),
                "@target-uri" => format!("\"{component}\": {target_uri}"),
                "content-digest" => format!("\"{component}\": {content_digest}"),
                other => panic!("unexpected component: {other}"),
            })
            .chain(std::iter::once(format!(
                "\"@signature-params\": {}",
                parsed.signature_params
            )))
            .collect::<Vec<_>>();
        lines.join("\n").into_bytes()
    }

    #[test]
    fn generates_and_verifies_e1_im_proof() {
        let bundle = create_did_wba_document(
            "example.com",
            DidDocumentOptions {
                path_segments: vec!["user".to_owned(), "alice".to_owned()],
                did_profile: DidProfile::E1,
                ..DidDocumentOptions::default()
            },
        )
        .expect("bundle should be created");
        let private_key = PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
            .expect("private key should load");
        let payload = br#"{"text":"hello"}"#;
        let signature_input = build_im_signature_input(
            &format!("{}#key-1", bundle.did().expect("did should exist")),
            ImProofGenerationOptions {
                created: Some(1_712_000_000),
                nonce: Some("nonce-1".to_owned()),
                ..ImProofGenerationOptions::default()
            },
        )
        .expect("signature input should build");
        let signature_base = business_signature_base(
            "direct.send",
            &format!(
                "anp://agent/{}",
                url::form_urlencoded::byte_serialize(
                    bundle.did().expect("did should exist").as_bytes()
                )
                .collect::<String>()
            ),
            &build_im_content_digest(payload),
            &signature_input,
        );
        let proof = generate_im_proof(
            payload,
            &signature_base,
            &private_key,
            &format!("{}#key-1", bundle.did().expect("did should exist")),
            ImProofGenerationOptions {
                created: Some(1_712_000_000),
                nonce: Some("nonce-1".to_owned()),
                ..ImProofGenerationOptions::default()
            },
        )
        .expect("proof should generate");
        let result = verify_im_proof_with_document(
            &proof,
            payload,
            &signature_base,
            &bundle.did_document,
            bundle.did(),
        )
        .expect("proof should verify");
        assert_eq!(
            result.parsed_signature_input.nonce.as_deref(),
            Some("nonce-1")
        );
    }

    #[test]
    fn rejects_tampered_payload() {
        let bundle = create_did_wba_document(
            "example.com",
            DidDocumentOptions {
                path_segments: vec!["user".to_owned(), "eve".to_owned()],
                ..DidDocumentOptions::default()
            },
        )
        .expect("bundle should be created");
        let private_key = PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
            .expect("private key should load");
        let payload = br#"{"text":"hello"}"#;
        let proof = generate_im_proof(
            payload,
            &business_signature_base(
                "direct.send",
                &format!(
                    "anp://agent/{}",
                    url::form_urlencoded::byte_serialize(
                        bundle.did().expect("did should exist").as_bytes()
                    )
                    .collect::<String>()
                ),
                &build_im_content_digest(payload),
                &build_im_signature_input(
                    &format!("{}#key-1", bundle.did().expect("did should exist")),
                    ImProofGenerationOptions::default(),
                )
                .expect("signature input should build"),
            ),
            &private_key,
            &format!("{}#key-1", bundle.did().expect("did should exist")),
            ImProofGenerationOptions::default(),
        )
        .expect("proof should generate");
        let signature_base = business_signature_base(
            "direct.send",
            &format!(
                "anp://agent/{}",
                url::form_urlencoded::byte_serialize(
                    bundle.did().expect("did should exist").as_bytes()
                )
                .collect::<String>()
            ),
            &proof.content_digest,
            &proof.signature_input,
        );
        let error = verify_im_proof_with_document(
            &proof,
            br#"{"text":"tampered"}"#,
            &signature_base,
            &bundle.did_document,
            bundle.did(),
        )
        .expect_err("tampered payload should fail");
        assert!(matches!(error, super::ImProofError::InvalidContentDigest));
    }

    #[test]
    fn signature_round_trip() {
        let encoded = super::encode_im_signature(b"hello", "sig2");
        let (label, decoded) = decode_im_signature(&encoded).expect("signature should decode");
        assert_eq!(label.as_deref(), Some("sig2"));
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn signer_did_match_requires_exact_did_url_owner() {
        let bundle = create_did_wba_document(
            "example.com",
            DidDocumentOptions {
                path_segments: vec!["user".to_owned(), "alice".to_owned()],
                did_profile: DidProfile::E1,
                ..DidDocumentOptions::default()
            },
        )
        .expect("bundle should be created");
        let private_key = PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
            .expect("private key should load");
        let payload = br#"{"text":"hello"}"#;
        let signature_input = build_im_signature_input(
            &format!("{}#key-1", bundle.did_document["id"].as_str().expect("did")),
            ImProofGenerationOptions {
                created: Some(1_712_000_000),
                nonce: Some("nonce-1".to_owned()),
                ..ImProofGenerationOptions::default()
            },
        )
        .expect("signature input should build");
        let signature_base = business_signature_base(
            "direct.send",
            "anp://agent/did%3Awba%3Aexample.com%3Auser%3Abob%3Ae1_bob",
            &build_im_content_digest(payload),
            &signature_input,
        );
        let proof = generate_im_proof(
            payload,
            &signature_base,
            &private_key,
            &format!("{}#key-1", bundle.did_document["id"].as_str().expect("did")),
            ImProofGenerationOptions {
                created: Some(1_712_000_000),
                nonce: Some("nonce-1".to_owned()),
                ..ImProofGenerationOptions::default()
            },
        )
        .expect("proof should generate");

        let error = verify_im_proof_with_document(
            &proof,
            payload,
            &signature_base,
            &bundle.did_document,
            Some("did:wba:example.com:user:alice"),
        )
        .expect_err("prefix-only DID match must fail");
        assert!(matches!(error, super::ImProofError::InvalidSignerDid));
    }

    #[test]
    fn defaults_to_authentication_relationship() {
        let bundle = create_did_wba_document(
            "example.com",
            DidDocumentOptions {
                path_segments: vec!["user".to_owned(), "assertion-only".to_owned()],
                did_profile: DidProfile::E1,
                ..DidDocumentOptions::default()
            },
        )
        .expect("bundle should be created");
        let private_key = PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
            .expect("private key should load");
        let payload = br#"{"text":"hello"}"#;
        let signature_input = build_im_signature_input(
            &format!("{}#key-1", bundle.did().expect("did should exist")),
            ImProofGenerationOptions {
                created: Some(1_712_000_200),
                nonce: Some("nonce-auth".to_owned()),
                ..ImProofGenerationOptions::default()
            },
        )
        .expect("signature input should build");
        let signature_base = business_signature_base(
            "direct.send",
            &format!(
                "anp://agent/{}",
                url::form_urlencoded::byte_serialize(
                    bundle.did().expect("did should exist").as_bytes()
                )
                .collect::<String>()
            ),
            &build_im_content_digest(payload),
            &signature_input,
        );
        let proof = generate_im_proof(
            payload,
            &signature_base,
            &private_key,
            &format!("{}#key-1", bundle.did().expect("did should exist")),
            ImProofGenerationOptions {
                created: Some(1_712_000_200),
                nonce: Some("nonce-auth".to_owned()),
                ..ImProofGenerationOptions::default()
            },
        )
        .expect("proof should generate");
        let mut did_document = bundle.did_document.clone();
        did_document
            .as_object_mut()
            .expect("document object")
            .insert("authentication".to_string(), json!([]));

        let error = verify_im_proof_with_document(
            &proof,
            payload,
            &business_signature_base(
                "direct.send",
                &format!(
                    "anp://agent/{}",
                    url::form_urlencoded::byte_serialize(
                        bundle.did().expect("did should exist").as_bytes()
                    )
                    .collect::<String>()
                ),
                &proof.content_digest,
                &proof.signature_input,
            ),
            &did_document,
            bundle.did(),
        )
        .expect_err("authentication relationship should be required by default");
        assert!(matches!(
            error,
            super::ImProofError::UnauthorizedVerificationMethod("authentication")
        ));

        verify_im_proof_with_document_for_relationship(
            &proof,
            payload,
            &business_signature_base(
                "direct.send",
                &format!(
                    "anp://agent/{}",
                    url::form_urlencoded::byte_serialize(
                        bundle.did().expect("did should exist").as_bytes()
                    )
                    .collect::<String>()
                ),
                &proof.content_digest,
                &proof.signature_input,
            ),
            &did_document,
            bundle.did(),
            ImProofVerificationRelationship::AssertionMethod,
        )
        .expect("assertionMethod verification should succeed");
    }
}
