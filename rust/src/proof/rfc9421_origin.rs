//! RFC 9421 origin proof helpers for ANP requests.

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

use crate::canonical_json::canonicalize_json;
use crate::proof::{
    build_im_content_digest, build_im_signature_input, encode_im_signature,
    parse_im_signature_input, verify_im_proof_with_document, verify_im_proof_with_public_key,
    ImProof, ImProofError, ImProofGenerationOptions, ImProofVerificationResult,
    IM_PROOF_DEFAULT_COMPONENTS,
};
use crate::PrivateKeyMaterial;

const RFC3986_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'!')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

pub const RFC9421_ORIGIN_PROOF_DEFAULT_LABEL: &str = "sig1";
pub const RFC9421_ORIGIN_PROOF_DEFAULT_COMPONENTS: [&str; 3] = IM_PROOF_DEFAULT_COMPONENTS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    Agent,
    Group,
    Service,
}

impl TargetKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Group => "group",
            Self::Service => "service",
        }
    }
}

impl TryFrom<&str> for TargetKind {
    type Error = Rfc9421OriginProofError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "agent" => Ok(Self::Agent),
            "group" => Ok(Self::Group),
            "service" => Ok(Self::Service),
            other => Err(Rfc9421OriginProofError::UnsupportedTargetKind(
                other.to_owned(),
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRequestObject {
    pub method: String,
    pub meta: Value,
    pub body: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rfc9421OriginProof {
    #[serde(rename = "contentDigest")]
    pub content_digest: String,
    #[serde(rename = "signatureInput")]
    pub signature_input: String,
    pub signature: String,
}

impl From<ImProof> for Rfc9421OriginProof {
    fn from(value: ImProof) -> Self {
        Self {
            content_digest: value.content_digest,
            signature_input: value.signature_input,
            signature: value.signature,
        }
    }
}

impl From<Rfc9421OriginProof> for ImProof {
    fn from(value: Rfc9421OriginProof) -> Self {
        Self {
            content_digest: value.content_digest,
            signature_input: value.signature_input,
            signature: value.signature,
        }
    }
}

impl From<&Rfc9421OriginProof> for ImProof {
    fn from(value: &Rfc9421OriginProof) -> Self {
        Self {
            content_digest: value.content_digest.clone(),
            signature_input: value.signature_input.clone(),
            signature: value.signature.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Rfc9421OriginProofGenerationOptions {
    pub created: Option<i64>,
    pub expires: Option<i64>,
    pub nonce: Option<String>,
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Rfc9421OriginProofVerificationOptions {
    pub did_document: Option<Value>,
    pub verification_method: Option<Value>,
    pub expected_signer_did: Option<String>,
}

#[derive(Debug, Error)]
pub enum Rfc9421OriginProofError {
    #[error("method is required")]
    MissingMethod,
    #[error("meta must be an object")]
    InvalidMeta,
    #[error("body must be an object")]
    InvalidBody,
    #[error("meta.target is required")]
    MissingTarget,
    #[error("target did is required")]
    MissingTargetDid,
    #[error("logical_target_uri is required")]
    MissingLogicalTargetUri,
    #[error("content_digest is required")]
    MissingContentDigest,
    #[error("unsupported target kind: {0}")]
    UnsupportedTargetKind(String),
    #[error("RFC 9421 origin proof requires signature label sig1")]
    InvalidLabel,
    #[error(
        "RFC 9421 origin proof requires covered components (\"@method\" \"@target-uri\" \"content-digest\")"
    )]
    InvalidCoveredComponents,
    #[error("did_document or verification_method is required")]
    MissingVerificationMaterial,
    #[error(transparent)]
    Canonicalization(#[from] crate::canonical_json::CanonicalJsonError),
    #[error(transparent)]
    ImProof(#[from] ImProofError),
}

pub fn build_signed_request_object(
    method: &str,
    meta: &Value,
    body: &Value,
) -> Result<SignedRequestObject, Rfc9421OriginProofError> {
    if method.trim().is_empty() {
        return Err(Rfc9421OriginProofError::MissingMethod);
    }
    if !meta.is_object() {
        return Err(Rfc9421OriginProofError::InvalidMeta);
    }
    if !body.is_object() {
        return Err(Rfc9421OriginProofError::InvalidBody);
    }
    Ok(SignedRequestObject {
        method: method.to_owned(),
        meta: meta.clone(),
        body: body.clone(),
    })
}

pub fn canonicalize_signed_request_object(
    signed_request_object: &SignedRequestObject,
) -> Result<Vec<u8>, Rfc9421OriginProofError> {
    if signed_request_object.method.trim().is_empty() {
        return Err(Rfc9421OriginProofError::MissingMethod);
    }
    if !signed_request_object.meta.is_object() {
        return Err(Rfc9421OriginProofError::InvalidMeta);
    }
    if !signed_request_object.body.is_object() {
        return Err(Rfc9421OriginProofError::InvalidBody);
    }
    canonicalize_json(&json!({
        "method": signed_request_object.method.clone(),
        "meta": signed_request_object.meta.clone(),
        "body": signed_request_object.body.clone(),
    }))
    .map_err(Rfc9421OriginProofError::from)
}

pub fn build_logical_target_uri(
    target_kind: TargetKind,
    target_did: &str,
) -> Result<String, Rfc9421OriginProofError> {
    if target_did.trim().is_empty() {
        return Err(Rfc9421OriginProofError::MissingTargetDid);
    }
    Ok(format!(
        "anp://{}/{}",
        target_kind.as_str(),
        utf8_percent_encode(target_did, RFC3986_ENCODE_SET)
    ))
}

pub fn build_rfc9421_origin_signature_base(
    method: &str,
    logical_target_uri: &str,
    content_digest: &str,
    signature_input: &str,
) -> Result<Vec<u8>, Rfc9421OriginProofError> {
    if method.trim().is_empty() {
        return Err(Rfc9421OriginProofError::MissingMethod);
    }
    if logical_target_uri.trim().is_empty() {
        return Err(Rfc9421OriginProofError::MissingLogicalTargetUri);
    }
    if content_digest.trim().is_empty() {
        return Err(Rfc9421OriginProofError::MissingContentDigest);
    }
    let parsed = parse_im_signature_input(signature_input)?;
    validate_parsed_signature_input(&parsed.label, &parsed.components)?;
    let lines = parsed
        .components
        .iter()
        .map(|component| match component.as_str() {
            "@method" => format!("\"{component}\": {method}"),
            "@target-uri" => format!("\"{component}\": {logical_target_uri}"),
            "content-digest" => format!("\"{component}\": {content_digest}"),
            _ => unreachable!("covered components validated above"),
        })
        .chain(std::iter::once(format!(
            "\"@signature-params\": {}",
            parsed.signature_params
        )))
        .collect::<Vec<_>>();
    Ok(lines.join("\n").into_bytes())
}

pub fn generate_rfc9421_origin_proof(
    method: &str,
    meta: &Value,
    body: &Value,
    private_key: &PrivateKeyMaterial,
    keyid: &str,
    options: Rfc9421OriginProofGenerationOptions,
) -> Result<Rfc9421OriginProof, Rfc9421OriginProofError> {
    let normalized_label = normalized_label(options.label.as_deref())?;
    let signed_request_object = build_signed_request_object(method, meta, body)?;
    let canonical_request = canonicalize_signed_request_object(&signed_request_object)?;
    let logical_target_uri = build_logical_target_uri_from_meta(&signed_request_object.meta)?;
    let proof_options = ImProofGenerationOptions {
        label: normalized_label.to_owned(),
        components: RFC9421_ORIGIN_PROOF_DEFAULT_COMPONENTS
            .iter()
            .map(|component| (*component).to_owned())
            .collect(),
        created: options.created,
        expires: options.expires,
        nonce: options.nonce.clone(),
    };
    let signature_input = build_im_signature_input(keyid, proof_options.clone())?;
    let content_digest = build_im_content_digest(&canonical_request);
    let signature_base = build_rfc9421_origin_signature_base(
        method,
        &logical_target_uri,
        &content_digest,
        &signature_input,
    )?;
    let signature = private_key
        .sign_message(&signature_base)
        .map_err(|_| Rfc9421OriginProofError::ImProof(ImProofError::SigningError))?;
    let proof = Rfc9421OriginProof {
        content_digest,
        signature_input,
        signature: encode_im_signature(&signature, normalized_label),
    };
    let parsed = parse_im_signature_input(&proof.signature_input)?;
    validate_parsed_signature_input(&parsed.label, &parsed.components)?;
    Ok(proof.into())
}

pub fn verify_rfc9421_origin_proof(
    origin_proof: &Rfc9421OriginProof,
    method: &str,
    meta: &Value,
    body: &Value,
    options: Rfc9421OriginProofVerificationOptions,
) -> Result<ImProofVerificationResult, Rfc9421OriginProofError> {
    let signed_request_object = build_signed_request_object(method, meta, body)?;
    let canonical_request = canonicalize_signed_request_object(&signed_request_object)?;
    let logical_target_uri = build_logical_target_uri_from_meta(&signed_request_object.meta)?;
    let parsed = parse_im_signature_input(&origin_proof.signature_input)?;
    validate_parsed_signature_input(&parsed.label, &parsed.components)?;
    let signature_base = build_rfc9421_origin_signature_base(
        method,
        &logical_target_uri,
        &origin_proof.content_digest,
        &origin_proof.signature_input,
    )?;
    let im_proof = ImProof::from(origin_proof);
    if let Some(verification_method) = options.verification_method.as_ref() {
        return verify_im_proof_with_public_key(
            &im_proof,
            &canonical_request,
            &signature_base,
            verification_method,
            options.expected_signer_did.as_deref(),
        )
        .map_err(Rfc9421OriginProofError::from);
    }
    let did_document = options
        .did_document
        .as_ref()
        .ok_or(Rfc9421OriginProofError::MissingVerificationMaterial)?;
    verify_im_proof_with_document(
        &im_proof,
        &canonical_request,
        &signature_base,
        did_document,
        options.expected_signer_did.as_deref(),
    )
    .map_err(Rfc9421OriginProofError::from)
}

fn build_logical_target_uri_from_meta(meta: &Value) -> Result<String, Rfc9421OriginProofError> {
    let target = meta
        .get("target")
        .and_then(Value::as_object)
        .ok_or(Rfc9421OriginProofError::MissingTarget)?;
    let target_kind = target
        .get("kind")
        .and_then(Value::as_str)
        .ok_or(Rfc9421OriginProofError::MissingTarget)?;
    let target_did = target
        .get("did")
        .and_then(Value::as_str)
        .ok_or(Rfc9421OriginProofError::MissingTargetDid)?;
    build_logical_target_uri(TargetKind::try_from(target_kind)?, target_did)
}

fn normalized_label(label: Option<&str>) -> Result<&str, Rfc9421OriginProofError> {
    match label {
        None | Some("") => Ok(RFC9421_ORIGIN_PROOF_DEFAULT_LABEL),
        Some(RFC9421_ORIGIN_PROOF_DEFAULT_LABEL) => Ok(RFC9421_ORIGIN_PROOF_DEFAULT_LABEL),
        Some(_) => Err(Rfc9421OriginProofError::InvalidLabel),
    }
}

fn validate_parsed_signature_input(
    label: &str,
    components: &[String],
) -> Result<(), Rfc9421OriginProofError> {
    normalized_label(Some(label))?;
    let expected = RFC9421_ORIGIN_PROOF_DEFAULT_COMPONENTS
        .iter()
        .map(|component| (*component).to_owned())
        .collect::<Vec<_>>();
    if components != expected {
        return Err(Rfc9421OriginProofError::InvalidCoveredComponents);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        build_logical_target_uri, build_signed_request_object, canonicalize_signed_request_object,
        generate_rfc9421_origin_proof, verify_rfc9421_origin_proof, Rfc9421OriginProofError,
        Rfc9421OriginProofGenerationOptions, Rfc9421OriginProofVerificationOptions, TargetKind,
        RFC9421_ORIGIN_PROOF_DEFAULT_COMPONENTS, RFC9421_ORIGIN_PROOF_DEFAULT_LABEL,
    };
    use crate::authentication::{create_did_wba_document, DidDocumentOptions};
    use crate::PrivateKeyMaterial;
    use serde_json::json;

    #[test]
    fn canonicalized_signed_request_object_omits_wrapper_fields() {
        let signed_request_object = build_signed_request_object(
            "direct.send",
            &json!({
                "anp_version": "1.0",
                "profile": "anp.direct.base.v1",
                "security_profile": "transport-protected",
                "sender_did": "did:wba:example.com:user:alice:e1_alice",
                "target": {"kind": "agent", "did": "did:wba:example.com:user:bob:e1_bob"},
                "operation_id": "op-1",
                "message_id": "msg-1",
                "content_type": "text/plain"
            }),
            &json!({"text": "hello"}),
        )
        .expect("signed request object should build");
        let canonical = canonicalize_signed_request_object(&signed_request_object)
            .expect("signed request object should canonicalize");
        let canonical_text = String::from_utf8(canonical).expect("utf-8 canonical json");
        assert!(!canonical_text.contains("\"auth\""));
        assert!(!canonical_text.contains("\"client\""));
        assert!(!canonical_text.contains("\"jsonrpc\""));
        assert!(!canonical_text.contains("\"id\""));
    }

    #[test]
    fn logical_target_uri_percent_encodes_did() {
        let target_uri = build_logical_target_uri(
            TargetKind::Service,
            "did:wba:example.com:services:message:e1_service",
        )
        .expect("target uri should build");
        assert_eq!(
            target_uri,
            "anp://service/did%3Awba%3Aexample.com%3Aservices%3Amessage%3Ae1_service"
        );
    }

    #[test]
    fn generates_and_verifies_direct_origin_proof() {
        let bundle = create_did_wba_document(
            "example.com",
            DidDocumentOptions {
                path_segments: vec!["user".to_owned(), "alice".to_owned()],
                ..DidDocumentOptions::default()
            },
        )
        .expect("bundle should be created");
        let private_key = PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
            .expect("private key should load");
        let did = bundle.did().expect("did should exist").to_owned();
        let meta = json!({
            "anp_version": "1.0",
            "profile": "anp.direct.base.v1",
            "security_profile": "transport-protected",
            "sender_did": did.clone(),
            "target": {"kind": "agent", "did": "did:wba:example.com:user:bob:e1_bob"},
            "operation_id": "op-1",
            "message_id": "msg-1",
            "content_type": "text/plain"
        });
        let body = json!({"text": "hello"});
        let origin_proof = generate_rfc9421_origin_proof(
            "direct.send",
            &meta,
            &body,
            &private_key,
            &format!("{did}#key-1"),
            Rfc9421OriginProofGenerationOptions {
                created: Some(1_712_000_000),
                nonce: Some("nonce-1".to_owned()),
                ..Rfc9421OriginProofGenerationOptions::default()
            },
        )
        .expect("origin proof should generate");
        let result = verify_rfc9421_origin_proof(
            &origin_proof,
            "direct.send",
            &meta,
            &body,
            Rfc9421OriginProofVerificationOptions {
                did_document: Some(bundle.did_document.clone()),
                expected_signer_did: Some(did.clone()),
                ..Rfc9421OriginProofVerificationOptions::default()
            },
        )
        .expect("origin proof should verify");
        assert_eq!(
            result.parsed_signature_input.label,
            RFC9421_ORIGIN_PROOF_DEFAULT_LABEL
        );
        assert_eq!(
            result.parsed_signature_input.components,
            RFC9421_ORIGIN_PROOF_DEFAULT_COMPONENTS
                .iter()
                .map(|component| (*component).to_owned())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn generates_and_verifies_direct_origin_proof_with_angle_brackets_and_arrow() {
        let bundle = create_did_wba_document(
            "example.com",
            DidDocumentOptions {
                path_segments: vec!["user".to_owned(), "alice".to_owned()],
                ..DidDocumentOptions::default()
            },
        )
        .expect("bundle should be created");
        let private_key = PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
            .expect("private key should load");
        let did = bundle.did().expect("did should exist").to_owned();
        let meta = json!({
            "anp_version": "1.0",
            "profile": "anp.direct.base.v1",
            "security_profile": "transport-protected",
            "sender_did": did.clone(),
            "target": {"kind": "agent", "did": "did:wba:example.com:user:bob:e1_bob"},
            "operation_id": "op-html-chars",
            "message_id": "msg-html-chars",
            "content_type": "text/plain"
        });
        let body = json!({"text": "alice->bob <hello> & goodbye"});
        let origin_proof = generate_rfc9421_origin_proof(
            "direct.send",
            &meta,
            &body,
            &private_key,
            &format!("{did}#key-1"),
            Rfc9421OriginProofGenerationOptions::default(),
        )
        .expect("origin proof should generate");
        verify_rfc9421_origin_proof(
            &origin_proof,
            "direct.send",
            &meta,
            &body,
            Rfc9421OriginProofVerificationOptions {
                did_document: Some(bundle.did_document.clone()),
                expected_signer_did: Some(did),
                ..Rfc9421OriginProofVerificationOptions::default()
            },
        )
        .expect("origin proof should verify");
    }

    #[test]
    fn generates_and_verifies_group_create_origin_proof() {
        let bundle = create_did_wba_document(
            "example.com",
            DidDocumentOptions {
                path_segments: vec!["user".to_owned(), "alice".to_owned()],
                ..DidDocumentOptions::default()
            },
        )
        .expect("bundle should be created");
        let private_key = PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
            .expect("private key should load");
        let did = bundle.did().expect("did should exist").to_owned();
        let meta = json!({
            "anp_version": "1.0",
            "profile": "anp.group.base.v1",
            "security_profile": "transport-protected",
            "sender_did": did.clone(),
            "target": {"kind": "service", "did": "did:wba:example.com:services:message:e1_service"},
            "operation_id": "op-group-create-1",
            "content_type": "application/json"
        });
        let body = json!({
            "group_profile": {"display_name": "Demo"},
            "group_policy": {
                "admission_mode": "open-join",
                "permissions": {
                    "send": "member",
                    "add": "admin",
                    "remove": "admin",
                    "update_profile": "admin",
                    "update_policy": "owner"
                }
            }
        });
        let origin_proof = generate_rfc9421_origin_proof(
            "group.create",
            &meta,
            &body,
            &private_key,
            &format!("{did}#key-1"),
            Rfc9421OriginProofGenerationOptions {
                created: Some(1_712_000_100),
                nonce: Some("nonce-group-create".to_owned()),
                ..Rfc9421OriginProofGenerationOptions::default()
            },
        )
        .expect("origin proof should generate");
        let result = verify_rfc9421_origin_proof(
            &origin_proof,
            "group.create",
            &meta,
            &body,
            Rfc9421OriginProofVerificationOptions {
                did_document: Some(bundle.did_document.clone()),
                expected_signer_did: Some(did),
                ..Rfc9421OriginProofVerificationOptions::default()
            },
        )
        .expect("origin proof should verify");
        assert_eq!(
            result.parsed_signature_input.nonce.as_deref(),
            Some("nonce-group-create")
        );
    }

    #[test]
    fn rejects_non_sig1_label() {
        let bundle = create_did_wba_document(
            "example.com",
            DidDocumentOptions {
                path_segments: vec!["user".to_owned(), "alice".to_owned()],
                ..DidDocumentOptions::default()
            },
        )
        .expect("bundle should be created");
        let private_key = PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
            .expect("private key should load");
        let did = bundle.did().expect("did should exist").to_owned();
        let meta = json!({
            "anp_version": "1.0",
            "profile": "anp.direct.base.v1",
            "security_profile": "transport-protected",
            "sender_did": did.clone(),
            "target": {"kind": "agent", "did": "did:wba:example.com:user:bob:e1_bob"},
            "operation_id": "op-2",
            "message_id": "msg-2",
            "content_type": "text/plain"
        });
        let error = generate_rfc9421_origin_proof(
            "direct.send",
            &meta,
            &json!({"text": "hello"}),
            &private_key,
            &format!("{did}#key-1"),
            Rfc9421OriginProofGenerationOptions {
                label: Some("sig2".to_owned()),
                ..Rfc9421OriginProofGenerationOptions::default()
            },
        )
        .expect_err("non-sig1 label should fail");
        assert!(matches!(error, Rfc9421OriginProofError::InvalidLabel));
    }

    #[test]
    fn rejects_extra_signature_component() {
        let bundle = create_did_wba_document(
            "example.com",
            DidDocumentOptions {
                path_segments: vec!["user".to_owned(), "alice".to_owned()],
                ..DidDocumentOptions::default()
            },
        )
        .expect("bundle should be created");
        let private_key = PrivateKeyMaterial::from_pem(&bundle.keys["key-1"].private_key_pem)
            .expect("private key should load");
        let did = bundle.did().expect("did should exist").to_owned();
        let meta = json!({
            "anp_version": "1.0",
            "profile": "anp.direct.base.v1",
            "security_profile": "transport-protected",
            "sender_did": did.clone(),
            "target": {"kind": "agent", "did": "did:wba:example.com:user:bob:e1_bob"},
            "operation_id": "op-3",
            "message_id": "msg-3",
            "content_type": "text/plain"
        });
        let body = json!({"text": "hello"});
        let mut origin_proof = generate_rfc9421_origin_proof(
            "direct.send",
            &meta,
            &body,
            &private_key,
            &format!("{did}#key-1"),
            Rfc9421OriginProofGenerationOptions {
                created: Some(1_712_000_200),
                nonce: Some("nonce-extra-component".to_owned()),
                ..Rfc9421OriginProofGenerationOptions::default()
            },
        )
        .expect("origin proof should generate");
        origin_proof.signature_input = origin_proof.signature_input.replace(
            "(\"@method\" \"@target-uri\" \"content-digest\")",
            "(\"@method\" \"@target-uri\" \"content-digest\" \"@authority\")",
        );
        let error = verify_rfc9421_origin_proof(
            &origin_proof,
            "direct.send",
            &meta,
            &body,
            Rfc9421OriginProofVerificationOptions {
                did_document: Some(bundle.did_document.clone()),
                expected_signer_did: Some(did),
                ..Rfc9421OriginProofVerificationOptions::default()
            },
        )
        .expect_err("extra component should fail");
        assert!(matches!(
            error,
            Rfc9421OriginProofError::InvalidCoveredComponents
        ));
    }
}
