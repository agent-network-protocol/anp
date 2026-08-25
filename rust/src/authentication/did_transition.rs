//! Verification and forward resolution for did:wba E1 transitions.

use std::collections::{HashMap, HashSet};

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::proof::{verify_w3c_proof, ProofVerificationOptions};
use crate::PublicKeyMaterial;

use super::{
    compute_multikey_fingerprint, extract_public_key, find_verification_method,
    is_assertion_method_authorized,
};

pub const ANP_DID_SUPERSEDED: u16 = 1019;
pub const ANP_DID_TRANSITION_INVALID: u16 = 1020;
pub const ANP_DID_TRANSITION_CONFLICT: u16 = 1021;
pub const DEFAULT_MAX_TRANSITION_HOPS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionAssurance {
    Verified,
    RecoveryVerified,
    ProviderAsserted,
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionStatus {
    Active,
    Superseded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionErrorKind {
    UnsupportedProfile,
    InvalidDocument,
    InvalidProof,
    RecoveryNotPreauthorized,
    InvalidProviderAssertion,
    StablePathMismatch,
    DirectSuccessorRequired,
    Cycle,
    Conflict,
    MaxHopsExceeded,
    NetworkError,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("{kind:?}: {message}")]
pub struct DidTransitionError {
    pub kind: TransitionErrorKind,
    pub code: u16,
    pub message: String,
}

impl DidTransitionError {
    fn new(kind: TransitionErrorKind, message: impl Into<String>) -> Self {
        let code = match kind {
            TransitionErrorKind::Cycle
            | TransitionErrorKind::Conflict
            | TransitionErrorKind::MaxHopsExceeded => ANP_DID_TRANSITION_CONFLICT,
            _ => ANP_DID_TRANSITION_INVALID,
        };
        Self {
            kind,
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DidWbaE1Profile {
    pub did: String,
    pub origin: String,
    pub stable_subject_path: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionHop {
    pub predecessor_did: String,
    pub successor_did: String,
    pub assurance: TransitionAssurance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionResult {
    pub requested_did: String,
    pub current_did: String,
    pub status: TransitionStatus,
    pub assurance: Option<TransitionAssurance>,
    pub hops: Vec<TransitionHop>,
}

pub trait DidDocumentFetcher {
    fn fetch(&self, did: &str) -> Result<Value, String>;
}

impl<F> DidDocumentFetcher for F
where
    F: Fn(&str) -> Result<Value, String>,
{
    fn fetch(&self, did: &str) -> Result<Value, String> {
        self(did)
    }
}

pub trait TransitionCache {
    fn get_successor(&self, predecessor_did: &str) -> Option<&str>;
    fn compare_and_set(&mut self, predecessor_did: &str, successor_did: &str) -> bool;
}

#[derive(Debug, Clone, Default)]
pub struct InMemoryTransitionCache {
    edges: HashMap<String, String>,
}

impl InMemoryTransitionCache {
    pub fn new(edges: HashMap<String, String>) -> Self {
        Self { edges }
    }

    pub fn snapshot(&self) -> HashMap<String, String> {
        self.edges.clone()
    }
}

impl TransitionCache for InMemoryTransitionCache {
    fn get_successor(&self, predecessor_did: &str) -> Option<&str> {
        self.edges.get(predecessor_did).map(String::as_str)
    }

    fn compare_and_set(&mut self, predecessor_did: &str, successor_did: &str) -> bool {
        match self.edges.get(predecessor_did) {
            Some(existing) => existing == successor_did,
            None => {
                self.edges
                    .insert(predecessor_did.to_string(), successor_did.to_string());
                true
            }
        }
    }
}

pub fn parse_did_wba_e1(did: &str) -> Result<DidWbaE1Profile, DidTransitionError> {
    let parts: Vec<&str> = did.split(':').collect();
    let valid_prefix = parts.len() >= 5 && parts[0] == "did" && parts[1] == "wba";
    let segment = parts.last().copied().unwrap_or_default();
    let valid_segment = Regex::new(r"^e1_[A-Za-z0-9_-]{43}$")
        .expect("static E1 regex")
        .is_match(segment);
    if !valid_prefix || !valid_segment {
        return Err(DidTransitionError::new(
            TransitionErrorKind::UnsupportedProfile,
            "automatic transition requires a path-based did:wba E1 DID",
        ));
    }
    Ok(DidWbaE1Profile {
        did: did.to_string(),
        origin: parts[2].to_string(),
        stable_subject_path: parts[2..parts.len() - 1].join(":"),
        fingerprint: segment[3..].to_string(),
    })
}

fn require_document_id(did: &str, document: &Value) -> Result<(), DidTransitionError> {
    if document.get("id").and_then(Value::as_str) != Some(did) {
        return Err(DidTransitionError::new(
            TransitionErrorKind::InvalidDocument,
            format!("DID Document id does not match {did}"),
        ));
    }
    Ok(())
}

fn binding_method(document: &Value, profile: &DidWbaE1Profile) -> Option<Value> {
    document
        .get("verificationMethod")?
        .as_array()?
        .iter()
        .find(|method| {
            extract_public_key(method)
                .ok()
                .and_then(|key| compute_multikey_fingerprint(&key).ok())
                .as_deref()
                == Some(profile.fingerprint.as_str())
        })
        .cloned()
}

fn proof_options() -> ProofVerificationOptions {
    ProofVerificationOptions {
        expected_purpose: Some("assertionMethod".to_string()),
        expected_domain: None,
        expected_challenge: None,
    }
}

pub fn verify_active_e1_document(did: &str, document: &Value) -> Result<(), DidTransitionError> {
    let profile = parse_did_wba_e1(did)?;
    require_document_id(did, document)?;
    if document.get("deactivated").and_then(Value::as_bool) == Some(true) {
        return Err(DidTransitionError::new(
            TransitionErrorKind::InvalidDocument,
            "expected an active DID Document",
        ));
    }
    let proof = document
        .get("proof")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            DidTransitionError::new(
                TransitionErrorKind::InvalidProof,
                "active E1 proof is required",
            )
        })?;
    let method_id = proof
        .get("verificationMethod")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            DidTransitionError::new(
                TransitionErrorKind::InvalidProof,
                "proof verificationMethod is required",
            )
        })?;
    if !is_assertion_method_authorized(document, method_id) {
        return Err(DidTransitionError::new(
            TransitionErrorKind::InvalidProof,
            "binding key is not authorized",
        ));
    }
    let method = find_verification_method(document, method_id).ok_or_else(|| {
        DidTransitionError::new(TransitionErrorKind::InvalidProof, "binding key is missing")
    })?;
    let public_key = extract_public_key(&method).map_err(|_| {
        DidTransitionError::new(TransitionErrorKind::InvalidProof, "invalid binding key")
    })?;
    if !matches!(public_key, PublicKeyMaterial::Ed25519(_)) {
        return Err(DidTransitionError::new(
            TransitionErrorKind::InvalidProof,
            "binding key must be Ed25519",
        ));
    }
    if compute_multikey_fingerprint(&public_key).ok().as_deref()
        != Some(profile.fingerprint.as_str())
    {
        return Err(DidTransitionError::new(
            TransitionErrorKind::InvalidProof,
            "binding fingerprint mismatch",
        ));
    }
    if !verify_w3c_proof(document, &public_key, proof_options()) {
        return Err(DidTransitionError::new(
            TransitionErrorKind::InvalidProof,
            "active E1 proof verification failed",
        ));
    }
    Ok(())
}

fn provider_did(profile: &DidWbaE1Profile) -> String {
    format!("did:wba:{}", profile.origin)
}

fn verify_provider_assertion(
    predecessor_document: &Value,
    predecessor: &DidWbaE1Profile,
    successor: &DidWbaE1Profile,
    provider_fetcher: &dyn DidDocumentFetcher,
) -> Result<(), DidTransitionError> {
    let assertion = predecessor_document
        .get("providerTransitionAssertion")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            DidTransitionError::new(
                TransitionErrorKind::InvalidProviderAssertion,
                "providerTransitionAssertion has an invalid shape",
            )
        })?;
    let required: HashSet<&str> = [
        "type",
        "providerDid",
        "predecessorDid",
        "successorDid",
        "stableSubjectPath",
        "issuedAt",
        "proof",
    ]
    .into_iter()
    .collect();
    if assertion.keys().map(String::as_str).collect::<HashSet<_>>() != required {
        return Err(DidTransitionError::new(
            TransitionErrorKind::InvalidProviderAssertion,
            "providerTransitionAssertion has an invalid shape",
        ));
    }
    let expected_provider = provider_did(predecessor);
    let issued_at = assertion.get("issuedAt").and_then(Value::as_str);
    let proof = assertion.get("proof").and_then(Value::as_object);
    let canonical_utc =
        Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$").expect("static UTC regex");
    let fields_valid = assertion.get("type").and_then(Value::as_str)
        == Some("DidWbaProviderTransitionAssertion")
        && assertion.get("providerDid").and_then(Value::as_str) == Some(expected_provider.as_str())
        && assertion.get("predecessorDid").and_then(Value::as_str)
            == Some(predecessor.did.as_str())
        && assertion.get("successorDid").and_then(Value::as_str) == Some(successor.did.as_str())
        && assertion.get("stableSubjectPath").and_then(Value::as_str)
            == Some(predecessor.stable_subject_path.as_str())
        && issued_at.is_some_and(|value| canonical_utc.is_match(value))
        && proof
            .and_then(|value| value.get("created"))
            .and_then(Value::as_str)
            == issued_at;
    if !fields_valid {
        return Err(DidTransitionError::new(
            TransitionErrorKind::InvalidProviderAssertion,
            "providerTransitionAssertion binding fields are invalid",
        ));
    }
    let provider_document = provider_fetcher
        .fetch(&expected_provider)
        .map_err(|error| DidTransitionError::new(TransitionErrorKind::NetworkError, error))?;
    require_document_id(&expected_provider, &provider_document)?;
    let method_id = proof
        .and_then(|value| value.get("verificationMethod"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            DidTransitionError::new(
                TransitionErrorKind::InvalidProviderAssertion,
                "provider proof key is missing",
            )
        })?;
    if !method_id.starts_with(&format!("{expected_provider}#"))
        || !is_assertion_method_authorized(&provider_document, method_id)
    {
        return Err(DidTransitionError::new(
            TransitionErrorKind::InvalidProviderAssertion,
            "provider proof key is not authorized",
        ));
    }
    let method = find_verification_method(&provider_document, method_id).ok_or_else(|| {
        DidTransitionError::new(
            TransitionErrorKind::InvalidProviderAssertion,
            "provider proof key is missing",
        )
    })?;
    let public_key = extract_public_key(&method).map_err(|_| {
        DidTransitionError::new(
            TransitionErrorKind::InvalidProviderAssertion,
            "invalid provider proof key",
        )
    })?;
    if !verify_w3c_proof(
        &Value::Object(assertion.clone()),
        &public_key,
        proof_options(),
    ) {
        return Err(DidTransitionError::new(
            TransitionErrorKind::InvalidProviderAssertion,
            "providerTransitionAssertion proof verification failed",
        ));
    }
    Ok(())
}

pub fn verify_transition_hop(
    predecessor_document: &Value,
    successor_document: &Value,
    trusted_predecessor: Option<&Value>,
    provider_fetcher: Option<&dyn DidDocumentFetcher>,
) -> Result<TransitionHop, DidTransitionError> {
    let predecessor_did = predecessor_document
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            DidTransitionError::new(
                TransitionErrorKind::InvalidDocument,
                "predecessor id is missing",
            )
        })?;
    let successor_did = predecessor_document
        .get("successorDid")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            DidTransitionError::new(
                TransitionErrorKind::InvalidDocument,
                "deactivated predecessor requires successorDid",
            )
        })?;
    let predecessor = parse_did_wba_e1(predecessor_did)?;
    let successor = parse_did_wba_e1(successor_did)?;
    require_document_id(successor_did, successor_document)?;
    if predecessor_document
        .get("deactivated")
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(DidTransitionError::new(
            TransitionErrorKind::InvalidDocument,
            "predecessor is not deactivated",
        ));
    }
    if predecessor.stable_subject_path != successor.stable_subject_path {
        return Err(DidTransitionError::new(
            TransitionErrorKind::StablePathMismatch,
            "predecessor and successor stable subject paths differ",
        ));
    }
    let binding = binding_method(predecessor_document, &predecessor).ok_or_else(|| {
        DidTransitionError::new(
            TransitionErrorKind::InvalidDocument,
            "deactivated predecessor does not retain its binding key",
        )
    })?;
    if let Some(aliases) = successor_document
        .get("alsoKnownAs")
        .and_then(Value::as_array)
    {
        let matching: Vec<&str> = aliases
            .iter()
            .filter_map(Value::as_str)
            .filter(|alias| {
                parse_did_wba_e1(alias)
                    .map(|value| value.stable_subject_path == successor.stable_subject_path)
                    .unwrap_or(false)
            })
            .collect();
        if !matching.is_empty() && !matching.contains(&predecessor_did) {
            return Err(DidTransitionError::new(
                TransitionErrorKind::DirectSuccessorRequired,
                "successor identifies a different direct predecessor",
            ));
        }
    }

    let provider_present = predecessor_document
        .get("providerTransitionAssertion")
        .is_some();
    if provider_present {
        let fetcher = provider_fetcher.ok_or_else(|| {
            DidTransitionError::new(
                TransitionErrorKind::InvalidProviderAssertion,
                "provider DID resolver is required",
            )
        })?;
        verify_provider_assertion(predecessor_document, &predecessor, &successor, fetcher)?;
    }

    let assurance = if let Some(proof) = predecessor_document.get("proof") {
        let method_id = proof
            .get("verificationMethod")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                DidTransitionError::new(
                    TransitionErrorKind::InvalidProof,
                    "transition proof key is missing",
                )
            })?;
        if binding.get("id").and_then(Value::as_str) == Some(method_id) {
            let public_key = extract_public_key(&binding).map_err(|_| {
                DidTransitionError::new(TransitionErrorKind::InvalidProof, "invalid binding key")
            })?;
            if !verify_w3c_proof(predecessor_document, &public_key, proof_options()) {
                return Err(DidTransitionError::new(
                    TransitionErrorKind::InvalidProof,
                    "old binding proof failed",
                ));
            }
            TransitionAssurance::Verified
        } else {
            let trusted = trusted_predecessor.ok_or_else(|| {
                DidTransitionError::new(
                    TransitionErrorKind::RecoveryNotPreauthorized,
                    "trusted predecessor is required for recovery",
                )
            })?;
            let trusted_method = find_verification_method(trusted, method_id)
                .filter(|_| is_assertion_method_authorized(trusted, method_id));
            let trusted_method = trusted_method.ok_or_else(|| {
                DidTransitionError::new(
                    TransitionErrorKind::RecoveryNotPreauthorized,
                    "recovery key was not pre-authorized by the trusted predecessor",
                )
            })?;
            let public_key = extract_public_key(&trusted_method).map_err(|_| {
                DidTransitionError::new(TransitionErrorKind::InvalidProof, "invalid recovery key")
            })?;
            if !verify_w3c_proof(predecessor_document, &public_key, proof_options()) {
                return Err(DidTransitionError::new(
                    TransitionErrorKind::InvalidProof,
                    "recovery proof failed",
                ));
            }
            TransitionAssurance::RecoveryVerified
        }
    } else if provider_present {
        TransitionAssurance::ProviderAsserted
    } else {
        TransitionAssurance::Unverified
    };

    Ok(TransitionHop {
        predecessor_did: predecessor_did.to_string(),
        successor_did: successor_did.to_string(),
        assurance,
    })
}

fn assurance_rank(value: TransitionAssurance) -> u8 {
    match value {
        TransitionAssurance::Verified => 0,
        TransitionAssurance::RecoveryVerified => 1,
        TransitionAssurance::ProviderAsserted => 2,
        TransitionAssurance::Unverified => 3,
    }
}

pub fn resolve_current_did(
    requested_did: &str,
    fetcher: &dyn DidDocumentFetcher,
    trusted_documents: &HashMap<String, Value>,
    provider_fetcher: Option<&dyn DidDocumentFetcher>,
    cache: &mut dyn TransitionCache,
    max_hops: usize,
) -> Result<TransitionResult, DidTransitionError> {
    parse_did_wba_e1(requested_did)?;
    if max_hops == 0 {
        return Err(DidTransitionError::new(
            TransitionErrorKind::MaxHopsExceeded,
            "max_hops must be positive",
        ));
    }
    let mut current = requested_did.to_string();
    let mut visited = HashSet::new();
    let mut hops = Vec::new();
    let mut verified_edges: Vec<(String, String)> = Vec::new();
    loop {
        if !visited.insert(current.clone()) {
            return Err(DidTransitionError::new(
                TransitionErrorKind::Cycle,
                "transition chain contains a cycle",
            ));
        }
        let document = fetcher
            .fetch(&current)
            .map_err(|error| DidTransitionError::new(TransitionErrorKind::NetworkError, error))?;
        require_document_id(&current, &document)?;
        if document.get("deactivated").and_then(Value::as_bool) != Some(true) {
            verify_active_e1_document(&current, &document)?;
            for (predecessor_did, successor_did) in &verified_edges {
                if !cache.compare_and_set(predecessor_did, successor_did) {
                    return Err(DidTransitionError::new(
                        TransitionErrorKind::Conflict,
                        "a different successor is already cached for predecessor",
                    ));
                }
            }
            let assurance = hops
                .iter()
                .map(|hop: &TransitionHop| hop.assurance)
                .max_by_key(|value| assurance_rank(*value));
            return Ok(TransitionResult {
                requested_did: requested_did.to_string(),
                current_did: current,
                status: if hops.is_empty() {
                    TransitionStatus::Active
                } else {
                    TransitionStatus::Superseded
                },
                assurance,
                hops,
            });
        }
        if hops.len() >= max_hops {
            return Err(DidTransitionError::new(
                TransitionErrorKind::MaxHopsExceeded,
                "transition chain exceeds max_hops",
            ));
        }
        let successor_did = document
            .get("successorDid")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                DidTransitionError::new(
                    TransitionErrorKind::InvalidDocument,
                    "deactivated transition document has no successorDid",
                )
            })?;
        if visited.contains(successor_did) {
            return Err(DidTransitionError::new(
                TransitionErrorKind::Cycle,
                "transition chain contains a cycle",
            ));
        }
        let successor_document = fetcher
            .fetch(successor_did)
            .map_err(|error| DidTransitionError::new(TransitionErrorKind::NetworkError, error))?;
        let hop = verify_transition_hop(
            &document,
            &successor_document,
            trusted_documents.get(&current),
            provider_fetcher,
        )?;
        if cache
            .get_successor(&current)
            .is_some_and(|cached| cached != successor_did)
        {
            return Err(DidTransitionError::new(
                TransitionErrorKind::Conflict,
                "a different successor is already cached for predecessor",
            ));
        }
        if matches!(
            hop.assurance,
            TransitionAssurance::Verified | TransitionAssurance::RecoveryVerified
        ) {
            verified_edges.push((current.clone(), successor_did.to_string()));
        }
        hops.push(hop);
        current = successor_did.to_string();
    }
}
