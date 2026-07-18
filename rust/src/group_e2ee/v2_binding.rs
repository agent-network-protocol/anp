use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::authentication::{find_eligible_device, PROFILE_GROUP_E2EE_V2};
use crate::canonical_json::canonicalize_json;
use crate::proof::{generate_object_proof, verify_object_proof};
use crate::PrivateKeyMaterial;

use super::v2_errors::GroupE2eeV2Error;
use super::v2_models::{
    require_non_empty, validate_ed25519_b64u, validate_non_empty_b64u, validate_rfc3339,
    V2DidWbaBinding, V2GroupKeyPackage, DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2,
    DID_WBA_DEVICE_BINDING_EXTENSION_REGISTERED_V2,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2DidWbaBindingUnsigned {
    pub agent_did: String,
    pub device_id: String,
    pub verification_method: String,
    pub leaf_signature_key_b64u: String,
    pub issued_at: String,
    pub expires_at: String,
}

impl V2DidWbaBindingUnsigned {
    fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        for (field, value) in [
            ("did_wba_binding.agent_did", self.agent_did.as_str()),
            ("did_wba_binding.device_id", self.device_id.as_str()),
            (
                "did_wba_binding.verification_method",
                self.verification_method.as_str(),
            ),
        ] {
            require_non_empty(field, value)?;
        }
        validate_ed25519_b64u(
            "did_wba_binding.leaf_signature_key_b64u",
            &self.leaf_signature_key_b64u,
        )?;
        validate_rfc3339("did_wba_binding.issued_at", &self.issued_at)?;
        validate_rfc3339("did_wba_binding.expires_at", &self.expires_at)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2LeafExtension {
    pub extension_type: u16,
    pub extension_data: Vec<u8>,
}

/// Projection from a validated MLS parser into the ANP binding verifier.
///
/// This helper deliberately does not treat the convenience JSON package as a
/// substitute for parsing and verifying the TLS-serialized MLS KeyPackage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2LeafBindingEvidence {
    pub credential_identity: Vec<u8>,
    pub leaf_signature_key_b64u: String,
    pub extensions: Vec<V2LeafExtension>,
    pub leaf_capability_extensions: Vec<u16>,
}

/// Output of a caller's cryptographically verified MLS KeyPackage parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2KeyPackageBindingEvidence {
    pub tls_serialized_key_package: Vec<u8>,
    pub leaf: V2LeafBindingEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct V2LeafIdentity {
    pub agent_did: String,
    pub device_id: String,
    pub leaf_signature_key_b64u: String,
}

/// Sign a complete P6 v2 binding using the shared P1 Object Proof profile.
pub fn generate_did_wba_binding_v2(
    unsigned: V2DidWbaBindingUnsigned,
    private_key: &PrivateKeyMaterial,
    created: Option<String>,
) -> Result<V2DidWbaBinding, GroupE2eeV2Error> {
    unsigned.validate()?;
    let verification_method = unsigned.verification_method.clone();
    let issuer_did = unsigned.agent_did.clone();
    let unsigned_value = serde_json::to_value(unsigned)?;
    let signed = generate_object_proof(
        &unsigned_value,
        private_key,
        &verification_method,
        &issuer_did,
        created,
    )?;
    let binding: V2DidWbaBinding = serde_json::from_value(signed)?;
    binding.validate_structure()?;
    Ok(binding)
}

/// Verify the DID/Manifest/Object-Proof/MLS-leaf chain required by P6 v2.
pub fn verify_did_wba_binding_v2(
    binding: &V2DidWbaBinding,
    issuer_document: &Value,
    evidence: &V2LeafBindingEvidence,
    group_required_extensions: &[u16],
    now: &str,
    p6_profile_negotiated: bool,
) -> Result<(), GroupE2eeV2Error> {
    binding.validate_structure()?;
    if !p6_profile_negotiated {
        return Err(GroupE2eeV2Error::invalid(
            "draft MLS binding extension requires explicit anp.group.e2ee.v2 negotiation",
        ));
    }
    if issuer_document.get("id").and_then(Value::as_str) != Some(binding.agent_did.as_str()) {
        return Err(GroupE2eeV2Error::invalid(
            "did_wba_binding.agent_did must equal issuer DID document id",
        ));
    }
    let device = find_eligible_device(issuer_document, &binding.device_id, PROFILE_GROUP_E2EE_V2)?
        .ok_or_else(|| {
            GroupE2eeV2Error::invalid(
                "did_wba_binding.device_id is not a current P6-eligible Manifest device",
            )
        })?;
    if device.signing_key_id != binding.verification_method {
        return Err(GroupE2eeV2Error::invalid(
            "did_wba_binding.verification_method must equal Manifest signing_key_id",
        ));
    }

    let binding_value = serde_json::to_value(binding)?;
    verify_object_proof(&binding_value, &binding.agent_did, issuer_document)?;
    validate_binding_window(binding, now)?;

    if evidence.credential_identity.as_slice() != binding.agent_did.as_bytes() {
        return Err(GroupE2eeV2Error::invalid(
            "MLS credential.identity must equal UTF-8 agent_did",
        ));
    }
    validate_ed25519_b64u("leaf_signature_key_b64u", &evidence.leaf_signature_key_b64u)?;
    if evidence.leaf_signature_key_b64u != binding.leaf_signature_key_b64u {
        return Err(GroupE2eeV2Error::invalid(
            "actual MLS leaf signature key must equal did_wba_binding leaf key",
        ));
    }

    let extension_matches: Vec<&V2LeafExtension> = evidence
        .extensions
        .iter()
        .filter(|extension| extension.extension_type == DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2)
        .collect();
    if extension_matches.len() != 1 {
        return Err(GroupE2eeV2Error::invalid(
            "LeafNode must contain exactly one anp_did_wba_device_binding extension",
        ));
    }
    let canonical = canonicalize_json(&binding_value)?;
    if extension_matches[0].extension_data != canonical {
        return Err(GroupE2eeV2Error::invalid(
            "embedded MLS binding extension must equal canonical did_wba_binding bytes",
        ));
    }
    require_capability_once(
        "LeafNode capabilities.extensions",
        &evidence.leaf_capability_extensions,
    )?;
    validate_group_required_capabilities_v2(group_required_extensions)
}

/// Validate a convenience package against independently parsed MLS evidence.
pub fn validate_group_key_package_binding_v2(
    package: &V2GroupKeyPackage,
    issuer_document: &Value,
    evidence: &V2KeyPackageBindingEvidence,
    group_required_extensions: &[u16],
    now: &str,
    p6_profile_negotiated: bool,
) -> Result<(), GroupE2eeV2Error> {
    package.validate_structure()?;
    let outer_bytes = validate_non_empty_b64u(
        "group_key_package.mls_key_package_b64u",
        &package.mls_key_package_b64u,
    )?;
    if outer_bytes != evidence.tls_serialized_key_package {
        return Err(GroupE2eeV2Error::invalid(
            "verified TLS KeyPackage bytes must equal mls_key_package_b64u",
        ));
    }
    verify_did_wba_binding_v2(
        &package.did_wba_binding,
        issuer_document,
        &evidence.leaf,
        group_required_extensions,
        now,
        p6_profile_negotiated,
    )?;
    if let Some(expires_at) = package.expires_at.as_deref() {
        let now = parse_timestamp("now", now)?;
        let expires = parse_timestamp("group_key_package.expires_at", expires_at)?;
        if now >= expires {
            return Err(GroupE2eeV2Error::invalid("group_key_package is expired"));
        }
    }
    Ok(())
}

pub fn validate_group_required_capabilities_v2(extensions: &[u16]) -> Result<(), GroupE2eeV2Error> {
    require_capability_once("GroupContext required_capabilities", extensions)
}

/// Same-DID sibling leaves are valid only when the device and leaf keys remain distinct.
pub fn validate_leaf_identity_set_v2(leaves: &[V2LeafIdentity]) -> Result<(), GroupE2eeV2Error> {
    let mut pairs = BTreeSet::new();
    let mut leaf_keys = BTreeSet::new();
    for leaf in leaves {
        require_non_empty("leaf.agent_did", &leaf.agent_did)?;
        require_non_empty("leaf.device_id", &leaf.device_id)?;
        validate_ed25519_b64u(
            "leaf.leaf_signature_key_b64u",
            &leaf.leaf_signature_key_b64u,
        )?;
        if !pairs.insert((leaf.agent_did.as_str(), leaf.device_id.as_str())) {
            return Err(GroupE2eeV2Error::invalid(
                "each (agent_did, device_id) leaf identity must be unique",
            ));
        }
        if !leaf_keys.insert(leaf.leaf_signature_key_b64u.as_str()) {
            return Err(GroupE2eeV2Error::invalid(
                "each device leaf must use a distinct MLS signature key",
            ));
        }
    }
    Ok(())
}

/// Draft operation is allowed behind explicit negotiation, but public release is fail-closed.
pub fn ensure_p6_v2_public_release_ready() -> Result<(), GroupE2eeV2Error> {
    if DID_WBA_DEVICE_BINDING_EXTENSION_REGISTERED_V2 {
        Ok(())
    } else {
        Err(GroupE2eeV2Error::PublicReleaseBlocked)
    }
}

fn validate_binding_window(binding: &V2DidWbaBinding, now: &str) -> Result<(), GroupE2eeV2Error> {
    let now = parse_timestamp("now", now)?;
    let issued = parse_timestamp("did_wba_binding.issued_at", &binding.issued_at)?;
    let expires = parse_timestamp("did_wba_binding.expires_at", &binding.expires_at)?;
    if issued >= expires {
        return Err(GroupE2eeV2Error::invalid(
            "did_wba_binding issued_at must precede expires_at",
        ));
    }
    if now < issued || now >= expires {
        return Err(GroupE2eeV2Error::invalid(
            "did_wba_binding is not valid at the requested time",
        ));
    }
    Ok(())
}

fn parse_timestamp(field: &str, value: &str) -> Result<DateTime<Utc>, GroupE2eeV2Error> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| GroupE2eeV2Error::invalid(format!("{field} must be RFC3339")))
}

fn require_capability_once(field: &str, extensions: &[u16]) -> Result<(), GroupE2eeV2Error> {
    if extensions
        .iter()
        .filter(|value| **value == DID_WBA_DEVICE_BINDING_EXTENSION_DRAFT_V2)
        .count()
        == 1
    {
        Ok(())
    } else {
        Err(GroupE2eeV2Error::invalid(format!(
            "{field} must list the draft binding extension exactly once"
        )))
    }
}
