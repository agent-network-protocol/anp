use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

pub const DEVICE_MANIFEST_TYPE: &str = "ANPDeviceManifest";
pub const PROFILE_CORE_BINDING_V2: &str = "anp.core.binding.v2";
pub const PROFILE_IDENTITY_DISCOVERY_V2: &str = "anp.identity.discovery.v2";
pub const PROFILE_DIRECT_BASE_V2: &str = "anp.direct.base.v2";
pub const PROFILE_DIRECT_E2EE_V2: &str = "anp.direct.e2ee.v2";
pub const PROFILE_GROUP_BASE_V2: &str = "anp.group.base.v2";
pub const PROFILE_GROUP_E2EE_V2: &str = "anp.group.e2ee.v2";

const P5_DEPENDENCIES: &[&str] = &[
    PROFILE_CORE_BINDING_V2,
    PROFILE_IDENTITY_DISCOVERY_V2,
    PROFILE_DIRECT_BASE_V2,
    PROFILE_DIRECT_E2EE_V2,
];
const P6_DEPENDENCIES: &[&str] = &[
    PROFILE_CORE_BINDING_V2,
    PROFILE_IDENTITY_DISCOVERY_V2,
    PROFILE_GROUP_BASE_V2,
    PROFILE_GROUP_E2EE_V2,
];

/// The closed, interoperable device entry defined by the vNext ANP Profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceManifestEntry {
    pub device_id: String,
    pub signing_key_id: String,
    pub e2ee_key_id: String,
    pub profiles: Vec<String>,
}

/// The `deviceManifest` DID Document extension defined by the vNext ANP Profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceManifest {
    #[serde(rename = "type")]
    pub manifest_type: String,
    pub devices: Vec<DeviceManifestEntry>,
}

#[derive(Debug, Error)]
pub enum DeviceManifestError {
    #[error("DID document must be a JSON object")]
    InvalidDidDocument,
    #[error("invalid deviceManifest schema: {0}")]
    InvalidSchema(String),
    #[error("invalid deviceManifest: {0}")]
    InvalidManifest(String),
}

/// Parse a `deviceManifest` without closing or reserializing the surrounding DID Document.
///
/// A DID Document without the optional extension returns `Ok(None)`.
pub fn parse_device_manifest(
    did_document: &Value,
) -> Result<Option<DeviceManifest>, DeviceManifestError> {
    let document = did_document
        .as_object()
        .ok_or(DeviceManifestError::InvalidDidDocument)?;
    let Some(value) = document.get("deviceManifest") else {
        return Ok(None);
    };
    let manifest: DeviceManifest = serde_json::from_value(value.clone())
        .map_err(|error| DeviceManifestError::InvalidSchema(error.to_string()))?;
    if manifest.manifest_type != DEVICE_MANIFEST_TYPE {
        return Err(DeviceManifestError::InvalidManifest(format!(
            "type must be {DEVICE_MANIFEST_TYPE}"
        )));
    }
    Ok(Some(manifest))
}

/// Parse and validate the vNext Manifest against its containing DID Document.
pub fn validate_device_manifest(
    did_document: &Value,
) -> Result<Option<DeviceManifest>, DeviceManifestError> {
    let Some(manifest) = parse_device_manifest(did_document)? else {
        return Ok(None);
    };
    let did = did_document
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("DID document id must be a non-empty string"))?;

    let mut device_ids = BTreeSet::new();
    let mut key_ids = BTreeSet::new();
    for device in &manifest.devices {
        validate_non_empty("device_id", &device.device_id)?;
        validate_non_empty("signing_key_id", &device.signing_key_id)?;
        validate_non_empty("e2ee_key_id", &device.e2ee_key_id)?;
        if device.profiles.is_empty() {
            return Err(invalid("profiles must be non-empty"));
        }
        if !device_ids.insert(device.device_id.as_str()) {
            return Err(invalid("device_id must be unique"));
        }
        if !key_ids.insert(device.signing_key_id.as_str())
            || !key_ids.insert(device.e2ee_key_id.as_str())
        {
            return Err(invalid("each key id must bind to exactly one device role"));
        }

        validate_same_document_key(did, &device.signing_key_id)?;
        validate_same_document_key(did, &device.e2ee_key_id)?;
        require_unique_verification_method(did_document, &device.signing_key_id)?;
        require_unique_verification_method(did_document, &device.e2ee_key_id)?;

        if !relationship_contains(did_document, "keyAgreement", &device.e2ee_key_id) {
            return Err(invalid("e2ee_key_id must be authorized by keyAgreement"));
        }

        let mut profiles = BTreeSet::new();
        for profile in &device.profiles {
            validate_non_empty("profile", profile)?;
            profiles.insert(profile.as_str());
        }
        if profiles.contains(PROFILE_DIRECT_E2EE_V2) {
            require_dependencies(&profiles, P5_DEPENDENCIES, PROFILE_DIRECT_E2EE_V2)?;
            if !relationship_contains(did_document, "assertionMethod", &device.signing_key_id) {
                return Err(invalid(
                    "P5 signing_key_id must be authorized by assertionMethod",
                ));
            }
        }
        if profiles.contains(PROFILE_GROUP_E2EE_V2) {
            require_dependencies(&profiles, P6_DEPENDENCIES, PROFILE_GROUP_E2EE_V2)?;
            if !relationship_contains(did_document, "assertionMethod", &device.signing_key_id) {
                return Err(invalid(
                    "P6 signing_key_id must be authorized by assertionMethod",
                ));
            }
            if !relationship_contains(did_document, "authentication", &device.signing_key_id) {
                return Err(invalid(
                    "P6 signing_key_id must be authorized by authentication",
                ));
            }
        }
    }

    Ok(Some(manifest))
}

/// Return a validated device entry when it supports the requested Profile.
pub fn find_eligible_device(
    did_document: &Value,
    device_id: &str,
    required_profile: &str,
) -> Result<Option<DeviceManifestEntry>, DeviceManifestError> {
    let Some(manifest) = validate_device_manifest(did_document)? else {
        return Ok(None);
    };
    if !matches!(
        required_profile,
        PROFILE_DIRECT_E2EE_V2 | PROFILE_GROUP_E2EE_V2
    ) {
        return Ok(None);
    }
    Ok(manifest.devices.into_iter().find(|device| {
        device.device_id == device_id
            && device
                .profiles
                .iter()
                .any(|profile| profile == required_profile)
    }))
}

fn validate_non_empty(field: &str, value: &str) -> Result<(), DeviceManifestError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be a non-empty string")));
    }
    Ok(())
}

fn validate_same_document_key(did: &str, key_id: &str) -> Result<(), DeviceManifestError> {
    let expected_prefix = format!("{did}#");
    if !key_id.starts_with(&expected_prefix) || key_id.len() == expected_prefix.len() {
        return Err(invalid(
            "device key ids must be DID URLs in the same document",
        ));
    }
    Ok(())
}

fn require_unique_verification_method(
    did_document: &Value,
    key_id: &str,
) -> Result<(), DeviceManifestError> {
    let matches = did_document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|method| method.get("id").and_then(Value::as_str) == Some(key_id))
        .count();
    if matches != 1 {
        return Err(invalid(format!(
            "key id {key_id} must resolve exactly once in verificationMethod"
        )));
    }
    Ok(())
}

fn relationship_contains(did_document: &Value, relationship: &str, key_id: &str) -> bool {
    did_document
        .get(relationship)
        .and_then(Value::as_array)
        .is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry.as_str() == Some(key_id)
                    || entry.get("id").and_then(Value::as_str) == Some(key_id)
            })
        })
}

fn require_dependencies(
    profiles: &BTreeSet<&str>,
    required: &[&str],
    profile: &str,
) -> Result<(), DeviceManifestError> {
    if let Some(missing) = required
        .iter()
        .find(|dependency| !profiles.contains(**dependency))
    {
        return Err(invalid(format!("{profile} requires dependency {missing}")));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> DeviceManifestError {
    DeviceManifestError::InvalidManifest(message.into())
}
