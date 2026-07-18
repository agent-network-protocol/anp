use std::collections::BTreeSet;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicKeyAlgorithm {
    Ed25519,
    X25519,
    P256,
    Secp256k1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicKeyIdentity {
    algorithm: PublicKeyAlgorithm,
    raw_public_key: Vec<u8>,
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

/// Build an unsigned vNext DID document from public key material only.
///
/// The caller must root-sign the returned document before publishing it.
pub fn build_vnext_did_document(
    base_document: &Value,
    root_key_id: &str,
    root_verification_method: &Value,
    device: &DeviceManifestEntry,
    device_signing_verification_method: &Value,
    device_e2ee_verification_method: &Value,
) -> Result<Value, DeviceManifestError> {
    let mut document = base_document
        .as_object()
        .cloned()
        .ok_or(DeviceManifestError::InvalidDidDocument)?;
    for field in [
        "verificationMethod",
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "deviceManifest",
        "proof",
    ] {
        if document.contains_key(field) {
            return Err(invalid(format!(
                "base DID document must not contain managed field {field}"
            )));
        }
    }

    let did = document_did(&document)?;
    validate_root_method(did, root_key_id, root_verification_method)?;
    validate_device_methods(
        did,
        root_key_id,
        device,
        device_signing_verification_method,
        device_e2ee_verification_method,
    )?;
    document.insert(
        "verificationMethod".to_string(),
        Value::Array(vec![
            root_verification_method.clone(),
            device_signing_verification_method.clone(),
            device_e2ee_verification_method.clone(),
        ]),
    );
    document.insert(
        "authentication".to_string(),
        Value::Array(vec![Value::String(device.signing_key_id.clone())]),
    );
    document.insert(
        "assertionMethod".to_string(),
        Value::Array(vec![
            Value::String(root_key_id.to_string()),
            Value::String(device.signing_key_id.clone()),
        ]),
    );
    document.insert(
        "keyAgreement".to_string(),
        Value::Array(vec![Value::String(device.e2ee_key_id.clone())]),
    );
    document.insert(
        "deviceManifest".to_string(),
        serde_json::to_value(DeviceManifest {
            manifest_type: DEVICE_MANIFEST_TYPE.to_string(),
            devices: vec![device.clone()],
        })
        .map_err(|error| DeviceManifestError::InvalidSchema(error.to_string()))?,
    );
    let result = Value::Object(document);
    validate_vnext_document(&result, root_key_id)?;
    Ok(result)
}

/// Add one device to a validated document and return an unsigned copy.
pub fn add_device_to_did_document(
    did_document: &Value,
    root_key_id: &str,
    device: &DeviceManifestEntry,
    device_signing_verification_method: &Value,
    device_e2ee_verification_method: &Value,
    retired_device_ids: &[String],
) -> Result<Value, DeviceManifestError> {
    let mut document = prepare_document_for_mutation(did_document, root_key_id)?;
    let manifest = validate_device_manifest(&document)?
        .ok_or_else(|| invalid("deviceManifest is required for device update"))?;
    if manifest
        .devices
        .iter()
        .any(|entry| entry.device_id == device.device_id)
    {
        return Err(invalid("device_id already exists"));
    }
    validate_retired_device_ids(retired_device_ids)?;
    if retired_device_ids
        .iter()
        .any(|retired| retired == &device.device_id)
    {
        return Err(invalid("retired device_id cannot be reused"));
    }
    append_device_material(
        &mut document,
        root_key_id,
        device,
        device_signing_verification_method,
        device_e2ee_verification_method,
    )?;
    validate_vnext_document(&document, root_key_id)?;
    Ok(document)
}

/// Replace one device's public keys/Profile entry in an unsigned copy.
pub fn update_device_in_did_document(
    did_document: &Value,
    root_key_id: &str,
    device: &DeviceManifestEntry,
    device_signing_verification_method: &Value,
    device_e2ee_verification_method: &Value,
) -> Result<Value, DeviceManifestError> {
    let mut document = prepare_document_for_mutation(did_document, root_key_id)?;
    let manifest = validate_device_manifest(&document)?
        .ok_or_else(|| invalid("deviceManifest is required for device update"))?;
    let old_entry = manifest
        .devices
        .iter()
        .find(|entry| entry.device_id == device.device_id)
        .cloned()
        .ok_or_else(|| invalid("device_id does not exist"))?;
    remove_device_material(&mut document, &old_entry)?;
    append_device_material(
        &mut document,
        root_key_id,
        device,
        device_signing_verification_method,
        device_e2ee_verification_method,
    )?;
    validate_vnext_document(&document, root_key_id)?;
    Ok(document)
}

/// Remove one device and its active key references from an unsigned copy.
pub fn remove_device_from_did_document(
    did_document: &Value,
    root_key_id: &str,
    device_id: &str,
) -> Result<Value, DeviceManifestError> {
    let mut document = prepare_document_for_mutation(did_document, root_key_id)?;
    let manifest = validate_device_manifest(&document)?
        .ok_or_else(|| invalid("deviceManifest is required for device update"))?;
    let old_entry = manifest
        .devices
        .iter()
        .find(|entry| entry.device_id == device_id)
        .cloned()
        .ok_or_else(|| invalid("device_id does not exist"))?;
    remove_device_material(&mut document, &old_entry)?;
    validate_vnext_document(&document, root_key_id)?;
    Ok(document)
}

fn prepare_document_for_mutation(
    did_document: &Value,
    root_key_id: &str,
) -> Result<Value, DeviceManifestError> {
    validate_vnext_document(did_document, root_key_id)?;
    let mut document = did_document.clone();
    document
        .as_object_mut()
        .ok_or(DeviceManifestError::InvalidDidDocument)?
        .remove("proof");
    Ok(document)
}

fn validate_vnext_document(
    did_document: &Value,
    root_key_id: &str,
) -> Result<(), DeviceManifestError> {
    reject_private_key_material(did_document, "DID document")?;
    let object = did_document
        .as_object()
        .ok_or(DeviceManifestError::InvalidDidDocument)?;
    let did = document_did(object)?;
    let methods = did_document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("DID document verificationMethod must be an array"))?;
    let root_methods = methods
        .iter()
        .filter(|method| method.get("id").and_then(Value::as_str) == Some(root_key_id))
        .collect::<Vec<_>>();
    if root_methods.len() != 1 {
        return Err(invalid(
            "root key must resolve exactly once in verificationMethod",
        ));
    }
    let root_identity = validate_root_method(did, root_key_id, root_methods[0])?;
    if !relationship_contains(did_document, "assertionMethod", root_key_id) {
        return Err(invalid("DID root key is not authorized by assertionMethod"));
    }
    let manifest = validate_device_manifest(did_document)?
        .ok_or_else(|| invalid("deviceManifest is required"))?;
    let mut seen_material = BTreeSet::from([root_identity.raw_public_key]);
    for device in &manifest.devices {
        if device.signing_key_id == root_key_id || device.e2ee_key_id == root_key_id {
            return Err(invalid("DID root key cannot be a device key"));
        }
        let signing_method = unique_method(did_document, &device.signing_key_id)?;
        let e2ee_method = unique_method(did_document, &device.e2ee_key_id)?;
        let (signing_identity, e2ee_identity) =
            validate_device_methods(did, root_key_id, device, signing_method, e2ee_method)?;
        for relationship in ["authentication", "assertionMethod"] {
            if !relationship_contains(did_document, relationship, &device.signing_key_id) {
                return Err(invalid(format!(
                    "device signing key is not authorized by {relationship}"
                )));
            }
        }
        if !relationship_contains(did_document, "keyAgreement", &device.e2ee_key_id) {
            return Err(invalid("device E2EE key is not authorized by keyAgreement"));
        }
        if relationship_contains(did_document, "keyAgreement", &device.signing_key_id) {
            return Err(invalid("device signing key must not be in keyAgreement"));
        }
        if relationship_contains(did_document, "authentication", &device.e2ee_key_id)
            || relationship_contains(did_document, "assertionMethod", &device.e2ee_key_id)
        {
            return Err(invalid(
                "device E2EE key must not be a signing relationship",
            ));
        }
        for identity in [signing_identity, e2ee_identity] {
            if !seen_material.insert(identity.raw_public_key) {
                return Err(invalid(
                    "root and device public key material must be unique",
                ));
            }
        }
    }
    Ok(())
}

fn document_did(document: &serde_json::Map<String, Value>) -> Result<&str, DeviceManifestError> {
    document
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("DID document id must be a non-empty string"))
}

fn validate_root_method(
    did: &str,
    root_key_id: &str,
    method: &Value,
) -> Result<PublicKeyIdentity, DeviceManifestError> {
    let identity =
        validate_public_method(did, root_key_id, method, "DID root verification method")?;
    if matches!(identity.algorithm, PublicKeyAlgorithm::X25519) {
        return Err(invalid(
            "DID root verification method must be signing-capable",
        ));
    }
    Ok(identity)
}

fn validate_device_methods(
    did: &str,
    root_key_id: &str,
    device: &DeviceManifestEntry,
    signing_method: &Value,
    e2ee_method: &Value,
) -> Result<(PublicKeyIdentity, PublicKeyIdentity), DeviceManifestError> {
    if device.signing_key_id == root_key_id || device.e2ee_key_id == root_key_id {
        return Err(invalid("DID root key cannot be a device key"));
    }
    let signing_identity = validate_public_method(
        did,
        &device.signing_key_id,
        signing_method,
        "device signing verification method",
    )?;
    let requires_eddsa = device.profiles.iter().any(|profile| {
        matches!(
            profile.as_str(),
            PROFILE_DIRECT_E2EE_V2 | PROFILE_GROUP_E2EE_V2
        )
    });
    if matches!(signing_identity.algorithm, PublicKeyAlgorithm::X25519)
        || (requires_eddsa && !matches!(signing_identity.algorithm, PublicKeyAlgorithm::Ed25519))
    {
        return Err(invalid(
            "device signing verification method uses the wrong key algorithm",
        ));
    }
    let e2ee_identity = validate_public_method(
        did,
        &device.e2ee_key_id,
        e2ee_method,
        "device E2EE verification method",
    )?;
    if !matches!(e2ee_identity.algorithm, PublicKeyAlgorithm::X25519) {
        return Err(invalid(
            "device E2EE verification method uses the wrong key algorithm",
        ));
    }
    if signing_identity.raw_public_key == e2ee_identity.raw_public_key {
        return Err(invalid("device key material must be unique across roles"));
    }
    Ok((signing_identity, e2ee_identity))
}

fn validate_public_method(
    did: &str,
    expected_key_id: &str,
    method: &Value,
    subject: &str,
) -> Result<PublicKeyIdentity, DeviceManifestError> {
    let method = method
        .as_object()
        .ok_or_else(|| invalid(format!("{subject} must be an object")))?;
    if method.get("id").and_then(Value::as_str) != Some(expected_key_id) {
        return Err(invalid(format!("{subject} id does not match its role")));
    }
    if method.get("controller").and_then(Value::as_str) != Some(did) {
        return Err(invalid(format!("{subject} controller must match the DID")));
    }
    validate_same_document_key_id(did, expected_key_id)?;
    reject_private_key_material(&Value::Object(method.clone()), subject)?;
    let method_type = method
        .get("type")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(format!("{subject}.type must be a non-empty string")))?;
    let material_fields = ["publicKeyJwk", "publicKeyMultibase", "publicKeyBase58"]
        .iter()
        .filter(|field| method.contains_key(**field))
        .copied()
        .collect::<Vec<_>>();
    if material_fields.len() != 1 {
        return Err(invalid(format!(
            "{subject} must contain exactly one supported public key field"
        )));
    }
    match material_fields[0] {
        "publicKeyJwk" => decode_public_jwk(
            method_type,
            method.get("publicKeyJwk").expect("field was checked"),
            subject,
        ),
        "publicKeyMultibase" => decode_public_multikey(
            method_type,
            method.get("publicKeyMultibase").expect("field was checked"),
            subject,
        ),
        _ => Err(invalid(format!(
            "{subject} publicKeyBase58 is not supported by vNext helpers"
        ))),
    }
}

fn validate_same_document_key_id(did: &str, key_id: &str) -> Result<(), DeviceManifestError> {
    let prefix = format!("{did}#");
    if !key_id.starts_with(&prefix) || key_id.len() == prefix.len() {
        return Err(invalid("key id must be a DID URL in the same document"));
    }
    Ok(())
}

fn decode_public_jwk(
    method_type: &str,
    value: &Value,
    subject: &str,
) -> Result<PublicKeyIdentity, DeviceManifestError> {
    if !matches!(
        method_type,
        "JsonWebKey2020"
            | "EcdsaSecp256k1VerificationKey2019"
            | "EcdsaSecp256r1VerificationKey2019"
    ) {
        return Err(invalid(format!(
            "{subject} type is incompatible with publicKeyJwk"
        )));
    }
    let jwk = value
        .as_object()
        .ok_or_else(|| invalid(format!("{subject}.publicKeyJwk must be an object")))?;
    let kty = jwk.get("kty").and_then(Value::as_str);
    let curve = jwk.get("crv").and_then(Value::as_str);
    if kty == Some("OKP") && matches!(curve, Some("Ed25519" | "X25519")) {
        if method_type != "JsonWebKey2020" {
            return Err(invalid(format!("{subject} type contradicts its JWK")));
        }
        let raw = decode_canonical_base64url_32(jwk.get("x"), &format!("{subject}.x"))?;
        return Ok(PublicKeyIdentity {
            algorithm: if curve == Some("Ed25519") {
                PublicKeyAlgorithm::Ed25519
            } else {
                PublicKeyAlgorithm::X25519
            },
            raw_public_key: raw,
        });
    }
    if kty == Some("EC") && matches!(curve, Some("P-256" | "secp256k1")) {
        let expected_type = if curve == Some("P-256") {
            "EcdsaSecp256r1VerificationKey2019"
        } else {
            "EcdsaSecp256k1VerificationKey2019"
        };
        if !matches!(method_type, "JsonWebKey2020") && method_type != expected_type {
            return Err(invalid(format!("{subject} type contradicts its JWK")));
        }
        let mut x = decode_canonical_base64url_32(jwk.get("x"), &format!("{subject}.x"))?;
        let y = decode_canonical_base64url_32(jwk.get("y"), &format!("{subject}.y"))?;
        let mut uncompressed = Vec::with_capacity(65);
        uncompressed.push(0x04);
        uncompressed.extend_from_slice(&x);
        uncompressed.extend_from_slice(&y);
        let algorithm = if curve == Some("P-256") {
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&uncompressed)
                .map_err(|_| invalid(format!("{subject} contains an invalid EC point")))?;
            PublicKeyAlgorithm::P256
        } else {
            k256::ecdsa::VerifyingKey::from_sec1_bytes(&uncompressed)
                .map_err(|_| invalid(format!("{subject} contains an invalid EC point")))?;
            PublicKeyAlgorithm::Secp256k1
        };
        x.extend_from_slice(&y);
        return Ok(PublicKeyIdentity {
            algorithm,
            raw_public_key: x,
        });
    }
    Err(invalid(format!(
        "{subject} contains an unsupported public JWK"
    )))
}

fn decode_public_multikey(
    method_type: &str,
    value: &Value,
    subject: &str,
) -> Result<PublicKeyIdentity, DeviceManifestError> {
    if !matches!(method_type, "Multikey" | "X25519KeyAgreementKey2019") {
        return Err(invalid(format!(
            "{subject} type is incompatible with publicKeyMultibase"
        )));
    }
    let multibase = value
        .as_str()
        .and_then(|value| value.strip_prefix('z'))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(format!("{subject}.publicKeyMultibase must be base58btc")))?;
    let decoded = bs58::decode(multibase)
        .into_vec()
        .map_err(|_| invalid(format!("{subject}.publicKeyMultibase is invalid")))?;
    if bs58::encode(&decoded).into_string() != multibase {
        return Err(invalid(format!(
            "{subject}.publicKeyMultibase must be canonical"
        )));
    }
    if decoded.len() != 34 {
        return Err(invalid(format!(
            "{subject}.publicKeyMultibase must contain a 32-byte key"
        )));
    }
    let algorithm = match decoded.get(..2) {
        Some([0xed, 0x01]) => PublicKeyAlgorithm::Ed25519,
        Some([0xec, 0x01]) => PublicKeyAlgorithm::X25519,
        _ => {
            return Err(invalid(format!(
                "{subject}.publicKeyMultibase uses an unsupported codec"
            )))
        }
    };
    if method_type == "X25519KeyAgreementKey2019"
        && !matches!(algorithm, PublicKeyAlgorithm::X25519)
    {
        return Err(invalid(format!("{subject} type contradicts its Multikey")));
    }
    Ok(PublicKeyIdentity {
        algorithm,
        raw_public_key: decoded[2..].to_vec(),
    })
}

fn decode_canonical_base64url_32(
    value: Option<&Value>,
    subject: &str,
) -> Result<Vec<u8>, DeviceManifestError> {
    let encoded = value
        .and_then(Value::as_str)
        .filter(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
        .ok_or_else(|| invalid(format!("{subject} must be unpadded base64url")))?;
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| invalid(format!("{subject} is invalid base64url")))?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(invalid(format!(
            "{subject} must canonically encode 32 bytes"
        )));
    }
    Ok(decoded)
}

fn reject_private_key_material(value: &Value, subject: &str) -> Result<(), DeviceManifestError> {
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                let normalized_key = key.to_ascii_lowercase().replace(['_', '-'], "");
                if normalized_key.contains("privatekey")
                    || (key == "d" && object.contains_key("kty"))
                {
                    return Err(invalid(format!(
                        "{subject} must not contain private key material"
                    )));
                }
                reject_private_key_material(nested, subject)?;
            }
        }
        Value::Array(values) => {
            for nested in values {
                reject_private_key_material(nested, subject)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn unique_method<'a>(
    did_document: &'a Value,
    key_id: &str,
) -> Result<&'a Value, DeviceManifestError> {
    let methods = did_document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("DID document verificationMethod must be an array"))?;
    let matches = methods
        .iter()
        .filter(|method| method.get("id").and_then(Value::as_str) == Some(key_id))
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(invalid(
            "key id must resolve exactly once in verificationMethod",
        ));
    }
    Ok(matches[0])
}

fn append_device_material(
    did_document: &mut Value,
    root_key_id: &str,
    device: &DeviceManifestEntry,
    signing_method: &Value,
    e2ee_method: &Value,
) -> Result<(), DeviceManifestError> {
    let did = did_document
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("DID document id must be a non-empty string"))?
        .to_string();
    validate_device_methods(&did, root_key_id, device, signing_method, e2ee_method)?;
    let document = did_document
        .as_object_mut()
        .ok_or(DeviceManifestError::InvalidDidDocument)?;
    array_mut(document, "verificationMethod")?
        .extend([signing_method.clone(), e2ee_method.clone()]);
    array_mut(document, "authentication")?.push(Value::String(device.signing_key_id.clone()));
    array_mut(document, "assertionMethod")?.push(Value::String(device.signing_key_id.clone()));
    array_mut(document, "keyAgreement")?.push(Value::String(device.e2ee_key_id.clone()));
    document
        .get_mut("deviceManifest")
        .and_then(Value::as_object_mut)
        .and_then(|manifest| manifest.get_mut("devices"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid("deviceManifest.devices must be an array"))?
        .push(
            serde_json::to_value(device)
                .map_err(|error| DeviceManifestError::InvalidSchema(error.to_string()))?,
        );
    Ok(())
}

fn remove_device_material(
    did_document: &mut Value,
    device: &DeviceManifestEntry,
) -> Result<(), DeviceManifestError> {
    let document = did_document
        .as_object_mut()
        .ok_or(DeviceManifestError::InvalidDidDocument)?;
    array_mut(document, "verificationMethod")?.retain(|method| {
        !matches!(
            method.get("id").and_then(Value::as_str),
            Some(key_id) if key_id == device.signing_key_id || key_id == device.e2ee_key_id
        )
    });
    for relationship in ["authentication", "assertionMethod", "keyAgreement"] {
        array_mut(document, relationship)?.retain(|entry| {
            !relationship_entry_is(entry, &device.signing_key_id)
                && !relationship_entry_is(entry, &device.e2ee_key_id)
        });
    }
    document
        .get_mut("deviceManifest")
        .and_then(Value::as_object_mut)
        .and_then(|manifest| manifest.get_mut("devices"))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid("deviceManifest.devices must be an array"))?
        .retain(|entry| {
            entry.get("device_id").and_then(Value::as_str) != Some(device.device_id.as_str())
        });
    Ok(())
}

fn array_mut<'a>(
    document: &'a mut serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a mut Vec<Value>, DeviceManifestError> {
    document
        .get_mut(field)
        .and_then(Value::as_array_mut)
        .ok_or_else(|| invalid(format!("{field} must be an array")))
}

fn relationship_entry_is(entry: &Value, key_id: &str) -> bool {
    entry.as_str() == Some(key_id) || entry.get("id").and_then(Value::as_str) == Some(key_id)
}

fn validate_retired_device_ids(retired_device_ids: &[String]) -> Result<(), DeviceManifestError> {
    for device_id in retired_device_ids {
        validate_non_empty("retired device_id", device_id)?;
    }
    Ok(())
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
