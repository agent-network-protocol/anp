use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::v2_errors::DirectE2eeV2Error;
use super::v2_models::{
    deserialize_present, V2KeyServiceMetadata, V2OneTimePrekey, V2PrekeyBundle, V2SignedPrekey,
    V2Target, DIRECT_E2EE_PROFILE_V2, MTI_DIRECT_E2EE_SUITE_V2,
    TRANSPORT_PROTECTED_SECURITY_PROFILE,
};
use crate::authentication::{find_eligible_device, PROFILE_DIRECT_E2EE_V2};
use crate::canonical_json::canonicalize_json;
use crate::proof::{generate_object_proof, verify_object_proof};
use crate::PrivateKeyMaterial;

pub fn build_prekey_bundle_v2(
    bundle_id: &str,
    owner_did: &str,
    owner_device_id: &str,
    static_key_agreement_id: &str,
    signed_prekey: V2SignedPrekey,
    signing_private_key: &PrivateKeyMaterial,
    verification_method: &str,
    created: Option<&str>,
) -> Result<V2PrekeyBundle, DirectE2eeV2Error> {
    signed_prekey.validate()?;
    let unsigned = json!({
        "bundle_id": bundle_id,
        "owner_did": owner_did,
        "owner_device_id": owner_device_id,
        "suite": MTI_DIRECT_E2EE_SUITE_V2,
        "static_key_agreement_id": static_key_agreement_id,
        "signed_prekey": signed_prekey,
    });
    let signed = generate_object_proof(
        &unsigned,
        signing_private_key,
        verification_method,
        owner_did,
        created.map(str::to_owned),
    )?;
    let bundle = V2PrekeyBundle {
        bundle_id: bundle_id.to_owned(),
        owner_did: owner_did.to_owned(),
        owner_device_id: owner_device_id.to_owned(),
        suite: MTI_DIRECT_E2EE_SUITE_V2.to_owned(),
        static_key_agreement_id: static_key_agreement_id.to_owned(),
        signed_prekey,
        proof: signed
            .get("proof")
            .cloned()
            .ok_or_else(|| DirectE2eeV2Error::invalid("generated bundle has no proof"))?,
    };
    bundle.validate_structure()?;
    Ok(bundle)
}

pub fn signed_bundle_object_jcs_v2(bundle: &V2PrekeyBundle) -> Result<Vec<u8>, DirectE2eeV2Error> {
    let mut value = serde_json::to_value(bundle)?;
    value
        .as_object_mut()
        .ok_or_else(|| DirectE2eeV2Error::invalid("prekey bundle must be an object"))?
        .remove("proof");
    Ok(canonicalize_json(&value)?)
}

pub fn verify_prekey_bundle_v2(
    bundle: &V2PrekeyBundle,
    did_document: &Value,
    now: DateTime<Utc>,
) -> Result<(), DirectE2eeV2Error> {
    bundle.validate_structure()?;
    if did_document.get("id").and_then(Value::as_str) != Some(bundle.owner_did.as_str()) {
        return Err(DirectE2eeV2Error::invalid(
            "owner_did must match the issuer DID document",
        ));
    }
    let device = find_eligible_device(
        did_document,
        &bundle.owner_device_id,
        PROFILE_DIRECT_E2EE_V2,
    )
    .map_err(|error| DirectE2eeV2Error::invalid(error.to_string()))?
    .ok_or_else(|| DirectE2eeV2Error::invalid("owner device is not P5 v2 eligible"))?;
    if device.e2ee_key_id != bundle.static_key_agreement_id {
        return Err(DirectE2eeV2Error::invalid(
            "static_key_agreement_id must equal the device e2ee_key_id",
        ));
    }
    if bundle
        .proof
        .get("verificationMethod")
        .and_then(Value::as_str)
        != Some(device.signing_key_id.as_str())
    {
        return Err(DirectE2eeV2Error::invalid(
            "proof.verificationMethod must equal the device signing_key_id",
        ));
    }
    let expires_at = DateTime::parse_from_rfc3339(&bundle.signed_prekey.expires_at)
        .map_err(|_| DirectE2eeV2Error::invalid("signed_prekey.expires_at must be RFC3339"))?
        .with_timezone(&Utc);
    if expires_at <= now {
        return Err(DirectE2eeV2Error::invalid("signed prekey is expired"));
    }
    verify_object_proof(
        &serde_json::to_value(bundle)?,
        &bundle.owner_did,
        did_document,
    )?;
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct V2PublishPrekeyBundleBody {
    pub prekey_bundle: V2PrekeyBundle,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub one_time_prekeys: Vec<V2OneTimePrekey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2GetPrekeyBundleBody {
    pub target_did: String,
    pub target_device_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub preferred_suite: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub require_opk: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2PublishPrekeyBundleResult {
    pub published: bool,
    pub owner_did: String,
    pub owner_device_id: String,
    pub bundle_id: String,
    pub published_at: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub published_opk_count: Option<u64>,
}

impl V2PublishPrekeyBundleResult {
    pub fn validate(&self) -> Result<(), DirectE2eeV2Error> {
        if !self.published {
            return Err(DirectE2eeV2Error::invalid(
                "published must be true in a successful result",
            ));
        }
        for (field, value) in [
            ("owner_did", self.owner_did.as_str()),
            ("owner_device_id", self.owner_device_id.as_str()),
            ("bundle_id", self.bundle_id.as_str()),
        ] {
            if value.is_empty() {
                return Err(DirectE2eeV2Error::invalid(format!(
                    "{field} must be a non-empty string"
                )));
            }
        }
        DateTime::parse_from_rfc3339(&self.published_at)
            .map_err(|_| DirectE2eeV2Error::invalid("published_at must be RFC3339"))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct V2GetPrekeyBundleResult {
    pub target_did: String,
    pub target_device_id: String,
    pub prekey_bundle: V2PrekeyBundle,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub one_time_prekey: Option<V2OneTimePrekey>,
}

impl V2GetPrekeyBundleResult {
    pub fn validate(&self) -> Result<(), DirectE2eeV2Error> {
        if self.target_did.is_empty() || self.target_device_id.is_empty() {
            return Err(DirectE2eeV2Error::invalid(
                "target_did and target_device_id must be non-empty",
            ));
        }
        self.prekey_bundle.validate_structure()?;
        if self.target_did != self.prekey_bundle.owner_did
            || self.target_device_id != self.prekey_bundle.owner_device_id
        {
            return Err(DirectE2eeV2Error::invalid(
                "get result target must equal the returned bundle owner",
            ));
        }
        if let Some(one_time_prekey) = &self.one_time_prekey {
            one_time_prekey.validate()?;
        }
        Ok(())
    }
}

pub fn key_service_metadata_v2(
    sender_did: &str,
    sender_device_id: &str,
    service_did: &str,
    operation_id: &str,
) -> V2KeyServiceMetadata {
    V2KeyServiceMetadata {
        anp_version: None,
        profile: DIRECT_E2EE_PROFILE_V2.to_owned(),
        security_profile: TRANSPORT_PROTECTED_SECURITY_PROFILE.to_owned(),
        sender_did: sender_did.to_owned(),
        sender_device_id: sender_device_id.to_owned(),
        target: V2Target {
            kind: "service".to_owned(),
            did: service_did.to_owned(),
        },
        operation_id: operation_id.to_owned(),
        created_at: None,
    }
}
