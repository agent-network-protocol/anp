use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::DateTime;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use super::v2_errors::DirectE2eeV2Error;

pub const DIRECT_E2EE_PROFILE_V2: &str = "anp.direct.e2ee.v2";
pub const DIRECT_E2EE_SECURITY_PROFILE: &str = "direct-e2ee";
pub const TRANSPORT_PROTECTED_SECURITY_PROFILE: &str = "transport-protected";
pub const CONTENT_TYPE_DIRECT_INIT_V2: &str = "application/anp-direct-init+json";
pub const CONTENT_TYPE_DIRECT_CIPHER_V2: &str = "application/anp-direct-cipher+json";
pub const MTI_DIRECT_E2EE_SUITE_V2: &str = "ANP-DIRECT-E2EE-X3DH-25519-CHACHA20POLY1305-SHA256-V1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2SignedPrekey {
    pub key_id: String,
    pub public_key_b64u: String,
    pub expires_at: String,
}

impl V2SignedPrekey {
    pub fn validate(&self) -> Result<(), DirectE2eeV2Error> {
        require_non_empty("signed_prekey.key_id", &self.key_id)?;
        validate_x25519_b64u("signed_prekey.public_key_b64u", &self.public_key_b64u)?;
        DateTime::parse_from_rfc3339(&self.expires_at)
            .map_err(|_| DirectE2eeV2Error::invalid("signed_prekey.expires_at must be RFC3339"))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2OneTimePrekey {
    pub key_id: String,
    pub public_key_b64u: String,
}

impl V2OneTimePrekey {
    pub fn validate(&self) -> Result<(), DirectE2eeV2Error> {
        require_non_empty("one_time_prekey.key_id", &self.key_id)?;
        validate_x25519_b64u("one_time_prekey.public_key_b64u", &self.public_key_b64u)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct V2PrekeyBundle {
    pub bundle_id: String,
    pub owner_did: String,
    pub owner_device_id: String,
    pub suite: String,
    pub static_key_agreement_id: String,
    pub signed_prekey: V2SignedPrekey,
    pub proof: Value,
}

impl V2PrekeyBundle {
    pub fn validate_structure(&self) -> Result<(), DirectE2eeV2Error> {
        for (name, value) in [
            ("prekey_bundle.bundle_id", self.bundle_id.as_str()),
            ("prekey_bundle.owner_did", self.owner_did.as_str()),
            (
                "prekey_bundle.owner_device_id",
                self.owner_device_id.as_str(),
            ),
            (
                "prekey_bundle.static_key_agreement_id",
                self.static_key_agreement_id.as_str(),
            ),
        ] {
            require_non_empty(name, value)?;
        }
        require_eq("prekey_bundle.suite", &self.suite, MTI_DIRECT_E2EE_SUITE_V2)?;
        self.signed_prekey.validate()?;
        let proof = self
            .proof
            .as_object()
            .ok_or_else(|| DirectE2eeV2Error::invalid("prekey_bundle.proof must be an object"))?;
        for field in [
            "type",
            "cryptosuite",
            "verificationMethod",
            "proofPurpose",
            "created",
            "proofValue",
        ] {
            if proof
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .is_empty()
            {
                return Err(DirectE2eeV2Error::invalid(format!(
                    "prekey_bundle.proof.{field} must be a non-empty string"
                )));
            }
        }
        require_eq(
            "prekey_bundle.proof.type",
            proof["type"].as_str().expect("validated string"),
            "DataIntegrityProof",
        )?;
        require_eq(
            "prekey_bundle.proof.cryptosuite",
            proof["cryptosuite"].as_str().expect("validated string"),
            "eddsa-jcs-2022",
        )?;
        require_eq(
            "prekey_bundle.proof.proofPurpose",
            proof["proofPurpose"].as_str().expect("validated string"),
            "assertionMethod",
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2Target {
    pub kind: String,
    pub did: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2KeyServiceMetadata {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub anp_version: Option<String>,
    pub profile: String,
    pub security_profile: String,
    pub sender_did: String,
    pub sender_device_id: String,
    pub target: V2Target,
    pub operation_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub created_at: Option<String>,
}

impl V2KeyServiceMetadata {
    pub fn validate(&self) -> Result<(), DirectE2eeV2Error> {
        require_eq("meta.profile", &self.profile, DIRECT_E2EE_PROFILE_V2)?;
        require_eq(
            "meta.security_profile",
            &self.security_profile,
            TRANSPORT_PROTECTED_SECURITY_PROFILE,
        )?;
        require_eq("meta.target.kind", &self.target.kind, "service")?;
        for (name, value) in [
            ("meta.sender_did", self.sender_did.as_str()),
            ("meta.sender_device_id", self.sender_device_id.as_str()),
            ("meta.target.did", self.target.did.as_str()),
            ("meta.operation_id", self.operation_id.as_str()),
        ] {
            require_non_empty(name, value)?;
        }
        validate_optional("meta.anp_version", self.anp_version.as_deref())?;
        validate_optional_rfc3339("meta.created_at", self.created_at.as_deref())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2DirectMetadata {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub anp_version: Option<String>,
    pub profile: String,
    pub security_profile: String,
    pub sender_did: String,
    pub sender_device_id: String,
    pub target: V2Target,
    pub recipient_device_id: String,
    pub operation_id: String,
    pub message_id: String,
    pub content_type: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub created_at: Option<String>,
}

impl V2DirectMetadata {
    pub fn validate(&self) -> Result<(), DirectE2eeV2Error> {
        require_eq("meta.profile", &self.profile, DIRECT_E2EE_PROFILE_V2)?;
        require_eq(
            "meta.security_profile",
            &self.security_profile,
            DIRECT_E2EE_SECURITY_PROFILE,
        )?;
        require_eq("meta.target.kind", &self.target.kind, "agent")?;
        if !matches!(
            self.content_type.as_str(),
            CONTENT_TYPE_DIRECT_INIT_V2 | CONTENT_TYPE_DIRECT_CIPHER_V2
        ) {
            return Err(DirectE2eeV2Error::invalid(
                "meta.content_type is not an MTI P5 v2 wire object",
            ));
        }
        for (name, value) in [
            ("meta.sender_did", self.sender_did.as_str()),
            ("meta.sender_device_id", self.sender_device_id.as_str()),
            ("meta.target.did", self.target.did.as_str()),
            (
                "meta.recipient_device_id",
                self.recipient_device_id.as_str(),
            ),
            ("meta.operation_id", self.operation_id.as_str()),
            ("meta.message_id", self.message_id.as_str()),
        ] {
            require_non_empty(name, value)?;
        }
        if self.operation_id != self.message_id {
            return Err(DirectE2eeV2Error::invalid(
                "meta.operation_id must equal meta.message_id",
            ));
        }
        validate_optional("meta.anp_version", self.anp_version.as_deref())?;
        validate_optional_rfc3339("meta.created_at", self.created_at.as_deref())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2RatchetHeader {
    pub dh_pub_b64u: String,
    pub pn: String,
    pub n: String,
}

impl V2RatchetHeader {
    pub fn validate(&self) -> Result<(), DirectE2eeV2Error> {
        validate_x25519_b64u("ratchet_header.dh_pub_b64u", &self.dh_pub_b64u)?;
        validate_decimal("ratchet_header.pn", &self.pn)?;
        validate_decimal("ratchet_header.n", &self.n)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2DirectInitBody {
    pub session_id: String,
    pub suite: String,
    pub sender_static_key_agreement_id: String,
    pub recipient_bundle_id: String,
    pub recipient_signed_prekey_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub recipient_one_time_prekey_id: Option<String>,
    pub sender_ephemeral_pub_b64u: String,
    pub ciphertext_b64u: String,
}

impl V2DirectInitBody {
    pub fn validate(&self) -> Result<(), DirectE2eeV2Error> {
        require_eq("body.suite", &self.suite, MTI_DIRECT_E2EE_SUITE_V2)?;
        validate_fixed_b64u("body.session_id", &self.session_id, 16)?;
        validate_x25519_b64u(
            "body.sender_ephemeral_pub_b64u",
            &self.sender_ephemeral_pub_b64u,
        )?;
        validate_b64u("body.ciphertext_b64u", &self.ciphertext_b64u)?;
        for (name, value) in [
            (
                "body.sender_static_key_agreement_id",
                self.sender_static_key_agreement_id.as_str(),
            ),
            (
                "body.recipient_bundle_id",
                self.recipient_bundle_id.as_str(),
            ),
            (
                "body.recipient_signed_prekey_id",
                self.recipient_signed_prekey_id.as_str(),
            ),
        ] {
            require_non_empty(name, value)?;
        }
        validate_optional(
            "body.recipient_one_time_prekey_id",
            self.recipient_one_time_prekey_id.as_deref(),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2DirectCipherBody {
    pub session_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub suite: Option<String>,
    pub ratchet_header: V2RatchetHeader,
    pub ciphertext_b64u: String,
}

impl V2DirectCipherBody {
    pub fn validate(&self) -> Result<(), DirectE2eeV2Error> {
        validate_fixed_b64u("body.session_id", &self.session_id, 16)?;
        validate_b64u("body.ciphertext_b64u", &self.ciphertext_b64u)?;
        if let Some(suite) = self.suite.as_deref() {
            require_eq("body.suite", suite, MTI_DIRECT_E2EE_SUITE_V2)?;
        }
        self.ratchet_header.validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct V2ApplicationPlaintext {
    pub application_content_type: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub logical_message_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub conversation_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub reply_to_message_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub annotations: Option<Value>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub text: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub payload: Option<Value>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present"
    )]
    pub payload_b64u: Option<String>,
}

impl V2ApplicationPlaintext {
    pub fn validate(&self) -> Result<(), DirectE2eeV2Error> {
        require_non_empty("application_content_type", &self.application_content_type)?;
        for (name, value) in [
            ("logical_message_id", self.logical_message_id.as_deref()),
            ("conversation_id", self.conversation_id.as_deref()),
            ("reply_to_message_id", self.reply_to_message_id.as_deref()),
        ] {
            validate_optional(name, value)?;
        }
        let bearer_count = usize::from(self.text.is_some())
            + usize::from(self.payload.is_some())
            + usize::from(self.payload_b64u.is_some());
        if bearer_count != 1 {
            return Err(DirectE2eeV2Error::invalid(
                "exactly one of text, payload, or payload_b64u must be present",
            ));
        }
        if let Some(payload) = self.payload.as_ref() {
            if !payload.is_object() {
                return Err(DirectE2eeV2Error::invalid("payload must be an object"));
            }
        }
        if let Some(annotations) = self.annotations.as_ref() {
            if !annotations.is_object() {
                return Err(DirectE2eeV2Error::invalid("annotations must be an object"));
            }
        }
        if self.application_content_type == "text/plain" && self.text.is_none() {
            return Err(DirectE2eeV2Error::invalid(
                "text/plain requires the text bearer",
            ));
        }
        if matches!(
            self.application_content_type.as_str(),
            "application/json" | "application/anp-attachment-manifest+json"
        ) && self.payload.is_none()
        {
            return Err(DirectE2eeV2Error::invalid(format!(
                "{} requires the payload bearer",
                self.application_content_type
            )));
        }
        validate_optional("text", self.text.as_deref())?;
        if let Some(payload_b64u) = self.payload_b64u.as_deref() {
            validate_b64u("payload_b64u", payload_b64u)?;
        }
        Ok(())
    }
}

/// Deserialize an optional wire member while rejecting an explicit JSON null.
///
/// With `default`, serde calls this only when the member is present; the inner
/// type therefore owns null rejection instead of collapsing null into None.
pub(crate) fn deserialize_present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2DirectBody {
    Init(V2DirectInitBody),
    Cipher(V2DirectCipherBody),
}

pub(crate) fn require_non_empty(field: &str, value: &str) -> Result<(), DirectE2eeV2Error> {
    if value.is_empty() {
        Err(DirectE2eeV2Error::invalid(format!(
            "{field} must be a non-empty string"
        )))
    } else {
        Ok(())
    }
}

pub(crate) fn require_eq(
    field: &str,
    actual: &str,
    expected: &str,
) -> Result<(), DirectE2eeV2Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(DirectE2eeV2Error::invalid(format!(
            "{field} must equal {expected}"
        )))
    }
}

fn validate_optional(field: &str, value: Option<&str>) -> Result<(), DirectE2eeV2Error> {
    if value.is_some_and(str::is_empty) {
        Err(DirectE2eeV2Error::invalid(format!(
            "{field} must be omitted rather than empty"
        )))
    } else {
        Ok(())
    }
}

fn validate_optional_rfc3339(field: &str, value: Option<&str>) -> Result<(), DirectE2eeV2Error> {
    if let Some(value) = value {
        require_non_empty(field, value)?;
        DateTime::parse_from_rfc3339(value)
            .map_err(|_| DirectE2eeV2Error::invalid(format!("{field} must be RFC3339")))?;
    }
    Ok(())
}

fn validate_decimal(field: &str, value: &str) -> Result<(), DirectE2eeV2Error> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DirectE2eeV2Error::invalid(format!(
            "{field} must be a decimal string"
        )));
    }
    Ok(())
}

fn validate_x25519_b64u(field: &str, value: &str) -> Result<(), DirectE2eeV2Error> {
    validate_fixed_b64u(field, value, 32).map_err(|_| {
        DirectE2eeV2Error::invalid(format!(
            "{field} must be unpadded base64url encoding a 32-byte X25519 public key"
        ))
    })
}

fn validate_fixed_b64u(
    field: &str,
    value: &str,
    expected_len: usize,
) -> Result<(), DirectE2eeV2Error> {
    let decoded = decode_b64u(field, value)?;
    if decoded.len() != expected_len {
        return Err(DirectE2eeV2Error::invalid(format!(
            "{field} must encode {expected_len} bytes"
        )));
    }
    Ok(())
}

fn validate_b64u(field: &str, value: &str) -> Result<(), DirectE2eeV2Error> {
    decode_b64u(field, value).map(|_| ())
}

fn decode_b64u(field: &str, value: &str) -> Result<Vec<u8>, DirectE2eeV2Error> {
    if value.is_empty() || value.contains('=') {
        return Err(DirectE2eeV2Error::invalid(format!(
            "{field} must be unpadded base64url"
        )));
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| DirectE2eeV2Error::invalid(format!("{field} must be base64url")))
}
