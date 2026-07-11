use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

pub const ANP_HANDLE_SERVICE_TYPE: &str = "ANPHandleService";

/// Canonical, positive decimal generation of a Handle binding.
///
/// The wire representation is a string and comparisons do not use a
/// fixed-width integer, so providers can increase the generation indefinitely.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BindingGeneration(String);

impl BindingGeneration {
    pub fn new(value: impl Into<String>) -> Result<Self, BindingGenerationError> {
        let value = value.into();
        if value.is_empty()
            || value == "0"
            || value.starts_with('0')
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(BindingGenerationError);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_newer_than(&self, previous: &Self) -> bool {
        self > previous
    }
}

impl fmt::Display for BindingGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for BindingGeneration {
    type Err = BindingGenerationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl Ord for BindingGeneration {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.cmp(&other.0))
    }
}

impl PartialOrd for BindingGeneration {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Serialize for BindingGeneration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for BindingGeneration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingGenerationError;

impl fmt::Display for BindingGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("binding_generation must be a canonical positive decimal string")
    }
}

impl std::error::Error for BindingGenerationError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HandleStatus {
    Active,
    Suspended,
    Revoked,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SubjectType {
    Person,
    Agent,
    Group,
    Organization,
    Service,
    Application,
    Unknown,
}

impl<'de> Deserialize<'de> for SubjectType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(match value.as_str() {
            "person" => SubjectType::Person,
            "agent" => SubjectType::Agent,
            "group" => SubjectType::Group,
            "organization" => SubjectType::Organization,
            "service" => SubjectType::Service,
            "application" => SubjectType::Application,
            _ => SubjectType::Unknown,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DidSubjectProfile {
    #[serde(default = "default_did_subject_profile_type")]
    pub r#type: String,
    pub subject_did: String,
    #[serde(default = "default_subject_type")]
    pub subject_type: SubjectType,
    pub handle: Option<String>,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub avatar_uri: Option<String>,
    pub profile_uri: Option<String>,
    pub discoverability: Option<String>,
    pub labels: Option<Value>,
    pub updated: Option<String>,
    #[serde(rename = "versionId")]
    pub version_id: Option<String>,
    pub ttl: Option<u64>,
    pub proof: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HandleResolutionDocument {
    pub handle: String,
    pub did: String,
    pub status: HandleStatus,
    pub binding_generation: BindingGeneration,
    pub updated: Option<String>,
    #[serde(rename = "versionId")]
    pub version_id: Option<String>,
    pub ttl: Option<u64>,
    pub profile: Option<DidSubjectProfile>,
}

impl HandleResolutionDocument {
    pub fn new(
        handle: impl Into<String>,
        did: impl Into<String>,
        status: HandleStatus,
        binding_generation: BindingGeneration,
    ) -> Self {
        Self {
            handle: handle.into(),
            did: did.into(),
            status,
            binding_generation,
            updated: None,
            version_id: None,
            ttl: None,
            profile: None,
        }
    }

    pub fn drop_invalid_profile_projection(&mut self) {
        let Some(profile) = &self.profile else {
            return;
        };
        if profile.subject_did != self.did {
            self.profile = None;
            return;
        }
        if let Some(handle) = &profile.handle {
            if handle != &self.handle {
                self.profile = None;
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandleServiceEntry {
    pub id: String,
    #[serde(default = "default_handle_service_type")]
    pub r#type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParsedWbaUri {
    pub local_part: String,
    pub domain: String,
    pub handle: String,
    pub original_uri: String,
}

fn default_handle_service_type() -> String {
    ANP_HANDLE_SERVICE_TYPE.to_string()
}

fn default_did_subject_profile_type() -> String {
    "DIDSubjectProfile".to_string()
}

fn default_subject_type() -> SubjectType {
    SubjectType::Unknown
}
