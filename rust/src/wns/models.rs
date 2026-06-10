use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub const ANP_HANDLE_SERVICE_TYPE: &str = "ANPHandleService";

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
    pub updated: Option<String>,
    #[serde(rename = "versionId")]
    pub version_id: Option<String>,
    pub ttl: Option<u64>,
    pub profile: Option<DidSubjectProfile>,
}

impl HandleResolutionDocument {
    pub fn new(handle: impl Into<String>, did: impl Into<String>, status: HandleStatus) -> Self {
        Self {
            handle: handle.into(),
            did: did.into(),
            status,
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
