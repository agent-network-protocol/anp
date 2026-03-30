use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HandleStatus {
    Active,
    Suspended,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HandleResolutionDocument {
    pub handle: String,
    pub did: String,
    pub status: HandleStatus,
    pub updated: Option<String>,
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
    "HandleService".to_string()
}
