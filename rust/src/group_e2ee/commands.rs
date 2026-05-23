//! Compatibility command metadata and JSON response helpers for `anp-mls/v1`.
//!
//! The real MLS operations are extracted separately. This module intentionally
//! only owns command-surface constants and response helpers that are safe for
//! both the library and the compatibility binary to share.

use serde_json::{json, Value};

pub const API_VERSION: &str = super::ANP_MLS_API_VERSION;
pub const BINARY_NAME: &str = "anp-mls";
pub const DEVICE_ID_DEFAULT: &str = "default";
pub const GROUP_CIPHER_CONTENT_TYPE: &str = "application/anp-group-cipher+json";

pub const SUPPORTED_COMMANDS: &[&str] = &[
    "system version",
    "key-package generate",
    "group create",
    "group add-member",
    "group update-member-prepare",
    "group update-member-finalize",
    "group update-member-abort",
    "group recover-member-prepare",
    "group recover-member-finalize",
    "group recover-member-abort",
    "group remove-member",
    "group leave",
    "group commit-finalize",
    "group commit-abort",
    "welcome process",
    "commit process",
    "notice process",
    "message encrypt",
    "message decrypt",
    "group restore",
    "group status",
];

pub fn system_version() -> Value {
    json!({
        "api_version": API_VERSION,
        "binary_name": BINARY_NAME,
        "binary_version": env!("CARGO_PKG_VERSION"),
        "build_version": env!("CARGO_PKG_VERSION"),
        "supported_commands": SUPPORTED_COMMANDS,
    })
}

pub fn ok_response(request_id: &str, result: Value) -> Value {
    json!({
        "ok": true,
        "api_version": API_VERSION,
        "request_id": request_id,
        "result": result,
    })
}

pub fn error_response(code: &str, message: &str, request_id: Option<String>) -> Value {
    json!({
        "ok": false,
        "api_version": API_VERSION,
        "request_id": request_id,
        "error": {"code": code, "message": message}
    })
}

pub fn response_for_operation_log(command: &str, response: &Value) -> Value {
    let mut stored = response.clone();
    if command == "message decrypt" {
        if let Some(result) = stored.get_mut("result").and_then(Value::as_object_mut) {
            result.remove("application_plaintext");
            result.insert(
                "plaintext_redacted".to_owned(),
                json!({"redacted": true, "reason": "plaintext is never persisted in operations"}),
            );
        }
    }
    stored
}
