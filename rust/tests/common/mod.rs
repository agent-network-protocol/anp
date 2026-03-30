#![allow(dead_code)]

use std::sync::OnceLock;

use serde_json::Value;

const RUST_INTEROP_CONFIG_JSON: &str = include_str!("../../../tests/rust_interop_config.json");
static RELEASED_PYTHON_ANP_VERSION: OnceLock<String> = OnceLock::new();

pub fn released_python_anp_version() -> &'static str {
    RELEASED_PYTHON_ANP_VERSION
        .get_or_init(|| {
            let value: Value = serde_json::from_str(RUST_INTEROP_CONFIG_JSON)
                .expect("rust interop config must be valid JSON");
            value
                .get("released_python_anp_version")
                .and_then(Value::as_str)
                .expect("released_python_anp_version must be configured")
                .to_string()
        })
        .as_str()
}
