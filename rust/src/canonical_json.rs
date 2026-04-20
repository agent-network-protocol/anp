use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CanonicalJsonError {
    #[error("JCS canonicalization failed: {0}")]
    Canonicalization(#[from] serde_json::Error),
}

pub(crate) fn canonicalize_json(value: &Value) -> Result<Vec<u8>, CanonicalJsonError> {
    serde_json_canonicalizer::to_vec(value).map_err(CanonicalJsonError::from)
}

#[cfg(test)]
mod tests {
    use super::canonicalize_json;
    use serde_json::{json, Value};

    #[test]
    fn canonicalize_json_matches_rfc8785_sample() {
        let value = json!({
            "numbers": [
                333333333.33333329,
                1e30,
                4.50,
                2e-3,
                0.000000000000000000000000001
            ],
            "string": "\u{20ac}$\u{000f}\nA'B\"\\\\\"/",
            "literals": [Value::Null, true, false]
        });

        let canonical = canonicalize_json(&value).expect("JCS canonicalization should succeed");
        assert_eq!(
            String::from_utf8(canonical).expect("canonical JSON must be UTF-8"),
            "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
        );
    }

    #[test]
    fn canonicalize_json_sorts_keys_by_utf16_code_units() {
        let value = json!({
            "\u{20ac}": "euro",
            "\r": "cr",
            "\u{fb33}": "hebrew",
            "1": "digit",
            "\u{1f600}": "emoji",
            "\u{0080}": "control",
            "\u{00f6}": "oumlaut"
        });

        let canonical = canonicalize_json(&value).expect("JCS canonicalization should succeed");
        assert_eq!(
            String::from_utf8(canonical).expect("canonical JSON must be UTF-8"),
            "{\"\\r\":\"cr\",\"1\":\"digit\",\"\u{0080}\":\"control\",\"\u{00f6}\":\"oumlaut\",\"\u{20ac}\":\"euro\",\"\u{1f600}\":\"emoji\",\"\u{fb33}\":\"hebrew\"}"
        );
    }
}
