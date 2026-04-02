use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CanonicalJsonError {
    #[error("Unsupported non-finite JSON number")]
    NonFiniteNumber,
    #[error("Unsupported value for canonicalization")]
    UnsupportedValue,
}

pub(crate) fn canonicalize_json(value: &Value) -> Result<Vec<u8>, CanonicalJsonError> {
    let mut output = String::new();
    write_canonical_json(value, &mut output)?;
    Ok(output.into_bytes())
}

fn write_canonical_json(value: &Value, output: &mut String) -> Result<(), CanonicalJsonError> {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => {
            output.push_str(
                &serde_json::to_string(value).map_err(|_| CanonicalJsonError::UnsupportedValue)?,
            );
            Ok(())
        }
        Value::Number(number) => {
            if number.as_f64().map(|it| it.is_finite()).unwrap_or(true) {
                output.push_str(&number.to_string());
                Ok(())
            } else {
                Err(CanonicalJsonError::NonFiniteNumber)
            }
        }
        Value::Array(items) => {
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical_json(item, output)?;
            }
            output.push(']');
            Ok(())
        }
        Value::Object(map) => {
            output.push('{');
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key)
                        .map_err(|_| CanonicalJsonError::UnsupportedValue)?,
                );
                output.push(':');
                let value = map.get(*key).ok_or(CanonicalJsonError::UnsupportedValue)?;
                write_canonical_json(value, output)?;
            }
            output.push('}');
            Ok(())
        }
    }
}
