use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};

use chrono::DateTime;

use super::v2_bundle::{
    V2GetPrekeyBundleBody, V2GetPrekeyBundleResult, V2PublishPrekeyBundleBody,
    V2PublishPrekeyBundleResult,
};
use super::v2_errors::DirectE2eeV2Error;
use super::v2_models::{
    V2DirectBody, V2DirectCipherBody, V2DirectInitBody, V2DirectMetadata, V2KeyServiceMetadata,
    CONTENT_TYPE_DIRECT_CIPHER_V2, CONTENT_TYPE_DIRECT_INIT_V2,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct RpcRequest<P> {
    method: String,
    params: P,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Params<M, B> {
    meta: M,
    body: B,
}

/// Successful result for one exact device-qualified `direct.send` request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2DirectSendResult {
    pub accepted: bool,
    pub message_id: String,
    pub operation_id: String,
    pub target_did: String,
    pub recipient_device_id: String,
    pub accepted_at: String,
}

impl V2DirectSendResult {
    pub fn validate(&self) -> Result<(), DirectE2eeV2Error> {
        if !self.accepted {
            return Err(DirectE2eeV2Error::invalid(
                "accepted must be true in a successful result",
            ));
        }
        for (field, value) in [
            ("message_id", self.message_id.as_str()),
            ("operation_id", self.operation_id.as_str()),
            ("target_did", self.target_did.as_str()),
            ("recipient_device_id", self.recipient_device_id.as_str()),
        ] {
            if value.is_empty() {
                return Err(DirectE2eeV2Error::invalid(format!(
                    "{field} must be a non-empty string"
                )));
            }
        }
        if self.operation_id != self.message_id {
            return Err(DirectE2eeV2Error::invalid(
                "result.operation_id must equal result.message_id",
            ));
        }
        DateTime::parse_from_rfc3339(&self.accepted_at)
            .map_err(|_| DirectE2eeV2Error::invalid("accepted_at must be RFC3339"))?;
        Ok(())
    }
}

pub fn parse_publish_prekey_bundle_result_v2(
    value: &Value,
) -> Result<V2PublishPrekeyBundleResult, DirectE2eeV2Error> {
    let result: V2PublishPrekeyBundleResult = parse(value)?;
    result.validate()?;
    Ok(result)
}

pub fn parse_get_prekey_bundle_result_v2(
    value: &Value,
) -> Result<V2GetPrekeyBundleResult, DirectE2eeV2Error> {
    let result: V2GetPrekeyBundleResult = parse(value)?;
    result.validate()?;
    Ok(result)
}

pub fn parse_direct_send_result_v2(value: &Value) -> Result<V2DirectSendResult, DirectE2eeV2Error> {
    let result: V2DirectSendResult = parse(value)?;
    result.validate()?;
    Ok(result)
}

pub fn publish_prekey_bundle_request_v2(
    meta: V2KeyServiceMetadata,
    body: V2PublishPrekeyBundleBody,
) -> Result<Value, DirectE2eeV2Error> {
    meta.validate()?;
    body.prekey_bundle.validate_structure()?;
    for opk in &body.one_time_prekeys {
        opk.validate()?;
    }
    if body.prekey_bundle.owner_did != meta.sender_did
        || body.prekey_bundle.owner_device_id != meta.sender_device_id
    {
        return Err(DirectE2eeV2Error::invalid(
            "published bundle owner must equal the sending device",
        ));
    }
    if body.one_time_prekeys.is_empty() {
        return Ok(json!({
            "method": "direct.e2ee.publish_prekey_bundle",
            "params": { "meta": meta, "body": { "prekey_bundle": body.prekey_bundle } }
        }));
    }
    Ok(serde_json::to_value(RpcRequest {
        method: "direct.e2ee.publish_prekey_bundle".to_owned(),
        params: Params { meta, body },
    })?)
}

pub fn parse_publish_prekey_bundle_request_v2(
    value: &Value,
) -> Result<(V2KeyServiceMetadata, V2PublishPrekeyBundleBody), DirectE2eeV2Error> {
    if value
        .pointer("/params/body/one_time_prekeys")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        return Err(DirectE2eeV2Error::invalid(
            "one_time_prekeys must be omitted or non-empty",
        ));
    }
    let request: RpcRequest<Params<V2KeyServiceMetadata, V2PublishPrekeyBundleBody>> =
        parse(value)?;
    require_method(&request.method, "direct.e2ee.publish_prekey_bundle")?;
    request.params.meta.validate()?;
    request.params.body.prekey_bundle.validate_structure()?;
    for opk in &request.params.body.one_time_prekeys {
        opk.validate()?;
    }
    if request.params.body.prekey_bundle.owner_did != request.params.meta.sender_did
        || request.params.body.prekey_bundle.owner_device_id != request.params.meta.sender_device_id
    {
        return Err(DirectE2eeV2Error::invalid(
            "published bundle owner must equal the sending device",
        ));
    }
    Ok((request.params.meta, request.params.body))
}

pub fn get_prekey_bundle_request_v2(
    meta: V2KeyServiceMetadata,
    body: V2GetPrekeyBundleBody,
) -> Result<Value, DirectE2eeV2Error> {
    meta.validate()?;
    validate_get_body(&body)?;
    Ok(serde_json::to_value(RpcRequest {
        method: "direct.e2ee.get_prekey_bundle".to_owned(),
        params: Params { meta, body },
    })?)
}

pub fn parse_get_prekey_bundle_request_v2(
    value: &Value,
) -> Result<(V2KeyServiceMetadata, V2GetPrekeyBundleBody), DirectE2eeV2Error> {
    let request: RpcRequest<Params<V2KeyServiceMetadata, V2GetPrekeyBundleBody>> = parse(value)?;
    require_method(&request.method, "direct.e2ee.get_prekey_bundle")?;
    request.params.meta.validate()?;
    validate_get_body(&request.params.body)?;
    Ok((request.params.meta, request.params.body))
}

pub fn direct_send_request_v2(
    meta: V2DirectMetadata,
    body: V2DirectBody,
) -> Result<Value, DirectE2eeV2Error> {
    meta.validate()?;
    let body_value = match body {
        V2DirectBody::Init(body) => {
            if meta.content_type != CONTENT_TYPE_DIRECT_INIT_V2 {
                return Err(DirectE2eeV2Error::invalid(
                    "init body/content_type mismatch",
                ));
            }
            body.validate()?;
            serde_json::to_value(body)?
        }
        V2DirectBody::Cipher(body) => {
            if meta.content_type != CONTENT_TYPE_DIRECT_CIPHER_V2 {
                return Err(DirectE2eeV2Error::invalid(
                    "cipher body/content_type mismatch",
                ));
            }
            body.validate()?;
            serde_json::to_value(body)?
        }
    };
    Ok(json!({
        "method": "direct.send",
        "params": { "meta": meta, "body": body_value }
    }))
}

pub fn parse_direct_send_request_v2(
    value: &Value,
) -> Result<(V2DirectMetadata, V2DirectBody), DirectE2eeV2Error> {
    let request: RpcRequest<Params<V2DirectMetadata, Value>> = parse(value)?;
    require_method(&request.method, "direct.send")?;
    request.params.meta.validate()?;
    let body = match request.params.meta.content_type.as_str() {
        CONTENT_TYPE_DIRECT_INIT_V2 => {
            let body: V2DirectInitBody = serde_json::from_value(request.params.body)?;
            body.validate()?;
            V2DirectBody::Init(body)
        }
        CONTENT_TYPE_DIRECT_CIPHER_V2 => {
            let body: V2DirectCipherBody = serde_json::from_value(request.params.body)?;
            body.validate()?;
            V2DirectBody::Cipher(body)
        }
        _ => unreachable!("metadata validation has checked content_type"),
    };
    Ok((request.params.meta, body))
}

fn parse<T: DeserializeOwned>(value: &Value) -> Result<T, DirectE2eeV2Error> {
    Ok(serde_json::from_value(value.clone())?)
}

fn require_method(actual: &str, expected: &str) -> Result<(), DirectE2eeV2Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(DirectE2eeV2Error::invalid(format!(
            "method must equal {expected}"
        )))
    }
}

fn validate_get_body(body: &V2GetPrekeyBundleBody) -> Result<(), DirectE2eeV2Error> {
    if body.target_did.is_empty() || body.target_device_id.is_empty() {
        return Err(DirectE2eeV2Error::invalid(
            "target_did and target_device_id must be non-empty",
        ));
    }
    if body.preferred_suite.as_deref().is_some_and(str::is_empty) {
        return Err(DirectE2eeV2Error::invalid(
            "preferred_suite must be omitted rather than empty",
        ));
    }
    Ok(())
}
