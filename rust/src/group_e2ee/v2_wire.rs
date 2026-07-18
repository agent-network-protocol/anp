use chrono::DateTime;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

use super::v2_errors::GroupE2eeV2Error;
use super::v2_models::*;

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct AuthenticatedParams<M, B> {
    meta: M,
    body: B,
    auth: V2OriginAuth,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2PublishKeyPackageResult {
    pub published: bool,
    pub owner_did: String,
    pub owner_device_id: String,
    pub key_package_id: String,
    pub published_at: String,
}

impl V2PublishKeyPackageResult {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        if !self.published {
            return Err(GroupE2eeV2Error::invalid(
                "published must be true in a successful result",
            ));
        }
        validate_identifiers(&[
            ("owner_did", &self.owner_did),
            ("owner_device_id", &self.owner_device_id),
            ("key_package_id", &self.key_package_id),
        ])?;
        validate_timestamp("published_at", &self.published_at)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2GetKeyPackageResult {
    pub target_did: String,
    pub target_device_id: String,
    pub group_key_package: V2GroupKeyPackage,
}

impl V2GetKeyPackageResult {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        validate_identifiers(&[
            ("target_did", &self.target_did),
            ("target_device_id", &self.target_device_id),
        ])?;
        self.group_key_package.validate_structure()?;
        if self.target_did != self.group_key_package.owner_did
            || self.target_device_id != self.group_key_package.owner_device_id
        {
            return Err(GroupE2eeV2Error::invalid(
                "get result target pair must equal group_key_package owner pair",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2GroupCreateResult {
    pub created: bool,
    pub group_did: String,
    pub group_state_ref: V2GroupStateRef,
    pub crypto_group_id_b64u: String,
    pub epoch: String,
    pub accepted_at: String,
}

impl V2GroupCreateResult {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        if !self.created {
            return Err(GroupE2eeV2Error::invalid(
                "created must be true in a successful result",
            ));
        }
        require_non_empty("group_did", &self.group_did)?;
        self.group_state_ref.validate()?;
        if self.group_state_ref.group_did != self.group_did {
            return Err(GroupE2eeV2Error::invalid(
                "result group_state_ref.group_did must equal group_did",
            ));
        }
        validate_non_empty_b64u("crypto_group_id_b64u", &self.crypto_group_id_b64u)?;
        validate_decimal("epoch", &self.epoch)?;
        validate_timestamp("accepted_at", &self.accepted_at)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct V2GroupMembershipResult {
    pub accepted: bool,
    pub group_did: String,
    pub member_did: String,
    pub member_device_id: String,
    pub group_state_ref: V2GroupStateRef,
    pub crypto_group_id_b64u: String,
    pub epoch: String,
    pub accepted_at: String,
}

impl V2GroupMembershipResult {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        if !self.accepted {
            return Err(GroupE2eeV2Error::invalid(
                "accepted must be true in a successful result",
            ));
        }
        validate_identifiers(&[
            ("group_did", &self.group_did),
            ("member_did", &self.member_did),
            ("member_device_id", &self.member_device_id),
        ])?;
        self.group_state_ref.validate()?;
        if self.group_state_ref.group_did != self.group_did {
            return Err(GroupE2eeV2Error::invalid(
                "result group_state_ref.group_did must equal group_did",
            ));
        }
        validate_non_empty_b64u("crypto_group_id_b64u", &self.crypto_group_id_b64u)?;
        validate_decimal("epoch", &self.epoch)?;
        validate_timestamp("accepted_at", &self.accepted_at)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct V2GroupSendResult {
    pub accepted: bool,
    pub group_did: String,
    pub message_id: String,
    pub operation_id: String,
    pub group_event_seq: String,
    pub group_state_version: String,
    pub accepted_at: String,
    pub epoch: String,
    pub group_receipt: Value,
}

impl V2GroupSendResult {
    pub fn validate(&self) -> Result<(), GroupE2eeV2Error> {
        if !self.accepted {
            return Err(GroupE2eeV2Error::invalid(
                "accepted must be true in a successful result",
            ));
        }
        validate_identifiers(&[
            ("group_did", &self.group_did),
            ("message_id", &self.message_id),
            ("operation_id", &self.operation_id),
        ])?;
        validate_decimal("group_event_seq", &self.group_event_seq)?;
        require_non_empty("group_state_version", &self.group_state_version)?;
        validate_decimal("epoch", &self.epoch)?;
        validate_timestamp("accepted_at", &self.accepted_at)?;
        if !self.group_receipt.is_object() {
            return Err(GroupE2eeV2Error::invalid(
                "group_receipt must be a JSON object",
            ));
        }
        Ok(())
    }
}

pub fn publish_key_package_request_v2(
    meta: V2ServiceMetadata,
    body: V2PublishKeyPackageBody,
) -> Result<Value, GroupE2eeV2Error> {
    validate_publish(&meta, &body)?;
    request(METHOD_PUBLISH_KEY_PACKAGE_V2, Params { meta, body })
}

pub fn parse_publish_key_package_request_v2(
    value: &Value,
) -> Result<(V2ServiceMetadata, V2PublishKeyPackageBody), GroupE2eeV2Error> {
    let request: RpcRequest<Params<V2ServiceMetadata, V2PublishKeyPackageBody>> = parse(value)?;
    require_method(&request.method, METHOD_PUBLISH_KEY_PACKAGE_V2)?;
    validate_publish(&request.params.meta, &request.params.body)?;
    Ok((request.params.meta, request.params.body))
}

pub fn get_key_package_request_v2(
    meta: V2ServiceMetadata,
    body: V2GetKeyPackageBody,
) -> Result<Value, GroupE2eeV2Error> {
    validate_get(&meta, &body)?;
    request(METHOD_GET_KEY_PACKAGE_V2, Params { meta, body })
}

pub fn parse_get_key_package_request_v2(
    value: &Value,
) -> Result<(V2ServiceMetadata, V2GetKeyPackageBody), GroupE2eeV2Error> {
    let request: RpcRequest<Params<V2ServiceMetadata, V2GetKeyPackageBody>> = parse(value)?;
    require_method(&request.method, METHOD_GET_KEY_PACKAGE_V2)?;
    validate_get(&request.params.meta, &request.params.body)?;
    Ok((request.params.meta, request.params.body))
}

pub fn group_create_request_v2(
    meta: V2ServiceMetadata,
    body: V2GroupCreateBody,
    auth: V2OriginAuth,
) -> Result<Value, GroupE2eeV2Error> {
    validate_create(&meta, &body, &auth)?;
    request(
        METHOD_GROUP_CREATE_V2,
        AuthenticatedParams { meta, body, auth },
    )
}

pub fn parse_group_create_request_v2(
    value: &Value,
) -> Result<(V2ServiceMetadata, V2GroupCreateBody, V2OriginAuth), GroupE2eeV2Error> {
    let request: RpcRequest<AuthenticatedParams<V2ServiceMetadata, V2GroupCreateBody>> =
        parse(value)?;
    require_method(&request.method, METHOD_GROUP_CREATE_V2)?;
    validate_create(
        &request.params.meta,
        &request.params.body,
        &request.params.auth,
    )?;
    Ok((
        request.params.meta,
        request.params.body,
        request.params.auth,
    ))
}

pub fn group_add_request_v2(
    meta: V2GroupControlMetadata,
    body: V2GroupAddBody,
    auth: V2OriginAuth,
) -> Result<Value, GroupE2eeV2Error> {
    validate_add(&meta, &body, &auth)?;
    request(
        METHOD_GROUP_ADD_V2,
        AuthenticatedParams { meta, body, auth },
    )
}

pub fn parse_group_add_request_v2(
    value: &Value,
) -> Result<(V2GroupControlMetadata, V2GroupAddBody, V2OriginAuth), GroupE2eeV2Error> {
    let request: RpcRequest<AuthenticatedParams<V2GroupControlMetadata, V2GroupAddBody>> =
        parse(value)?;
    require_method(&request.method, METHOD_GROUP_ADD_V2)?;
    validate_add(
        &request.params.meta,
        &request.params.body,
        &request.params.auth,
    )?;
    Ok((
        request.params.meta,
        request.params.body,
        request.params.auth,
    ))
}

pub fn group_remove_request_v2(
    meta: V2GroupControlMetadata,
    body: V2GroupRemoveBody,
    auth: V2OriginAuth,
) -> Result<Value, GroupE2eeV2Error> {
    validate_remove(&meta, &body, &auth)?;
    request(
        METHOD_GROUP_REMOVE_V2,
        AuthenticatedParams { meta, body, auth },
    )
}

pub fn parse_group_remove_request_v2(
    value: &Value,
) -> Result<(V2GroupControlMetadata, V2GroupRemoveBody, V2OriginAuth), GroupE2eeV2Error> {
    let request: RpcRequest<AuthenticatedParams<V2GroupControlMetadata, V2GroupRemoveBody>> =
        parse(value)?;
    require_method(&request.method, METHOD_GROUP_REMOVE_V2)?;
    validate_remove(
        &request.params.meta,
        &request.params.body,
        &request.params.auth,
    )?;
    Ok((
        request.params.meta,
        request.params.body,
        request.params.auth,
    ))
}

pub fn group_send_request_v2(
    meta: V2GroupSendMetadata,
    body: V2GroupCipherObject,
    auth: V2OriginAuth,
) -> Result<Value, GroupE2eeV2Error> {
    validate_send(&meta, &body, &auth)?;
    request(
        METHOD_GROUP_SEND_V2,
        AuthenticatedParams { meta, body, auth },
    )
}

pub fn parse_group_send_request_v2(
    value: &Value,
) -> Result<(V2GroupSendMetadata, V2GroupCipherObject, V2OriginAuth), GroupE2eeV2Error> {
    let request: RpcRequest<AuthenticatedParams<V2GroupSendMetadata, V2GroupCipherObject>> =
        parse(value)?;
    require_method(&request.method, METHOD_GROUP_SEND_V2)?;
    validate_send(
        &request.params.meta,
        &request.params.body,
        &request.params.auth,
    )?;
    Ok((
        request.params.meta,
        request.params.body,
        request.params.auth,
    ))
}

pub fn group_notice_notification_v2(
    meta: V2GroupNoticeMetadata,
    body: V2E2eeNotice,
) -> Result<Value, GroupE2eeV2Error> {
    validate_notice(&meta, &body)?;
    request(METHOD_GROUP_NOTICE_V2, Params { meta, body })
}

pub fn parse_group_notice_notification_v2(
    value: &Value,
) -> Result<(V2GroupNoticeMetadata, V2E2eeNotice), GroupE2eeV2Error> {
    let request: RpcRequest<Params<V2GroupNoticeMetadata, V2E2eeNotice>> = parse(value)?;
    require_method(&request.method, METHOD_GROUP_NOTICE_V2)?;
    validate_notice(&request.params.meta, &request.params.body)?;
    Ok((request.params.meta, request.params.body))
}

pub fn group_incoming_notification_v2(
    meta: V2GroupIncomingMetadata,
    body: V2GroupIncomingBody,
    auth: V2OriginAuth,
) -> Result<Value, GroupE2eeV2Error> {
    validate_incoming(&meta, &body, &auth)?;
    request(
        METHOD_GROUP_INCOMING_V2,
        AuthenticatedParams { meta, body, auth },
    )
}

pub fn parse_group_incoming_notification_v2(
    value: &Value,
) -> Result<(V2GroupIncomingMetadata, V2GroupIncomingBody, V2OriginAuth), GroupE2eeV2Error> {
    let request: RpcRequest<AuthenticatedParams<V2GroupIncomingMetadata, V2GroupIncomingBody>> =
        parse(value)?;
    require_method(&request.method, METHOD_GROUP_INCOMING_V2)?;
    validate_incoming(
        &request.params.meta,
        &request.params.body,
        &request.params.auth,
    )?;
    Ok((
        request.params.meta,
        request.params.body,
        request.params.auth,
    ))
}

pub fn parse_publish_key_package_result_v2(
    value: &Value,
) -> Result<V2PublishKeyPackageResult, GroupE2eeV2Error> {
    parse_result(value, V2PublishKeyPackageResult::validate)
}

pub fn parse_get_key_package_result_v2(
    value: &Value,
) -> Result<V2GetKeyPackageResult, GroupE2eeV2Error> {
    parse_result(value, V2GetKeyPackageResult::validate)
}

pub fn parse_group_create_result_v2(
    value: &Value,
) -> Result<V2GroupCreateResult, GroupE2eeV2Error> {
    parse_result(value, V2GroupCreateResult::validate)
}

pub fn parse_group_membership_result_v2(
    value: &Value,
) -> Result<V2GroupMembershipResult, GroupE2eeV2Error> {
    parse_result(value, V2GroupMembershipResult::validate)
}

pub fn parse_group_send_result_v2(value: &Value) -> Result<V2GroupSendResult, GroupE2eeV2Error> {
    parse_result(value, V2GroupSendResult::validate)
}

fn validate_publish(
    meta: &V2ServiceMetadata,
    body: &V2PublishKeyPackageBody,
) -> Result<(), GroupE2eeV2Error> {
    meta.validate(GROUP_E2EE_TRANSPORT_PROFILE_V2)?;
    body.group_key_package.validate_structure()?;
    if body.group_key_package.owner_did != meta.sender_did
        || body.group_key_package.owner_device_id != meta.sender_device_id
    {
        return Err(GroupE2eeV2Error::invalid(
            "published KeyPackage owner pair must equal sending device pair",
        ));
    }
    Ok(())
}

fn validate_get(
    meta: &V2ServiceMetadata,
    body: &V2GetKeyPackageBody,
) -> Result<(), GroupE2eeV2Error> {
    meta.validate(GROUP_E2EE_TRANSPORT_PROFILE_V2)?;
    body.validate()
}

fn validate_create(
    meta: &V2ServiceMetadata,
    body: &V2GroupCreateBody,
    auth: &V2OriginAuth,
) -> Result<(), GroupE2eeV2Error> {
    meta.validate(GROUP_E2EE_SECURITY_PROFILE_V2)?;
    body.validate()?;
    auth.validate()?;
    if body.creator_key_package.owner_did != meta.sender_did
        || body.creator_key_package.owner_device_id != meta.sender_device_id
    {
        return Err(GroupE2eeV2Error::invalid(
            "creator KeyPackage owner pair must equal sending owner device pair",
        ));
    }
    Ok(())
}

fn validate_add(
    meta: &V2GroupControlMetadata,
    body: &V2GroupAddBody,
    auth: &V2OriginAuth,
) -> Result<(), GroupE2eeV2Error> {
    meta.validate()?;
    body.validate()?;
    auth.validate()?;
    validate_group_target(&meta.target, &body.group_state_ref)
}

fn validate_remove(
    meta: &V2GroupControlMetadata,
    body: &V2GroupRemoveBody,
    auth: &V2OriginAuth,
) -> Result<(), GroupE2eeV2Error> {
    meta.validate()?;
    body.validate()?;
    auth.validate()?;
    validate_group_target(&meta.target, &body.group_state_ref)
}

fn validate_send(
    meta: &V2GroupSendMetadata,
    body: &V2GroupCipherObject,
    auth: &V2OriginAuth,
) -> Result<(), GroupE2eeV2Error> {
    meta.validate()?;
    body.validate()?;
    auth.validate()?;
    validate_group_target(&meta.target, &body.group_state_ref)
}

fn validate_notice(
    meta: &V2GroupNoticeMetadata,
    body: &V2E2eeNotice,
) -> Result<(), GroupE2eeV2Error> {
    meta.validate()?;
    body.validate()?;
    if body.notice_type == "welcome-delivery"
        && (meta.target.did != body.subject_did
            || meta.recipient_device_id != body.subject_device_id)
    {
        return Err(GroupE2eeV2Error::invalid(
            "welcome-delivery target must equal the added subject device pair",
        ));
    }
    Ok(())
}

fn validate_incoming(
    meta: &V2GroupIncomingMetadata,
    body: &V2GroupIncomingBody,
    auth: &V2OriginAuth,
) -> Result<(), GroupE2eeV2Error> {
    meta.validate()?;
    body.validate()?;
    auth.validate()
}

fn validate_group_target(
    target: &V2Target,
    state_ref: &V2GroupStateRef,
) -> Result<(), GroupE2eeV2Error> {
    if target.did == state_ref.group_did {
        Ok(())
    } else {
        Err(GroupE2eeV2Error::invalid(
            "meta.target.did must equal group_state_ref.group_did",
        ))
    }
}

fn request<P: Serialize>(method: &str, params: P) -> Result<Value, GroupE2eeV2Error> {
    Ok(serde_json::to_value(RpcRequest {
        method: method.to_owned(),
        params,
    })?)
}

fn parse<T: DeserializeOwned>(value: &Value) -> Result<T, GroupE2eeV2Error> {
    Ok(serde_json::from_value(value.clone())?)
}

fn parse_result<T, F>(value: &Value, validate: F) -> Result<T, GroupE2eeV2Error>
where
    T: DeserializeOwned,
    F: FnOnce(&T) -> Result<(), GroupE2eeV2Error>,
{
    let result = parse(value)?;
    validate(&result)?;
    Ok(result)
}

fn require_method(actual: &str, expected: &str) -> Result<(), GroupE2eeV2Error> {
    if actual == expected {
        Ok(())
    } else {
        Err(GroupE2eeV2Error::invalid(format!(
            "method must equal {expected}"
        )))
    }
}

fn validate_identifiers(fields: &[(&str, &String)]) -> Result<(), GroupE2eeV2Error> {
    for (field, value) in fields {
        require_non_empty(field, value)?;
    }
    Ok(())
}

fn validate_timestamp(field: &str, value: &str) -> Result<(), GroupE2eeV2Error> {
    DateTime::parse_from_rfc3339(value)
        .map(|_| ())
        .map_err(|_| GroupE2eeV2Error::invalid(format!("{field} must be RFC3339")))
}
