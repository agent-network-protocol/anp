"""Construction and strict parsing of P5 v2 JSON-RPC objects."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Union

from .v2_bundle import parse_one_time_prekeys
from .v2_errors import DirectE2eeV2Error
from .v2_models import (
    CONTENT_TYPE_DIRECT_CIPHER_V2,
    CONTENT_TYPE_DIRECT_INIT_V2,
    V2DirectCipherBody,
    V2DirectInitBody,
    V2DirectMetadata,
    V2KeyServiceMetadata,
    V2OneTimePrekey,
    V2PrekeyBundle,
)

V2DirectBody = Union[V2DirectInitBody, V2DirectCipherBody]


def _result_fields(
    value: Mapping[str, Any], required: set[str], optional: set[str], subject: str
) -> None:
    if not required.issubset(value) or not set(value).issubset(required | optional):
        raise DirectE2eeV2Error(f"invalid fields in {subject}")


def _result_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise DirectE2eeV2Error(f"{field} must be a non-empty string")
    return value


def _result_time(value: Any, field: str) -> str:
    text = _result_text(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DirectE2eeV2Error(f"{field} must be RFC3339") from exc
    if "T" not in text or parsed.tzinfo is None:
        raise DirectE2eeV2Error(f"{field} must be RFC3339")
    return text


@dataclass(frozen=True)
class V2PublishPrekeyBundleResult:
    published: bool
    owner_did: str
    owner_device_id: str
    bundle_id: str
    published_at: str
    published_opk_count: int | None = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "V2PublishPrekeyBundleResult":
        _result_fields(
            value,
            {"published", "owner_did", "owner_device_id", "bundle_id", "published_at"},
            {"published_opk_count"},
            "publish result",
        )
        if value["published"] is not True:
            raise DirectE2eeV2Error("published must be true in a successful result")
        published_opk_count = value.get("published_opk_count")
        if published_opk_count is not None and (
            isinstance(published_opk_count, bool)
            or not isinstance(published_opk_count, int)
            or published_opk_count < 0
        ):
            raise DirectE2eeV2Error(
                "published_opk_count must be a non-negative integer"
            )
        return cls(
            published=True,
            owner_did=_result_text(value["owner_did"], "owner_did"),
            owner_device_id=_result_text(value["owner_device_id"], "owner_device_id"),
            bundle_id=_result_text(value["bundle_id"], "bundle_id"),
            published_at=_result_time(value["published_at"], "published_at"),
            published_opk_count=published_opk_count,
        )


@dataclass(frozen=True)
class V2GetPrekeyBundleResult:
    target_did: str
    target_device_id: str
    prekey_bundle: V2PrekeyBundle
    one_time_prekey: V2OneTimePrekey | None = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "V2GetPrekeyBundleResult":
        _result_fields(
            value,
            {"target_did", "target_device_id", "prekey_bundle"},
            {"one_time_prekey"},
            "get result",
        )
        target_did = _result_text(value["target_did"], "target_did")
        target_device_id = _result_text(value["target_device_id"], "target_device_id")
        if not isinstance(value["prekey_bundle"], Mapping):
            raise DirectE2eeV2Error("prekey_bundle must be an object")
        bundle = V2PrekeyBundle.from_dict(value["prekey_bundle"])
        if bundle.owner_did != target_did or bundle.owner_device_id != target_device_id:
            raise DirectE2eeV2Error(
                "get result target must equal the returned bundle owner"
            )
        raw_opk = value.get("one_time_prekey")
        if raw_opk is not None and not isinstance(raw_opk, Mapping):
            raise DirectE2eeV2Error("one_time_prekey must be an object")
        return cls(
            target_did=target_did,
            target_device_id=target_device_id,
            prekey_bundle=bundle,
            one_time_prekey=(
                V2OneTimePrekey.from_dict(raw_opk) if raw_opk is not None else None
            ),
        )


@dataclass(frozen=True)
class V2DirectSendResult:
    accepted: bool
    message_id: str
    operation_id: str
    target_did: str
    recipient_device_id: str
    accepted_at: str

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "V2DirectSendResult":
        _result_fields(
            value,
            {
                "accepted",
                "message_id",
                "operation_id",
                "target_did",
                "recipient_device_id",
                "accepted_at",
            },
            set(),
            "direct.send result",
        )
        if value["accepted"] is not True:
            raise DirectE2eeV2Error("accepted must be true in a successful result")
        message_id = _result_text(value["message_id"], "message_id")
        operation_id = _result_text(value["operation_id"], "operation_id")
        if operation_id != message_id:
            raise DirectE2eeV2Error("result.operation_id must equal result.message_id")
        return cls(
            accepted=True,
            message_id=message_id,
            operation_id=operation_id,
            target_did=_result_text(value["target_did"], "target_did"),
            recipient_device_id=_result_text(
                value["recipient_device_id"], "recipient_device_id"
            ),
            accepted_at=_result_time(value["accepted_at"], "accepted_at"),
        )


def parse_publish_prekey_bundle_result_v2(
    value: Mapping[str, Any],
) -> V2PublishPrekeyBundleResult:
    return V2PublishPrekeyBundleResult.from_dict(value)


def parse_get_prekey_bundle_result_v2(
    value: Mapping[str, Any],
) -> V2GetPrekeyBundleResult:
    return V2GetPrekeyBundleResult.from_dict(value)


def parse_direct_send_result_v2(value: Mapping[str, Any]) -> V2DirectSendResult:
    return V2DirectSendResult.from_dict(value)


def _request(value: Mapping[str, Any], method: str) -> Mapping[str, Any]:
    if set(value) != {"method", "params"} or value.get("method") != method:
        raise DirectE2eeV2Error(f"request method must equal {method}")
    params = value.get("params")
    if not isinstance(params, dict) or set(params) != {"meta", "body"}:
        raise DirectE2eeV2Error("params must contain only meta and body")
    return params


def publish_prekey_bundle_request_v2(
    meta: V2KeyServiceMetadata,
    bundle: V2PrekeyBundle,
    one_time_prekeys: tuple[V2OneTimePrekey, ...] = (),
) -> dict[str, Any]:
    meta.validate()
    bundle.validate_structure()
    for opk in one_time_prekeys:
        opk.validate()
    if (
        bundle.owner_did != meta.sender_did
        or bundle.owner_device_id != meta.sender_device_id
    ):
        raise DirectE2eeV2Error("published bundle owner must equal sending device")
    body: dict[str, Any] = {"prekey_bundle": bundle.to_dict()}
    if one_time_prekeys:
        body["one_time_prekeys"] = [entry.to_dict() for entry in one_time_prekeys]
    return {
        "method": "direct.e2ee.publish_prekey_bundle",
        "params": {"meta": meta.to_dict(), "body": body},
    }


def parse_publish_prekey_bundle_request_v2(
    value: Mapping[str, Any],
) -> tuple[V2KeyServiceMetadata, V2PrekeyBundle, tuple[V2OneTimePrekey, ...]]:
    params = _request(value, "direct.e2ee.publish_prekey_bundle")
    meta = V2KeyServiceMetadata.from_dict(params["meta"])
    body = params["body"]
    if (
        not isinstance(body, dict)
        or not {"prekey_bundle"}.issubset(body)
        or not set(body).issubset({"prekey_bundle", "one_time_prekeys"})
    ):
        raise DirectE2eeV2Error("invalid publish body")
    if "one_time_prekeys" in body and body["one_time_prekeys"] is None:
        raise DirectE2eeV2Error(
            "one_time_prekeys must be omitted rather than null"
        )
    bundle = V2PrekeyBundle.from_dict(body["prekey_bundle"])
    opks = parse_one_time_prekeys(body.get("one_time_prekeys"))
    publish_prekey_bundle_request_v2(meta, bundle, opks)
    return meta, bundle, opks


def get_prekey_bundle_request_v2(
    meta: V2KeyServiceMetadata,
    target_did: str,
    target_device_id: str,
    preferred_suite: str | None = None,
    require_opk: bool | None = None,
) -> dict[str, Any]:
    meta.validate()
    if not target_did or not target_device_id:
        raise DirectE2eeV2Error("get request requires exact target DID/device")
    body: dict[str, Any] = {
        "target_did": target_did,
        "target_device_id": target_device_id,
    }
    if preferred_suite is not None:
        if not isinstance(preferred_suite, str) or not preferred_suite:
            raise DirectE2eeV2Error("preferred_suite must be a non-empty string")
        body["preferred_suite"] = preferred_suite
    if require_opk is not None:
        if not isinstance(require_opk, bool):
            raise DirectE2eeV2Error("require_opk must be a boolean")
        body["require_opk"] = require_opk
    return {
        "method": "direct.e2ee.get_prekey_bundle",
        "params": {"meta": meta.to_dict(), "body": body},
    }


def parse_get_prekey_bundle_request_v2(
    value: Mapping[str, Any],
) -> tuple[V2KeyServiceMetadata, dict[str, Any]]:
    params = _request(value, "direct.e2ee.get_prekey_bundle")
    meta = V2KeyServiceMetadata.from_dict(params["meta"])
    body = params["body"]
    required, optional = (
        {"target_did", "target_device_id"},
        {"preferred_suite", "require_opk"},
    )
    if (
        not isinstance(body, dict)
        or not required.issubset(body)
        or not set(body).issubset(required | optional)
    ):
        raise DirectE2eeV2Error("invalid get body")
    for field in optional.intersection(body):
        if body[field] is None:
            raise DirectE2eeV2Error(
                f"get body.{field} must be omitted rather than null"
            )
    rebuilt = get_prekey_bundle_request_v2(meta, **body)
    return meta, rebuilt["params"]["body"]


def direct_send_request_v2(
    meta: V2DirectMetadata, body: V2DirectBody
) -> dict[str, Any]:
    meta.validate()
    body.validate()
    expected = (
        CONTENT_TYPE_DIRECT_INIT_V2
        if isinstance(body, V2DirectInitBody)
        else CONTENT_TYPE_DIRECT_CIPHER_V2
    )
    if meta.content_type != expected:
        raise DirectE2eeV2Error("direct body/content_type mismatch")
    return {
        "method": "direct.send",
        "params": {"meta": meta.to_dict(), "body": body.to_dict()},
    }


def parse_direct_send_request_v2(
    value: Mapping[str, Any],
) -> tuple[V2DirectMetadata, V2DirectBody]:
    params = _request(value, "direct.send")
    meta = V2DirectMetadata.from_dict(params["meta"])
    body = (
        V2DirectInitBody.from_dict(params["body"])
        if meta.content_type == CONTENT_TYPE_DIRECT_INIT_V2
        else V2DirectCipherBody.from_dict(params["body"])
    )
    direct_send_request_v2(meta, body)
    return meta, body
