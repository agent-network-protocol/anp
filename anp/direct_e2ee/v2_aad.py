"""RFC 8785 AAD builders for device-qualified P5 v2 messages."""

import jcs

from .v2_errors import DirectE2eeV2Error
from .v2_models import (
    CONTENT_TYPE_DIRECT_CIPHER_V2,
    CONTENT_TYPE_DIRECT_INIT_V2,
    V2ApplicationPlaintext,
    V2DirectCipherBody,
    V2DirectInitBody,
    V2DirectMetadata,
)


def build_init_aad_v2(meta: V2DirectMetadata, body: V2DirectInitBody) -> bytes:
    meta.validate()
    body.validate()
    if meta.content_type != CONTENT_TYPE_DIRECT_INIT_V2:
        raise DirectE2eeV2Error("init AAD content_type mismatch")
    value = {
        "content_type": CONTENT_TYPE_DIRECT_INIT_V2,
        "message_id": meta.message_id,
        "operation_id": meta.operation_id,
        "profile": meta.profile,
        "security_profile": meta.security_profile,
        "sender_did": meta.sender_did,
        "sender_device_id": meta.sender_device_id,
        "recipient_did": meta.target.did,
        "recipient_device_id": meta.recipient_device_id,
        "suite": body.suite,
        "recipient_bundle_id": body.recipient_bundle_id,
        "sender_static_key_agreement_id": body.sender_static_key_agreement_id,
        "recipient_signed_prekey_id": body.recipient_signed_prekey_id,
        "session_id": body.session_id,
    }
    if body.recipient_one_time_prekey_id is not None:
        value["recipient_one_time_prekey_id"] = body.recipient_one_time_prekey_id
    return jcs.canonicalize(value)


def build_message_aad_v2(meta: V2DirectMetadata, body: V2DirectCipherBody) -> bytes:
    meta.validate()
    body.validate()
    if meta.content_type != CONTENT_TYPE_DIRECT_CIPHER_V2:
        raise DirectE2eeV2Error("message AAD content_type mismatch")
    return jcs.canonicalize(
        {
            "content_type": CONTENT_TYPE_DIRECT_CIPHER_V2,
            "message_id": meta.message_id,
            "operation_id": meta.operation_id,
            "profile": meta.profile,
            "security_profile": meta.security_profile,
            "sender_did": meta.sender_did,
            "sender_device_id": meta.sender_device_id,
            "recipient_did": meta.target.did,
            "recipient_device_id": meta.recipient_device_id,
            "session_id": body.session_id,
            "ratchet_header": body.ratchet_header.to_dict(),
        }
    )


def canonical_application_plaintext_v2(value: V2ApplicationPlaintext) -> bytes:
    value.validate()
    return jcs.canonicalize(value.to_dict())
