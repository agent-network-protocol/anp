"""Shared wire-contract tests for ANP P5 v2."""

import copy
import json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from anp.authentication import create_did_wba_document
from anp.direct_e2ee.v2_aad import (
    build_init_aad_v2,
    build_message_aad_v2,
    canonical_application_plaintext_v2,
)
from anp.direct_e2ee.v2_bundle import (
    build_prekey_bundle_v2,
    signed_bundle_object_jcs_v2,
    verify_prekey_bundle_v2,
)
from anp.direct_e2ee.v2_errors import (
    DIRECT_E2EE_V2_ERRORS,
    direct_e2ee_v2_error,
)
from anp.direct_e2ee.v2_models import (
    MTI_DIRECT_E2EE_SUITE_V2,
    V2ApplicationPlaintext,
    V2DirectCipherBody,
    V2DirectInitBody,
    V2PrekeyBundle,
    V2SignedPrekey,
)
from anp.direct_e2ee.v2_wire import (
    direct_send_request_v2,
    get_prekey_bundle_request_v2,
    parse_direct_send_request_v2,
    parse_direct_send_result_v2,
    parse_get_prekey_bundle_request_v2,
    parse_get_prekey_bundle_result_v2,
    parse_publish_prekey_bundle_request_v2,
    parse_publish_prekey_bundle_result_v2,
    publish_prekey_bundle_request_v2,
)
from anp.proof import (
    CRYPTOSUITE_EDDSA_JCS_2022,
    PROOF_TYPE_DATA_INTEGRITY,
    generate_w3c_proof,
)


@pytest.fixture(scope="module")
def vectors() -> dict:
    path = Path(__file__).parents[3] / "testdata/direct_e2ee/p5_v2_wire_vectors.json"
    return json.loads(path.read_text())


def test_shared_bundle_and_rpc_vectors(vectors: dict) -> None:
    bundle = V2PrekeyBundle.from_dict(vectors["prekey_bundle"])
    assert (
        signed_bundle_object_jcs_v2(bundle).decode()
        == vectors["expected_signed_bundle_object_jcs"]
    )

    meta, parsed, opks = parse_publish_prekey_bundle_request_v2(
        vectors["publish_request"]
    )
    assert (
        publish_prekey_bundle_request_v2(meta, parsed, opks)
        == vectors["publish_request"]
    )
    meta, body = parse_get_prekey_bundle_request_v2(vectors["get_request"])
    assert get_prekey_bundle_request_v2(meta, **body) == vectors["get_request"]

    assert parse_publish_prekey_bundle_result_v2(vectors["publish_result"])
    assert parse_get_prekey_bundle_result_v2(vectors["get_result"])
    assert parse_direct_send_result_v2(vectors["direct_send_result"])

    invalid = copy.deepcopy(vectors["get_result"])
    invalid["target_device_id"] = "dev-sibling"
    with pytest.raises(ValueError):
        parse_get_prekey_bundle_result_v2(invalid)
    invalid = copy.deepcopy(vectors["direct_send_result"])
    invalid["operation_id"] = "different-operation"
    with pytest.raises(ValueError):
        parse_direct_send_result_v2(invalid)
    invalid = copy.deepcopy(vectors["publish_result"])
    invalid["unexpected"] = True
    with pytest.raises(ValueError):
        parse_publish_prekey_bundle_result_v2(invalid)


def test_shared_signed_bundle_golden_verifies(vectors: dict) -> None:
    golden = vectors["signed_bundle_golden"]
    bundle = V2PrekeyBundle.from_dict(golden["prekey_bundle"])
    verify_prekey_bundle_v2(
        bundle,
        golden["did_document"],
        datetime.fromisoformat(golden["now"].replace("Z", "+00:00")),
    )
    tampered = copy.deepcopy(golden["prekey_bundle"])
    tampered["signed_prekey"]["key_id"] = "spk-tampered"
    with pytest.raises(ValueError):
        verify_prekey_bundle_v2(
            V2PrekeyBundle.from_dict(tampered),
            golden["did_document"],
            datetime.fromisoformat(golden["now"].replace("Z", "+00:00")),
        )


def test_shared_aad_and_plaintext_vectors(vectors: dict) -> None:
    meta, body = parse_direct_send_request_v2(vectors["direct_init_request"])
    assert isinstance(body, V2DirectInitBody)
    assert build_init_aad_v2(meta, body).decode() == vectors["expected_ad_init"]
    assert direct_send_request_v2(meta, body) == vectors["direct_init_request"]

    meta, body = parse_direct_send_request_v2(vectors["direct_cipher_request"])
    assert isinstance(body, V2DirectCipherBody)
    assert build_message_aad_v2(meta, body).decode() == vectors["expected_ad_msg"]
    plaintext = V2ApplicationPlaintext.from_dict(vectors["application_plaintext"])
    assert (
        canonical_application_plaintext_v2(plaintext).decode()
        == vectors["expected_application_plaintext_jcs"]
    )
    numeric = V2ApplicationPlaintext.from_dict(
        vectors["application_plaintext_numeric"]
    )
    assert (
        canonical_application_plaintext_v2(numeric).decode()
        == vectors["expected_application_plaintext_numeric_jcs"]
    )


def test_device_tamper_changes_aad_and_forbidden_outer_fields_fail(
    vectors: dict,
) -> None:
    request = copy.deepcopy(vectors["direct_init_request"])
    request["params"]["meta"]["recipient_device_id"] = "dev-sibling"
    meta, body = parse_direct_send_request_v2(request)
    assert isinstance(body, V2DirectInitBody)
    assert build_init_aad_v2(meta, body).decode() != vectors["expected_ad_init"]

    request = copy.deepcopy(vectors["direct_init_request"])
    request["params"]["meta"]["sender_device_id"] = "dev-sender-sibling"
    meta, body = parse_direct_send_request_v2(request)
    assert isinstance(body, V2DirectInitBody)
    assert build_init_aad_v2(meta, body).decode() != vectors["expected_ad_init"]

    for field in ("auth", "deliveries", "root_private_key", "document_version"):
        invalid = copy.deepcopy(vectors["direct_init_request"])
        invalid["params"][field] = {}
        with pytest.raises(ValueError):
            parse_direct_send_request_v2(invalid)
    invalid = copy.deepcopy(vectors["direct_init_request"])
    invalid["params"]["meta"]["logical_message_id"] = "outer-logical"
    with pytest.raises(ValueError):
        parse_direct_send_request_v2(invalid)
    invalid = copy.deepcopy(vectors["direct_init_request"])
    invalid["params"]["meta"]["operation_id"] = "different-id"
    with pytest.raises(ValueError):
        parse_direct_send_request_v2(invalid)


def test_publish_rejects_explicit_empty_opks_and_bad_public_key(vectors: dict) -> None:
    invalid = copy.deepcopy(vectors["publish_request"])
    invalid["params"]["body"]["one_time_prekeys"] = []
    with pytest.raises(ValueError):
        parse_publish_prekey_bundle_request_v2(invalid)


def test_v2_rejects_explicit_nulls_and_invalid_plaintext_bindings(
    vectors: dict,
) -> None:
    invalid = copy.deepcopy(vectors["direct_init_request"])
    invalid["params"]["body"]["recipient_one_time_prekey_id"] = None
    with pytest.raises(ValueError):
        parse_direct_send_request_v2(invalid)

    for field, value in (("preferred_suite", None), ("require_opk", None)):
        invalid = copy.deepcopy(vectors["get_request"])
        invalid["params"]["body"][field] = value
        with pytest.raises(ValueError):
            parse_get_prekey_bundle_request_v2(invalid)
    invalid = copy.deepcopy(vectors["get_request"])
    invalid["params"]["body"]["require_opk"] = "true"
    with pytest.raises(ValueError):
        parse_get_prekey_bundle_request_v2(invalid)

    for plaintext in (
        {"application_content_type": "text/plain", "payload": {}},
        {"application_content_type": "application/json", "text": "wrong"},
        {
            "application_content_type": "application/json",
            "annotations": [],
            "payload": {},
        },
        {
            "application_content_type": "application/json",
            "annotations": None,
            "payload": {},
        },
    ):
        with pytest.raises(ValueError):
            V2ApplicationPlaintext.from_dict(plaintext)
    invalid = copy.deepcopy(vectors["publish_request"])
    invalid["params"]["body"]["prekey_bundle"]["signed_prekey"]["public_key_b64u"] = (
        "AA=="
    )
    with pytest.raises(ValueError):
        parse_publish_prekey_bundle_request_v2(invalid)


def test_shared_invalid_wire_encodings_are_rejected(vectors: dict) -> None:
    invalid_values = vectors["encoding_negative_values"]
    cases = (
        ("direct_init_request", ("params", "body", "session_id"), "session_id"),
        (
            "direct_init_request",
            ("params", "body", "sender_ephemeral_pub_b64u"),
            "x25519_public_key",
        ),
        (
            "direct_init_request",
            ("params", "body", "ciphertext_b64u"),
            "ciphertext_b64u",
        ),
        (
            "direct_cipher_request",
            ("params", "body", "ratchet_header", "dh_pub_b64u"),
            "x25519_public_key",
        ),
        (
            "direct_cipher_request",
            ("params", "meta", "created_at"),
            "created_at",
        ),
    )
    for request_name, path, value_name in cases:
        request = copy.deepcopy(vectors[request_name])
        target = request
        for field in path[:-1]:
            target = target[field]
        target[path[-1]] = invalid_values[value_name]
        with pytest.raises(ValueError):
            parse_direct_send_request_v2(request)

    with pytest.raises(ValueError):
        V2ApplicationPlaintext.from_dict(
            {
                "application_content_type": "application/octet-stream",
                "payload_b64u": invalid_values["payload_b64u"],
            }
        )


def test_optional_outer_meta_never_enters_aad(vectors: dict) -> None:
    meta, body = parse_direct_send_request_v2(vectors["direct_init_request"])
    assert isinstance(body, V2DirectInitBody)
    original = build_init_aad_v2(meta, body)
    changed = replace(meta, anp_version="9.9", created_at="2030-01-01T00:00:00Z")
    assert build_init_aad_v2(changed, body) == original


def test_error_table_is_exact(vectors: dict) -> None:
    assert len(vectors["errors"]) == len(DIRECT_E2EE_V2_ERRORS) == 13
    for expected in vectors["errors"]:
        assert direct_e2ee_v2_error(expected["code"]).anp_code == expected["anp_code"]
    assert direct_e2ee_v2_error(5000) is None


def test_bundle_object_proof_covers_device_and_static_fields() -> None:
    document, keys = create_did_wba_document(
        "bundle-v2.example", path_segments=["agents", "alice"]
    )
    did = document["id"]
    unsigned_document = {
        key: value for key, value in document.items() if key != "proof"
    }
    unsigned_document["deviceManifest"] = {
        "type": "ANPDeviceManifest",
        "devices": [
            {
                "device_id": "dev-a",
                "signing_key_id": f"{did}#key-1",
                "e2ee_key_id": f"{did}#key-3",
                "profiles": [
                    "anp.core.binding.v2",
                    "anp.identity.discovery.v2",
                    "anp.direct.base.v2",
                    "anp.direct.e2ee.v2",
                ],
            }
        ],
    }
    signing_key = serialization.load_pem_private_key(keys["key-1"][0], password=None)
    document = generate_w3c_proof(
        unsigned_document,
        signing_key,
        f"{did}#key-1",
        proof_type=PROOF_TYPE_DATA_INTEGRITY,
        cryptosuite=CRYPTOSUITE_EDDSA_JCS_2022,
        created="2026-07-19T00:00:00Z",
    )
    bundle = build_prekey_bundle_v2(
        "bundle-v2",
        did,
        "dev-a",
        f"{did}#key-3",
        V2SignedPrekey(
            key_id="spk-v2",
            public_key_b64u="UKYUCbHd0DJemxa3AOcZ6XcsBwALG9d4bpB8ZT0gSV0",
            expires_at="2035-01-01T00:00:00Z",
        ),
        signing_key,
        f"{did}#key-1",
        "2026-07-19T00:00:00Z",
    )
    with pytest.raises(ValueError):
        build_prekey_bundle_v2(
            "bundle-invalid",
            did,
            "dev-a",
            f"{did}#key-3",
            V2SignedPrekey(
                key_id="spk-invalid",
                public_key_b64u="AA==",
                expires_at="not-rfc3339",
            ),
            signing_key,
            f"{did}#key-1",
            "2026-07-19T00:00:00Z",
        )
    verify_prekey_bundle_v2(
        bundle, document, datetime(2026, 7, 19, tzinfo=timezone.utc)
    )
    with pytest.raises(ValueError):
        verify_prekey_bundle_v2(
            replace(bundle, owner_device_id="dev-sibling"),
            document,
            datetime(2026, 7, 19, tzinfo=timezone.utc),
        )
    with pytest.raises(ValueError):
        verify_prekey_bundle_v2(
            replace(bundle, suite=MTI_DIRECT_E2EE_SUITE_V2 + "-tampered"),
            document,
            datetime(2026, 7, 19, tzinfo=timezone.utc),
        )
