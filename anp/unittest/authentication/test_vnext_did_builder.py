"""Shared contract tests for the additive vNext DID document helpers."""

import copy
import datetime
import json
from pathlib import Path

import pytest

from anp.authentication import (
    DeviceManifestEntry,
    DeviceManifestError,
    add_device_to_did_document,
    build_vnext_did_document,
    remove_device_from_did_document,
    update_device_in_did_document,
    validate_device_manifest,
)

_FIXTURE_PATH = (
    Path(__file__).parents[3]
    / "testdata"
    / "device_manifest"
    / "vnext_did_builder_fixtures.json"
)


def _load_fixture():
    with _FIXTURE_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def _entry(device_fixture):
    value = device_fixture["entry"]
    return DeviceManifestEntry(
        device_id=value["device_id"],
        signing_key_id=value["signing_key_id"],
        e2ee_key_id=value["e2ee_key_id"],
        profiles=tuple(value["profiles"]),
    )


def _build(fixture):
    device = fixture["device_a"]
    return build_vnext_did_document(
        fixture["base_document"],
        fixture["root_key_id"],
        fixture["root_verification_method"],
        _entry(device),
        device["signing_verification_method"],
        device["e2ee_verification_method"],
    )


def test_shared_vnext_did_build_add_update_remove_vectors():
    fixture = _load_fixture()
    base_before = copy.deepcopy(fixture["base_document"])

    built = _build(fixture)
    assert built == fixture["expected_build"]
    assert fixture["base_document"] == base_before
    assert built["x-example"] == fixture["base_document"]["x-example"]

    with_stale_proof = {**built, "proof": {"proofValue": "stale"}}
    device_b = fixture["device_b"]
    added = add_device_to_did_document(
        with_stale_proof,
        fixture["root_key_id"],
        _entry(device_b),
        device_b["signing_verification_method"],
        device_b["e2ee_verification_method"],
        fixture["retired_device_ids"],
    )
    assert added == fixture["expected_add"]
    assert "proof" not in added
    assert "proof" in with_stale_proof

    rotated = fixture["device_b_rotated"]
    updated = update_device_in_did_document(
        added,
        fixture["root_key_id"],
        _entry(rotated),
        rotated["signing_verification_method"],
        rotated["e2ee_verification_method"],
    )
    assert updated == fixture["expected_update"]

    removed = remove_device_from_did_document(
        updated,
        fixture["root_key_id"],
        rotated["entry"]["device_id"],
    )
    assert removed == fixture["expected_remove"]
    assert removed["deviceManifest"]["devices"] == built["deviceManifest"]["devices"]
    assert validate_device_manifest(removed) is not None

    multikey_built = build_vnext_did_document(
        fixture["base_document"],
        fixture["root_key_id"],
        fixture["root_verification_method"],
        _entry(fixture["device_a"]),
        fixture["device_a"]["signing_verification_method"],
        fixture["x25519_multikey_verification_method"],
    )
    assert (
        multikey_built["verificationMethod"][2]
        == fixture["x25519_multikey_verification_method"]
    )


def test_vnext_builder_rejects_root_as_device_key_and_private_material():
    fixture = _load_fixture()
    device = copy.deepcopy(fixture["device_a"])
    device["entry"]["signing_key_id"] = fixture["root_key_id"]
    device["signing_verification_method"] = copy.deepcopy(
        fixture["root_verification_method"]
    )
    with pytest.raises(DeviceManifestError, match="root key"):
        build_vnext_did_document(
            fixture["base_document"],
            fixture["root_key_id"],
            fixture["root_verification_method"],
            _entry(device),
            device["signing_verification_method"],
            device["e2ee_verification_method"],
        )

    private_root = copy.deepcopy(fixture["root_verification_method"])
    private_root["publicKeyJwk"]["d"] = "PRIVATE"
    with pytest.raises(DeviceManifestError, match="private key"):
        build_vnext_did_document(
            fixture["base_document"],
            fixture["root_key_id"],
            private_root,
            _entry(fixture["device_a"]),
            fixture["device_a"]["signing_verification_method"],
            fixture["device_a"]["e2ee_verification_method"],
        )

    private_base = copy.deepcopy(fixture["base_document"])
    private_base["root_private_key"] = "PRIVATE"
    with pytest.raises(DeviceManifestError, match="private key"):
        build_vnext_did_document(
            private_base,
            fixture["root_key_id"],
            fixture["root_verification_method"],
            _entry(fixture["device_a"]),
            fixture["device_a"]["signing_verification_method"],
            fixture["device_a"]["e2ee_verification_method"],
        )


def test_vnext_mutation_rejects_duplicate_foreign_and_missing_relationship():
    fixture = _load_fixture()
    built = _build(fixture)
    device_a = fixture["device_a"]
    with pytest.raises(DeviceManifestError, match="already exists"):
        add_device_to_did_document(
            built,
            fixture["root_key_id"],
            _entry(device_a),
            device_a["signing_verification_method"],
            device_a["e2ee_verification_method"],
            fixture["retired_device_ids"],
        )

    foreign = copy.deepcopy(fixture["device_b"])
    foreign["signing_verification_method"]["controller"] = "did:example:other"
    with pytest.raises(DeviceManifestError, match="controller"):
        add_device_to_did_document(
            built,
            fixture["root_key_id"],
            _entry(foreign),
            foreign["signing_verification_method"],
            foreign["e2ee_verification_method"],
            fixture["retired_device_ids"],
        )

    missing_relationship = copy.deepcopy(built)
    missing_relationship["keyAgreement"] = []
    with pytest.raises(DeviceManifestError, match="keyAgreement"):
        add_device_to_did_document(
            missing_relationship,
            fixture["root_key_id"],
            _entry(fixture["device_b"]),
            fixture["device_b"]["signing_verification_method"],
            fixture["device_b"]["e2ee_verification_method"],
            fixture["retired_device_ids"],
        )


@pytest.mark.parametrize("case", _load_fixture()["invalid_public_key_cases"])
def test_shared_invalid_public_key_cases(case):
    fixture = _load_fixture()
    root = fixture["root_verification_method"]
    signing = fixture["device_a"]["signing_verification_method"]
    e2ee = fixture["device_a"]["e2ee_verification_method"]
    if case["role"] == "root":
        root = case["verification_method"]
    elif case["role"] == "device_signing":
        signing = case["verification_method"]
    else:
        e2ee = case["verification_method"]
    with pytest.raises(DeviceManifestError):
        build_vnext_did_document(
            fixture["base_document"],
            fixture["root_key_id"],
            root,
            _entry(fixture["device_a"]),
            signing,
            e2ee,
        )


@pytest.mark.parametrize("case", _load_fixture()["duplicate_key_material_cases"])
def test_shared_duplicate_key_material_cases(case):
    fixture = _load_fixture()
    if case["operation"] == "build":
        with pytest.raises(DeviceManifestError, match="unique"):
            build_vnext_did_document(
                fixture["base_document"],
                fixture["root_key_id"],
                case["root_verification_method"],
                _entry(fixture["device_a"]),
                fixture["device_a"]["signing_verification_method"],
                fixture["device_a"]["e2ee_verification_method"],
            )
        return

    device_b = fixture["device_b"]
    with pytest.raises(DeviceManifestError, match="unique"):
        add_device_to_did_document(
            _build(fixture),
            fixture["root_key_id"],
            _entry(device_b),
            case.get(
                "signing_verification_method",
                device_b["signing_verification_method"],
            ),
            case.get(
                "e2ee_verification_method",
                device_b["e2ee_verification_method"],
            ),
            fixture["retired_device_ids"],
        )


@pytest.mark.parametrize("case", _load_fixture()["invalid_relationship_cases"])
def test_shared_invalid_relationship_cases(case):
    fixture = _load_fixture()
    document = _build(fixture)
    document[case["relationship"]].append(case["key_id"])
    with pytest.raises(DeviceManifestError):
        add_device_to_did_document(
            document,
            fixture["root_key_id"],
            _entry(fixture["device_b"]),
            fixture["device_b"]["signing_verification_method"],
            fixture["device_b"]["e2ee_verification_method"],
            fixture["retired_device_ids"],
        )


def test_retired_device_id_and_removed_relationship_cleanup():
    fixture = _load_fixture()
    device_b = fixture["device_b"]
    added = add_device_to_did_document(
        _build(fixture),
        fixture["root_key_id"],
        _entry(device_b),
        device_b["signing_verification_method"],
        device_b["e2ee_verification_method"],
        fixture["retired_device_ids"],
    )
    old_ids = {
        device_b["entry"]["signing_key_id"],
        device_b["entry"]["e2ee_key_id"],
    }
    added["authentication"].append(device_b["entry"]["signing_key_id"])
    added["assertionMethod"].append(device_b["entry"]["signing_key_id"])
    added["keyAgreement"].append(device_b["entry"]["e2ee_key_id"])
    rotated = fixture["device_b_rotated"]
    updated = update_device_in_did_document(
        added,
        fixture["root_key_id"],
        _entry(rotated),
        rotated["signing_verification_method"],
        rotated["e2ee_verification_method"],
    )
    for relationship in ("authentication", "assertionMethod", "keyAgreement"):
        assert not any(
            entry in old_ids or isinstance(entry, dict) and entry.get("id") in old_ids
            for entry in updated[relationship]
        )

    removed = remove_device_from_did_document(
        added, fixture["root_key_id"], device_b["entry"]["device_id"]
    )
    with pytest.raises(DeviceManifestError, match="retired"):
        add_device_to_did_document(
            removed,
            fixture["root_key_id"],
            _entry(device_b),
            device_b["signing_verification_method"],
            device_b["e2ee_verification_method"],
            [device_b["entry"]["device_id"]],
        )


@pytest.mark.parametrize(
    "invalid_value",
    [
        datetime.datetime.now(datetime.timezone.utc),
        object(),
        lambda: None,
        float("nan"),
        float("inf"),
        float("-inf"),
    ],
)
def test_vnext_builder_rejects_non_json_values(invalid_value):
    fixture = _load_fixture()
    base = copy.deepcopy(fixture["base_document"])
    base["x-invalid"] = invalid_value
    with pytest.raises(DeviceManifestError, match="JSON|finite"):
        build_vnext_did_document(
            base,
            fixture["root_key_id"],
            fixture["root_verification_method"],
            _entry(fixture["device_a"]),
            fixture["device_a"]["signing_verification_method"],
            fixture["device_a"]["e2ee_verification_method"],
        )
