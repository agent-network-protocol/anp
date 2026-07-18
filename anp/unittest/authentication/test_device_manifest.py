"""Shared contract tests for the ANP vNext Device Manifest."""

import copy
import json
from pathlib import Path

import pytest

from anp.authentication import (
    DeviceManifestError,
    find_eligible_device,
    parse_device_manifest,
    validate_device_manifest,
)


_FIXTURE_PATH = (
    Path(__file__).resolve().parents[3]
    / "testdata"
    / "device_manifest"
    / "vnext_device_manifest_fixtures.json"
)


def _load_fixtures():
    with _FIXTURE_PATH.open(encoding="utf-8") as fixture_file:
        return json.load(fixture_file)


def _build_document(fixtures, case):
    document = copy.deepcopy(fixtures["base_did_document"])
    document.update(copy.deepcopy(case.get("document_patch", {})))
    document["deviceManifest"] = copy.deepcopy(case["device_manifest"])
    return document


@pytest.mark.parametrize("case", _load_fixtures()["valid"], ids=lambda c: c["name"])
def test_valid_shared_device_manifest_fixture(case):
    fixtures = _load_fixtures()
    document = _build_document(fixtures, case)
    before = copy.deepcopy(document)

    parsed = parse_device_manifest(document)
    assert parsed is not None
    assert parsed.to_dict() == case["device_manifest"]
    assert validate_device_manifest(document) == parsed

    lookup = case["lookup"]
    device = find_eligible_device(
        document,
        lookup["device_id"],
        lookup["profile"],
    )
    assert (device is not None) is lookup["found"]
    assert document == before
    assert document["x-fixture-extension"]["must_survive_validation"] is True


@pytest.mark.parametrize(
    "case", _load_fixtures()["invalid"], ids=lambda c: c["name"]
)
def test_invalid_shared_device_manifest_fixture(case):
    fixtures = _load_fixtures()
    document = _build_document(fixtures, case)
    with pytest.raises(DeviceManifestError):
        validate_device_manifest(document)


def test_manifest_absence_is_valid_and_does_not_create_a_default_device():
    fixtures = _load_fixtures()
    document = copy.deepcopy(fixtures["base_did_document"])
    assert parse_device_manifest(document) is None
    assert validate_device_manifest(document) is None
    assert find_eligible_device(
        document,
        "dev-a-7N3KQ2",
        "anp.direct.e2ee.v2",
    ) is None
