"""Public-only Web device lifecycle and purpose boundaries shared across SDKs."""

import copy
import json
from pathlib import Path

import pytest
from anp.authentication import validate_did_document_method

from anp.authentication.device_manifest import (
    DeviceManifestEntry,
    DeviceManifestError,
    validate_device_manifest,
    build_web_did_document,
    add_device_to_web_did_document,
    remove_device_from_web_did_document,
    find_eligible_device,
)

FIXTURE = json.loads(
    (Path(__file__).parents[3] / "fixtures/did-method-lifecycle-v1.json").read_text()
)
MANAGED = {
    "verificationMethod",
    "authentication",
    "assertionMethod",
    "keyAgreement",
    "deviceManifest",
    "proof",
}


def test_rootless_web_build_join_revoke():
    single = FIXTURE["documents"]["web_single_device"]
    base = {key: value for key, value in single.items() if key not in MANAGED}
    first = DeviceManifestEntry(**single["deviceManifest"]["devices"][0])
    built = build_web_did_document(base, first, *single["verificationMethod"])
    assert built == single
    signed = copy.deepcopy(built)
    signed["proof"] = {"stale": "must disappear from mutated copy"}
    second = DeviceManifestEntry(**FIXTURE["device_b"])
    joined = add_device_to_web_did_document(
        signed, second, *FIXTURE["device_b_verification_methods"], []
    )
    assert joined == FIXTURE["documents"]["web_two_devices"]
    assert "proof" in signed  # Caller input is not mutated.
    assert remove_device_from_web_did_document(joined, "device-b") == single
    with pytest.raises(DeviceManifestError, match="retired"):
        add_device_to_web_did_document(
            single, second, *FIXTURE["device_b_verification_methods"], ["device-b"]
        )


@pytest.mark.parametrize(
    "name", ["web_single_device", "web_two_devices", "wba_two_devices"]
)
def test_current_p6_manifest(name):
    assert validate_device_manifest(FIXTURE["documents"][name]) is not None
    assert validate_did_document_method(FIXTURE["documents"][name], verify_proof=True)


@pytest.mark.parametrize("name", ["web_api", "web_group_assertion_only"])
def test_non_device_web_does_not_require_manifest(name):
    assert validate_device_manifest(FIXTURE["documents"][name]) is None


@pytest.mark.parametrize(
    "failure",
    ["private", "purpose", "duplicate-material", "wrong-method", "dependency"],
)
def test_web_mutation_keeps_validation(failure):
    document = copy.deepcopy(FIXTURE["documents"]["web_two_devices"])
    if failure == "private":
        document["verificationMethod"][0]["privateKeyMultibase"] = "not-public"
    elif failure == "purpose":
        document["authentication"] = []
    elif failure == "duplicate-material":
        document["verificationMethod"][2]["publicKeyMultibase"] = document[
            "verificationMethod"
        ][0]["publicKeyMultibase"]
    elif failure == "wrong-method":
        document = copy.deepcopy(FIXTURE["documents"]["wba_two_devices"])
    else:
        document["deviceManifest"]["devices"][0]["profiles"].remove(
            "anp.core.binding.v1"
        )
    with pytest.raises(DeviceManifestError):
        remove_device_from_web_did_document(document, "device-b")


def test_web_e2ee_lookup_checks_key_algorithm():
    document = copy.deepcopy(FIXTURE["documents"]["web_single_device"])
    assert find_eligible_device(document, "device-a", "anp.direct.e2ee.v2") is not None
    document["verificationMethod"][0]["publicKeyMultibase"] = document[
        "verificationMethod"
    ][1]["publicKeyMultibase"]
    with pytest.raises(DeviceManifestError):
        find_eligible_device(document, "device-a", "anp.direct.e2ee.v2")


def test_current_wba_multibase_proof_protects_context():
    document = copy.deepcopy(FIXTURE["documents"]["wba_two_devices"])
    assert validate_did_document_method(document, verify_proof=True)
    document["@context"].append("https://changed.example/context")
    assert not validate_did_document_method(document, verify_proof=True)
