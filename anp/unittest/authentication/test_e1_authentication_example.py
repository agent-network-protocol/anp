"""Unit tests for the current e1 authentication example."""

import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from anp.authentication import create_did_wba_document
from anp.authentication.did_wba import validate_did_document_binding
from examples.python.did_wba_examples.e1_authenticate_and_verify import (
    create_e1_identity,
)
from examples.python.did_wba_examples.validate_did_document import (
    validate_did_document,
)


def test_create_e1_identity_writes_strongly_bound_authentication_material(
    tmp_path,
):
    """The example should create an e1 document and its Ed25519 auth key."""
    did_document, did_document_path, private_key_path = create_e1_identity(tmp_path)

    assert ":e1_" in did_document["id"]
    assert did_document["proof"]["type"] == "DataIntegrityProof"
    assert did_document["proof"]["cryptosuite"] == "eddsa-jcs-2022"
    assert validate_did_document_binding(did_document)
    assert json.loads(did_document_path.read_text(encoding="utf-8")) == did_document

    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(),
        password=None,
    )
    assert isinstance(private_key, ed25519.Ed25519PrivateKey)
    assert did_document["authentication"] == [f'{did_document["id"]}#key-1']


def test_current_validation_example_rejects_legacy_profiles():
    """The streamlined validation example should focus only on e1 DIDs."""
    legacy_document, _ = create_did_wba_document(
        hostname="example.com",
        path_segments=["agents", "legacy"],
        did_profile="k1",
    )

    with pytest.raises(ValueError, match="requires an e1 DID identifier"):
        validate_did_document(legacy_document)
