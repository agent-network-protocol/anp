"""System test for the complete e1 DID-WBA authentication flow."""

import asyncio

from examples.python.did_wba_examples.e1_authenticate_and_verify import run_demo
from examples.python.did_wba_examples.validate_did_document import (
    validate_did_document,
)


def test_e1_http_signature_exchange_and_bearer_reuse():
    """The generated e1 identity should authenticate and reuse its token."""
    result = asyncio.run(run_demo(verbose=False))

    assert result["did"].split(":")[-1].startswith("e1_")
    assert "Signature-Input" in result["signature_headers"]
    assert "Signature" in result["signature_headers"]
    assert result["first_result"]["auth_scheme"] == "http_signatures"
    assert result["first_result"]["did"] == result["did"]
    assert result["bearer_headers"]["Authorization"].startswith("Bearer ")
    assert result["bearer_result"]["auth_scheme"] == "bearer"
    assert result["bearer_result"]["did"] == result["did"]
    validate_did_document(result["did_document"])
