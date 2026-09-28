"""Tests for the ANP-06 error table."""

import pytest

from anp.meta_negotiation import (
    META_NEGOTIATION_ERRORS,
    NO_MATCHING_INTERFACE,
    UNSUPPORTED_SECURITY_PROFILE,
    MetaNegotiationError,
    meta_negotiation_error,
)

# ANP-06 section 11
SPEC_TABLE = {
    1600: "meta.negotiation_rejected",
    1601: "meta.no_matching_interface",
    1602: "meta.unsupported_negotiation_mode",
    1603: "meta.unsupported_candidate_profile",
    1604: "meta.unsupported_security_profile",
    1605: "meta.unsupported_content_type",
    1606: "meta.more_information_required",
    1607: "meta.authorization_required",
    1608: "meta.negotiation_expired",
}


def test_table_matches_spec():
    assert {e.code: e.anp_code for e in META_NEGOTIATION_ERRORS} == SPEC_TABLE


@pytest.mark.parametrize("code, anp_code", SPEC_TABLE.items())
def test_lookup_by_code(code, anp_code):
    assert meta_negotiation_error(code).anp_code == anp_code


def test_lookup_unknown_code():
    assert meta_negotiation_error(-32602) is None


def test_serializes_like_spec_example():
    error = MetaNegotiationError(
        NO_MATCHING_INTERFACE,
        details={"unsupportedConstraints": ["requiredSecurityProfile"]},
    )
    assert error.to_jsonrpc_error() == {
        "code": 1601,
        "message": "No matching interface",
        "data": {
            "anp_code": "meta.no_matching_interface",
            "retryable": False,
            "details": {"unsupportedConstraints": ["requiredSecurityProfile"]},
        },
    }


def test_omits_details_when_unset():
    data = MetaNegotiationError(UNSUPPORTED_SECURITY_PROFILE).to_jsonrpc_error()["data"]
    assert "details" not in data


def test_parses_jsonrpc_error():
    wire = MetaNegotiationError(
        UNSUPPORTED_SECURITY_PROFILE,
        "direct-e2ee is not available",
        retryable=True,
        details={"required": "direct-e2ee"},
    ).to_jsonrpc_error()

    parsed = MetaNegotiationError.from_jsonrpc_error(wire)

    assert parsed.error is UNSUPPORTED_SECURITY_PROFILE
    assert parsed.message == "direct-e2ee is not available"
    assert parsed.retryable is True
    assert parsed.details == {"required": "direct-e2ee"}
    assert parsed.to_jsonrpc_error() == wire


def test_parses_error_without_data():
    parsed = MetaNegotiationError.from_jsonrpc_error({"code": 1600, "message": ""})
    assert parsed.anp_code == "meta.negotiation_rejected"
    assert parsed.message == "Negotiation rejected"
    assert parsed.retryable is False


def test_non_meta_error_is_not_parsed():
    assert (
        MetaNegotiationError.from_jsonrpc_error(
            {"code": -32602, "message": "Invalid params"}
        )
        is None
    )
