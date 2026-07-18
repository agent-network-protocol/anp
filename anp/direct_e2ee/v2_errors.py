"""Normative error allocations for ANP P5 v2."""

from dataclasses import dataclass


@dataclass(frozen=True)
class DirectE2eeV2ProtocolError:
    code: int
    anp_code: str


DIRECT_E2EE_V2_ERRORS = (
    DirectE2eeV2ProtocolError(4000, "anp.direct.e2ee.bundle_not_found"),
    DirectE2eeV2ProtocolError(4001, "anp.direct.e2ee.bundle_invalid"),
    DirectE2eeV2ProtocolError(4002, "anp.direct.e2ee.bundle_expired"),
    DirectE2eeV2ProtocolError(4003, "anp.direct.e2ee.opk_unavailable"),
    DirectE2eeV2ProtocolError(4004, "anp.direct.e2ee.missing_key_agreement"),
    DirectE2eeV2ProtocolError(4005, "anp.direct.e2ee.session_not_found"),
    DirectE2eeV2ProtocolError(4006, "anp.direct.e2ee.session_conflict"),
    DirectE2eeV2ProtocolError(4007, "anp.direct.e2ee.bad_init_message"),
    DirectE2eeV2ProtocolError(4008, "anp.direct.e2ee.replay_detected"),
    DirectE2eeV2ProtocolError(4009, "anp.direct.e2ee.decrypt_failed"),
    DirectE2eeV2ProtocolError(4010, "anp.direct.e2ee.max_skip_exceeded"),
    DirectE2eeV2ProtocolError(4011, "anp.direct.e2ee.reset_required"),
    DirectE2eeV2ProtocolError(4012, "anp.direct.e2ee.invalid_security_binding"),
)


class DirectE2eeV2Error(ValueError):
    """Raised when a P5 v2 wire object violates the frozen contract."""


def direct_e2ee_v2_error(code: int) -> DirectE2eeV2ProtocolError | None:
    return next((entry for entry in DIRECT_E2EE_V2_ERRORS if entry.code == code), None)
