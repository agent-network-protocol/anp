"""Wire model tests for ANP-06, using the examples from the spec text."""

import copy
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from anp.meta_negotiation import (
    DEFAULT_NEGOTIATION_MODE,
    META_NEGOTIATION_PROFILE,
    MetaProtocolInterface,
    NegotiateRequestBody,
    NegotiationResult,
    SelectedPath,
)

# ANP-06 section 5.4
INTERFACE = {
    "id": "interface.negotiation.default",
    "type": "MetaProtocolInterface",
    "protocol": "ANP",
    "version": "1.0",
    "profile": "anp.meta.negotiation.v1",
    "binding": "jsonrpc-2.0",
    "url": "https://grand-hotel.com/anp",
    "methods": ["anp.get_capabilities", "anp.negotiate"],
    "security": ["didwba_sc"],
    "securityProfiles": ["transport-protected"],
    "negotiates": [
        "profiles",
        "interfaces",
        "schemas",
        "security_profiles",
        "content_types",
        "execution_modes",
    ],
    "description": (
        "Semantic meta-protocol negotiation interface for selecting the best "
        "execution interface."
    ),
}

# ANP-06 section 7.2, params.body
REQUEST_BODY = {
    "negotiation_id": "neg-20260627-001",
    "mode": "structured_selection",
    "intent": {
        "name": "book_hotel_room",
        "description": "Book a hotel room for two people next Friday.",
        "intentTags": ["hotel.booking", "reservation.create"],
    },
    "requiredCapabilities": ["cap.hotel.booking"],
    "callerCapabilities": {
        "supportedProfiles": [
            "anp.core.binding.v1",
            "anp.direct.base.v1",
            "anp.rpc.v1",
        ],
        "supportedSecurityProfiles": ["transport-protected", "direct-e2ee"],
        "supportedContentTypes": ["application/json", "text/plain"],
    },
    "constraints": {
        "preferredInterfaceTypes": [
            "StructuredInterface",
            "NaturalLanguageInterface",
        ],
        "requiresHumanAuthorization": True,
        "maxLatencyMs": 3000,
        "allowNaturalLanguageFallback": True,
    },
    "candidateInterfaceRefs": [
        "interface.booking.structured.v1",
        "interface.conversation.nl.v1",
    ],
}

# ANP-06 section 8.1, result
RESULT = {
    "negotiationId": "neg-20260627-001",
    "status": "accepted",
    "selected": {
        "capability": "cap.hotel.booking",
        "interface": "interface.booking.structured.v1",
        "protocol": "openrpc",
        "profile": "anp.rpc.v1",
        "securityProfile": "transport-protected",
        "contentType": "application/json",
        "url": "https://grand-hotel.com/api/booking.openrpc.json",
    },
    "execution": {
        "mode": "direct_structured_call",
        "requiresHumanAuthorization": True,
        "timeoutMs": 3000,
    },
    "schemas": {
        "requestSchema": "https://grand-hotel.com/schemas/create-booking-request.schema.json",
        "responseSchema": "https://grand-hotel.com/schemas/create-booking-response.schema.json",
    },
    "validUntil": "2026-06-27T12:10:05Z",
    "negotiationDigest": "sha-256:BASE64URL_DIGEST",
}


class TestMetaProtocolInterface:
    def test_spec_example_round_trips(self):
        parsed = MetaProtocolInterface.from_dict(INTERFACE)
        assert parsed.security_profiles == ["transport-protected"]
        assert parsed.to_dict() == INTERFACE

    def test_minimal_declaration_fills_fixed_fields(self):
        declared = MetaProtocolInterface(url="https://example.com/anp")
        assert declared.to_dict() == {
            "type": "MetaProtocolInterface",
            "profile": META_NEGOTIATION_PROFILE,
            "binding": "jsonrpc-2.0",
            "url": "https://example.com/anp",
            "methods": ["anp.negotiate"],
        }

    def test_accepts_single_security_reference(self):
        value = dict(INTERFACE, security="didwba_sc")
        assert MetaProtocolInterface.from_dict(value).security == "didwba_sc"

    @pytest.mark.parametrize(
        "field, value",
        [
            ("type", "StructuredInterface"),
            ("profile", "anp.meta.negotiation.v2"),
            ("methods", ["anp.get_capabilities"]),
        ],
    )
    def test_rejects_wrong_fixed_values(self, field, value):
        with pytest.raises(ValidationError):
            MetaProtocolInterface.from_dict(dict(INTERFACE, **{field: value}))

    def test_requires_url(self):
        value = {k: v for k, v in INTERFACE.items() if k != "url"}
        with pytest.raises(ValidationError):
            MetaProtocolInterface.from_dict(value)

    def test_keeps_extension_members(self):
        value = dict(INTERFACE, **{"x-vendor": {"region": "cn"}})
        assert MetaProtocolInterface.from_dict(value).to_dict() == value


class TestNegotiateRequestBody:
    def test_spec_example_round_trips(self):
        parsed = NegotiateRequestBody.from_dict(REQUEST_BODY)
        assert parsed.negotiation_id == "neg-20260627-001"
        assert parsed.intent.intent_tags == ["hotel.booking", "reservation.create"]
        assert parsed.constraints.max_latency_ms == 3000
        assert parsed.caller_capabilities.supported_security_profiles == [
            "transport-protected",
            "direct-e2ee",
        ]
        assert parsed.to_dict() == REQUEST_BODY

    def test_negotiation_id_stays_snake_case_on_the_wire(self):
        body = NegotiateRequestBody(
            negotiation_id="neg-1", intent={"name": "book_hotel_room"}
        )
        assert body.to_dict() == {
            "negotiation_id": "neg-1",
            "intent": {"name": "book_hotel_room"},
        }

    def test_intent_is_required(self):
        value = {k: v for k, v in REQUEST_BODY.items() if k != "intent"}
        with pytest.raises(ValidationError):
            NegotiateRequestBody.from_dict(value)

    def test_mode_defaults_when_omitted(self):
        value = {k: v for k, v in REQUEST_BODY.items() if k != "mode"}
        assert NegotiateRequestBody.from_dict(value).effective_mode == (
            DEFAULT_NEGOTIATION_MODE
        )

    def test_unknown_mode_is_left_for_the_server_to_reject(self):
        value = dict(REQUEST_BODY, mode="consensus_vote")
        assert NegotiateRequestBody.from_dict(value).effective_mode == "consensus_vote"

    def test_candidate_protocols_accept_uris_and_artifacts(self):
        artifact = {"protocol_id": "example.product-info.v1", "version": "1.0"}
        value = dict(
            REQUEST_BODY,
            candidateProtocols=["https://example.com/protocols/x/1.0", artifact],
        )
        assert NegotiateRequestBody.from_dict(value).to_dict() == value

    @pytest.mark.parametrize(
        "path, bad",
        [
            (("constraints", "maxLatencyMs"), "3000"),
            (("constraints", "maxLatencyMs"), -1),
            (("constraints", "requiresHumanAuthorization"), "yes"),
            (("intent", "intentTags"), "hotel.booking"),
            (("callerCapabilities", "supportedProfiles"), [1, 2]),
        ],
    )
    def test_rejects_wrong_types(self, path, bad):
        value = copy.deepcopy(REQUEST_BODY)
        value[path[0]][path[1]] = bad
        with pytest.raises(ValidationError):
            NegotiateRequestBody.from_dict(value)


class TestNegotiationResult:
    def test_spec_example_round_trips(self):
        parsed = NegotiationResult.from_dict(RESULT)
        assert parsed.selected.security_profile == "transport-protected"
        assert parsed.execution.timeout_ms == 3000
        assert parsed.to_dict() == RESULT

    def test_accepted_requires_selected(self):
        value = {k: v for k, v in RESULT.items() if k != "selected"}
        with pytest.raises(ValidationError):
            NegotiationResult.from_dict(value)

    @pytest.mark.parametrize("status", ["rejected", "needs_more_information"])
    def test_other_statuses_need_no_selection(self, status):
        value = {"negotiationId": "neg-1", "status": status, "reason": "no slot"}
        assert NegotiationResult.from_dict(value).to_dict() == value

    def test_rejects_unknown_status(self):
        with pytest.raises(ValidationError):
            NegotiationResult.from_dict(dict(RESULT, status="ok"))

    def test_requires_negotiation_id(self):
        value = {k: v for k, v in RESULT.items() if k != "negotiationId"}
        with pytest.raises(ValidationError):
            NegotiationResult.from_dict(value)

    @pytest.mark.parametrize(
        "valid_until", ["2026-06-27", "2026-06-27T12:10:05", "tomorrow"]
    )
    def test_rejects_bad_valid_until(self, valid_until):
        with pytest.raises(ValidationError):
            NegotiationResult.from_dict(dict(RESULT, validUntil=valid_until))

    def test_is_expired(self):
        result = NegotiationResult.from_dict(RESULT)
        before = datetime(2026, 6, 27, 12, 10, 4, tzinfo=timezone.utc)
        after = datetime(2026, 6, 27, 12, 10, 5, tzinfo=timezone.utc)
        assert not result.is_expired(before)
        assert result.is_expired(after)

    def test_without_valid_until_never_expires(self):
        value = {k: v for k, v in RESULT.items() if k != "validUntil"}
        assert not NegotiationResult.from_dict(value).is_expired()

    def test_built_in_code_serializes_with_spec_names(self):
        result = NegotiationResult(
            negotiation_id="neg-1",
            status="accepted",
            selected=SelectedPath(
                interface="interface.booking.structured.v1",
                security_profile="direct-e2ee",
            ),
        )
        assert result.to_dict() == {
            "negotiationId": "neg-1",
            "status": "accepted",
            "selected": {
                "interface": "interface.booking.structured.v1",
                "securityProfile": "direct-e2ee",
            },
        }
