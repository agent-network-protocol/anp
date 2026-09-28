"""Wire models for ANP-06 ``anp.meta.negotiation.v1``.

Field names follow the spec exactly, including its mix of ``negotiation_id``
in the request body and camelCase elsewhere. Every model keeps unknown members
so extension fields survive a parse/serialize round trip. Parsing is strict:
wrong JSON types are rejected instead of coerced.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Mapping, Optional, TypeVar, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pydantic.alias_generators import to_camel

META_NEGOTIATION_PROFILE = "anp.meta.negotiation.v1"
NEGOTIATE_METHOD = "anp.negotiate"
META_PROTOCOL_INTERFACE_TYPE = "MetaProtocolInterface"
JSONRPC_BINDING = "jsonrpc-2.0"

MODE_STRUCTURED_SELECTION = "structured_selection"
MODE_NATURAL_LANGUAGE_PROTOCOL_DRAFTING = "natural_language_protocol_drafting"
DEFAULT_NEGOTIATION_MODE = MODE_STRUCTURED_SELECTION

STATUS_ACCEPTED = "accepted"
STATUS_REJECTED = "rejected"
STATUS_NEEDS_MORE_INFORMATION = "needs_more_information"
NegotiationStatus = Literal["accepted", "rejected", "needs_more_information"]

# Common values from sections 5.3 and 8.4. The spec treats both lists as open,
# so the models accept other strings too.
NEGOTIABLE_OBJECTS = (
    "profiles",
    "interfaces",
    "schemas",
    "security_profiles",
    "content_types",
    "execution_modes",
    "protocol_artifacts",
)
EXECUTION_MODES = (
    "direct_structured_call",
    "direct_message",
    "group_message",
    "async_task",
    "stream",
    "natural_language",
    "natural_language_protocol_drafting",
)

_M = TypeVar("_M", bound="MetaNegotiationModel")


def _parse_rfc3339(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if "T" not in value or parsed.tzinfo is None:
        raise ValueError("must be an RFC 3339 timestamp with a timezone")
    return parsed


class MetaNegotiationModel(BaseModel):
    """Base for ANP-06 wire objects."""

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        extra="allow",
        strict=True,
    )

    @classmethod
    def from_dict(cls: type[_M], value: Mapping[str, Any]) -> _M:
        """Parses a wire object, raising ``pydantic.ValidationError`` if invalid."""
        return cls.model_validate(value)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes to wire JSON, omitting unset optional members."""
        return self.model_dump(by_alias=True, exclude_none=True, mode="json")


class MetaProtocolInterface(MetaNegotiationModel):
    """Agent Description ``interfaces`` entry declaring ANP-06 support (section 5)."""

    type: Literal["MetaProtocolInterface"] = META_PROTOCOL_INTERFACE_TYPE
    profile: Literal["anp.meta.negotiation.v1"] = META_NEGOTIATION_PROFILE
    binding: str = JSONRPC_BINDING
    url: str
    methods: List[str] = Field(default_factory=lambda: [NEGOTIATE_METHOD])
    id: Optional[str] = None
    protocol: Optional[str] = None
    version: Optional[str] = None
    security: Optional[Union[str, List[str]]] = None
    security_profiles: Optional[List[str]] = None
    negotiates: Optional[List[str]] = None
    input_schema: Optional[str] = None
    output_schema: Optional[str] = None
    description: Optional[str] = None

    @field_validator("methods")
    @classmethod
    def _requires_negotiate(cls, methods: List[str]) -> List[str]:
        if NEGOTIATE_METHOD not in methods:
            raise ValueError(f"methods must include {NEGOTIATE_METHOD}")
        return methods


class Intent(MetaNegotiationModel):
    """What the caller wants to accomplish (section 7.4)."""

    name: Optional[str] = None
    description: Optional[str] = None
    intent_tags: Optional[List[str]] = None
    input_summary: Optional[Dict[str, Any]] = None


class CallerCapabilities(MetaNegotiationModel):
    """Runtime capabilities the caller declares (section 7.5)."""

    supported_profiles: Optional[List[str]] = None
    supported_security_profiles: Optional[List[str]] = None
    supported_content_types: Optional[List[str]] = None
    supported_execution_modes: Optional[List[str]] = None
    limits: Optional[Dict[str, Any]] = None


class NegotiationConstraints(MetaNegotiationModel):
    """Caller preferences and hard requirements (section 7.6)."""

    preferred_interface_types: Optional[List[str]] = None
    requires_human_authorization: Optional[bool] = None
    max_latency_ms: Optional[int] = Field(default=None, ge=0)
    allow_natural_language_fallback: Optional[bool] = None
    required_security_profile: Optional[str] = None
    preferred_content_types: Optional[List[str]] = None


class NegotiateRequestBody(MetaNegotiationModel):
    """``params.body`` of an ``anp.negotiate`` request (section 7.3).

    ``mode`` stays a free string so a server can answer an unknown mode with
    ``meta.unsupported_negotiation_mode`` instead of a parse error.
    """

    intent: Intent
    negotiation_id: Optional[str] = Field(default=None, alias="negotiation_id")
    mode: Optional[str] = None
    required_capabilities: Optional[List[str]] = None
    caller_capabilities: Optional[CallerCapabilities] = None
    constraints: Optional[NegotiationConstraints] = None
    candidate_interface_refs: Optional[List[str]] = None
    candidate_protocols: Optional[List[Union[str, Dict[str, Any]]]] = None

    @property
    def effective_mode(self) -> str:
        """The requested mode, or the spec default when omitted."""
        return self.mode or DEFAULT_NEGOTIATION_MODE


class SelectedPath(MetaNegotiationModel):
    """``result.selected``: the path for the business interaction (section 8.3)."""

    capability: Optional[str] = None
    interface: Optional[str] = None
    protocol: Optional[str] = None
    profile: Optional[str] = None
    security_profile: Optional[str] = None
    content_type: Optional[str] = None
    url: Optional[str] = None
    protocol_artifact: Optional[str] = None


class ExecutionPlan(MetaNegotiationModel):
    """``result.execution`` (section 8.4)."""

    mode: Optional[str] = None
    requires_human_authorization: Optional[bool] = None
    timeout_ms: Optional[int] = Field(default=None, ge=0)


class NegotiationSchemas(MetaNegotiationModel):
    """``result.schemas``."""

    request_schema: Optional[str] = None
    response_schema: Optional[str] = None


class NegotiationResult(MetaNegotiationModel):
    """``result`` of a successful ``anp.negotiate`` call (section 8).

    A result is a description of how to proceed, not an authorization to
    perform the business action (section 12.2).
    """

    negotiation_id: str
    status: NegotiationStatus
    selected: Optional[SelectedPath] = None
    execution: Optional[ExecutionPlan] = None
    schemas: Optional[NegotiationSchemas] = None
    valid_until: Optional[str] = None
    negotiation_digest: Optional[str] = None
    alternatives: Optional[List[Dict[str, Any]]] = None
    reason: Optional[str] = None

    @field_validator("valid_until")
    @classmethod
    def _valid_until_is_rfc3339(cls, value: Optional[str]) -> Optional[str]:
        if value is not None:
            _parse_rfc3339(value)
        return value

    @model_validator(mode="after")
    def _accepted_needs_selection(self) -> "NegotiationResult":
        if self.status == STATUS_ACCEPTED and self.selected is None:
            raise ValueError("selected is required when status is accepted")
        return self

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        """Whether ``validUntil`` has passed. Results without it never expire here."""
        if self.valid_until is None:
            return False
        now = now or datetime.now(timezone.utc)
        return now >= _parse_rfc3339(self.valid_until)
