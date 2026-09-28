"""ANP-06 error table (spec section 11) and the matching exception type."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional


@dataclass(frozen=True)
class MetaNegotiationErrorCode:
    """One row of the ANP-06 error table."""

    code: int
    anp_code: str
    message: str


NEGOTIATION_REJECTED = MetaNegotiationErrorCode(
    1600, "meta.negotiation_rejected", "Negotiation rejected"
)
NO_MATCHING_INTERFACE = MetaNegotiationErrorCode(
    1601, "meta.no_matching_interface", "No matching interface"
)
UNSUPPORTED_NEGOTIATION_MODE = MetaNegotiationErrorCode(
    1602, "meta.unsupported_negotiation_mode", "Unsupported negotiation mode"
)
UNSUPPORTED_CANDIDATE_PROFILE = MetaNegotiationErrorCode(
    1603, "meta.unsupported_candidate_profile", "Unsupported candidate profile"
)
UNSUPPORTED_SECURITY_PROFILE = MetaNegotiationErrorCode(
    1604, "meta.unsupported_security_profile", "Unsupported security profile"
)
UNSUPPORTED_CONTENT_TYPE = MetaNegotiationErrorCode(
    1605, "meta.unsupported_content_type", "Unsupported content type"
)
MORE_INFORMATION_REQUIRED = MetaNegotiationErrorCode(
    1606, "meta.more_information_required", "More information required"
)
AUTHORIZATION_REQUIRED = MetaNegotiationErrorCode(
    1607, "meta.authorization_required", "Authorization required"
)
NEGOTIATION_EXPIRED = MetaNegotiationErrorCode(
    1608, "meta.negotiation_expired", "Negotiation expired"
)

META_NEGOTIATION_ERRORS = (
    NEGOTIATION_REJECTED,
    NO_MATCHING_INTERFACE,
    UNSUPPORTED_NEGOTIATION_MODE,
    UNSUPPORTED_CANDIDATE_PROFILE,
    UNSUPPORTED_SECURITY_PROFILE,
    UNSUPPORTED_CONTENT_TYPE,
    MORE_INFORMATION_REQUIRED,
    AUTHORIZATION_REQUIRED,
    NEGOTIATION_EXPIRED,
)

_BY_CODE = {entry.code: entry for entry in META_NEGOTIATION_ERRORS}


def meta_negotiation_error(code: int) -> Optional[MetaNegotiationErrorCode]:
    """Looks up an ANP-06 error table row by JSON-RPC code."""
    return _BY_CODE.get(code)


class MetaNegotiationError(Exception):
    """An ANP-06 negotiation failure that maps onto a JSON-RPC error object.

    Args:
        error: Row of the ANP-06 error table.
        message: Optional override for the JSON-RPC ``message``.
        retryable: Value for ``error.data.retryable``.
        details: Optional ``error.data.details`` object.
    """

    def __init__(
        self,
        error: MetaNegotiationErrorCode,
        message: Optional[str] = None,
        *,
        retryable: bool = False,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.error = error
        self.message = message or error.message
        self.retryable = retryable
        self.details = details
        super().__init__(self.message)

    @property
    def code(self) -> int:
        return self.error.code

    @property
    def anp_code(self) -> str:
        return self.error.anp_code

    def to_jsonrpc_error(self) -> Dict[str, Any]:
        """Builds the JSON-RPC ``error`` member for this failure."""
        data: Dict[str, Any] = {
            "anp_code": self.anp_code,
            "retryable": self.retryable,
        }
        if self.details is not None:
            data["details"] = self.details
        return {"code": self.code, "message": self.message, "data": data}

    @classmethod
    def from_jsonrpc_error(
        cls, error: Mapping[str, Any]
    ) -> Optional["MetaNegotiationError"]:
        """Parses a JSON-RPC ``error`` member.

        Returns:
            The parsed error, or ``None`` when the code is not an ANP-06 code
            (for example a plain JSON-RPC -32602).
        """
        entry = meta_negotiation_error(error.get("code"))
        if entry is None:
            return None
        data = error.get("data")
        data = data if isinstance(data, Mapping) else {}
        details = data.get("details")
        return cls(
            entry,
            error.get("message") or None,
            retryable=data.get("retryable") is True,
            details=dict(details) if isinstance(details, Mapping) else None,
        )

    def __repr__(self) -> str:
        return f"MetaNegotiationError({self.code}, {self.anp_code!r}, {self.message!r})"
