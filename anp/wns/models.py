"""WNS data models (Pydantic v2)."""

from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


ANP_HANDLE_SERVICE_TYPE = "ANPHandleService"


class HandleStatus(str, Enum):
    """Handle lifecycle status as defined in WNS spec section 4.7."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class SubjectType(str, Enum):
    """Recommended DID Subject Profile subject_type values."""

    PERSON = "person"
    AGENT = "agent"
    GROUP = "group"
    ORGANIZATION = "organization"
    SERVICE = "service"
    APPLICATION = "application"
    UNKNOWN = "unknown"


class DIDSubjectProfile(BaseModel):
    """Public presentational metadata for a DID subject.

    This model represents the optional WNS Handle Resolution Document
    ``profile`` object. It is UI metadata and must not be used for routing,
    authentication, authorization, service discovery, or E2EE binding.
    """

    type: Optional[str] = Field(
        default="DIDSubjectProfile",
        description="Profile object type, recommended to be DIDSubjectProfile",
    )
    subject_did: str = Field(description="DID subject described by this profile")
    subject_type: SubjectType = Field(
        default=SubjectType.UNKNOWN,
        description="Recommended DID subject type; missing means unknown",
    )
    handle: Optional[str] = Field(
        default=None, description="Handle corresponding to this profile"
    )
    display_name: Optional[str] = Field(default=None, description="UI display name")
    description: Optional[str] = Field(default=None, description="Profile description")
    avatar_uri: Optional[str] = Field(default=None, description="Avatar or icon URI")
    profile_uri: Optional[str] = Field(default=None, description="Public profile URI")
    discoverability: Optional[str] = Field(
        default=None, description="Discoverability hint"
    )
    labels: Optional[Dict[str, Any]] = Field(
        default=None, description="Non-security extension labels"
    )
    updated: Optional[str] = Field(
        default=None, description="Profile update time in ISO 8601 format"
    )
    versionId: Optional[str] = Field(
        default=None, description="Profile version identifier"
    )
    ttl: Optional[int] = Field(
        default=None, description="Suggested profile cache lifetime in seconds"
    )
    proof: Optional[Dict[str, Any]] = Field(
        default=None, description="Optional object-level assertion proof"
    )

    @field_validator("subject_type", mode="before")
    @classmethod
    def normalize_unknown_subject_type(cls, value: Any) -> Any:
        if value is None:
            return SubjectType.UNKNOWN
        if isinstance(value, SubjectType):
            return value
        try:
            return SubjectType(str(value).lower())
        except ValueError:
            return SubjectType.UNKNOWN


class HandleResolutionDocument(BaseModel):
    """JSON document returned by the Handle Resolution Endpoint.

    See WNS spec section 4.3.
    """

    handle: str = Field(description="Full handle identifier, e.g. alice.example.com")
    did: str = Field(description="The did:wba DID bound to this handle")
    status: HandleStatus = Field(description="Current handle status")
    updated: Optional[str] = Field(
        default=None, description="Last update time in ISO 8601 format"
    )
    versionId: Optional[str] = Field(
        default=None, description="Mapping version identifier"
    )
    ttl: Optional[int] = Field(
        default=None, description="Suggested cache lifetime in seconds"
    )
    profile: Optional[DIDSubjectProfile] = Field(
        default=None,
        description="Optional public DID Subject Profile for display only",
    )

    @model_validator(mode="before")
    @classmethod
    def drop_invalid_profile(cls, data: Any) -> Any:
        """Ignore invalid profile projections without failing handle resolution."""
        if not isinstance(data, dict):
            return data

        profile = data.get("profile")
        if not isinstance(profile, dict):
            return data

        did = data.get("did")
        handle = data.get("handle")
        profile_did = profile.get("subject_did")
        profile_handle = profile.get("handle")
        if profile_did != did or (
            profile_handle is not None and profile_handle != handle
        ):
            updated = dict(data)
            updated["profile"] = None
            return updated
        return data

    @model_validator(mode="after")
    def validate_profile_consistency(self) -> "HandleResolutionDocument":
        """Ensure profile projection matches the authoritative outer binding."""
        if self.profile is None:
            return self
        if self.profile.subject_did != self.did:
            self.profile = None
            return self
        if self.profile.handle is not None and self.profile.handle != self.handle:
            self.profile = None
        return self


class HandleServiceEntry(BaseModel):
    """DID Document service entry for reverse binding verification.

    See WNS spec section 6.2.
    """

    id: str = Field(description="Service unique identifier, e.g. did:wba:...#handle")
    type: str = Field(
        default=ANP_HANDLE_SERVICE_TYPE,
        description=f"Must be {ANP_HANDLE_SERVICE_TYPE}",
    )
    serviceEndpoint: str = Field(
        description=(
            "HTTPS URL under the Handle Provider domain used for reverse "
            "binding verification"
        )
    )


class ParsedWbaUri(BaseModel):
    """Result of parsing a wba:// URI."""

    local_part: str = Field(description="User identifier portion of the handle")
    domain: str = Field(description="Domain portion of the handle")
    handle: str = Field(description="Normalized full handle (local_part.domain)")
    original_uri: str = Field(description="Original wba:// URI before parsing")
