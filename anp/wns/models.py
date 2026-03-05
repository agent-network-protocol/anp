"""WNS data models (Pydantic v2)."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class HandleStatus(str, Enum):
    """Handle lifecycle status as defined in WNS spec section 4.7."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


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


class HandleServiceEntry(BaseModel):
    """DID Document service entry for reverse binding verification.

    See WNS spec section 6.2.
    """

    id: str = Field(description="Service unique identifier, e.g. did:wba:...#handle")
    type: str = Field(default="HandleService", description="Must be HandleService")
    serviceEndpoint: str = Field(
        description="URL pointing to Handle Resolution Endpoint"
    )


class ParsedWbaUri(BaseModel):
    """Result of parsing a wba:// URI."""

    local_part: str = Field(description="User identifier portion of the handle")
    domain: str = Field(description="Domain portion of the handle")
    handle: str = Field(description="Normalized full handle (local_part.domain)")
    original_uri: str = Field(description="Original wba:// URI before parsing")
