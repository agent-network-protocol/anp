"""DID Web Handle evidence retains the actual HTTPS provider declaration."""

from unittest.mock import AsyncMock, patch

import pytest

from anp.wns.binding import verify_handle_binding
from anp.wns.models import HandleResolutionDocument, HandleStatus


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "returned_did,endpoint,valid",
    [
        (
            "did:web:identity.example:users:alice",
            "https://example.com/providers/wns",
            True,
        ),
        (
            "did:web:identity.example:users:alice",
            "https://identity.example/providers/wns",
            False,
        ),
        (
            "did:web:identity.example:users:alice",
            "http://example.com/providers/wns",
            False,
        ),
        ("did:web:other.example", "https://example.com/providers/wns", False),
    ],
)
async def test_web_handle_binding(returned_did, endpoint, valid):
    forward = HandleResolutionDocument(
        handle="alice.example.com",
        did="did:web:identity.example:users:alice",
        status=HandleStatus.ACTIVE,
        binding_generation="8",
    )
    document = {
        "id": returned_did,
        "service": [
            {
                "id": returned_did + "#handle",
                "type": "ANPHandleService",
                "serviceEndpoint": endpoint,
            }
        ],
    }
    with patch("anp.wns.binding.resolve_handle", AsyncMock(return_value=forward)):
        result = await verify_handle_binding("alice.example.com", did_document=document)
    assert result.is_valid == valid
    assert (result.binding_generation is not None) == valid
