"""Example: Verify bidirectional binding between a Handle and a DID.

Usage:
    uv run python examples/python/wns_examples/verify_binding.py
"""

import asyncio

from anp.wns import (
    build_handle_service_entry,
    verify_handle_binding,
)


async def main():
    handle = "alice.example.com"

    # 1. Build an ANPHandleService entry (for inclusion in a DID Document)
    did = "did:wba:example.com:user:alice"
    entry = build_handle_service_entry(did, "alice", "example.com")
    print("ANPHandleService entry for DID Document:")
    import json

    print(json.dumps(entry, indent=2))

    # 2. Verify bidirectional binding (requires real providers)
    print(f"\nVerifying binding for '{handle}' ...")
    result = await verify_handle_binding(handle)
    print(f"  is_valid:          {result.is_valid}")
    print(f"  forward_verified:  {result.forward_verified}")
    print(f"  reverse_verified:  {result.reverse_verified}")
    if result.error_message:
        print(f"  error:             {result.error_message}")

    # 3. Verify with a pre-fetched DID Document
    print("\nVerifying with a provided DID Document ...")
    did_document = {
        "id": did,
        "service": [
            {
                "id": f"{did}#handle",
                "type": "ANPHandleService",
                "serviceEndpoint": "https://example.com/providers/wns",
            }
        ],
    }
    result = await verify_handle_binding(handle, did_document=did_document)
    print(f"  is_valid:          {result.is_valid}")
    if result.error_message:
        print(f"  error:             {result.error_message}")


if __name__ == "__main__":
    asyncio.run(main())
