"""Example: Resolve a Handle to a DID.

Usage:
    uv run python examples/python/wns_examples/resolve_handle.py
"""

import asyncio

from anp.wns import (
    HandleNotFoundError,
    HandleResolutionError,
    HandleValidationError,
    normalize_handle,
    parse_wba_uri,
    resolve_handle,
    resolve_handle_from_uri,
    validate_handle,
)


async def main():
    # 1. Validate and normalise a Handle
    handle = "Alice.Example.com"
    normalized = normalize_handle(handle)
    print(f"Normalized: {handle} → {normalized}")

    local_part, domain = validate_handle(normalized)
    print(f"  local_part = {local_part}")
    print(f"  domain     = {domain}")

    # 2. Parse a wba:// URI
    uri = "wba://alice.example.com"
    parsed = parse_wba_uri(uri)
    print(f"\nParsed URI: {parsed.original_uri}")
    print(f"  handle = {parsed.handle}")

    # 3. Resolve a Handle (requires a real Handle Provider)
    print(f"\nResolving handle '{normalized}' ...")
    try:
        doc = await resolve_handle(normalized)
        print(f"  DID:     {doc.did}")
        print(f"  Status:  {doc.status.value}")
        print(f"  Updated: {doc.updated}")
    except HandleNotFoundError:
        print("  Handle not found (expected if no real provider is running)")
    except HandleResolutionError as exc:
        print(f"  Resolution error: {exc}")

    # 4. Resolve from a wba:// URI
    print(f"\nResolving URI '{uri}' ...")
    try:
        doc = await resolve_handle_from_uri(uri)
        print(f"  DID: {doc.did}")
    except (HandleNotFoundError, HandleResolutionError) as exc:
        print(f"  Could not resolve: {exc}")


if __name__ == "__main__":
    asyncio.run(main())
