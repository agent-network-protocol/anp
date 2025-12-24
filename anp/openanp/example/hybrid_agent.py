"""Hybrid mode: Demonstrates all OpenANP capabilities.

Shows two approaches:
1. Manual schema definition (explicit control)
2. Automatic schema extraction from type hints (convenience)
"""

import asyncio

from anp.openanp.client.agent import RemoteAgent
from fastapi import FastAPI

from anp.authentication import DIDWbaAuthHeader
from anp.openanp import (
    AgentConfig,
    create_agent_router,
    extract_method_schemas,
)
from anp.openanp.types import RPCMethodInfo

# =============================================================================
# Pure Functions - Business Logic
# =============================================================================


async def plan_trip(
    destination: str, budget: int, auth: DIDWbaAuthHeader | None
) -> dict:
    """Plan a trip by calling remote hotel agent.

    Args:
        destination: City name
        budget: Maximum budget in USD
        auth: DID-WBA authentication (required for remote calls)

    Returns:
        Trip plan with hotels

    Pure function: Explicit parameters, no side effects.
    Fail Fast: Raises if auth is None.
    """
    if auth is None:
        raise ValueError("Auth required for remote agent discovery")

    hotel = await RemoteAgent.discover(
        "http://localhost:8000/hotel/ad.json",
        auth,
    )

    print(f"\n[plan_trip] Discovered: {hotel.name}")
    print(f"[plan_trip] Methods: {', '.join(hotel.method_names)}")

    hotels = await hotel.search(query=destination)
    return {
        "destination": destination,
        "budget": budget,
        "hotels": hotels,
        "status": "planned",
    }


async def quick_search(query: str, auth: DIDWbaAuthHeader) -> dict:
    """Quick hotel search without planning.

    Args:
        query: Search query
        auth: DID-WBA authentication

    Returns:
        Search results

    Simpler function for demonstration.
    """
    hotel = await RemoteAgent.discover(
        "http://localhost:8000/hotel/ad.json",
        auth,
    )

    print(f"\n[quick_search] Searching: {query}")
    results = await hotel.search(query=query)
    return {"query": query, "results": results}


# =============================================================================
# Router Creation - Two Approaches
# =============================================================================


def create_app(auth: DIDWbaAuthHeader) -> FastAPI:
    """Create FastAPI app demonstrating both approaches.

    Approach 1: Manual schema (plan_trip)
    - Full control over schema
    - Explicit type definitions
    - Good for complex schemas

    Approach 2: Auto-extraction (quick_search)
    - Uses extract_method_schemas()
    - Parses type hints automatically
    - Less boilerplate
    """
    config = AgentConfig(
        name="Travel Agent",
        did="did:wba:example.com:travel",
        prefix="/travel",
        description="Hybrid agent demonstrating all OpenANP features",
    )

    # Create async wrapper functions (must be real async functions, not lambdas)
    async def plan_trip_handler(destination: str, budget: int) -> dict:
        return await plan_trip(destination, budget, auth)

    async def quick_search_handler(query: str) -> dict:
        return await quick_search(query, auth)

    # Approach 1: Manual schema definition
    # Full control, explicit types
    method1 = RPCMethodInfo(
        name="plan_trip",
        description="Plan a complete trip with budget",
        params_schema={
            "type": "object",
            "properties": {
                "destination": {
                    "type": "string",
                    "description": "Destination city",
                },
                "budget": {
                    "type": "integer",
                    "description": "Maximum budget in USD",
                    "minimum": 0,
                },
            },
            "required": ["destination", "budget"],
        },
        result_schema={
            "type": "object",
            "properties": {
                "destination": {"type": "string"},
                "budget": {"type": "integer"},
                "hotels": {"type": "object"},
                "status": {"type": "string"},
            },
        },
        handler=plan_trip_handler,
    )

    # Approach 2: Automatic schema extraction from type hints
    # Convenience, less boilerplate
    params_schema_raw, result_schema = extract_method_schemas(quick_search)

    # Filter out auth parameter (internal, not exposed to RPC)
    params_schema = {
        "type": "object",
        "properties": {
            k: v
            for k, v in params_schema_raw.get("properties", {}).items()
            if k != "auth"
        },
        "required": [r for r in params_schema_raw.get("required", []) if r != "auth"],
    }

    method2 = RPCMethodInfo(
        name="quick_search",
        description="Quick hotel search",
        params_schema=params_schema,
        result_schema=result_schema,
        handler=quick_search_handler,
    )

    # Create router with both methods
    methods = [method1, method2]
    router = create_agent_router(config, methods)

    app = FastAPI(title="Travel Agent - Hybrid Demo")
    app.include_router(router)

    return app


# =============================================================================
# Demo & Testing
# =============================================================================


async def demo_all_features(auth: DIDWbaAuthHeader) -> None:
    """Demonstrate all features."""
    print("=" * 60)
    print("OpenANP Hybrid Demo - All Features")
    print("=" * 60)

    # Feature 1: Manual schema method
    print("\n1. Manual schema (plan_trip):")
    result1 = await plan_trip("Tokyo", 1000, auth)
    print(f"   Result: {result1['status']}, hotels: {len(result1['hotels'])}")

    # Feature 2: Auto-extracted schema method
    print("\n2. Auto-extracted schema (quick_search):")
    result2 = await quick_search("Paris", auth)
    print(f"   Result: {result2['query']}")

    print("\n" + "=" * 60)


# Create app instance for uvicorn
# Must provide valid auth for production use
auth = DIDWbaAuthHeader(
    did_document_path="/Users/amdoi7/Desktop/work/anp/docs/did_public/public-did-doc.json",
    private_key_path="/Users/amdoi7/Desktop/work/anp/docs/did_public/public-private-key.pem",
)
app = create_app(auth)


if __name__ == "__main__":
    auth = DIDWbaAuthHeader(
        did_document_path="/Users/amdoi7/Desktop/work/anp/docs/did_public/public-did-doc.json",
        private_key_path="/Users/amdoi7/Desktop/work/anp/docs/did_public/public-private-key.pem",
    )
    asyncio.run(demo_all_features(auth))
