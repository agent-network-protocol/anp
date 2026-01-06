"""Hybrid P2P agent example - demonstrates both server and client capabilities.

This example demonstrates:
1. An agent that is both a server (exposes methods) and a client (calls other agents)
2. Manual schema definition vs automatic extraction
3. Context injection with session management
4. Dynamic dependencies via constructor injection

Prerequisites:
- Start the simple_server first: uvicorn anp.openanp.example.simple_server:app --port 8000
- Then run this: uvicorn anp.openanp.example.hybrid_agent:app --port 8001

Run demo:
    uv run python -m anp.openanp.example.hybrid_agent
"""

import asyncio
from pathlib import Path

from fastapi import FastAPI

from anp.authentication import DIDWbaAuthHeader
from anp.openanp import (
    AgentConfig,
    Context,
    RemoteAgent,
    anp_agent,
    create_agent_router,
    extract_method_schemas,
    interface,
)
from anp.openanp.types import RPCMethodInfo


# Default paths - update for your environment
DEFAULT_DID_DOC = Path(__file__).parent.parent.parent.parent.parent / "docs/did_public/public-did-doc.json"
DEFAULT_PRIVATE_KEY = Path(__file__).parent.parent.parent.parent.parent / "docs/did_public/public-private-key.pem"


# =============================================================================
# Approach 1: Class-based with @anp_agent decorator (recommended)
# =============================================================================


@anp_agent(
    AgentConfig(
        name="Travel Planner",
        did="did:wba:example.com:travel",
        prefix="/travel",
        description="A P2P travel agent that calls hotel agents",
    )
)
class TravelAgent:
    """Hybrid agent - acts as both server and client.

    This agent:
    - Exposes methods via JSON-RPC (server)
    - Calls remote hotel agents to get data (client)
    - Uses Context for session management
    """

    def __init__(self, auth: DIDWbaAuthHeader):
        """Initialize with authentication for remote calls.

        Args:
            auth: DID-WBA authentication for calling other agents
        """
        self.auth = auth
        self._hotel_agent: RemoteAgent | None = None

    async def _get_hotel_agent(self) -> RemoteAgent:
        """Lazily discover hotel agent."""
        if self._hotel_agent is None:
            self._hotel_agent = await RemoteAgent.discover(
                "http://localhost:8000/hotel/ad.json",
                self.auth,
            )
        return self._hotel_agent

    @interface
    async def plan_trip(
        self,
        destination: str,
        budget: int,
        ctx: Context,
    ) -> dict:
        """Plan a complete trip by calling remote hotel agent.

        This method:
        1. Discovers the hotel agent
        2. Searches for hotels
        3. Saves the search to session
        4. Returns a trip plan

        Args:
            destination: City name
            budget: Maximum budget in USD
            ctx: Context with session and DID

        Returns:
            Trip plan with matched hotels
        """
        # Track planning history in session
        history = ctx.session.get("trip_history", [])
        history.append({"destination": destination, "budget": budget})
        ctx.session.set("trip_history", history[-10:])  # Keep last 10

        # Call remote hotel agent (we're a client here)
        hotel_agent = await self._get_hotel_agent()
        hotels = await hotel_agent.search(query=destination)

        return {
            "destination": destination,
            "budget": budget,
            "hotels": hotels,
            "planner_did": ctx.did,
            "trips_planned": len(history),
            "status": "planned",
        }

    @interface
    async def quick_search(self, query: str) -> dict:
        """Quick hotel search without session tracking.

        Args:
            query: Search query

        Returns:
            Search results from hotel agent
        """
        hotel_agent = await self._get_hotel_agent()
        results = await hotel_agent.search(query=query)
        return {"query": query, "results": results}

    @interface(mode="link")
    async def book_trip(
        self,
        hotel_id: str,
        check_in: str,
        check_out: str,
        ctx: Context,
    ) -> dict:
        """Book a trip by calling the hotel's book method.

        This uses link mode so it has its own interface file.

        Args:
            hotel_id: Hotel to book
            check_in: Check-in date
            check_out: Check-out date
            ctx: Context with session

        Returns:
            Booking confirmation
        """
        hotel_agent = await self._get_hotel_agent()
        booking = await hotel_agent.call(
            "book",
            hotel_id=hotel_id,
            check_in=check_in,
            check_out=check_out,
        )

        # Track bookings in session
        bookings = ctx.session.get("bookings", [])
        bookings.append(booking)
        ctx.session.set("bookings", bookings)

        return {
            "booking": booking,
            "total_bookings": len(bookings),
            "booker_did": ctx.did,
        }


# =============================================================================
# Approach 2: Functional with manual router creation
# =============================================================================


async def compare_hotels(destination: str, auth: DIDWbaAuthHeader) -> dict:
    """Compare hotels across multiple destinations.

    This is a standalone async function that we'll wire up manually.

    Args:
        destination: City to search
        auth: Authentication for remote calls

    Returns:
        Comparison results
    """
    hotel = await RemoteAgent.discover(
        "http://localhost:8000/hotel/ad.json",
        auth,
    )
    results = await hotel.search(query=destination)
    return {
        "destination": destination,
        "comparison": results,
        "source": "hotel_agent",
    }


def create_functional_router(auth: DIDWbaAuthHeader):
    """Create router using functional approach with manual schema.

    This approach gives you full control over:
    - Schema definitions
    - Handler wiring
    - Route configuration

    Args:
        auth: Authentication for remote calls

    Returns:
        FastAPI APIRouter
    """
    config = AgentConfig(
        name="Comparison Service",
        did="did:wba:example.com:compare",
        prefix="/compare",
        description="Functional hotel comparison service",
    )

    # Create handler that captures auth
    async def compare_handler(destination: str) -> dict:
        return await compare_hotels(destination, auth)

    # Manual schema definition (full control)
    method = RPCMethodInfo(
        name="compare",
        description="Compare hotels in a destination",
        params_schema={
            "type": "object",
            "properties": {
                "destination": {
                    "type": "string",
                    "description": "Destination city",
                },
            },
            "required": ["destination"],
        },
        result_schema={
            "type": "object",
            "properties": {
                "destination": {"type": "string"},
                "comparison": {"type": "object"},
                "source": {"type": "string"},
            },
        },
        handler=compare_handler,
    )

    return create_agent_router(config, [method])


# =============================================================================
# App Creation
# =============================================================================


def create_app() -> FastAPI:
    """Create FastAPI app with both class-based and functional agents."""
    auth = DIDWbaAuthHeader(
        did_document_path=str(DEFAULT_DID_DOC),
        private_key_path=str(DEFAULT_PRIVATE_KEY),
    )

    app = FastAPI(
        title="Hybrid P2P Agents",
        description="Demonstrates class-based and functional agent approaches",
    )

    # Class-based agent (recommended)
    travel_agent = TravelAgent(auth)
    app.include_router(travel_agent.router())

    # Functional agent (for advanced use cases)
    app.include_router(create_functional_router(auth))

    return app


# Create app instance for uvicorn
app = create_app()


# =============================================================================
# Demo
# =============================================================================


async def demo_hybrid_features() -> None:
    """Demonstrate hybrid agent features."""
    print("=" * 60)
    print("Hybrid P2P Agent Demo")
    print("=" * 60)

    auth = DIDWbaAuthHeader(
        did_document_path=str(DEFAULT_DID_DOC),
        private_key_path=str(DEFAULT_PRIVATE_KEY),
    )

    print("\nNote: This demo requires the simple_server running on port 8000.")
    print("Start it with: uvicorn anp.openanp.example.simple_server:app --port 8000")

    try:
        # Test quick search
        print("\n1. Quick search (no context):")
        result = await compare_hotels("Tokyo", auth)
        print(f"   Found: {result}")

    except Exception as e:
        print(f"\n   Error: {e}")
        print("   Make sure simple_server is running on port 8000")

    print("\n" + "=" * 60)
    print("To test the full agent, run:")
    print("  uvicorn anp.openanp.example.hybrid_agent:app --port 8001")
    print("\nEndpoints available:")
    print("  GET  /travel/ad.json")
    print("  GET  /travel/interface.json")
    print("  GET  /travel/interface/book_trip.json")
    print("  POST /travel/rpc")
    print("  GET  /compare/ad.json")
    print("  POST /compare/rpc")


if __name__ == "__main__":
    asyncio.run(demo_hybrid_features())
