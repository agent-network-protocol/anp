"""OpenANP server example with Context, Information, and different interface modes.

This example demonstrates:
1. @interface with default content mode (embedded in interface.json)
2. @interface with link mode (separate interface file)
3. Context injection for session/DID access
4. Static Information definitions
5. Dynamic Information via @information decorator

Run with:
    uvicorn anp.openanp.example.simple_server:app --reload
"""

from fastapi import FastAPI

from anp.openanp import (
    AgentConfig,
    Context,
    Information,
    anp_agent,
    information,
    interface,
)


@anp_agent(
    AgentConfig(
        name="Hotel Service",
        did="did:wba:example.com:hotel",
        prefix="/hotel",
        description="A hotel booking service agent",
    )
)
class HotelAgent:
    """Example hotel agent with full feature demonstration."""

    # Static Information definitions (URL and Content modes)
    informations = [
        # URL mode: external link
        Information(
            type="VideoObject",
            description="Hotel tour video",
            url="https://cdn.example.com/hotel-tour.mp4",
        ),
        # Content mode: embedded content
        Information(
            type="Organization",
            description="Hotel contact information",
            mode="content",
            content={"name": "Grand Hotel", "phone": "+1-234-567-8900"},
        ),
    ]

    # Default content mode: included in interface.json
    @interface
    async def search(self, query: str) -> dict:
        """Search for hotels by query string.

        Args:
            query: Search query (city name, hotel name, etc.)

        Returns:
            Search results with hotel list
        """
        return {
            "results": [
                {"name": "Tokyo Grand Hotel", "price": 150, "rating": 4.5},
                {"name": "Tokyo Business Inn", "price": 80, "rating": 4.0},
            ]
        }

    # Context injection: access session and DID
    @interface
    async def search_with_context(self, query: str, ctx: Context) -> dict:
        """Search with context - demonstrates session and DID access.

        Args:
            query: Search query
            ctx: Context with session, DID, and request

        Returns:
            Search results with user info
        """
        # Store last query in session
        ctx.session.set("last_query", query)

        # Get previous searches
        history = ctx.session.get("search_history", [])
        history.append(query)
        ctx.session.set("search_history", history[-5:])  # Keep last 5

        return {
            "results": [{"name": "Tokyo Hotel", "price": 100}],
            "user_did": ctx.did,
            "search_count": len(history),
        }

    # Link mode: separate interface file at /hotel/interface/book.json
    @interface(mode="link")
    async def book(self, hotel_id: str, check_in: str, check_out: str) -> dict:
        """Book a hotel room.

        This method uses link mode - it will have its own interface file.

        Args:
            hotel_id: Hotel identifier
            check_in: Check-in date (YYYY-MM-DD)
            check_out: Check-out date (YYYY-MM-DD)

        Returns:
            Booking confirmation
        """
        return {
            "booking_id": "BK-12345",
            "hotel_id": hotel_id,
            "check_in": check_in,
            "check_out": check_out,
            "status": "confirmed",
        }

    # Dynamic Information via decorator (URL mode)
    @information(
        type="Product",
        description="Today's available rooms",
        path="/products/availability.json",
    )
    def get_availability(self) -> dict:
        """Get current room availability - called dynamically."""
        return {
            "date": "2024-01-15",
            "rooms": [
                {"type": "standard", "available": 10, "price": 100},
                {"type": "deluxe", "available": 5, "price": 200},
                {"type": "suite", "available": 2, "price": 500},
            ],
        }

    # Dynamic Information (Content mode - embedded in ad.json)
    @information(
        type="Service",
        description="Today's special offers",
        mode="content",
    )
    def get_specials(self) -> dict:
        """Get special offers - content embedded in ad.json."""
        return {
            "specials": [
                {"name": "Early Bird Discount", "discount": "20%"},
                {"name": "Weekend Package", "discount": "15%"},
            ]
        }


app = FastAPI(
    title="Hotel Agent API",
    description="OpenANP Hotel Agent with full feature demonstration",
)
app.include_router(HotelAgent.router())


# What endpoints are generated:
#
# GET  /hotel/ad.json              - Agent description (with Informations)
# GET  /hotel/interface.json       - OpenRPC for content mode methods (search, search_with_context)
# GET  /hotel/interface/book.json  - OpenRPC for book method (link mode)
# GET  /hotel/products/availability.json - Dynamic Information endpoint
# POST /hotel/rpc                  - JSON-RPC 2.0 endpoint
#
# The ad.json will include:
# - interfaces: links to interface.json and interface/book.json
# - Infomations: VideoObject (URL), Organization (content), Product (URL), Service (content)
