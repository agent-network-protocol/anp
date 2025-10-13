#!/usr/bin/env python3
"""
Hotel Booking Agent Example

This example demonstrates a complete FastANP agent with:
- Multiple Information documents (static and dynamic)
- Complex data models using Pydantic
- Multiple interface methods
- Context injection for session management
- Custom ad.json route
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from fastapi import FastAPI
from pydantic import BaseModel

from anp.authentication.did_wba_verifier import DidWbaVerifierConfig
from anp.fastanp import Context, FastANP

# Initialize FastAPI app
app = FastAPI(
    title="Hotel Booking Assistant",
    description="Intelligent hotel booking agent with room search and reservation capabilities",
    version="1.0.0"
)

# Load JWT keys for authentication
jwt_private_key_path = project_root / "docs" / "jwt_rs256" / "private_key.pem"
jwt_public_key_path = project_root / "docs" / "jwt_rs256" / "public_key.pem"

with open(jwt_private_key_path, 'r') as f:
    jwt_private_key = f.read()
with open(jwt_public_key_path, 'r') as f:
    jwt_public_key = f.read()

# Create auth config
auth_config = DidWbaVerifierConfig(
    jwt_private_key=jwt_private_key,
    jwt_public_key=jwt_public_key,
    jwt_algorithm="RS256",
    allowed_domains=["localhost", "0.0.0.0", "127.0.0.1"]
)

# Initialize FastANP plugin
anp = FastANP(
    app=app,
    name="Hotel Booking Assistant",
    description="Intelligent hotel booking agent with room search and reservation capabilities",
    base_url="http://localhost:8000/",
    did="did:wba:hotel.example.com:service:booking",
    owner={
        "type": "Organization",
        "name": "Hotel Group International",
        "url": "http://localhost:8000/",
        "email": "info@hotel.example.com"
    },
    jsonrpc_server_path="/rpc",
    jsonrpc_server_name="Hotel Booking API",
    jsonrpc_server_description="Hotel Booking JSON-RPC API",
    enable_auth_middleware=True,  # Enable auth for demo
    auth_config=auth_config
)


# Define data models
class RoomQuery(BaseModel):
    """Room search query parameters."""
    check_in_date: str
    check_out_date: str
    guest_count: int
    room_type: str = "standard"


class Room(BaseModel):
    """Room information."""
    id: str
    type: str
    price: float
    available: bool


# Custom ad.json route
@app.get("/{agent_id}/ad.json", tags=["agent"])
def get_agent_description(agent_id: str):
    """
    Get Agent Description for the specified agent.
    
    Args:
        agent_id: Agent identifier
    """
    # 1. Get common header from FastANP
    ad = anp.get_common_header()
    
    # 2. Add Information items (user-defined)
    ad["Infomations"] = [
        {
            "type": "Product",
            "description": "Luxury hotel rooms with premium amenities and personalized services.",
            "url": f"{anp.base_url}/products/luxury-rooms.json"
        },
        {
            "type": "Information",
            "description": "Complete hotel information including facilities, amenities, location, and policies.",
            "url": f"{anp.base_url}/info/hotel-basic-info.json"
        }
    ]
    
    # 3. Add Interface items using FastANP helpers
    # Can use link_summary for URL reference or content for embedded OpenRPC
    ad["interfaces"] = [
        anp.interfaces[search_rooms].link_summary,
        anp.interfaces[get_rooms].content,  # This one is embedded
    ]
    
    return ad


# Alternative: Simple ad.json route
@app.get("/ad.json", tags=["agent"])
def get_simple_agent_description():
    """Get Agent Description (simple version)."""
    ad = anp.get_common_header()
    
    # Add all interfaces as links
    ad["interfaces"] = [
        anp.interfaces[search_rooms].link_summary,
        anp.interfaces[get_rooms].link_summary,
    ]
    
    return ad


# Register interface methods
@anp.interface("/info/search_rooms.json", description="Search available hotel rooms")
def search_rooms(query: RoomQuery) -> dict:
    """
    Search available hotel rooms based on criteria.
    
    Args:
        query: Room search criteria including dates, guest count, and room type
        
    Returns:
        Dictionary with search results
    """
    # Demo implementation
    return {
        "success": True,
        "rooms": [
            {
                "id": "101",
                "type": query.room_type,
                "price": 150.0,
                "available": True
            },
            {
                "id": "102",
                "type": query.room_type,
                "price": 180.0,
                "available": True
            }
        ],
        "total": 2
    }


# Interface with Context injection
@anp.interface("/info/get_rooms.json", description="Get rooms with session context")
def get_rooms(query: str, ctx: Context) -> dict:
    """
    Get available rooms with session context.
    
    Context is automatically injected by FastANP based on DID + Access Token.
    
    Args:
        query: Room search query string
        ctx: Automatically injected context (contains session, DID, request info)
        
    Returns:
        Dictionary with room results and session information
    """
    # Access session data
    session_id = ctx.session.id
    did = ctx.did
    
    # Store/retrieve session data
    visit_count = ctx.session.get("visit_count", 0)
    visit_count += 1
    ctx.session.set("visit_count", visit_count)
    
    return {
        "session_id": session_id,
        "did": did,
        "visit_count": visit_count,
        "query": query,
        "rooms": [
            {"id": "201", "type": "deluxe", "price": 250.0},
            {"id": "202", "type": "suite", "price": 400.0}
        ]
    }


# Additional static routes (user-defined)
@app.get("/products/luxury-rooms.json", tags=["information"])
def get_luxury_rooms():
    """Get luxury room products."""
    return {
        "products": [
            {
                "id": "deluxe-suite",
                "name": "Deluxe Suite",
                "description": "Spacious suite with ocean view",
                "price": 450.0,
                "amenities": ["Ocean view", "King bed", "Jacuzzi"]
            },
            {
                "id": "presidential-suite",
                "name": "Presidential Suite",
                "description": "Ultimate luxury experience",
                "price": 1200.0,
                "amenities": ["Panoramic view", "Private terrace", "Butler service"]
            }
        ]
    }


@app.get("/info/hotel-basic-info.json", tags=["information"])
def get_hotel_info():
    """Get basic hotel information."""
    return {
        "name": "Grand Hotel International",
        "address": "123 Ocean Drive, Miami Beach, FL 33139",
        "phone": "+1-305-555-0100",
        "email": "info@hotel.example.com",
        "checkin_time": "15:00",
        "checkout_time": "11:00",
        "facilities": [
            "Swimming pool",
            "Fitness center",
            "Spa",
            "Restaurant",
            "Bar",
            "Business center"
        ],
        "policies": {
            "pets": "Allowed with additional fee",
            "smoking": "Non-smoking property",
            "cancellation": "Free cancellation up to 24 hours before check-in"
        }
    }


def main():
    """Run the hotel booking agent server."""
    import uvicorn
    
    print("Starting Hotel Booking Agent...")
    print("- Agent Description: http://localhost:8000/ad.json")
    print("- JSON-RPC endpoint: http://localhost:8000/rpc")
    print("- OpenRPC docs: http://localhost:8000/info/search_rooms.json")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
