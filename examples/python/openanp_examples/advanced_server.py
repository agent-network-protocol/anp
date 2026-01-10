#!/usr/bin/env python3
"""OpenANP Advanced Server Example.

Demonstrates all advanced features:
1. @interface with two modes (content / link)
2. Context injection and Session management
3. Static Information (URL / Content modes)
4. Dynamic @information decorator
5. Constructor dependency injection
6. customize_ad() hook for customizing ad.json

Context Core Concepts:
======================
Context is one of the core features of OpenANP, automatically provided to methods
via parameter injection.

[IMPORTANT] ctx.did - Caller Identity
    - ctx.did contains the caller's DID (Decentralized Identifier)
    - Use DID to uniquely identify which Agent is calling your service
    - Essential for: user tracking, access control, personalized services
    - Example: did:wba:example.com:user:alice

[IMPORTANT] ctx.session - Custom Session Storage
    - Sessions are automatically isolated by DID; different users' data don't interfere
    - Store any custom fields: ctx.session.set("key", value)
    - Read fields: ctx.session.get("key", default_value)
    - Use cases: shopping cart, user preferences, temporary state

Run:
    uvicorn examples.python.openanp_examples.advanced_server:app --port 8000

Generated Endpoints:
    GET  /shop/ad.json                      - Agent Description
    GET  /shop/interface.json               - OpenRPC Interface (content mode methods)
    GET  /shop/interface/checkout.json      - Checkout method interface (link mode)
    GET  /shop/products/featured.json       - Featured products (dynamic Information)
    POST /shop/rpc                          - JSON-RPC Endpoint
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
        name="Online Shop",
        did="did:wba:example.com:shop",
        prefix="/shop",
        description="A full-featured online shop agent",
        tags=["shopping", "e-commerce"],
    )
)
class ShopAgent:
    """Online Shop Agent - Demonstrates all OpenANP advanced features."""

    # =========================================================================
    # Static Information Definitions
    # =========================================================================
    informations = [
        # URL mode: external link
        Information(
            type="ImageObject",
            description="Shop Logo",
            url="https://cdn.example.com/logo.png",
        ),
        # Content mode: embedded content
        Information(
            type="Organization",
            description="Contact Information",
            mode="content",
            content={
                "name": "Example Shop",
                "phone": "+1-234-567-8900",
                "email": "contact@example.com",
            },
        ),
    ]

    def __init__(self, discount_rate: float = 0.1):
        """Initialize the shop agent.

        Args:
            discount_rate: Default discount rate
        """
        self.discount_rate = discount_rate
        self._products = {
            "P001": {"name": "Laptop", "price": 999, "stock": 10},
            "P002": {"name": "Wireless Mouse", "price": 29, "stock": 50},
            "P003": {"name": "Mechanical Keyboard", "price": 89, "stock": 30},
        }

    # =========================================================================
    # Content Mode Interfaces (embedded in interface.json)
    # =========================================================================

    @interface
    async def list_products(self) -> dict:
        """List all products.

        Returns:
            Product list
        """
        return {"products": list(self._products.values())}

    @interface
    async def get_product(self, product_id: str) -> dict:
        """Get product details.

        Args:
            product_id: Product ID

        Returns:
            Product details
        """
        product = self._products.get(product_id)
        if not product:
            return {"error": "Product not found"}
        return {"product": product}

    # =========================================================================
    # Context Injection Demo
    # =========================================================================
    #
    # [CORE CONCEPT] Context is auto-injected via parameter `ctx: Context`
    #
    # ctx.did - Caller's DID identity (VERY IMPORTANT!)
    #   - Use ctx.did to know "who is calling me"
    #   - Use for: identity verification, access control, personalization, audit logs
    #   - Example value: did:wba:example.com:user:alice
    #
    # ctx.session - DID-isolated session storage
    #   - Different DIDs' data are automatically isolated
    #   - Store any custom fields (cart, preferences, etc.)
    #   - get(key, default) / set(key, value) / clear()
    #
    # =========================================================================

    @interface
    async def add_to_cart(
        self, product_id: str, quantity: int, ctx: Context
    ) -> dict:
        """Add product to shopping cart.

        Demonstrates:
        - ctx.did to get caller identity
        - ctx.session to store custom field "cart"

        Args:
            product_id: Product ID
            quantity: Quantity
            ctx: Context (auto-injected, not passed by client)

        Returns:
            Cart status
        """
        # =====================================================================
        # [IMPORTANT] ctx.did - Identify the caller
        # =====================================================================
        # ctx.did tells us "who is calling this interface"
        # Critical for multi-user systems:
        # - Different users' carts need isolation
        # - Access control based on DID
        # - User behavior logging
        caller_did = ctx.did
        print(f"[add_to_cart] Caller DID: {caller_did}")

        # =====================================================================
        # [IMPORTANT] ctx.session - Custom session fields
        # =====================================================================
        # Sessions are automatically isolated by DID
        # Store any custom fields: cart, preferences, history, etc.

        # Read custom field "cart", returns default {} on first access
        cart: dict = ctx.session.get("cart", {})

        # Update cart
        if product_id in cart:
            cart[product_id] += quantity
        else:
            cart[product_id] = quantity

        # Save custom field "cart" to Session
        ctx.session.set("cart", cart)

        # You can also store other custom fields
        ctx.session.set("last_action", "add_to_cart")
        ctx.session.set("last_product", product_id)

        return {
            "cart": cart,
            "caller_did": caller_did,  # Return caller DID for client verification
            "message": f"Added {quantity} item(s)",
        }

    @interface
    async def get_cart(self, ctx: Context) -> dict:
        """Get current shopping cart.

        Demonstrates: ctx.session reading multiple custom fields

        Args:
            ctx: Context (auto-injected)

        Returns:
            Cart contents and total price
        """
        # Read custom fields
        cart: dict = ctx.session.get("cart", {})
        last_action = ctx.session.get("last_action", None)

        total = 0
        items = []

        for product_id, quantity in cart.items():
            product = self._products.get(product_id)
            if product:
                subtotal = product["price"] * quantity
                total += subtotal
                items.append({
                    "product_id": product_id,
                    "name": product["name"],
                    "quantity": quantity,
                    "subtotal": subtotal,
                })

        # Apply discount
        discount = total * self.discount_rate
        final_total = total - discount

        return {
            "items": items,
            "subtotal": total,
            "discount": discount,
            "discount_rate": self.discount_rate,
            "total": final_total,
            "caller_did": ctx.did,  # Caller identity
            "last_action": last_action,  # Custom field example
        }

    # =========================================================================
    # Link Mode Interface (separate interface file)
    # =========================================================================

    @interface(mode="link")
    async def checkout(self, address: str, ctx: Context) -> dict:
        """Checkout the shopping cart.

        This method uses link mode, generating a separate interface file.

        Demonstrates:
        - Using ctx.did to generate user-specific order ID
        - Using ctx.session.set() to clear cart

        Args:
            address: Shipping address
            ctx: Context (auto-injected)

        Returns:
            Order confirmation
        """
        cart: dict = ctx.session.get("cart", {})
        if not cart:
            return {"error": "Cart is empty"}

        # [IMPORTANT] Use ctx.did to generate user-specific order ID
        # Same user's orders follow a pattern for easy tracking
        order_id = f"ORD-{hash(ctx.did) % 100000:05d}"

        # Clear cart (custom fields can be overwritten anytime)
        ctx.session.set("cart", {})

        # Record order history (demo storing complex data structures)
        order_history: list = ctx.session.get("order_history", [])
        order_history.append({
            "order_id": order_id,
            "address": address,
        })
        ctx.session.set("order_history", order_history)

        return {
            "order_id": order_id,
            "address": address,
            "status": "confirmed",
            "caller_did": ctx.did,  # Order owner
            "total_orders": len(order_history),  # User's total order count
        }

    # =========================================================================
    # Dynamic Information
    # =========================================================================

    @information(
        type="Product",
        description="Today's featured products",
        path="/products/featured.json",
    )
    def get_featured_products(self) -> dict:
        """Get featured products (URL mode, separate endpoint).

        Returns:
            Featured products list
        """
        return {
            "featured": [
                self._products["P001"],
                self._products["P003"],
            ],
            "updated_at": "2024-01-15",
        }

    @information(
        type="Offer",
        description="Limited time offers",
        mode="content",
    )
    def get_special_offers(self) -> dict:
        """Get special offers (Content mode, embedded in ad.json).

        Returns:
            Offer information list
        """
        return {
            "offers": [
                {"name": "New Year Sale", "discount": "20%", "expires": "2024-02-01"},
                {"name": "Bundle Deal", "condition": "Spend $100 save $10"},
            ]
        }

    # =========================================================================
    # Custom ad.json Hook
    # =========================================================================

    def customize_ad(self, ad: dict, base_url: str) -> dict:
        """Customize the auto-generated ad.json.

        This method is automatically called by OpenANP when generating ad.json.
        You can modify the ad dict to add custom fields, additional Informations,
        or any other customization.

        Args:
            ad: The auto-generated ad.json dict
            base_url: The base URL of the server

        Returns:
            The modified ad.json dict
        """
        # Add custom metadata
        ad["custom_metadata"] = {
            "version": "2.0.0",
            "environment": "production",
            "features": ["discount", "session", "cart"],
        }

        # Add additional Informations
        if "Infomations" not in ad:
            ad["Infomations"] = []

        ad["Infomations"].append({
            "type": "FAQ",
            "description": "Frequently Asked Questions",
            "url": f"{base_url}/shop/faq.json",
        })

        ad["Infomations"].append({
            "type": "Policy",
            "description": "Return Policy",
            "content": {
                "return_window_days": 30,
                "conditions": ["unused", "original packaging"],
            },
        })

        # Add custom service links
        ad["support"] = {
            "email": "support@example-shop.com",
            "phone": "+1-800-SHOP",
            "hours": "24/7",
        }

        return ad


def create_app() -> FastAPI:
    """Create FastAPI application.

    Returns:
        Configured FastAPI application instance
    """
    app = FastAPI(
        title="Online Shop Agent",
        description="OpenANP Advanced Server Example",
    )

    # Use constructor injection for custom configuration
    agent = ShopAgent(discount_rate=0.15)  # 15% discount
    app.include_router(agent.router())

    return app


app = create_app()


# =============================================================================
# Additional Custom Endpoints
# =============================================================================
# You can add additional endpoints to the app that are referenced in ad.json
# (e.g., the FAQ endpoint added via customize_ad)

from fastapi.responses import JSONResponse


@app.get("/shop/faq.json")
async def get_faq() -> JSONResponse:
    """Custom FAQ endpoint referenced in ad.json via customize_ad."""
    return JSONResponse({
        "faqs": [
            {"question": "How long does shipping take?", "answer": "3-5 business days."},
            {"question": "Do you offer international shipping?", "answer": "Yes, 50+ countries."},
        ],
        "updated_at": "2024-01-15",
    }, media_type="application/json; charset=utf-8")


if __name__ == "__main__":
    import uvicorn

    print("Starting Advanced ANP Server...")
    print("  Agent Description:    http://localhost:8000/shop/ad.json")
    print("  OpenRPC Document:     http://localhost:8000/shop/interface.json")
    print("  Checkout Interface:   http://localhost:8000/shop/interface/checkout.json")
    print("  Featured Products:    http://localhost:8000/shop/products/featured.json")
    print("  JSON-RPC Endpoint:    http://localhost:8000/shop/rpc")
    uvicorn.run(app, host="0.0.0.0", port=8000)
