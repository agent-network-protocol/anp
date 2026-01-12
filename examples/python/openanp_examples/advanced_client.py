#!/usr/bin/env python3
"""OpenANP Advanced Client Example.

Demonstrates all client features:
1. Agent discovery and method listing
2. Dynamic attribute access vs explicit call
3. OpenAI Tools format export (LLM integration)
4. Session management demo
5. Error handling

Prerequisites:
    Start advanced_server.py first:
    uvicorn examples.python.openanp_examples.advanced_server:app --port 8000

Run:
    uv run python examples/python/openanp_examples/advanced_client.py
"""

import asyncio
import json
from pathlib import Path

from anp.authentication import DIDWbaAuthHeader
from anp.openanp import RemoteAgent


# DID document and private key paths
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
DID_DOC = PROJECT_ROOT / "docs/did_public/public-did-doc.json"
PRIVATE_KEY = PROJECT_ROOT / "docs/did_public/public-private-key.pem"


def print_section(title: str) -> None:
    """Print section divider.

    Args:
        title: Section title
    """
    print(f"\n{'=' * 60}")
    print(f" {title}")
    print("=" * 60)


async def main() -> None:
    """Advanced client demo."""
    # =========================================================================
    # 1. Initialize Authentication
    # =========================================================================
    print_section("1. Initialize Authentication")
    auth = DIDWbaAuthHeader(
        did_document_path=str(DID_DOC),
        private_key_path=str(PRIVATE_KEY),
    )
    print("✓ Authentication created")

    # =========================================================================
    # 2. Discover Agent
    # =========================================================================
    print_section("2. Discover Agent")
    try:
        agent = await RemoteAgent.discover(
            "http://localhost:8000/shop/ad.json",
            auth,
        )
    except Exception as e:
        print(f"✗ Connection failed: {e}")
        print("\nPlease start the server first:")
        print("  uvicorn examples.python.openanp_examples.advanced_server:app --port 8000")
        return

    print(f"Name: {agent.name}")
    print(f"Description: {agent.description}")
    print(f"URL: {agent.url}")

    # =========================================================================
    # 3. View Available Methods
    # =========================================================================
    print_section("3. Available Methods")
    for i, method in enumerate(agent.methods, 1):
        print(f"\n  [{i}] {method.name}")
        print(f"      Description: {method.description}")
        if method.params:
            params = [p.get("name", "?") for p in method.params]
            print(f"      Parameters: {', '.join(params)}")

    # =========================================================================
    # 4. OpenAI Tools Format (LLM Integration)
    # =========================================================================
    print_section("4. OpenAI Tools Format")
    tools = agent.tools
    print(f"Total {len(tools)} tools available for LLM")
    if tools:
        print("\nExample (first tool):")
        tool_str = json.dumps(tools[0], indent=2, ensure_ascii=False)
        # Truncate long output
        if len(tool_str) > 500:
            tool_str = tool_str[:500] + "..."
        print(tool_str)

    # =========================================================================
    # 5. Call Methods - Dynamic Attribute Access
    # =========================================================================
    print_section("5. Call Methods - Dynamic Attribute")

    # List products
    result = await agent.list_products()
    print("Product list:")
    for p in result.get("products", []):
        print(f"  - {p['name']}: ${p['price']}")

    # Get single product
    result = await agent.get_product(product_id="P001")
    print(f"\nProduct details: {result}")

    # =========================================================================
    # 6. Call Methods - Explicit Call
    # =========================================================================
    print_section("6. Call Methods - Explicit Call")

    result = await agent.call("get_product", product_id="P002")
    print(f"Using call() to get product: {result}")

    # =========================================================================
    # 7. Session Demo - Context Core Feature
    # =========================================================================
    print_section("7. Session Demo")

    # Add products to cart
    print("Adding products to cart...")
    result1 = await agent.add_to_cart(product_id="P001", quantity=2)
    result2 = await agent.add_to_cart(product_id="P002", quantity=3)

    # [IMPORTANT] Server identified our identity via ctx.did
    print(f"\nServer identified caller DID: {result2.get('caller_did')}")

    # View cart
    cart = await agent.get_cart()
    print("\nCart contents:")
    for item in cart.get("items", []):
        print(f"  - {item['name']} x{item['quantity']} = ${item['subtotal']}")
    print(f"\nSubtotal: ${cart.get('subtotal', 0)}")
    print(f"Discount: -${cart.get('discount', 0):.2f} ({cart.get('discount_rate', 0)*100:.0f}%)")
    print(f"Total: ${cart.get('total', 0):.2f}")

    # Server-stored custom field
    print(f"\nServer custom field last_action: {cart.get('last_action')}")

    # Checkout
    print("\nChecking out...")
    order = await agent.checkout(address="123 Main St, Anytown, USA")
    print(f"Order ID: {order.get('order_id')}")
    print(f"Status: {order.get('status')}")
    print(f"User's total orders: {order.get('total_orders')}")

    # =========================================================================
    # 8. Error Handling
    # =========================================================================
    print_section("8. Error Handling")

    # Call non-existent method
    try:
        await agent.non_existent_method()
    except AttributeError as e:
        print(f"✓ Caught AttributeError: {e}")

    print_section("Demo Completed")


if __name__ == "__main__":
    asyncio.run(main())
