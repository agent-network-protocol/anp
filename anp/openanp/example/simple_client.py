"""Minimal OpenANP client calling remote agents discovered via AD."""

import asyncio

from anp.authentication import DIDWbaAuthHeader
from anp.openanp import RemoteAgent


async def main() -> None:
    auth = DIDWbaAuthHeader(
        did_document_path="/Users/amdoi7/Desktop/work/anp/docs/did_public/public-did-doc.json",
        private_key_path="/Users/amdoi7/Desktop/work/anp/docs/did_public/public-private-key.pem",
    )

    # For local testing, use localhost URL
    # In production, replace with actual agent URL
    agent = await RemoteAgent.discover("http://localhost:8000/hotel/ad.json", auth)

    # Print all available methods
    print(f"\nDiscovered agent: {agent.name}")
    print(f"Description: {agent.description}")
    print(f"\nAvailable methods ({len(agent.methods)}):")
    for i, method in enumerate(agent.methods, 1):
        print(f"  {i}. {method.name}")
        if method.description:
            print(f"     {method.description}")
        if method.params:
            print(f"     Params: {len(method.params)} parameter(s)")
    print()

    hotels = await agent.search(query="Tokyo")
    print("search →", hotels)

    booking = await agent.call("book", hotel_id="tokyo-001", date="2024-06-01")
    print("book →", booking)


if __name__ == "__main__":
    asyncio.run(main())
