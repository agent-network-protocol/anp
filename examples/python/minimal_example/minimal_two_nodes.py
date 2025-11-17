#!/usr/bin/env python3
"""
Two-node ANP demonstration.

This script launches two ANPNode instances (Node A and Node B) in-process, then:
1. Each node exposes its own JSON-RPC interface and information endpoint.
2. Node A calls Node B's RPC and information endpoint.
3. Node B calls Node A's RPC and agent description.

Run with:
    uv run python examples/python/minimal_example/minimal_two_nodes.py
"""

import asyncio
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from anp.node import ANPNode  # noqa: E402

DID_DOC_PATH = project_root / "docs" / "did_public" / "public-did-doc.json"
PRIVATE_KEY_PATH = project_root / "docs" / "did_public" / "public-private-key.pem"
KEY_PATH = PRIVATE_KEY_PATH if PRIVATE_KEY_PATH.exists() else DID_DOC_PATH

NODE_A_BASE = "http://localhost:8020"
NODE_B_BASE = "http://localhost:8021"


def build_node(name: str, description: str, base_url: str, port: int) -> ANPNode:
    return ANPNode(
        name=name,
        description=description,
        did="did:wba:didhost.cc:public",
        did_document_path=str(DID_DOC_PATH),
        private_key_path=str(KEY_PATH),
        agent_domain=base_url,
        host="0.0.0.0",
        port=port,
        enable_auth_middleware=False,
    )


node_a = build_node("Node A", "Calculator node", NODE_A_BASE, 8020)
node_b = build_node("Node B", "Echo node", NODE_B_BASE, 8021)


@node_a.interface("/info/calculate.json", description="Evaluate expressions")
def calculate(expression: str):
    try:
        result = eval(expression, {"__builtins__": {}})  # noqa: S307
        return {"result": result}
    except Exception as exc:  # pylint: disable=broad-except
        return {"error": str(exc)}


@node_a.information("/info/hello.json", description="Node A hello")
async def hello_a():
    return {"message": "Hello from Node A"}


@node_b.interface("/info/echo.json", description="Echo a message")
def echo(message: str):
    return {"echo": message}


@node_b.information("/info/status.json", description="Node B status")
async def status_b():
    return {"status": "Node B ready"}


async def run_demo():
    print("=" * 60)
    print("Two-node ANP demo")
    print("=" * 60)
    await asyncio.gather(node_a.start(), node_b.start())
    print("✓ Both nodes running\n")

    try:
        calc = await node_b.call_remote_method(
            base_url=NODE_A_BASE,
            method="calculate",
            params={"expression": "3 * (4 + 5)"},
        )
        print("Node B -> Node A calculate:", calc)

        status = await node_a.fetch_information_endpoint(NODE_B_BASE, "/info/status.json")
        print("Node A -> Node B status:", status)

        ad_b = await node_a.fetch_agent_description(NODE_B_BASE)
        print("Node A fetched Node B ad.json interfaces:", len(ad_b.get("interfaces", [])))

        echo_result = await node_a.call_remote_method(
            base_url=NODE_B_BASE,
            method="echo",
            params={"message": "Ping from Node A"},
        )
        print("Node A -> Node B echo:", echo_result)
    finally:
        await asyncio.gather(node_a.stop(), node_b.stop())
        print("\n✓ Nodes stopped")
        print("=" * 60)


if __name__ == "__main__":
    asyncio.run(run_demo())

