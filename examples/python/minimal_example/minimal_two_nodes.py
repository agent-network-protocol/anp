#!/usr/bin/env python3
"""
Two-node ANP demo.

This example spins up two ANPNode instances (Node A and Node B) in process,
each with its own FastANP server. After both nodes start, they call each
other’s JSON-RPC and information endpoints using the unified client helpers.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Dict

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path so `python minimal_two_nodes.py` works
# ---------------------------------------------------------------------------
project_root = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(project_root))

from anp.fastanp import FastANP  # noqa: E402
from anp.node import ANPNode  # noqa: E402

# Demo configuration
DID_DOC_PATH = project_root / "docs" / "did_public" / "public-did-doc.json"
PRIVATE_KEY_PATH = project_root / "docs" / "did_public" / "public-private-key.pem"
KEY_PATH = PRIVATE_KEY_PATH if PRIVATE_KEY_PATH.exists() else DID_DOC_PATH

NODE_A_BASE = "http://localhost:8020"
NODE_B_BASE = "http://localhost:8021"


def build_node_a() -> ANPNode:
    """Calculator node."""
    anp = FastANP(
        name="Node A",
        description="Calculator node",
        did="did:wba:node-a",
        agent_domain=NODE_A_BASE,
        enable_auth_middleware=False,
    )

    @anp.interface("/info/calculate.json", description="Evaluate expressions")
    def calculate(expression: str) -> Dict[str, float]:
        try:
            result = eval(expression, {"__builtins__": {}})  # noqa: S307
            return {"result": result}
        except Exception as exc:  # pylint: disable=broad-except
            return {"error": str(exc)}

    @anp.information("/info/hello.json", description="Node A hello")
    async def hello_a():
        return {"message": "Hello from Node A"}

    return ANPNode(
        fastanp=anp,
        did_document_path=str(DID_DOC_PATH),
        private_key_path=str(KEY_PATH),
        host="0.0.0.0",
        port=8020,
    )


def build_node_b() -> ANPNode:
    """Echo node."""
    anp = FastANP(
        name="Node B",
        description="Echo node",
        did="did:wba:node-b",
        agent_domain=NODE_B_BASE,
        enable_auth_middleware=False,
    )

    @anp.interface("/info/echo.json", description="Echo a message")
    def echo(message: str) -> Dict[str, str]:
        return {"echo": message}

    @anp.information("/info/status.json", description="Node B status")
    async def status_b():
        return {"status": "Node B ready"}

    return ANPNode(
        fastanp=anp,
        did_document_path=str(DID_DOC_PATH),
        private_key_path=str(KEY_PATH),
        host="0.0.0.0",
        port=8021,
    )


async def run_demo() -> None:
    node_a = build_node_a()
    node_b = build_node_b()

    print("=" * 60)
    print("Two-node ANP demo")
    print("=" * 60)

    await asyncio.gather(node_a.start(), node_b.start())
    print("✓ Both nodes running\n")

    try:
        # Node B calls Node A's calculator RPC
        calc = await node_b.call_jsonrpc(
            f"{NODE_A_BASE}/rpc",
            method="calculate",
            params={"expression": "3 * (4 + 5)"},
        )
        print("Node B -> Node A calculate:", calc)

        # Node A fetches Node B status information endpoint
        status = await node_a.fetch(f"{NODE_B_BASE}/info/status.json")
        print("Node A -> Node B status:", status)

        # Node A fetches Node B agent description
        ad_b = await node_a.fetch(f"{NODE_B_BASE}/ad.json")
        print("Node A fetched Node B ad.json interfaces:", len(ad_b.get("interfaces", [])))

        # Node A calls Node B's echo RPC
        echo_result = await node_a.call_jsonrpc(
            f"{NODE_B_BASE}/rpc",
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

