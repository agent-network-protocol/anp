#!/usr/bin/env python3
"""OpenANP Minimal Server Example.

Build a complete ANP Server with minimal code.

Run:
    uvicorn examples.python.openanp_examples.minimal_server:app --port 8000

Generated Endpoints:
    GET  /agent/ad.json           - Agent Description
    GET  /agent/interface.json    - OpenRPC Interface Document
    POST /agent/rpc               - JSON-RPC Endpoint

Test:
    curl -X POST http://localhost:8000/agent/rpc \
        -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"add","params":{"a":10,"b":20},"id":1}'
"""

from fastapi import FastAPI

from anp.openanp import AgentConfig, anp_agent, interface


@anp_agent(
    AgentConfig(
        name="Calculator",
        did="did:wba:example.com:calculator",
        prefix="/agent",
        description="A simple calculator agent",
    )
)
class CalculatorAgent:
    """Minimal calculator agent."""

    @interface
    async def add(self, a: int, b: int) -> int:
        """Calculate the sum of two numbers.

        Args:
            a: First number
            b: Second number

        Returns:
            Sum of the two numbers
        """
        return a + b

    @interface
    async def multiply(self, a: int, b: int) -> int:
        """Calculate the product of two numbers.

        Args:
            a: First number
            b: Second number

        Returns:
            Product of the two numbers
        """
        return a * b


app = FastAPI(title="Calculator Agent")
app.include_router(CalculatorAgent.router())


if __name__ == "__main__":
    import uvicorn

    print("Starting Minimal ANP Server...")
    print("  Agent Description: http://localhost:8000/agent/ad.json")
    print("  OpenRPC Document:  http://localhost:8000/agent/interface.json")
    print("  JSON-RPC Endpoint: http://localhost:8000/agent/rpc")
    uvicorn.run(app, host="0.0.0.0", port=8000)
