"""Minimal OpenANP server exposing RPC methods with @interface."""

from fastapi import FastAPI

from anp.openanp import AgentConfig, anp_agent, interface


@anp_agent(
    AgentConfig(
        name="Hotel Service",
        did="did:wba:example.com:hotel",
        prefix="/hotel",
    )
)
class HotelAgent:
    @interface
    async def search(self, query: str) -> dict:
        return {"results": [{"name": "Tokyo Hotel", "price": 100}]}

    @interface
    async def book(self, hotel_id: str, date: str) -> dict:
        return {"booking_id": "12345", "status": "confirmed"}


app = FastAPI()
app.include_router(HotelAgent.router())
