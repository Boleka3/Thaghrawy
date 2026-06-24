"""FastAPI entry point: serves the frontend at / and the API under /api,
plus the streaming chat WebSocket at /ws/chat."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

import config
from api.routes import chat, engagements, findings, memory as memory_routes
from api import websocket as websocket_routes
from engagements.manager import EngagementManager
from memory.store import MemoryStore


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.memory = MemoryStore()
    app.state.engagements = EngagementManager()
    app.state.agents = {}
    yield


app = FastAPI(title="RedTeam AI", lifespan=lifespan)

app.include_router(chat.router)
app.include_router(engagements.router)
app.include_router(findings.router)
app.include_router(memory_routes.router)
app.include_router(websocket_routes.router)

app.mount("/static", StaticFiles(directory="frontend"), name="static")


@app.get("/")
def index():
    return FileResponse("frontend/index.html")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host=config.APP_HOST, port=config.APP_PORT, reload=config.DEBUG)
