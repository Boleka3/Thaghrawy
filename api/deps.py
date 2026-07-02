"""Shared FastAPI dependency accessors for HTTP routes. Singletons live on
app.state, created once in main.py's lifespan. WebSocket routes don't go
through Depends() the same way - see api/websocket.py for its own accessor.
"""
from __future__ import annotations

from fastapi import Request

from core.agent import PentestAgent
from core.control import AgentControl
from core.tools import build_filtered_registry
from engagements.manager import EngagementManager
from memory.store import MemoryStore


def get_memory(request: Request) -> MemoryStore:
    return request.app.state.memory


def get_engagements(request: Request) -> EngagementManager:
    return request.app.state.engagements


def get_or_create_agent(request: Request, engagement_id: str) -> PentestAgent:
    return _get_or_create_agent(request.app.state, engagement_id)


def _get_or_create_agent(state, engagement_id: str) -> PentestAgent:
    agents: dict[str, PentestAgent] = state.agents
    if engagement_id not in agents:
        engagement = state.engagements.get(engagement_id)
        target = engagement.target if engagement else ""
        mode = engagement.analysis_mode if engagement else "full_analysis"
        phase = engagement.phase if engagement else "enumeration"
        registry = build_filtered_registry(mode, state.memory, engagement_id)
        control = AgentControl(phase=phase)
        agents[engagement_id] = PentestAgent(
            engagement_id=engagement_id,
            target=target,
            memory=state.memory,
            registry=registry,
            engagement_manager=state.engagements,
            control=control,
        )
    return agents[engagement_id]
