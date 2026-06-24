"""REST fallback for chat (non-streaming). Prefer /ws/chat for the real
streaming experience used by the frontend."""
from __future__ import annotations

from fastapi import APIRouter, Request
from pydantic import BaseModel

from api.deps import get_or_create_agent

router = APIRouter(prefix="/api/chat", tags=["chat"])


class ChatRequest(BaseModel):
    engagement_id: str
    message: str


@router.post("")
async def chat(body: ChatRequest, request: Request):
    agent = get_or_create_agent(request, body.engagement_id)
    events = [event async for event in agent.chat(body.message)]
    return {"events": events}
