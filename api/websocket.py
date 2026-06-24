"""Streaming chat over WebSocket. Each received text frame is treated as
one user turn; every event PentestAgent.chat() yields is relayed straight
to the client as JSON, matching the frontend's expected event shapes:
memory_hit, tool_call, tool_result, token, finding_saved, done, error.
"""
from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from api.deps import _get_or_create_agent

router = APIRouter()


@router.websocket("/ws/chat")
async def websocket_chat(websocket: WebSocket, engagement_id: str):
    await websocket.accept()
    try:
        while True:
            message = await websocket.receive_text()
            agent = _get_or_create_agent(websocket.app.state, engagement_id)
            try:
                async for event in agent.chat(message):
                    await websocket.send_json(event)
            except Exception as e:
                await websocket.send_json({"type": "error", "message": str(e)})
    except WebSocketDisconnect:
        pass
