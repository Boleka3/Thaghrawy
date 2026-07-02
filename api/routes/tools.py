"""Human-run-a-tool: let the operator invoke a registered tool directly, outside
the LLM loop, when the model is stuck or the human wants a specific scan run with
the right arguments. The result is injected into the engagement's agent so the
model sees what the human did on the next turn. Mirrors the WebSocket `run_tool`
control message for scripting / non-WS callers.
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Body, HTTPException, Request

from api.deps import get_or_create_agent

router = APIRouter(prefix="/api/engagements", tags=["tools"])


@router.post("/{engagement_id}/tools/{tool_name}")
async def run_tool(
    engagement_id: str,
    tool_name: str,
    request: Request,
    arguments: dict[str, Any] = Body(default_factory=dict),
):
    agent = get_or_create_agent(request, engagement_id)
    if agent.registry.get(tool_name) is None:
        raise HTTPException(status_code=404, detail=f"Unknown tool: {tool_name}")
    result = await agent.registry.execute(tool_name, arguments)
    # Feed the operator's action back into the conversation.
    agent.messages.append({
        "role": "user",
        "content": f"[operator ran {tool_name} {json.dumps(arguments)}]\nResult:\n"
        + agent.context.summarize_tool_output(str(result)),
    })
    return {"tool": tool_name, "arguments": arguments, "output": result}
