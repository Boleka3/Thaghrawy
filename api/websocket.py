"""Streaming chat over WebSocket, now with a human-in-the-loop control channel.

A frame can be a plain chat string (legacy), a JSON control message, or a
`/slash` command (parsed into the same control messages). Two cooperating tasks
run over the persisted per-engagement agent:

  * reader  - receives frames; approval/stop/phase controls go straight to the
              agent's AgentControl (so a mid-turn approval resolves the awaiting
              tool-call prompt), everything else is queued as sequential work.
  * worker  - drains the work queue one item at a time (chat turns, human-run
              tools, …) so nothing races on the shared agent.messages history.

Events relayed to the client: memory_hit, token, tool_call, tool_call_pending,
tool_result, tool_rejected, tool_edited, finding_saved, step, stopped, phase,
help, info, done, error.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from api.deps import _get_or_create_agent
from core.agent import PentestAgent
from core.control import APPROVE, EDIT, REJECT, STOP, AgentControl

router = APIRouter()

_HELP = [
    "/approve [id] — run the pending tool call",
    "/reject [id] — decline it; the model re-plans",
    "/edit [id] {json} — run it with corrected arguments",
    "/run <tool> {json} — run a tool yourself; result is fed to the model",
    "/suggest — ask the model for the next step",
    "/draft [ref] — ask the model to draft a finding from a result",
    "/promote <ref> — turn a scanner result into a finding",
    "/enumerate — run the autonomous enumeration sweep + auto-ingest findings",
    "/phase collab|report — advance the workflow phase",
    "/auto off|safe|all — change what auto-approves this turn",
    "/report — generate both reports",
    "/stop — halt the current turn",
    "/help — show this list",
]

_PHASE_ALIASES = {
    "collab": "collaboration",
    "collaboration": "collaboration",
    "enum": "enumeration",
    "enumeration": "enumeration",
    "report": "reporting",
    "reporting": "reporting",
}


def _parse_slash(raw: str) -> dict[str, Any]:
    """Map a `/command ...` string to a control-message dict."""
    body = raw[1:].strip()
    parts = body.split(maxsplit=1)
    cmd = parts[0].lower() if parts else ""
    rest = parts[1].strip() if len(parts) > 1 else ""

    def _json_tail(text: str) -> tuple[str, dict[str, Any]]:
        """Split '<token> {json}' or '{json}' into (token, parsed-json)."""
        text = text.strip()
        token, obj = "", {}
        if text.startswith("{"):
            payload = text
        else:
            bits = text.split(maxsplit=1)
            token = bits[0]
            payload = bits[1].strip() if len(bits) > 1 else "{}"
        try:
            obj = json.loads(payload) if payload else {}
        except json.JSONDecodeError:
            obj = {}
        return token, obj

    if cmd in ("approve", "reject"):
        msg = {"type": cmd}
        if rest:
            msg["id"] = rest
        return msg
    if cmd == "edit":
        cid, args = _json_tail(rest)
        return {"type": EDIT, "id": cid or None, "arguments": args}
    if cmd == "run":
        tool, args = _json_tail(rest)
        return {"type": "run_tool", "tool": tool, "arguments": args}
    if cmd == "suggest":
        return {"type": "ask", "mode": "suggest_next"}
    if cmd == "draft":
        return {"type": "ask", "mode": "draft_finding", "ref": rest or None}
    if cmd == "promote":
        return {"type": "promote", "ref": rest or None}
    if cmd == "phase":
        return {"type": "set_phase", "phase": rest}
    if cmd == "auto":
        return {"type": "set_auto_approve", "mode": rest or "off"}
    if cmd == "enumerate":
        return {"type": "enumerate"}
    if cmd == "report":
        return {"type": "report"}
    if cmd == "stop":
        return {"type": STOP}
    if cmd == "help":
        return {"type": "help"}
    return {"type": "chat", "text": raw}


def _parse_frame(raw: str) -> dict[str, Any]:
    text = raw.strip()
    if text.startswith("{"):
        try:
            msg = json.loads(text)
            if isinstance(msg, dict) and "type" in msg:
                return msg
        except json.JSONDecodeError:
            pass
    if text.startswith("/"):
        return _parse_slash(text)
    return {"type": "chat", "text": raw}


_CONTROL_TYPES = {APPROVE, REJECT, EDIT, "set_auto_approve"}


async def _handle_work(
    ws: WebSocket, agent: PentestAgent, control: AgentControl, msg: dict[str, Any]
) -> None:
    """Process one queued work item (anything that touches agent state)."""
    mtype = msg.get("type")

    if mtype == "chat":
        control.begin_turn()
        async for event in agent.chat(msg.get("text", ""), control):
            await ws.send_json(event)
        return

    if mtype == "run_tool":
        name = msg.get("tool") or ""
        args = msg.get("arguments") or {}
        result = await agent.registry.execute(name, args)
        await ws.send_json({"type": "tool_result", "tool": name, "output": result, "source": "human"})
        # Inject what the operator did so the model sees it on the next turn.
        agent.messages.append({
            "role": "user",
            "content": f"[operator ran {name} {json.dumps(args)}]\nResult:\n"
            + agent.context.summarize_tool_output(str(result)),
        })
        if isinstance(result, dict) and result.get("status") == "saved":
            await ws.send_json({"type": "finding_saved", "finding": args})
        return

    if mtype == "enumerate":
        control.begin_turn()
        async for event in agent.enumerate():
            await ws.send_json(event)
        return

    if mtype == "report":
        result = await agent.registry.execute("generate_report", {"engagement_id": agent.engagement_id})
        control.set_phase("reporting")
        if agent.engagement_manager is not None:
            try:
                agent.engagement_manager.update(agent.engagement_id, phase="reporting")
            except Exception:
                pass
        await ws.send_json({"type": "phase", "phase": "reporting"})
        await ws.send_json({"type": "report_ready", "reports": result})
        return

    if mtype == "help":
        await ws.send_json({"type": "help", "commands": _HELP})
        return

    # ask / promote are wired in later parts of the HITL work.
    await ws.send_json({"type": "info", "message": f"'{mtype}' is not available yet"})


@router.websocket("/ws/chat")
async def websocket_chat(websocket: WebSocket, engagement_id: str) -> None:
    await websocket.accept()
    agent = _get_or_create_agent(websocket.app.state, engagement_id)
    control = agent.control or AgentControl()
    agent.control = control
    work: "asyncio.Queue[dict[str, Any]]" = asyncio.Queue()

    async def reader() -> None:
        while True:
            raw = await websocket.receive_text()
            msg = _parse_frame(raw)
            mtype = msg.get("type")
            if mtype in _CONTROL_TYPES:
                control.push(msg)
            elif mtype == STOP:
                control.request_stop()
            elif mtype == "set_phase":
                control.set_phase(_PHASE_ALIASES.get(str(msg.get("phase", "")).lower(), control.phase))
                await websocket.send_json({"type": "phase", "phase": control.phase})
            else:
                await work.put(msg)

    async def worker() -> None:
        while True:
            msg = await work.get()
            try:
                await _handle_work(websocket, agent, control, msg)
            except Exception as e:  # never let one bad turn kill the socket
                await websocket.send_json({"type": "error", "message": str(e)})

    reader_task = asyncio.create_task(reader())
    worker_task = asyncio.create_task(worker())
    try:
        await reader_task
    except WebSocketDisconnect:
        pass
    finally:
        for task in (reader_task, worker_task):
            task.cancel()
        await asyncio.gather(reader_task, worker_task, return_exceptions=True)
