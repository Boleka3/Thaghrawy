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
tool_result, tool_rejected, tool_edited, finding_draft, finding_saved, step,
stopped, phase, help, info, done, error.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from api.deps import _get_or_create_agent
from core.agent import PentestAgent
from core.control import APPROVE, EDIT, REJECT, STOP, AgentControl
from core.finding_drafts import finding_from_tool_result, flag_findings_from_output

logger = logging.getLogger(__name__)

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
    "/tools — list available tools",
    "/compact — summarize + shrink the session context",
    "/interrupt <text> — halt the current turn and send new instructions",
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
    if cmd == "tools":
        return {"type": "list_tools"}
    if cmd == "compact":
        return {"type": "compact"}
    if cmd == "interrupt":
        return {"type": "interrupt", "text": rest}
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

# Event types worth persisting to the engagement transcript for replay. Streaming
# tokens are aggregated into a single `agent_message` instead (see _Emitter); the
# `user` line is written separately. Transient UI-only events (memory_hit, step,
# tool_call_pending, help, tools) are not persisted.
_PERSIST_TYPES = {
    "tool_call", "tool_result", "tool_edited", "tool_rejected", "finding_saved",
    "handoff", "phase", "report_ready", "assistant_suggestion", "info", "error",
}


def _user_echo(msg: dict[str, Any]) -> str | None:
    """A friendly one-line echo of what the operator did, for the transcript, so
    a replayed conversation shows the human's side. None for items with no echo."""
    t = msg.get("type")
    if t == "chat":
        return msg.get("text", "")
    if t == "ask":
        return "/draft" if msg.get("mode") == "draft_finding" else "/suggest"
    if t == "promote":
        ref = msg.get("ref")
        return f"/promote {ref}" if ref else "/promote"
    if t == "run_tool":
        return f"/run {msg.get('tool', '')} {json.dumps(msg.get('arguments') or {})}".rstrip()
    if t == "enumerate":
        return "/enumerate"
    if t == "report":
        return "/report"
    return None


class _Emitter:
    """Sends events to the browser and persists a curated subset to the
    engagement transcript so the chat can be restored on reselect/reload.

    Streamed model tokens are buffered and flushed as one `agent_message` (never
    sent — the live tokens already were). Also remembers the last tool_result so
    `/promote` can act on it."""

    def __init__(self, ws: WebSocket, agent: PentestAgent) -> None:
        self._ws = ws
        self._manager = agent.engagement_manager
        self._eid = agent.engagement_id
        self._buf: list[str] = []
        self.last_tool: tuple[str, Any] | None = None

    def _persist(self, event: dict[str, Any]) -> None:
        if self._manager is not None:
            self._manager.append_chat_event(self._eid, event)

    def flush(self) -> None:
        """Persist any buffered streamed model text as a single agent_message."""
        if self._buf:
            text = "".join(self._buf)
            self._buf = []
            if text.strip():
                self._persist({"type": "agent_message", "content": text})

    def persist_user(self, text: str) -> None:
        if text:
            self._persist({"type": "user", "text": text})

    async def __call__(self, event: dict[str, Any]) -> None:
        await self._ws.send_json(event)
        etype = event.get("type")
        if etype == "token":
            self._buf.append(event.get("content", ""))
            return
        # Any non-token event ends the current streamed assistant run.
        self.flush()
        if etype == "tool_result":
            self.last_tool = (event.get("tool", ""), event.get("output"))
        if etype in _PERSIST_TYPES:
            self._persist(event)


async def _handle_work(
    emit: _Emitter, agent: PentestAgent, control: AgentControl, msg: dict[str, Any]
) -> None:
    """Process one queued work item (anything that touches agent state)."""
    mtype = msg.get("type")

    echo = _user_echo(msg)
    if echo is not None:
        emit.persist_user(echo)

    if mtype == "chat":
        control.begin_turn()
        async for event in agent.chat(msg.get("text", ""), control):
            await emit(event)
        emit.flush()
        return

    if mtype == "ask":
        # /suggest and /draft: a plain model turn with a synthesized instruction,
        # no tools expected. Streams like any chat turn.
        if msg.get("mode") == "draft_finding":
            prompt = (
                "Draft a single finding from the most recent tool result: give a title, "
                "severity, vuln_type, affected component, and remediation. Do not call any tools."
            )
        else:
            prompt = (
                "Suggest the single best next step for this engagement given the "
                "conversation so far. Be concise. Do not call any tools."
            )
        control.begin_turn()
        async for event in agent.chat(prompt, control):
            await emit(event)
        emit.flush()
        return

    if mtype == "promote":
        # Turn the most recent tool result into finding(s) the same way the UI's
        # →finding button does, then persist them via the shared save path.
        if emit.last_tool is None:
            await emit({"type": "info",
                        "message": "No recent tool result to promote — run a scanner first, then /promote."})
            return
        tool_name, output = emit.last_tool
        drafts = finding_from_tool_result(tool_name, output, agent.engagement_id, agent.target)
        if not drafts:
            await emit({"type": "info", "message": f"No findings derivable from the last {tool_name} result."})
            return
        for draft in drafts:
            await agent.registry.execute("save_finding", {"finding": draft.model_dump()})
            await emit({"type": "finding_saved", "finding": {"title": draft.title, "vuln_type": draft.vuln_type}})
        return

    if mtype == "run_tool":
        name = msg.get("tool") or ""
        args = msg.get("arguments") or {}
        result = await agent.registry.execute(name, args)
        await emit({"type": "tool_result", "tool": name, "output": result, "source": "human"})
        # Flag/secret detection for human-run tools
        for draft in flag_findings_from_output(name, result, agent.engagement_id, agent.target):
            match = draft.description.split(": ", 1)[-1] if ": " in draft.description else ""
            if match and match not in agent._captured_flags:
                agent._captured_flags.add(match)
                await emit({
                    "type": "finding_draft",
                    "draft": draft.model_dump(),
                    "note": f"flag/secret detected in {name} output",
                })
        # Inject what the operator did so the model sees it on the next turn.
        agent.messages.append({
            "role": "user",
            "content": f"[operator ran {name} {json.dumps(args)}]\nResult:\n"
            + agent.context.summarize_tool_output(str(result)),
        })
        if isinstance(result, dict) and result.get("status") == "saved":
            await emit({"type": "finding_saved", "finding": args})
        return

    if mtype == "enumerate":
        control.begin_turn()
        async for event in agent.enumerate():
            await emit(event)
        emit.flush()
        return

    if mtype == "report":
        result = await agent.registry.execute("generate_report", {"engagement_id": agent.engagement_id})
        control.set_phase("reporting")
        if agent.engagement_manager is not None:
            try:
                agent.engagement_manager.update(agent.engagement_id, phase="reporting")
            except Exception as exc:
                logger.warning("Failed to update engagement phase to reporting: %s", exc)
        await emit({"type": "phase", "phase": "reporting"})
        await emit({"type": "report_ready", "reports": result})
        return

    if mtype == "list_tools":
        tools = [
            {"name": name, "description": tool.description, "dangerous": tool.dangerous}
            for name, tool in sorted(
                ((n, agent.registry.get(n)) for n in agent.registry.names()),
                key=lambda pair: pair[0],
            )
            if tool is not None
        ]
        await emit({"type": "tools", "tools": tools})
        return

    if mtype == "compact":
        # Deterministically shrink the agent's context, then replace the
        # persisted transcript with a single summary marker so a reload shows the
        # compacted view. Sent (not emit-persisted) to avoid duplicating it.
        recap = agent.compact()
        if agent.engagement_manager is not None:
            agent.engagement_manager.overwrite_chat_events(
                agent.engagement_id, [{"type": "compacted", "summary": recap}])
        await emit({"type": "compacted", "summary": recap})  # not in _PERSIST_TYPES → send only
        return

    if mtype == "help":
        await emit({"type": "help", "commands": _HELP})
        return

    await emit({"type": "info", "message": f"'{mtype}' is not available yet"})


@router.websocket("/ws/chat")
async def websocket_chat(websocket: WebSocket, engagement_id: str) -> None:
    await websocket.accept()
    agent = _get_or_create_agent(websocket.app.state, engagement_id)
    control = agent.control or AgentControl()
    agent.control = control
    emit = _Emitter(websocket, agent)
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
            elif mtype == "interrupt":
                # Halt the in-flight turn, then queue the operator's new
                # instruction as the next turn (begin_turn clears the stop).
                control.request_stop()
                text = str(msg.get("text", "")).strip()
                if text:
                    await work.put({"type": "chat", "text": text})
            elif mtype == "set_phase":
                control.set_phase(_PHASE_ALIASES.get(str(msg.get("phase", "")).lower(), control.phase))
                await emit({"type": "phase", "phase": control.phase})
            else:
                await work.put(msg)

    async def worker() -> None:
        while True:
            msg = await work.get()
            try:
                await _handle_work(emit, agent, control, msg)
            except Exception as e:  # never let one bad turn kill the socket
                await emit({"type": "error", "message": str(e)})

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
