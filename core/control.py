"""Human-in-the-loop control channel.

The chat WebSocket is normally a one-way stream: the agent loop only *yields*
events, so a human can't touch a turn once it starts. `AgentControl` is the
bridge that changes that. The WebSocket reader task pushes human control
messages here (approve / reject / edit / stop / auto-approve); the agent loop
awaits a decision at each tool-approval point. It also carries the per-engagement
interaction state - workflow phase and auto-approve mode - so the approval gate
can decide, per call, whether to pause.

See core/agent.py (the awaiting side) and api/websocket.py (the pushing side).
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Optional

import config

# Decision actions returned to the agent loop.
APPROVE = "approve"
REJECT = "reject"
EDIT = "edit"
STOP = "stop"


@dataclass
class Decision:
    """The outcome of a human approval prompt for one pending tool call."""

    action: str  # one of APPROVE / REJECT / EDIT / STOP
    arguments: Optional[dict[str, Any]] = None  # replacement args when action == EDIT


class AgentControl:
    """Per-engagement human-in-the-loop state + an inbound control-message queue.

    A single instance is attached to the persisted per-engagement agent
    (see api/deps.py) so it survives across turns.
    """

    def __init__(
        self,
        phase: str = "enumeration",
        approval_mode: Optional[str] = None,
    ) -> None:
        self._queue: "asyncio.Queue[dict[str, Any]]" = asyncio.Queue()
        self.phase = phase
        # all | dangerous | off  (governs the collaboration phase only)
        self.approval_mode = (approval_mode or config.HUMAN_APPROVAL_MODE).lower()
        # off | safe | all  (human escape hatch to stop clicking mid-turn)
        self.auto_approve = "off"
        self.stopped = False

    # ── inbound (WebSocket reader side) ──

    def push(self, msg: dict[str, Any]) -> None:
        """Enqueue a control message for the awaiting agent loop."""
        self._queue.put_nowait(msg)

    def request_stop(self) -> None:
        self.stopped = True
        self.push({"type": STOP})

    def set_phase(self, phase: str) -> None:
        self.phase = phase

    def begin_turn(self) -> None:
        """Reset per-turn state before a new chat turn: clear a stale stop and
        drain any leftover control messages so a click meant for a previous turn
        can't resolve the wrong prompt."""
        self.stopped = False
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break

    # ── gate policy ──

    def needs_approval(self, *, dangerous: bool) -> bool:
        """Whether a tool call should pause for human approval right now."""
        if self.phase != "collaboration":
            return False  # enumeration/reporting run approval-free
        if self.auto_approve == "all":
            return False
        if self.auto_approve == "safe" and not dangerous:
            return False
        if self.approval_mode == "off":
            return False
        if self.approval_mode == "dangerous":
            return dangerous
        return True  # approval_mode == "all"

    # ── awaiting (agent-loop side) ──

    async def await_decision(self, call_id: str, *, dangerous: bool) -> Decision:
        """Block until a decision for this pending tool call arrives.

        Recognizes approve/reject/edit/stop and mid-wait auto-approve changes.
        Messages carrying an `id` that doesn't match `call_id` are ignored so a
        stale click for an earlier call can't resolve the wrong prompt.
        """
        while True:
            msg = await self._queue.get()
            mtype = msg.get("type")

            if mtype == STOP:
                self.stopped = True
                return Decision(STOP)

            if mtype == "set_auto_approve":
                self.auto_approve = str(msg.get("mode", "off")).lower()
                if not self.needs_approval(dangerous=dangerous):
                    return Decision(APPROVE)
                continue

            if mtype in (APPROVE, REJECT, EDIT):
                mid = msg.get("id")
                if mid is not None and str(mid) != str(call_id):
                    continue  # decision for a different call
                if mtype == EDIT:
                    return Decision(EDIT, msg.get("arguments") or {})
                return Decision(mtype)

            # chat / run_tool / ask etc. are handled by the WS runner, not here.
