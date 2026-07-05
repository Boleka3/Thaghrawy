"""Main agent loop: a real tool-calling ReAct loop (unlike the original
4-phase linear pipeline this replaces). Streams normalized events suitable
for direct relay over the chat WebSocket - see api/websocket.py.
"""
from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, Any, AsyncIterator, Callable, Optional

import logging

import config
from core.context import ContextManager
from core.control import EDIT, REJECT, STOP, AgentControl
from core.finding_drafts import flag_findings_from_output
from core.llm import BaseLLMProvider, get_provider
from core.tools import ToolRegistry, build_default_registry
from memory.store import MemoryStore
from prompt_builder import build_system_prompt

logger = logging.getLogger(__name__)


def _strip_hash_from_urls(value: Any) -> Any:
    """Recursively strip #hash fragments from any string that looks like a URL.
    Scanner tools choke on hash-fragment URLs (the # part is never sent to the
    server), so strip them before forwarding to tools.
    """
    if isinstance(value, str):
        return re.sub(r"^((?:https?://)[^#]+)#.*", r"\1", value)
    if isinstance(value, dict):
        return {k: _strip_hash_from_urls(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return list(_strip_hash_from_urls(v) for v in value)
    return value


if TYPE_CHECKING:
    from engagements.manager import EngagementManager

MAX_TOOL_ITERATIONS = config.MAX_TOOL_ITERATIONS

# When the model emits several independent tool calls in one step, run them
# concurrently up to this fan-out instead of one-at-a-time — recon fan-outs
# (several nuclei/httpx/curl probes) then finish in ~max(latency) rather than
# the sum. Ported from the reference agent's MAX_PARALLEL_TOOL_CALLS ("E1").
MAX_PARALLEL_TOOL_CALLS = 4
# Tools whose handler reads-then-writes shared state that a sibling call in the
# SAME step could race (save_finding/save_technique both dedup against existing
# findings before writing). A step containing one of these falls back to
# sequential execution so ordering and dedup stay deterministic.
STATEFUL_TOOLS = frozenset({"save_finding", "save_technique"})
# Cap read_file calls per turn so the model can't burn the tool budget re-reading
# output that scanners already returned into context.
MAX_READ_FILE_PER_TURN = 3

MEMORY_EXTRA_SECTION = (
    "\nWhen search_memory returns hits above your judgment of relevance, weave them "
    "into your reasoning before proposing next steps."
)


class PentestAgent:
    def __init__(
        self,
        engagement_id: str,
        target: str,
        memory: Optional[MemoryStore] = None,
        registry: Optional[ToolRegistry] = None,
        provider: Optional[BaseLLMProvider] = None,
        engagement_manager: Optional["EngagementManager"] = None,
        control: Optional[AgentControl] = None,
        on_decision: Optional[Callable[[dict[str, Any]], None]] = None,
    ):
        self.engagement_id = engagement_id
        self.target = target
        self.memory = memory or MemoryStore()
        self.registry = registry or build_default_registry(self.memory, engagement_id)
        self.provider = provider or get_provider()
        self.context = ContextManager()
        self.engagement_manager = engagement_manager
        # Human-in-the-loop control channel (None = fully autonomous, legacy behavior).
        self.control = control
        # Best-effort sink for structured HITL decision records (training data).
        self.on_decision = on_decision
        self._captured_flags: set[str] = set()
        self.messages: list[dict[str, Any]] = []

    def _record_decision(
        self,
        call: dict[str, Any],
        verdict: str,
        arguments: dict[str, Any],
        result: Any,
    ) -> None:
        """Emit a structured trajectory record (proposed call + human verdict +
        outcome) to the optional sink. Best-effort: never breaks the turn."""
        if self.on_decision is None:
            return
        try:
            self.on_decision({
                "engagement_id": self.engagement_id,
                "tool": call["name"],
                "proposed_arguments": call.get("arguments"),
                "verdict": verdict,
                "final_arguments": arguments,
                "rejected": verdict == REJECT,
                "result": result,
            })
        except Exception as exc:
            logger.warning("on_decision callback failed: %s", exc)

    def _record_steps(self, steps: int) -> None:
        """Persist this turn's step count for the AST metric. Best-effort: a
        persistence failure (e.g. unknown engagement) never breaks the turn."""
        try:
            manager = self.engagement_manager
            if manager is None:
                from engagements.manager import EngagementManager
                manager = EngagementManager()
            manager.record_steps(self.engagement_id, steps)
        except Exception as exc:
            logger.warning("record_steps failed: %s", exc)

    def _is_dangerous(self, name: str) -> bool:
        tool = self.registry.get(name)
        return bool(tool and tool.dangerous)

    def _check_read_file_cap(
        self, call: dict[str, Any]
    ) -> Optional[tuple[dict[str, Any], dict[str, Any]]]:
        """Enforce the per-turn read_file budget. Returns None to allow the call,
        or a (tool_result_event, tool_message) pair to skip it once the cap is
        hit. Increments self._read_file_count. Shared by the sequential and
        parallel execution paths so the budget can't diverge between them."""
        if call["name"] != "read_file":
            return None
        self._read_file_count += 1
        if self._read_file_count <= MAX_READ_FILE_PER_TURN:
            return None
        result = {
            "status": "error",
            "error": f"Read-file limit ({MAX_READ_FILE_PER_TURN}) hit — "
            "tool output was already returned above; read_file is unnecessary.",
        }
        event = {"type": "tool_result", "tool": call["name"], "output": result}
        message = {
            "role": "tool",
            "tool_call_id": call["id"],
            "name": call["name"],
            "content": "[read_file skipped: limit reached. Use the scanner output already in context.]",
        }
        return event, message

    async def _postprocess_result(
        self, call: dict[str, Any], arguments: dict[str, Any], result: Any, verdict: str
    ) -> AsyncIterator[dict[str, Any]]:
        """Emit the post-execution events for one tool call, append its tool
        message to history, and record the HITL decision. Shared by the
        sequential and parallel paths so the per-call side effects stay
        identical regardless of how the call was scheduled."""
        self._step_count += 1
        yield {"type": "step", "count": self._step_count, "tool": call["name"]}
        yield {"type": "tool_result", "tool": call["name"], "output": result}

        # Flag/secret detection — propose drafts, don't auto-save.
        for draft in flag_findings_from_output(call["name"], result, self.engagement_id, self.target):
            match = draft.description.split(": ", 1)[-1] if ": " in draft.description else ""
            if match and match not in self._captured_flags:
                self._captured_flags.add(match)
                yield {
                    "type": "finding_draft",
                    "draft": draft.model_dump(),
                    "note": f"flag/secret detected in {call['name']} output",
                }

        is_save = call["name"] in ("save_finding", "save_technique")
        if is_save and isinstance(result, dict) and result.get("status") == "saved":
            yield {"type": "finding_saved", "finding": arguments}

        self.messages.append({
            "role": "tool",
            "tool_call_id": call["id"],
            "name": call["name"],
            "content": self.context.summarize_tool_output(str(result)),
        })
        self._record_decision(call, verdict, arguments, result)

    async def _gather_calls(
        self, prepared: list[tuple[dict[str, Any], dict[str, Any], Optional[Any]]]
    ) -> list[Any]:
        """Execute the non-skipped prepared calls concurrently, bounded by
        MAX_PARALLEL_TOOL_CALLS, returning results in input order. Skipped calls
        (read_file over budget) map to None. registry.execute() folds tool
        exceptions into a structured error result, so gather never raises."""
        sem = asyncio.Semaphore(MAX_PARALLEL_TOOL_CALLS)

        async def _run(call: dict[str, Any], arguments: dict[str, Any], skip: Optional[Any]) -> Any:
            if skip is not None:
                return None
            async with sem:
                return await self.registry.execute(call["name"], arguments)

        return await asyncio.gather(*(_run(c, a, s) for c, a, s in prepared))

    async def _run_sequential(
        self, pending_tool_calls: list[dict[str, Any]], control: Optional[AgentControl]
    ) -> AsyncIterator[dict[str, Any]]:
        """One-at-a-time execution. Used whenever a step needs serialization —
        a human approval gate, a stateful tool, or a lone call — and drives the
        interactive approve/reject/edit/stop modal. Behaviorally identical to the
        original in-line loop."""
        for call in pending_tool_calls:
            if control is not None and control.stopped:
                return

            arguments = call["arguments"]
            dangerous = self._is_dangerous(call["name"])
            verdict = "auto"

            if control is not None and control.needs_approval(dangerous=dangerous):
                yield {
                    "type": "tool_call_pending",
                    "id": call["id"],
                    "tool": call["name"],
                    "arguments": arguments,
                    "dangerous": dangerous,
                }
                decision = await control.await_decision(call["id"], dangerous=dangerous)
                verdict = decision.action
                if decision.action == STOP:
                    yield {"type": "stopped", "reason": "human"}
                    self._record_decision(call, STOP, arguments, None)
                    return
                if decision.action == REJECT:
                    yield {"type": "tool_rejected", "id": call["id"], "tool": call["name"]}
                    self.messages.append({
                        "role": "tool",
                        "tool_call_id": call["id"],
                        "name": call["name"],
                        "content": "[rejected by human] The operator declined this "
                        "tool call. Reconsider and propose a different approach.",
                    })
                    self._record_decision(call, REJECT, arguments, None)
                    continue
                if decision.action == EDIT and decision.arguments:
                    arguments = decision.arguments
                    yield {
                        "type": "tool_edited",
                        "id": call["id"],
                        "tool": call["name"],
                        "arguments": arguments,
                    }

            # Strip URL hash fragments — scanners choke on #/path?q= URLs
            arguments = _strip_hash_from_urls(arguments)

            cap = self._check_read_file_cap(call)
            if cap is not None:
                event, message = cap
                yield event
                self.messages.append(message)
                continue

            result = await self.registry.execute(call["name"], arguments)
            async for ev in self._postprocess_result(call, arguments, result, verdict):
                yield ev

    async def _run_parallel(
        self, pending_tool_calls: list[dict[str, Any]], control: Optional[AgentControl]
    ) -> AsyncIterator[dict[str, Any]]:
        """Concurrent execution for an un-gated, stateless, multi-call step. Args
        are finalized and the read_file budget applied in a deterministic
        pre-pass; calls then execute together (bounded by MAX_PARALLEL_TOOL_CALLS)
        while events are emitted in input order so history stays deterministic."""
        if control is not None and control.stopped:
            return

        prepared: list[tuple[dict[str, Any], dict[str, Any], Optional[Any]]] = []
        for call in pending_tool_calls:
            arguments = _strip_hash_from_urls(call["arguments"])
            skip = self._check_read_file_cap(call)
            prepared.append((call, arguments, skip))

        results = await self._gather_calls(prepared)

        for (call, arguments, skip), result in zip(prepared, results):
            if skip is not None:
                event, message = skip
                yield event
                self.messages.append(message)
                continue
            async for ev in self._postprocess_result(call, arguments, result, "auto"):
                yield ev

    # Deterministic recon probes run during autonomous enumeration. Kept small
    # and reliable: nuclei is the richest structured source of easy misconfig /
    # CVE / exposure findings and is a recon-tier tool (present even in
    # recon_only registries).
    ENUMERATION_PROBES: list[tuple[str, dict[str, Any]]] = [
        ("nuclei_scan", {}),
        ("headers_audit", {}),
    ]

    async def enumerate(self) -> AsyncIterator[dict[str, Any]]:
        """Autonomous enumeration phase: run recon probes against the target and
        auto-ingest the easy structured findings (no LLM, no approvals), then
        hand off to the human for collaboration. Yields tool_call / tool_result /
        finding_saved / handoff / done events."""
        from core.finding_drafts import finding_from_tool_result
        from core.tools import persist_finding

        yield {"type": "phase", "phase": "enumeration"}
        saved = 0
        for tool_name, extra in self.ENUMERATION_PROBES:
            if self.registry.get(tool_name) is None:
                continue
            args = {"target": self.target, **extra}
            yield {"type": "tool_call", "tool": tool_name, "command": args}
            result = await self.registry.execute(tool_name, args)
            yield {"type": "tool_result", "tool": tool_name, "output": result}
            for finding in finding_from_tool_result(tool_name, result, self.engagement_id, self.target):
                try:
                    persist_finding(self.memory, finding, self.engagement_manager)
                    saved += 1
                    yield {"type": "finding_saved", "finding": finding.model_dump()}
                except Exception as e:  # one bad finding shouldn't abort enumeration
                    yield {"type": "error", "message": f"auto-ingest failed: {e}"}

        # Flip to the collaboration phase so the human takes over with approvals on.
        if self.control is not None:
            self.control.set_phase("collaboration")
        if self.engagement_manager is not None:
            try:
                self.engagement_manager.update(self.engagement_id, phase="collaboration")
            except Exception as exc:
                logger.warning("Failed to update engagement phase to collaboration: %s", exc)
        yield {
            "type": "handoff",
            "findings_saved": saved,
            "phase": "collaboration",
            "message": (
                f"Autonomous enumeration complete — {saved} finding(s) auto-ingested. "
                "Handing off: review them, then drive the exploitation phase together "
                "(every tool call now asks for your approval). Type /help for commands."
            ),
        }
        yield {"type": "done", "steps": len(self.ENUMERATION_PROBES)}

    async def chat(
        self, user_input: str, control: Optional[AgentControl] = None
    ) -> AsyncIterator[dict[str, Any]]:
        """Drive one user turn through the ReAct loop, yielding streaming events:
        memory_hit, token, tool_call, tool_call_pending, tool_result,
        finding_saved, stopped, done, error.

        If a control channel is present (self.control or the `control` arg), tool
        calls may pause for human approve/reject/edit during the collaboration
        phase; without one the loop runs fully autonomously (legacy behavior)."""
        control = control or self.control
        try:
            memory_hits = self.memory.search_context(user_input, engagement_id=self.engagement_id)
        except Exception as e:
            memory_hits = {"findings": [], "techniques": []}
            yield {"type": "error", "message": f"Memory search failed: {e}"}

        for hit in memory_hits.get("findings", []) + memory_hits.get("techniques", []):
            yield {"type": "memory_hit", "data": hit}

        system_prompt = build_system_prompt(self.target, memory_hits=memory_hits, extra_sections=[MEMORY_EXTRA_SECTION])

        self.messages.append({"role": "user", "content": user_input})
        self.messages = self.context.trim(self.messages)

        self._step_count = 0
        self._read_file_count = 0
        for _ in range(MAX_TOOL_ITERATIONS):
            assistant_text = ""
            pending_tool_calls: list[dict[str, Any]] = []

            try:
                async for event in self.provider.stream(self.messages, system_prompt, self.registry.schemas()):
                    # Preempt a running turn: an interrupt/stop cuts token
                    # generation at the next boundary rather than waiting for the
                    # whole reply (or the next tool-call gate).
                    if control is not None and control.stopped:
                        break
                    if event["type"] == "token":
                        assistant_text += event["content"]
                        yield event
                    elif event["type"] == "tool_call":
                        pending_tool_calls.append(event)
                        yield {"type": "tool_call", "tool": event["name"], "command": event["arguments"]}
            except Exception as e:
                yield {"type": "error", "message": f"LLM call failed: {e}"}
                return

            if control is not None and control.stopped:
                # Interrupted mid-generation: keep any partial text, end the turn
                # cleanly (don't run tools). The queued follow-up runs next.
                if assistant_text:
                    self.messages.append({"role": "assistant", "content": assistant_text})
                yield {"type": "stopped", "reason": "human"}
                break

            if not pending_tool_calls:
                if assistant_text:
                    self.messages.append({"role": "assistant", "content": assistant_text})
                break

            tool_calls = [
                {"id": c["id"], "name": c["name"], "arguments": c["arguments"]}
                for c in pending_tool_calls
            ]
            self.messages.append({
                "role": "assistant",
                "content": assistant_text or None,
                "tool_calls": tool_calls,
            })

            # Choose an execution strategy for this step. A batch runs
            # concurrently only when nothing forces serialization: no approval
            # gate would pause it, no stateful tool needs deterministic ordering,
            # and there's more than one call to actually overlap. Otherwise the
            # sequential path runs — it also drives the one-at-a-time human
            # approve/reject/edit/stop modal.
            gated = control is not None and any(
                control.needs_approval(dangerous=self._is_dangerous(c["name"]))
                for c in pending_tool_calls
            )
            can_parallel = (
                len(pending_tool_calls) > 1
                and not gated
                and not any(c["name"] in STATEFUL_TOOLS for c in pending_tool_calls)
            )

            runner = self._run_parallel if can_parallel else self._run_sequential
            async for event in runner(pending_tool_calls, control):
                yield event

            if control is not None and control.stopped:
                break
        else:
            limit_msg = f"Reached the {MAX_TOOL_ITERATIONS}-iteration tool-call limit for this turn."
            yield {"type": "error", "message": limit_msg}

        self._record_steps(self._step_count)
        yield {"type": "done", "steps": self._step_count}

    def compact(self) -> str:
        """Deterministically summarize the running conversation and replace the
        message history with a single compact recap. No LLM call — reliable even
        when the provider is flaky. Keeps the context small and well-formed so a
        long tool-calling turn can't blow the budget or leave a malformed window
        that breaks the model's chat template. Returns the recap text."""
        from collections import Counter

        tool_counts: Counter = Counter()
        user_msgs: list[str] = []
        findings_saved = 0
        last_assistant = ""
        for m in self.messages:
            role = m.get("role")
            if role == "user":
                content = str(m.get("content", "")).strip()
                # Skip prior compaction markers and operator-run tool echoes;
                # keep only genuine human instructions.
                if content and not content.startswith(("[Session summary", "[operator ran")):
                    user_msgs.append(content)
            elif role == "assistant":
                for call in (m.get("tool_calls") or []):
                    tool_counts[call.get("name", "?")] += 1
                text = str(m.get("content") or "").strip()
                if text:
                    last_assistant = text
            elif role == "tool":
                if m.get("name") in ("save_finding", "save_technique") and "saved" in str(m.get("content", "")):
                    findings_saved += 1

        def _trunc(s: str, n: int) -> str:
            s = " ".join(s.split())
            return s if len(s) <= n else s[:n] + "…"

        tools_line = ", ".join(f"{name}×{n}" for name, n in tool_counts.most_common()) or "none"
        instructions = " | ".join(_trunc(u, 200) for u in user_msgs[-5:]) or "(none)"
        recap = (
            "[Session summary — compacted]\n"
            f"Target: {self.target}\n"
            f"Instructions so far: {_trunc(instructions, 600)}\n"
            f"Tools run: {tools_line}\n"
            f"Findings saved this session: {findings_saved}\n"
            f"Last agent note: {_trunc(last_assistant, 500) or '(none)'}"
        )
        self.messages = [{"role": "user", "content": recap}]
        return recap
