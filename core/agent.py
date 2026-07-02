"""Main agent loop: a real tool-calling ReAct loop (unlike the original
4-phase linear pipeline this replaces). Streams normalized events suitable
for direct relay over the chat WebSocket - see api/websocket.py.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, AsyncIterator, Callable, Optional

import config
from core.context import ContextManager
from core.control import EDIT, REJECT, STOP, AgentControl
from core.llm import BaseLLMProvider, get_provider
from core.tools import ToolRegistry, build_default_registry
from memory.store import MemoryStore
from prompt_builder import build_system_prompt

if TYPE_CHECKING:
    from engagements.manager import EngagementManager

MAX_TOOL_ITERATIONS = config.MAX_TOOL_ITERATIONS

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
        except Exception:
            pass

    def _record_steps(self, steps: int) -> None:
        """Persist this turn's step count for the AST metric. Best-effort: a
        persistence failure (e.g. unknown engagement) never breaks the turn."""
        try:
            manager = self.engagement_manager
            if manager is None:
                from engagements.manager import EngagementManager
                manager = EngagementManager()
            manager.record_steps(self.engagement_id, steps)
        except Exception:
            pass

    # Deterministic recon probes run during autonomous enumeration. Kept small
    # and reliable: nuclei is the richest structured source of easy misconfig /
    # CVE / exposure findings and is a recon-tier tool (present even in
    # recon_only registries).
    ENUMERATION_PROBES: list[tuple[str, dict[str, Any]]] = [
        ("nuclei_scan", {}),
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
            except Exception:
                pass
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

        step_count = 0
        for _ in range(MAX_TOOL_ITERATIONS):
            assistant_text = ""
            pending_tool_calls: list[dict[str, Any]] = []

            try:
                async for event in self.provider.stream(self.messages, system_prompt, self.registry.schemas()):
                    if event["type"] == "token":
                        assistant_text += event["content"]
                        yield event
                    elif event["type"] == "tool_call":
                        pending_tool_calls.append(event)
                        yield {"type": "tool_call", "tool": event["name"], "command": event["arguments"]}
            except Exception as e:
                yield {"type": "error", "message": f"LLM call failed: {e}"}
                return

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

            stopped = False
            for call in pending_tool_calls:
                if control is not None and control.stopped:
                    stopped = True
                    break

                arguments = call["arguments"]
                tool = self.registry.get(call["name"])
                dangerous = bool(tool and tool.dangerous)
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
                        stopped = True
                        yield {"type": "stopped", "reason": "human"}
                        self._record_decision(call, STOP, arguments, None)
                        break
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

                result = await self.registry.execute(call["name"], arguments)
                step_count += 1
                yield {"type": "step", "count": step_count, "tool": call["name"]}
                yield {"type": "tool_result", "tool": call["name"], "output": result}

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

            if stopped:
                break
        else:
            limit_msg = f"Reached the {MAX_TOOL_ITERATIONS}-iteration tool-call limit for this turn."
            yield {"type": "error", "message": limit_msg}

        self._record_steps(step_count)
        yield {"type": "done", "steps": step_count}
