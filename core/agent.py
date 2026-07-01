"""Main agent loop: a real tool-calling ReAct loop (unlike the original
4-phase linear pipeline this replaces). Streams normalized events suitable
for direct relay over the chat WebSocket - see api/websocket.py.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, AsyncIterator, Optional

import config
from core.context import ContextManager
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
    ):
        self.engagement_id = engagement_id
        self.target = target
        self.memory = memory or MemoryStore()
        self.registry = registry or build_default_registry(self.memory, engagement_id)
        self.provider = provider or get_provider()
        self.context = ContextManager()
        self.engagement_manager = engagement_manager
        self.messages: list[dict[str, Any]] = []

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

    async def chat(self, user_input: str) -> AsyncIterator[dict[str, Any]]:
        """Drive one user turn through the ReAct loop, yielding streaming
        events: memory_hit, token, tool_call, tool_result, finding_saved, done, error."""
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

            for call in pending_tool_calls:
                result = await self.registry.execute(call["name"], call["arguments"])
                step_count += 1
                yield {"type": "step", "count": step_count, "tool": call["name"]}
                yield {"type": "tool_result", "tool": call["name"], "output": result}

                is_save = call["name"] in ("save_finding", "save_technique")
                if is_save and isinstance(result, dict) and result.get("status") == "saved":
                    yield {"type": "finding_saved", "finding": call["arguments"]}

                self.messages.append({
                    "role": "tool",
                    "tool_call_id": call["id"],
                    "name": call["name"],
                    "content": self.context.summarize_tool_output(str(result)),
                })
        else:
            limit_msg = f"Reached the {MAX_TOOL_ITERATIONS}-iteration tool-call limit for this turn."
            yield {"type": "error", "message": limit_msg}

        self._record_steps(step_count)
        yield {"type": "done", "steps": step_count}
