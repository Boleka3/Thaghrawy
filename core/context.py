"""Context window management: keeps the running conversation under a
character budget so long recon/exploit tool output doesn't blow the
context window. Uses a conservative chars-per-token heuristic rather than
a real tokenizer - good enough to bound growth, not exact accounting."""
from __future__ import annotations

from typing import Any, Optional

import config


class ContextManager:
    def __init__(self, max_chars: Optional[int] = None):
        self.max_chars = max_chars or config.MAX_CONTEXT_CHARS

    @staticmethod
    def _size(messages: list[dict[str, Any]]) -> int:
        return sum(len(str(m.get("content", ""))) for m in messages)

    @staticmethod
    def _is_orphan_head(message: dict[str, Any]) -> bool:
        """A leading message that can't validly start a window handed to the
        model: a `tool` result (its `assistant` tool_call turn was trimmed away)
        or an `assistant` message that itself carries `tool_calls`. Some model
        chat templates (notably weak local LM Studio models) fail to render a
        conversation that opens on one of these — e.g. "No user query found in
        messages"."""
        role = message.get("role")
        return role == "tool" or (role == "assistant" and bool(message.get("tool_calls")))

    def trim(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Drop oldest turns until under budget, then drop any leading orphan
        tool/tool-call messages so the window starts on a clean user/assistant
        turn. Always keeps the most recent message so the conversation can still
        proceed."""
        trimmed = list(messages)
        while len(trimmed) > 1 and self._size(trimmed) > self.max_chars:
            trimmed.pop(0)
        # Never open the window on an orphaned tool result / dangling tool-call.
        while len(trimmed) > 1 and self._is_orphan_head(trimmed[0]):
            trimmed.pop(0)
        return trimmed

    @staticmethod
    def summarize_tool_output(output: str, max_chars: int = 1500) -> str:
        """Truncate large tool output before it enters conversation history."""
        if len(output) <= max_chars:
            return output
        half = max_chars // 2
        return f"{output[:half]}\n\n[...TRUNCATED...]\n\n{output[-half:]}"
