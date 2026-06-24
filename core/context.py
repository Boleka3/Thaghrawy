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

    def trim(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Drop oldest turns until under budget. Always keeps the most
        recent message so the conversation can still proceed."""
        if self._size(messages) <= self.max_chars:
            return messages
        trimmed = list(messages)
        while len(trimmed) > 1 and self._size(trimmed) > self.max_chars:
            trimmed.pop(0)
        return trimmed

    @staticmethod
    def summarize_tool_output(output: str, max_chars: int = 1500) -> str:
        """Truncate large tool output before it enters conversation history."""
        if len(output) <= max_chars:
            return output
        half = max_chars // 2
        return f"{output[:half]}\n\n[...TRUNCATED...]\n\n{output[-half:]}"
