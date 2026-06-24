"""System prompt construction. core/agent.py calls build_system_prompt()
once per turn - this is the single place memory context gets injected."""
from __future__ import annotations

from typing import Any, Optional

BASE_PROMPT = "You are RedTeam AI, an autonomous AI penetration testing assistant."

MEMORY_INSTRUCTIONS = """
You have persistent memory across engagements. Before answering any technical
question, call search_memory to check whether we've encountered a similar
vulnerability or used a relevant technique before. When you discover a new
finding or learn a new technique, call save_finding or save_technique to
persist it for future engagements. When memory search returns hits, reference
them explicitly, e.g. "In engagement X, we found a similar IDOR pattern on...".
""".strip()

DEFAULT_CONSTRAINTS = [
    "Operate only within the defined engagement scope.",
    "Do not hallucinate findings - every finding must be backed by tool output evidence.",
    "Prefer calling a tool over guessing when you need live information about the target.",
]


class SystemPromptBuilder:
    """Builds the system prompt for a single agent turn: target scope,
    constraints, retrieved memory, and any extra context blocks."""

    def __init__(self, target: str):
        self.target = target
        self.constraints: list[str] = list(DEFAULT_CONSTRAINTS)
        self.memory_notes: list[str] = []
        self.extra_sections: list[str] = []

    def add_constraint(self, rule: str) -> None:
        self.constraints.append(rule)

    def add_memory_note(self, note: str) -> None:
        self.memory_notes.append(note)

    def add_memory_hits(self, findings: list[dict[str, Any]], techniques: list[dict[str, Any]]) -> None:
        for f in findings:
            meta = f.get("metadata", {})
            self.memory_notes.append(
                f"[past finding, similarity={f.get('similarity', 0):.2f}] "
                f"{meta.get('title', f.get('id', 'unknown'))} "
                f"({meta.get('severity', '?')}, {meta.get('vuln_type', '?')}) "
                f"on engagement {meta.get('engagement_id', '?')}: {f.get('document', '')[:200]}"
            )
        for t in techniques:
            meta = t.get("metadata", {})
            self.memory_notes.append(
                f"[past technique, similarity={t.get('similarity', 0):.2f}] "
                f"{meta.get('name', t.get('id', 'unknown'))} "
                f"(works against: {meta.get('works_against', '?')}): {t.get('document', '')[:200]}"
            )

    def add_section(self, text: str) -> None:
        self.extra_sections.append(text)

    def build(self) -> str:
        sections = [
            BASE_PROMPT,
            MEMORY_INSTRUCTIONS,
            f"\nSCOPE: {self.target}",
            "\nCONSTRAINTS:",
            "\n".join(f"- {c}" for c in self.constraints),
            "\nRELEVANT PAST FINDINGS/TECHNIQUES:",
            "\n".join(self.memory_notes) if self.memory_notes else "No relevant memory found for this query.",
        ]
        sections.extend(self.extra_sections)
        return "\n".join(sections)


def build_system_prompt(
    target: str,
    memory_hits: Optional[dict[str, list[dict[str, Any]]]] = None,
    extra_sections: Optional[list[str]] = None,
) -> str:
    """Convenience wrapper used by core/agent.py."""
    builder = SystemPromptBuilder(target)
    if memory_hits:
        builder.add_memory_hits(memory_hits.get("findings", []), memory_hits.get("techniques", []))
    for section in extra_sections or []:
        builder.add_section(section)
    return builder.build()
