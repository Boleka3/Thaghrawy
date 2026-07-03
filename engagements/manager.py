"""Engagement lifecycle: create/list/get/update/close, persisted as JSON
files under ENGAGEMENTS_DIR, each paired with a markdown session log."""
from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import config
from memory.schemas import Engagement

logger = logging.getLogger("engagements.manager")


def _normalize_target(target: str) -> str:
    """Canonical form of a target for duplicate detection: lowercased, with any
    http(s):// scheme and a trailing slash stripped, so 'https://Acme.com/',
    'http://acme.com' and 'acme.com' all collapse to the same key."""
    t = (target or "").strip().lower()
    for scheme in ("https://", "http://"):
        if t.startswith(scheme):
            t = t[len(scheme):]
            break
    return t.rstrip("/")


class EngagementManager:
    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = base_dir or config.ENGAGEMENTS_DIR
        os.makedirs(self.base_dir, exist_ok=True)

    def _path(self, engagement_id: str) -> str:
        return os.path.join(self.base_dir, f"{engagement_id}.json")

    def _log_path(self, engagement_id: str) -> str:
        return os.path.join(self.base_dir, f"{engagement_id}.md")

    def _trajectory_path(self, engagement_id: str) -> str:
        return os.path.join(self.base_dir, f"{engagement_id}.trajectory.jsonl")

    def _chat_path(self, engagement_id: str) -> str:
        return os.path.join(self.base_dir, f"{engagement_id}.chat.jsonl")

    def create(
        self,
        name: str,
        target: str,
        scope: str = "",
        tech_stack: Optional[list[str]] = None,
        analysis_mode: str = "full_analysis",
    ) -> Engagement:
        # Combine engagements that share a target: if one already exists for the
        # same normalized target, reuse it so findings/chat accumulate in one
        # record instead of fragmenting across duplicates. Prefer an active
        # match; among matches pick the most recently started.
        existing = self._find_by_target(target)
        if existing is not None:
            new_stack = [t for t in (tech_stack or []) if t not in existing.tech_stack]
            if new_stack:
                existing = self.update(existing.id, tech_stack=existing.tech_stack + new_stack) or existing
            self.append_log(
                existing.id,
                f"\nRe-opened for target {target} (name: {name}) — combined into this engagement.\n",
            )
            return existing

        engagement = Engagement(
            id=str(uuid.uuid4()),
            name=name,
            target=target,
            scope=scope or target,
            start_date=datetime.now(timezone.utc).date().isoformat(),
            status="active",
            tech_stack=tech_stack or [],
            analysis_mode=analysis_mode,
        )
        self._save(engagement)
        self.append_log(
            engagement.id,
            f"# Engagement: {engagement.name}\n\nTarget: {engagement.target}\n"
            f"Scope: {engagement.scope}\nStarted: {engagement.start_date}\n",
        )
        return engagement

    def _save(self, engagement: Engagement) -> None:
        # Atomic write: serialize to a temp file then os.replace, so a crash
        # mid-write can't leave a half-written (corrupt) engagement JSON.
        path = self._path(engagement.id)
        tmp_path = f"{path}.{uuid.uuid4().hex}.tmp"
        with open(tmp_path, "w") as f:
            json.dump(engagement.model_dump(), f, indent=2)
        os.replace(tmp_path, path)

    def _load(self, path: str) -> Optional[Engagement]:
        """Load and validate one engagement file. A corrupt or invalid file is
        logged and treated as absent rather than crashing the caller."""
        try:
            with open(path) as f:
                return Engagement(**json.load(f))
        except (OSError, ValueError) as exc:
            logger.warning(f"Skipping unreadable engagement file {path}: {exc}")
            return None

    def get(self, engagement_id: str) -> Optional[Engagement]:
        path = self._path(engagement_id)
        if not os.path.isfile(path):
            return None
        return self._load(path)

    def list(self) -> list[Engagement]:
        engagements = []
        for entry in sorted(os.listdir(self.base_dir)):
            if entry.endswith(".json"):
                engagement = self._load(os.path.join(self.base_dir, entry))
                if engagement is not None:
                    engagements.append(engagement)
        return sorted(engagements, key=lambda e: e.start_date, reverse=True)

    def _find_by_target(self, target: str) -> Optional[Engagement]:
        """Return an existing engagement with the same normalized target, or
        None. Active engagements win over completed ones; ties break toward the
        most recently started (list() is already sorted newest-first)."""
        key = _normalize_target(target)
        if not key:
            return None
        matches = [e for e in self.list() if _normalize_target(e.target) == key]
        if not matches:
            return None
        active = [e for e in matches if e.status == "active"]
        return (active or matches)[0]

    def update(self, engagement_id: str, **fields: Any) -> Optional[Engagement]:
        engagement = self.get(engagement_id)
        if engagement is None:
            return None
        unknown = set(fields) - set(Engagement.model_fields)
        if unknown:
            raise ValueError(f"Unknown engagement field(s): {sorted(unknown)}")
        # Re-validate the whole record so bad types/ranges (e.g. an invalid
        # status or out-of-range score) are rejected, unlike model_copy.
        updated = Engagement(**{**engagement.model_dump(), **fields})
        self._save(updated)
        return updated

    def close(self, engagement_id: str) -> Optional[Engagement]:
        return self.update(engagement_id, status="completed", end_date=datetime.now(timezone.utc).date().isoformat())

    def increment_findings_count(self, engagement_id: str) -> Optional[Engagement]:
        engagement = self.get(engagement_id)
        if engagement is None:
            return None
        return self.update(engagement_id, findings_count=engagement.findings_count + 1)

    def decrement_findings_count(self, engagement_id: str) -> Optional[Engagement]:
        """Lower the count when a finding is deleted (e.g. a confirmed false
        positive). Never goes below zero."""
        engagement = self.get(engagement_id)
        if engagement is None:
            return None
        return self.update(engagement_id, findings_count=max(0, engagement.findings_count - 1))

    def record_steps(self, engagement_id: str, steps: int) -> Optional[Engagement]:
        """Record one completed task (turn): add `steps` tool-executions to the
        running total and increment the turn count. Feeds the Average Steps per
        Task (AST) metric. No-op if the engagement doesn't exist."""
        engagement = self.get(engagement_id)
        if engagement is None:
            return None
        return self.update(
            engagement_id,
            total_steps=engagement.total_steps + steps,
            turn_count=engagement.turn_count + 1,
        )

    def append_log(self, engagement_id: str, text: str) -> None:
        with open(self._log_path(engagement_id), "a") as f:
            f.write(text + "\n")

    def read_log(self, engagement_id: str) -> str:
        path = self._log_path(engagement_id)
        if not os.path.isfile(path):
            return ""
        with open(path) as f:
            return f.read()

    # ── structured HITL trajectory (machine-readable; feeds training export) ──

    def append_trajectory(self, engagement_id: str, record: dict[str, Any]) -> None:
        """Append one human-decision record (proposed tool call + verdict +
        outcome) as a JSONL line. Distinct from the freeform markdown log.
        Best-effort: never raise into the agent turn."""
        try:
            with open(self._trajectory_path(engagement_id), "a") as f:
                f.write(json.dumps(record, default=str) + "\n")
        except OSError:
            logger.warning("failed to append trajectory for %s", engagement_id)

    def read_trajectory(self, engagement_id: str) -> list[dict[str, Any]]:
        path = self._trajectory_path(engagement_id)
        if not os.path.isfile(path):
            return []
        records = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except ValueError:
                    continue
        return records

    # ── persisted chat transcript (per engagement; replayed by the web UI) ──

    def append_chat_event(self, engagement_id: str, event: dict[str, Any]) -> None:
        """Append one user-facing chat event (the same dicts the WebSocket sends
        to the browser) as a JSONL line, so an engagement's conversation can be
        restored when it's selected again or after a reload. Best-effort: never
        raise into the agent turn."""
        try:
            with open(self._chat_path(engagement_id), "a") as f:
                f.write(json.dumps(event, default=str) + "\n")
        except OSError:
            logger.warning("failed to append chat event for %s", engagement_id)

    def overwrite_chat_events(self, engagement_id: str, events: list[dict[str, Any]]) -> None:
        """Replace the whole persisted transcript (used by session compaction,
        which collapses the conversation into a single summary marker)."""
        try:
            with open(self._chat_path(engagement_id), "w") as f:
                for event in events:
                    f.write(json.dumps(event, default=str) + "\n")
        except OSError:
            logger.warning("failed to overwrite chat events for %s", engagement_id)

    def read_chat_events(self, engagement_id: str) -> list[dict[str, Any]]:
        path = self._chat_path(engagement_id)
        if not os.path.isfile(path):
            return []
        events = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except ValueError:
                    continue
        return events

    def all_trajectories(self) -> list[dict[str, Any]]:
        """Every decision record across all engagements (for training export)."""
        records: list[dict[str, Any]] = []
        for fname in sorted(os.listdir(self.base_dir)):
            if fname.endswith(".trajectory.jsonl"):
                records.extend(self.read_trajectory(fname[: -len(".trajectory.jsonl")]))
        return records

    def delete(self, engagement_id: str) -> bool:
        deleted = False
        for path in (
            self._path(engagement_id),
            self._log_path(engagement_id),
            self._trajectory_path(engagement_id),
            self._chat_path(engagement_id),
        ):
            if os.path.isfile(path):
                os.remove(path)
                deleted = True
        return deleted
