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


class EngagementManager:
    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = base_dir or config.ENGAGEMENTS_DIR
        os.makedirs(self.base_dir, exist_ok=True)

    def _path(self, engagement_id: str) -> str:
        return os.path.join(self.base_dir, f"{engagement_id}.json")

    def _log_path(self, engagement_id: str) -> str:
        return os.path.join(self.base_dir, f"{engagement_id}.md")

    def create(
        self,
        name: str,
        target: str,
        scope: str = "",
        tech_stack: Optional[list[str]] = None,
        analysis_mode: str = "full_analysis",
    ) -> Engagement:
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

    def delete(self, engagement_id: str) -> bool:
        deleted = False
        for path in (self._path(engagement_id), self._log_path(engagement_id)):
            if os.path.isfile(path):
                os.remove(path)
                deleted = True
        return deleted
