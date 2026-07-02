"""Expose the training-data export over HTTP so the UI (or a data pipeline) can
pull a fine-tuning dataset without shelling into the container. Mirrors
scripts/export_training_data.py. See training/exporter.py for the schemas.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.deps import get_engagements, get_memory
from engagements.manager import EngagementManager
from memory.store import MemoryStore
from training.exporter import build_dataset

router = APIRouter(prefix="/api/training", tags=["training"])


@router.get("/export")
def export_training_data(
    fmt: str = Query("messages", alias="format", pattern="^(messages|sft|preference)$"),
    memory: MemoryStore = Depends(get_memory),
    engagements: EngagementManager = Depends(get_engagements),
):
    findings = memory.export_all_findings()
    techniques = memory.export_all_techniques()
    trajectories = engagements.all_trajectories()
    dataset = build_dataset(findings, techniques, trajectories, fmt=fmt)
    return {
        "format": fmt,
        "count": len(dataset),
        "sources": {
            "findings": len(findings),
            "techniques": len(techniques),
            "decisions": len(trajectories),
        },
        "examples": dataset,
    }
