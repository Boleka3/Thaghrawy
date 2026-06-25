"""Report generation, listing, and download. Generation logic itself lives
in core/tools.py's generate_engagement_reports() - this module is just the
HTTP surface over it, shared with the agent's generate_report tool."""
from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

import config
from api.deps import get_engagements, get_memory
from core.tools import generate_engagement_reports
from engagements.manager import EngagementManager
from memory.store import MemoryStore

router = APIRouter(tags=["reports"])


@router.post("/api/engagements/{engagement_id}/reports")
def generate_reports(
    engagement_id: str,
    memory: MemoryStore = Depends(get_memory),
    engagements: EngagementManager = Depends(get_engagements),
):
    if engagements.get(engagement_id) is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    result = generate_engagement_reports(memory, engagement_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.get("/api/engagements/{engagement_id}/reports")
def list_reports(engagement_id: str, engagements: EngagementManager = Depends(get_engagements)):
    if engagements.get(engagement_id) is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    marker = f"_report_{engagement_id[:8]}_"
    reports = []
    for filename in sorted(os.listdir(config.REPORTS_DIR)):
        if marker not in filename:
            continue
        reports.append({
            "filename": filename,
            "type": "technical" if filename.startswith("technical_report_") else "executive",
            "format": "pdf" if filename.endswith(".pdf") else "md",
        })
    return reports


@router.get("/api/reports/{filename}")
def download_report(filename: str):
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    path = os.path.join(config.REPORTS_DIR, filename)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path, filename=filename)
