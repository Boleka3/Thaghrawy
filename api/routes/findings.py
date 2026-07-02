from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.deps import get_engagements, get_memory
from core.finding_drafts import finding_from_tool_result
from core.tools import persist_finding
from engagements.manager import EngagementManager
from memory.schemas import Finding
from memory.store import MemoryStore

router = APIRouter(prefix="/api/findings", tags=["findings"])


class SearchFindingsRequest(BaseModel):
    query: str
    top_k: int = 3
    engagement_id: Optional[str] = None


class UpdateFindingRequest(BaseModel):
    # All optional — a curation PATCH touches only the fields the human changed.
    # vuln_type/severity/tags are the scorer-relevant ones.
    title: Optional[str] = None
    severity: Optional[str] = None
    vuln_type: Optional[str] = None
    description: Optional[str] = None
    reproduction_steps: Optional[str] = None
    tags: Optional[list[str]] = None
    cvss_score: Optional[float] = None
    dread_score: Optional[float] = None
    affected_component: Optional[str] = None
    business_impact: Optional[str] = None
    remediation: Optional[str] = None


class PromoteRequest(BaseModel):
    tool: str
    # dict, or the JSON string the MCP tool wrappers emit — finding_from_tool_result
    # normalizes both.
    result: Any
    engagement_id: str
    target: str = ""


@router.post("")
def save_finding(
    finding: Finding,
    memory: MemoryStore = Depends(get_memory),
    engagements: EngagementManager = Depends(get_engagements),
):
    # Shared single write path with the agent's save_finding tool, so the
    # engagement findings_count stays consistent across both entry points.
    persist_finding(memory, finding, engagements)
    return {"status": "saved", "id": finding.id}


@router.post("/search")
def search_findings(body: SearchFindingsRequest, memory: MemoryStore = Depends(get_memory)):
    return memory.search_findings(body.query, top_k=body.top_k, engagement_id=body.engagement_id)


@router.get("/engagement/{engagement_id}")
def list_engagement_findings(engagement_id: str, memory: MemoryStore = Depends(get_memory)):
    return memory.load_engagement_findings(engagement_id)


@router.patch("/{finding_id}")
def update_finding(
    finding_id: str,
    body: UpdateFindingRequest,
    memory: MemoryStore = Depends(get_memory),
):
    """Curate a finding — fix its vuln_type/severity, add tags, etc. Only the
    provided fields are changed; the whole record is re-validated."""
    fields = body.model_dump(exclude_none=True)
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")
    try:
        updated = memory.update_finding(finding_id, fields)
    except ValueError as exc:  # schema violation (bad severity, out-of-range score)
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if updated is None:
        raise HTTPException(status_code=404, detail=f"Unknown finding: {finding_id}")
    return {"status": "updated", "finding": updated.model_dump()}


@router.delete("/{finding_id}")
def delete_finding(
    finding_id: str,
    memory: MemoryStore = Depends(get_memory),
    engagements: EngagementManager = Depends(get_engagements),
):
    """Delete a finding (e.g. mark a confirmed false positive) and keep the
    engagement's findings_count honest."""
    existing = memory.get_finding(finding_id)
    if existing is None:
        raise HTTPException(status_code=404, detail=f"Unknown finding: {finding_id}")
    memory.delete_finding(finding_id)
    engagements.decrement_findings_count(existing.engagement_id)
    return {"status": "deleted", "id": finding_id}


@router.post("/promote")
def promote_tool_result(body: PromoteRequest):
    """Pre-fill Finding drafts from a scanner result so the human can review and
    save them (via POST /api/findings). Does not persist anything itself — the
    operator is the intelligence deciding what's real."""
    drafts = finding_from_tool_result(body.tool, body.result, body.engagement_id, body.target)
    return {"drafts": [d.model_dump() for d in drafts]}
