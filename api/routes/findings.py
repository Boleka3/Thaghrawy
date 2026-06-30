from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from api.deps import get_engagements, get_memory
from core.tools import persist_finding
from engagements.manager import EngagementManager
from memory.schemas import Finding
from memory.store import MemoryStore

router = APIRouter(prefix="/api/findings", tags=["findings"])


class SearchFindingsRequest(BaseModel):
    query: str
    top_k: int = 3
    engagement_id: Optional[str] = None


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
