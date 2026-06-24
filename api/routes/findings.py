from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from api.deps import get_engagements, get_memory
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
    memory.add_finding(finding)
    engagements.increment_findings_count(finding.engagement_id)
    return {"status": "saved", "id": finding.id}


@router.post("/search")
def search_findings(body: SearchFindingsRequest, memory: MemoryStore = Depends(get_memory)):
    return memory.search_findings(body.query, top_k=body.top_k, engagement_id=body.engagement_id)


@router.get("/engagement/{engagement_id}")
def list_engagement_findings(engagement_id: str, memory: MemoryStore = Depends(get_memory)):
    return memory.load_engagement_findings(engagement_id)
