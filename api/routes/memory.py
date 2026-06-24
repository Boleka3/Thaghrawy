from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from api.deps import get_memory
from memory.store import MemoryStore

router = APIRouter(prefix="/api/memory", tags=["memory"])


class SearchMemoryRequest(BaseModel):
    query: str
    collection: str = "both"  # "findings" | "techniques" | "both"
    top_k: int = 3
    engagement_id: Optional[str] = None


@router.post("/search")
def search_memory(body: SearchMemoryRequest, memory: MemoryStore = Depends(get_memory)):
    if body.collection == "findings":
        return {"findings": memory.search_findings(body.query, top_k=body.top_k, engagement_id=body.engagement_id)}
    if body.collection == "techniques":
        return {"techniques": memory.search_techniques(body.query, top_k=body.top_k)}
    return memory.search_context(body.query, top_k=body.top_k, engagement_id=body.engagement_id)


@router.get("/stats")
def memory_stats(memory: MemoryStore = Depends(get_memory)):
    return memory.stats()
