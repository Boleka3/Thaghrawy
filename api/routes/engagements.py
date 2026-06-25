from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.deps import get_engagements
from engagements.manager import EngagementManager

router = APIRouter(prefix="/api/engagements", tags=["engagements"])


class CreateEngagementRequest(BaseModel):
    name: str
    target: str
    scope: Optional[str] = None
    tech_stack: Optional[list[str]] = None
    analysis_mode: Optional[str] = None


class UpdateEngagementRequest(BaseModel):
    notes: Optional[str] = None
    tech_stack: Optional[list[str]] = None
    scope: Optional[str] = None


@router.get("")
def list_engagements(manager: EngagementManager = Depends(get_engagements)):
    return manager.list()


@router.post("")
def create_engagement(body: CreateEngagementRequest, manager: EngagementManager = Depends(get_engagements)):
    return manager.create(
        name=body.name, target=body.target, scope=body.scope or "", tech_stack=body.tech_stack,
        analysis_mode=body.analysis_mode or "full_analysis",
    )


@router.get("/{engagement_id}")
def get_engagement(engagement_id: str, manager: EngagementManager = Depends(get_engagements)):
    engagement = manager.get(engagement_id)
    if engagement is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return engagement


@router.patch("/{engagement_id}")
def update_engagement(
    engagement_id: str,
    body: UpdateEngagementRequest,
    manager: EngagementManager = Depends(get_engagements),
):
    fields = {k: v for k, v in body.model_dump().items() if v is not None}
    updated = manager.update(engagement_id, **fields)
    if updated is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return updated


@router.post("/{engagement_id}/close")
def close_engagement(engagement_id: str, manager: EngagementManager = Depends(get_engagements)):
    closed = manager.close(engagement_id)
    if closed is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    return closed


@router.get("/{engagement_id}/log")
def get_engagement_log(engagement_id: str, manager: EngagementManager = Depends(get_engagements)):
    return {"engagement_id": engagement_id, "log": manager.read_log(engagement_id)}


@router.delete("/{engagement_id}")
def delete_engagement(engagement_id: str, manager: EngagementManager = Depends(get_engagements)):
    if not manager.delete(engagement_id):
        raise HTTPException(status_code=404, detail="Engagement not found")
    return {"status": "deleted"}
