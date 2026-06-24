from typing import Literal, Optional

from pydantic import BaseModel, Field


class Finding(BaseModel):
    id: str
    title: str
    severity: Literal["critical", "high", "medium", "low", "info"]
    vuln_type: str  # e.g. "IDOR", "SSRF", "XSS"
    description: str
    reproduction_steps: str
    technique_used: str
    target: str
    engagement_id: str
    date: str
    tags: list[str] = Field(default_factory=list)


class Technique(BaseModel):
    id: str
    name: str
    description: str
    works_against: list[str] = Field(default_factory=list)  # e.g. ["Apache Tomcat", "JWT", "GraphQL"]
    platform: str  # e.g. "web", "api", "network"
    engagement_id: str
    date: str
    tags: list[str] = Field(default_factory=list)


class Engagement(BaseModel):
    id: str
    name: str
    target: str
    scope: str
    start_date: str
    end_date: Optional[str] = None
    status: Literal["active", "completed"] = "active"
    findings_count: int = 0
    tech_stack: list[str] = Field(default_factory=list)
    notes: str = ""
