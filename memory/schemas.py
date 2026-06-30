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
    # CVSS base scores run 0.0-10.0; DREAD is estimated 1-10. Both are bounded
    # so a malformed agent estimate (e.g. 50 or -3) is rejected at construction.
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    dread_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    affected_component: Optional[str] = None
    business_impact: Optional[str] = None
    remediation: Optional[str] = None


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
    analysis_mode: Literal["recon_only", "full_analysis"] = "full_analysis"
    # Agent-effort tracking for the "Average Steps per Task" (AST) metric:
    # total_steps is the cumulative count of tool executions across all turns;
    # turn_count is the number of user turns (tasks) driven through the agent.
    total_steps: int = 0
    turn_count: int = 0

    @property
    def average_steps_per_task(self) -> float:
        """Mean tool-execution steps per task (lower = fewer rabbit holes)."""
        return self.total_steps / self.turn_count if self.turn_count else 0.0
