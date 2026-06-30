"""Computes the four evaluation metrics defined in Thaghrawy_Project.pdf
(Table 4.2) from a real engagement's saved Finding records against a
target's known vulnerability categories in ground_truth.py:

- ESR  (Exploit Success Rate): fraction of the target's known vulnerability
  categories for which the agent produced at least one confirmed finding. A
  persisted Finding represents a confirmed/exploited vulnerability (the agent
  only saves findings after confirmation). PDF target: >= 0.70.
- AST  (Average Steps per Task): mean number of tool-execution steps the
  agent took per task (turn), sourced from the engagement's step counters
  (core/agent.py instrumentation). Lower = fewer "rabbit holes".
- FP Rate: fraction of saved findings that don't map to any known category.
  PDF target: <= 0.15.
- Detection Rate: number of distinct OWASP Top 10 (2021) classes detected.
  PDF target: 8 / 10.

Pure function, no I/O - callers load the findings (e.g. via
MemoryStore.load_engagement_findings_as_models()) and the engagement's step
counters and pass them in.
"""
from __future__ import annotations

from pydantic import BaseModel, Field

from memory.schemas import Finding

from benchmarks.ground_truth import CATEGORY_TO_OWASP, GROUND_TRUTH, OWASP_TOP_10

ESR_TARGET = 0.70
FP_RATE_TARGET = 0.15
DETECTION_RATE_TARGET = 8


class BenchmarkResult(BaseModel):
    """Typed result of scoring one engagement against one benchmark target."""

    target: str
    total_categories: int
    categories_detected: int
    detected_categories: list[str] = Field(default_factory=list)
    # Metric 1: Exploit Success Rate
    esr: float
    esr_target: float = ESR_TARGET
    # Metric 2: Average Steps per Task
    total_steps: int
    turn_count: int
    ast: float
    # Metric 3: False-Positive Rate
    total_findings: int
    false_positive_count: int
    fp_rate: float
    fp_rate_target: float = FP_RATE_TARGET
    # Metric 4: Detection Rate (distinct OWASP Top 10 classes)
    owasp_categories_detected: list[str] = Field(default_factory=list)
    detection_rate: int
    detection_rate_target: int = DETECTION_RATE_TARGET
    owasp_total: int = len(OWASP_TOP_10)

    @property
    def meets_targets(self) -> bool:
        """True when all PDF success thresholds are met."""
        return (
            self.esr >= self.esr_target
            and self.fp_rate <= self.fp_rate_target
            and self.detection_rate >= self.detection_rate_target
        )


def _matches_category(finding: Finding, category: str) -> bool:
    # One-directional on purpose: checking the reverse (haystack-in-category)
    # would make a short generic vuln_type like "SQL Injection" falsely match
    # a longer sibling category like "SQL Injection (Blind)".
    haystack = " ".join([finding.vuln_type, *finding.tags]).lower()
    return category.lower() in haystack


def score_engagement(
    findings: list[Finding],
    target: str,
    total_steps: int = 0,
    turn_count: int = 0,
) -> BenchmarkResult:
    """Score `findings` against `target`'s known categories. `total_steps` and
    `turn_count` come from the engagement's persisted step counters and feed
    the Average Steps per Task (AST) metric."""
    if target not in GROUND_TRUTH:
        raise ValueError(
            f"No ground truth registered for target '{target}'. Known targets: {list(GROUND_TRUTH)}"
        )

    categories = GROUND_TRUTH[target]
    matched_categories = {c for c in categories if any(_matches_category(f, c) for f in findings)}
    false_positives = [f for f in findings if not any(_matches_category(f, c) for c in categories)]

    owasp_detected = sorted({CATEGORY_TO_OWASP[c] for c in matched_categories if c in CATEGORY_TO_OWASP})

    esr = len(matched_categories) / len(categories) if categories else 0.0
    ast = total_steps / turn_count if turn_count else 0.0
    fp_rate = len(false_positives) / len(findings) if findings else 0.0

    return BenchmarkResult(
        target=target,
        total_categories=len(categories),
        categories_detected=len(matched_categories),
        detected_categories=sorted(matched_categories),
        esr=round(esr, 3),
        total_steps=total_steps,
        turn_count=turn_count,
        ast=round(ast, 3),
        total_findings=len(findings),
        false_positive_count=len(false_positives),
        fp_rate=round(fp_rate, 3),
        owasp_categories_detected=owasp_detected,
        detection_rate=len(owasp_detected),
    )
