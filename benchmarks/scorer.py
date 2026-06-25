"""Computes the Term-1-proposal's evaluation metrics (ESR, AST, FP rate)
from a real engagement's saved Finding records against a target's known
vulnerability categories in ground_truth.py. Pure function, no I/O - callers
load the findings (e.g. via MemoryStore.load_engagement_findings_as_models())
and pass them in.
"""
from __future__ import annotations

from memory.schemas import Finding

from benchmarks.ground_truth import GROUND_TRUTH


def _matches_category(finding: Finding, category: str) -> bool:
    # One-directional on purpose: checking the reverse (haystack-in-category)
    # would make a short generic vuln_type like "SQL Injection" falsely match
    # a longer sibling category like "SQL Injection (Blind)".
    haystack = " ".join([finding.vuln_type, *finding.tags]).lower()
    return category.lower() in haystack


def _attempted_categories(findings: list[Finding], categories: list[str]) -> set[str]:
    """A category counts as 'attempted' if some finding's vuln_type/tags or
    technique_used hints at it - this is a coarse proxy for which attack
    classes were actually tried, since the agent doesn't log failed
    attempts as Finding records."""
    attempted = set()
    for finding in findings:
        haystack = " ".join([finding.vuln_type, finding.technique_used, *finding.tags]).lower()
        for category in categories:
            if category.lower() in haystack:
                attempted.add(category)
    return attempted


def score_engagement(findings: list[Finding], target: str) -> dict[str, float | int]:
    if target not in GROUND_TRUTH:
        raise ValueError(f"No ground truth registered for target '{target}'. Known targets: {list(GROUND_TRUTH)}")

    categories = GROUND_TRUTH[target]
    matched_categories = {c for c in categories if any(_matches_category(f, c) for f in findings)}
    attempted = _attempted_categories(findings, categories)

    false_positives = [f for f in findings if not any(_matches_category(f, c) for c in categories)]

    esr = len(matched_categories) / len(categories) if categories else 0.0
    ast = len(matched_categories & attempted) / len(attempted) if attempted else 0.0
    fp_rate = len(false_positives) / len(findings) if findings else 0.0

    return {
        "target": target,
        "total_categories": len(categories),
        "categories_detected": len(matched_categories),
        "esr": round(esr, 3),
        "categories_attempted": len(attempted),
        "ast": round(ast, 3),
        "total_findings": len(findings),
        "false_positive_count": len(false_positives),
        "fp_rate": round(fp_rate, 3),
        "detected_categories": sorted(matched_categories),
    }
