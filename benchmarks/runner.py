"""Benchmark driver: load a real engagement's saved findings + step counters,
compute the four PDF metrics (ESR / AST / FP-rate / Detection Rate) via
benchmarks/scorer.py, and emit a JSON + Markdown metrics report.

The scorer itself is pure; this module is the thin I/O layer the PDF's
"E2E run on DVWA / Juice Shop" implies. Usage:

    python -m benchmarks.runner <engagement_id> <target>

e.g. `python -m benchmarks.runner 1234abcd dvwa`. Run an engagement against
the target first (see benchmarks/README.md) so there are findings to score.
"""
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from typing import Optional

import config
from benchmarks.scorer import BenchmarkResult, score_engagement
from engagements.manager import EngagementManager
from memory.store import MemoryStore


def run_benchmark(
    engagement_id: str,
    target: str,
    memory: Optional[MemoryStore] = None,
    manager: Optional[EngagementManager] = None,
) -> BenchmarkResult:
    """Compute the benchmark metrics for one engagement against one target."""
    memory = memory or MemoryStore()
    manager = manager or EngagementManager()

    findings = memory.load_engagement_findings_as_models(engagement_id)
    engagement = manager.get(engagement_id)
    total_steps = engagement.total_steps if engagement else 0
    turn_count = engagement.turn_count if engagement else 0

    return score_engagement(findings, target, total_steps=total_steps, turn_count=turn_count)


def _check(ok: bool) -> str:
    return "PASS ✅" if ok else "FAIL ❌"


def render_markdown(result: BenchmarkResult) -> str:
    """Render a benchmark result as a Markdown metrics report."""
    lines = [
        f"# Benchmark Report — {result.target}",
        "",
        f"_Generated {datetime.now(timezone.utc).isoformat()}_",
        "",
        "## Metrics (Thaghrawy_Project.pdf, Table 4.2)",
        "",
        "| Metric | Value | Target | Result |",
        "|---|---|---|---|",
        f"| ESR (Exploit Success Rate) | {result.esr:.0%} "
        f"({result.categories_detected}/{result.total_categories} categories) | "
        f"≥ {result.esr_target:.0%} | {_check(result.esr >= result.esr_target)} |",
        f"| AST (Average Steps per Task) | {result.ast:.2f} "
        f"({result.total_steps} steps / {result.turn_count} tasks) | minimize | — |",
        f"| FP Rate | {result.fp_rate:.0%} "
        f"({result.false_positive_count}/{result.total_findings} findings) | "
        f"≤ {result.fp_rate_target:.0%} | {_check(result.fp_rate <= result.fp_rate_target)} |",
        f"| Detection Rate | {result.detection_rate}/{result.owasp_total} OWASP | "
        f"≥ {result.detection_rate_target}/{result.owasp_total} | "
        f"{_check(result.detection_rate >= result.detection_rate_target)} |",
        "",
        f"**Overall: {_check(result.meets_targets)}**",
        "",
        "## Detected categories",
        "",
    ]
    lines += [f"- {c}" for c in result.detected_categories] or ["- (none)"]
    lines += ["", "## OWASP Top 10 classes detected", ""]
    lines += [f"- {c}" for c in result.owasp_categories_detected] or ["- (none)"]
    return "\n".join(lines) + "\n"


def write_reports(result: BenchmarkResult, out_dir: Optional[str] = None) -> dict[str, str]:
    """Write the result as both .json and .md, returning the two file paths."""
    out_dir = out_dir or config.REPORTS_DIR
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base = f"benchmark_{result.target}_{stamp}"

    json_path = os.path.join(out_dir, f"{base}.json")
    md_path = os.path.join(out_dir, f"{base}.md")
    with open(json_path, "w") as f:
        json.dump(result.model_dump(), f, indent=2)
    with open(md_path, "w") as f:
        f.write(render_markdown(result))
    return {"json": json_path, "markdown": md_path}


def main() -> None:
    parser = argparse.ArgumentParser(description="Score an engagement against a benchmark target.")
    parser.add_argument("engagement_id")
    parser.add_argument("target", help="Benchmark target key, e.g. 'dvwa' or 'juice-shop'")
    args = parser.parse_args()

    result = run_benchmark(args.engagement_id, args.target)
    paths = write_reports(result)
    print(render_markdown(result))
    print(f"Wrote: {paths['json']}\n       {paths['markdown']}")


if __name__ == "__main__":
    main()
