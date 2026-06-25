"""Pure functions that turn an Engagement + its Finding records into two
audience-specific Markdown documents - a technical report for developers and
an executive report for management. No I/O here; mcp_servers/report_server.py
is responsible for turning the returned Markdown into files on disk."""
from __future__ import annotations

from memory.schemas import Engagement, Finding

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _sorted_by_severity(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, len(_SEVERITY_ORDER)))


def _sorted_by_dread_then_severity(findings: list[Finding]) -> list[Finding]:
    """Severity first (matches the technical report's ordering), DREAD score
    as a tiebreaker within the same severity - higher risk first, unscored
    findings sort last within their severity band."""
    return sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.get(f.severity, len(_SEVERITY_ORDER)),
            -(f.dread_score if f.dread_score is not None else -1),
        ),
    )


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {severity: 0 for severity in _SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def build_technical_report(engagement: Engagement, findings: list[Finding]) -> str:
    """Full technical depth: evidence, reproduction steps, tooling - for
    developers and other technical staff who need to fix the issues."""
    findings = _sorted_by_severity(findings)
    lines = [
        f"# Technical Penetration Test Report: {engagement.name}",
        "",
        "## Target & Scope",
        f"- **Target**: {engagement.target}",
        f"- **Scope**: {engagement.scope}",
        f"- **Engagement window**: {engagement.start_date} – {engagement.end_date or 'ongoing'}",
        f"- **Tech stack**: {', '.join(engagement.tech_stack) or 'not recorded'}",
        "",
        f"## Findings ({len(findings)} total, ordered by severity)",
        "",
    ]

    if not findings:
        lines.append("No findings have been recorded for this engagement yet.")

    for i, finding in enumerate(findings, start=1):
        lines.append(f"### {i}. {finding.title} [{finding.severity.upper()}]")
        lines.append(f"- **Type**: {finding.vuln_type}")
        if finding.cvss_score is not None:
            lines.append(f"- **CVSS score**: {finding.cvss_score}")
        lines.append(f"- **Affected component**: {finding.affected_component or finding.target}")
        lines.append(f"- **Technique used**: {finding.technique_used}")
        lines.append(f"- **Date**: {finding.date}")
        if finding.tags:
            lines.append(f"- **Tags**: {', '.join(finding.tags)}")
        lines.append("")
        lines.append("**Description**")
        lines.append(finding.description)
        lines.append("")
        lines.append("**Reproduction steps**")
        lines.append(finding.reproduction_steps)
        if finding.remediation:
            lines.append("")
            lines.append("**Remediation**")
            lines.append(finding.remediation)
        lines.append("")

    return "\n".join(lines)


def build_executive_report(engagement: Engagement, findings: list[Finding]) -> str:
    """Business framing only: risk posture, impact, priority - no payloads,
    no reproduction steps, no tool names. Written for non-technical
    stakeholders deciding where to spend remediation budget."""
    findings = _sorted_by_dread_then_severity(findings)
    counts = _severity_counts(findings)

    lines = [
        f"# Executive Summary: {engagement.name}",
        "",
        f"**Target**: {engagement.target}  ",
        f"**Assessment period**: {engagement.start_date} – {engagement.end_date or 'ongoing'}",
        "",
        "## Risk Overview",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"| {severity.capitalize()} | {counts.get(severity, 0)} |")
    lines.append("")

    if counts["critical"] or counts["high"]:
        lines.append(
            "This assessment identified issues that pose a **material risk** to the "
            "business if left unaddressed, including the potential for data exposure, "
            "service disruption, or unauthorized access. We recommend prioritizing the "
            "items below."
        )
    elif findings:
        lines.append(
            "This assessment did not identify any critical or high-severity issues. "
            "The items below represent lower-priority risks worth addressing as part "
            "of normal maintenance."
        )
    else:
        lines.append("No findings have been recorded for this engagement yet.")
    lines.append("")

    lines.append("## Business Impact by Finding")
    lines.append("")
    for i, finding in enumerate(findings, start=1):
        lines.append(f"### {i}. {finding.title} ({finding.severity.capitalize()})")
        if finding.dread_score is not None:
            lines.append(f"- **DREAD risk score**: {finding.dread_score}/10")
        impact = finding.business_impact or (
            "Impact not yet assessed - see the technical report for details."
        )
        lines.append(f"- **What this means for the business**: {impact}")
        remediation = finding.remediation or "Remediation guidance pending from the technical team."
        lines.append(f"- **Recommended action**: {remediation}")
        lines.append("")

    lines.append("## Recommended Next Steps")
    lines.append("")
    if counts["critical"]:
        lines.append("1. Remediate all **critical** findings immediately - these represent the highest risk.")
    if counts["high"]:
        lines.append("2. Schedule **high** severity fixes within the next sprint/patch cycle.")
    if counts["medium"] or counts["low"]:
        lines.append("3. Address **medium/low** findings as part of routine maintenance.")
    if not findings:
        lines.append("1. No action required - re-assess after the next round of changes to the target.")

    return "\n".join(lines)
