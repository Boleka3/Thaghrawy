"""nuclei vulnerability scanner."""
from __future__ import annotations

import re
from typing import Any

from mcp_servers.tools._common import run_command, sanitize_input


def _parse_nuclei(stdout: str) -> dict[str, Any]:
    findings = []
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        # nuclei output: [template-id] [protocol] [severity] url
        match = re.search(r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(.*)", line)
        if match:
            findings.append({
                "template": match.group(1),
                "protocol": match.group(2),
                "severity": match.group(3),
                "matched": match.group(4).strip(),
            })

    severity_count: dict[str, int] = {}
    for f in findings:
        sev = f["severity"].lower()
        severity_count[sev] = severity_count.get(sev, 0) + 1

    return {
        "summary": f"Found {len(findings)} vulnerabilities",
        "total_findings": len(findings),
        "severity_breakdown": severity_count,
        "findings": findings[:50],
    }


def nuclei_scan(
    target: str,
    templates: str = "",
    severity: str = "",
    tags: str = "",
) -> dict[str, Any]:
    target = sanitize_input(target)
    if not target:
        return {"status": "error", "error": "Target required"}

    cmd = ["nuclei", "-u", target, "-nc", "-silent"]
    if templates:
        cmd.extend(["-t", sanitize_input(templates)])
    if severity:
        cmd.extend(["-severity", sanitize_input(severity)])
    if tags:
        cmd.extend(["-tags", sanitize_input(tags)])

    return run_command(cmd, "nuclei", target, parser=_parse_nuclei)
