"""Nikto web-server vulnerability scanner.

Builds an argv list and runs through run_command() for consistent
timeout / workspace / envelope / logging behavior.
"""
from __future__ import annotations

from typing import Any

from mcp_servers.tools._common import run_command, sanitize_input

_NIKTO_TIMEOUT = 600


def _parse_nikto(stdout: str) -> dict[str, Any]:
    findings = [
        line.strip()[1:].strip()
        for line in stdout.splitlines()
        if line.strip().startswith("+ ")
    ]
    return {
        "summary": f"Nikto reported {len(findings)} item(s)",
        "finding_count": len(findings),
        "findings": findings[:100],
    }


def nikto_scan(target: str) -> dict[str, Any]:
    """Run a Nikto vulnerability scan against a web server.

    Args:
        target: The target URL or IP.
    """
    target = sanitize_input(target)
    if not target:
        return {"status": "error", "error": "Target required"}

    cmd = ["nikto", "-h", target]
    return run_command(cmd, "nikto", target, parser=_parse_nikto, timeout=_NIKTO_TIMEOUT)
