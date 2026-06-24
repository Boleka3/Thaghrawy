"""OWASP Amass subdomain enumeration (passive/active, optional brute-force)."""
from __future__ import annotations

import json
from typing import Any

from mcp_servers.tools._common import run_command, sanitize_input


def _parse_amass(stdout: str) -> dict[str, Any]:
    subdomains: set[str] = set()
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "name" in data:
            subdomains.add(data["name"])
    sorted_subs = sorted(subdomains)
    return {
        "summary": f"Found {len(sorted_subs)} subdomains",
        "subdomain_count": len(sorted_subs),
        "subdomains": sorted_subs,
    }


def amass_scan(domain: str, mode: str = "passive", brute: bool = False) -> dict[str, Any]:
    domain = sanitize_input(domain)
    if not domain:
        return {"status": "error", "error": "Domain required"}
    if mode not in ("passive", "active"):
        return {"status": "error", "error": "mode must be 'passive' or 'active'"}

    cmd = ["amass", "enum", "-d", domain, "-json", "/dev/stdout", f"-{mode}"]
    if brute:
        cmd.append("-brute")

    # Active/brute-force amass runs can legitimately take a while.
    timeout = 600 if (mode == "active" or brute) else None
    return run_command(cmd, "amass", domain, parser=_parse_amass, timeout=timeout)
