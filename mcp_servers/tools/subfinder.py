"""Subfinder subdomain enumeration."""
from __future__ import annotations

import re
from typing import Any

from mcp_servers.tools._common import run_command, sanitize_input, safe_filename, save_to_workspace


def _parse_subfinder(stdout: str) -> dict[str, Any]:
    subdomains = [
        line.strip()
        for line in stdout.strip().split("\n")
        if line.strip() and not line.startswith("[")
    ]
    return {
        "summary": f"Found {len(subdomains)} subdomains",
        "subdomain_count": len(subdomains),
        "subdomains": subdomains,
    }


_LOCAL_TARGETS = re.compile(
    r"^(localhost|127\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)$"
)


def subfinder_scan(domain: str) -> dict[str, Any]:
    domain = sanitize_input(domain)
    if not domain:
        return {"status": "error", "error": "Domain required"}

    if _LOCAL_TARGETS.match(domain):
        return {
            "status": "skipped",
            "tool": "subfinder",
            "target": domain,
            "note": "Subdomain enumeration not applicable for local/private targets. Use nmap or gobuster instead.",
        }

    cmd = ["subfinder", "-d", domain, "-silent", "-nc"]
    result = run_command(cmd, "subfinder", domain, parser=_parse_subfinder)

    if result.get("status") == "success" and result.get("subdomains"):
        list_filename = safe_filename(domain, "subfinder_list")
        list_path = save_to_workspace(list_filename, "\n".join(result["subdomains"]))
        result["subdomain_list_file"] = list_path

    return result
