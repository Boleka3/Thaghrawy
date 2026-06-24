"""Subfinder subdomain enumeration."""
from __future__ import annotations

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


def subfinder_scan(domain: str) -> dict[str, Any]:
    domain = sanitize_input(domain)
    if not domain:
        return {"status": "error", "error": "Domain required"}

    cmd = ["subfinder", "-d", domain, "-silent", "-nc"]
    result = run_command(cmd, "subfinder", domain, parser=_parse_subfinder)

    if result.get("status") == "success" and result.get("subdomains"):
        list_filename = safe_filename(domain, "subfinder_list")
        list_path = save_to_workspace(list_filename, "\n".join(result["subdomains"]))
        result["subdomain_list_file"] = list_path

    return result
