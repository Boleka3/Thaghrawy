"""WPScan WordPress vulnerability scanner."""
from __future__ import annotations

import json
from typing import Any

from mcp_servers.tools._common import run_command, sanitize_input


def _parse_wpscan(stdout: str) -> dict[str, Any]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return {"summary": "Could not parse JSON output", "raw_preview": stdout[:1000]}

    version_info = data.get("version", {}) or {}
    plugins = data.get("plugins", {}) or {}
    vulnerable_plugins = {
        name: p for name, p in plugins.items() if p.get("vulnerabilities")
    }

    return {
        "summary": f"WordPress {version_info.get('number', 'unknown')} - "
                   f"{len(vulnerable_plugins)} vulnerable plugin(s) detected",
        "wordpress_version": version_info.get("number"),
        "version_vulnerabilities": version_info.get("vulnerabilities", []),
        "vulnerable_plugins": {
            name: p.get("vulnerabilities", []) for name, p in vulnerable_plugins.items()
        },
        "total_plugins_found": len(plugins),
    }


def wpscan_scan(target: str, enumerate: str = "vp,vt,u") -> dict[str, Any]:
    """Scan a WordPress site for core/plugin/theme vulnerabilities and
    enumerate users. `enumerate` follows wpscan's --enumerate syntax
    (default: vulnerable plugins, vulnerable themes, users)."""
    target = sanitize_input(target)
    if not target:
        return {"status": "error", "error": "Target required"}

    cmd = [
        "wpscan", "--url", target,
        "--enumerate", sanitize_input(enumerate),
        "--format", "json",
        "--no-banner",
        "--random-user-agent",
    ]
    return run_command(cmd, "wpscan", target, parser=_parse_wpscan, timeout=300)
