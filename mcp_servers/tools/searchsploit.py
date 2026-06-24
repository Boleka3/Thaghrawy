"""searchsploit - offline Exploit-DB lookup. Chains naturally after
web_tech_detect/nmap_scan: feed it a software name + version and see if a
known public exploit already exists."""
from __future__ import annotations

import json
from typing import Any

from mcp_servers.tools._common import run_command, sanitize_input


def _parse_searchsploit(stdout: str) -> dict[str, Any]:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return {"summary": "Could not parse JSON output", "raw_preview": stdout[:1000]}

    exploits = [
        {"title": e.get("Title"), "path": e.get("Path"), "edb_id": e.get("EDB-ID")}
        for e in data.get("RESULTS_EXPLOIT", [])
    ]
    return {
        "summary": f"Found {len(exploits)} known exploit(s)",
        "exploits": exploits[:30],
    }


def searchsploit_lookup(query: str) -> dict[str, Any]:
    """Search the local Exploit-DB mirror for known public exploits
    matching a software name/version (e.g. 'Apache 2.4.49' or 'wordpress
    5.8')."""
    query = sanitize_input(query)
    if not query:
        return {"status": "error", "error": "Query required"}

    cmd = ["searchsploit", "--json", *query.split()]
    return run_command(cmd, "searchsploit", query, parser=_parse_searchsploit)
