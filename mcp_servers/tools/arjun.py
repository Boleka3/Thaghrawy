"""Arjun HTTP parameter discovery - finds hidden GET/POST/JSON parameters
an endpoint accepts, which often expose IDOR/SQLi/SSRF surface that plain
crawling/fuzzing misses."""
from __future__ import annotations

import re
from typing import Any

from mcp_servers.tools._common import run_command, sanitize_input


def _parse_arjun(stdout: str) -> dict[str, Any]:
    match = re.search(r"Parameters found:\s*(.+)", stdout)
    params = [p.strip() for p in match.group(1).split(",")] if match else []
    return {
        "summary": f"Found {len(params)} hidden parameter(s)" if params else "No parameters found",
        "parameters": params,
    }


def arjun_scan(url: str, method: str = "GET", threads: int = 10) -> dict[str, Any]:
    """Discover hidden HTTP parameters on an endpoint by brute-forcing a
    wordlist of common parameter names. `method`: GET, POST, or JSON."""
    url = sanitize_input(url)
    if not url:
        return {"status": "error", "error": "URL required"}

    cmd = ["arjun", "-u", url, "-m", method.upper(), "-t", str(threads)]
    return run_command(cmd, "arjun", url, parser=_parse_arjun)
