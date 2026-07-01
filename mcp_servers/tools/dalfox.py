"""dalfox - fast parameter-analysis XSS scanner (OWASP A03: Injection).

Builds an argv list (never a shell string) and runs it through
run_command() so it gets the same timeout / workspace-persistence /
JSON-envelope / command-logging behavior as every other tool.
"""
from __future__ import annotations

import re
from typing import Any

from mcp_servers.tools._common import run_command

_DALFOX_TIMEOUT = 600


def _parse_dalfox(stdout: str) -> dict[str, Any]:
    # In --silence mode dalfox emits one `[POC]...` line per confirmed vector,
    # e.g. `[POC][V][GET] http://host/?q=<script>...`. Count and sample them.
    pocs = [line.strip() for line in stdout.splitlines() if "[POC]" in line]
    params = sorted(set(re.findall(r"\[PARAM\]\s*([^\s]+)", stdout)))
    return {
        "summary": (
            f"dalfox confirmed {len(pocs)} XSS vector(s)"
            if pocs
            else "No XSS vectors confirmed"
        ),
        "xss_found": bool(pocs),
        "poc_count": len(pocs),
        "pocs": pocs[:50],
        "reflected_params": params[:50],
    }


def dalfox_scan(url: str, method: str = "GET", cookie: str = "") -> dict[str, Any]:
    """Scan a URL for reflected/stored/DOM XSS with dalfox (OWASP A03).

    Args:
        url: Target URL, ideally including a parameter to test (e.g. ?q=test).
        method: HTTP method to use (GET/POST).
        cookie: Optional session cookie ("name=value; ...") for authenticated
            testing (e.g. a DVWA PHPSESSID + security level).
    """
    if not url:
        return {"status": "error", "error": "URL required"}

    # URL/cookie pass verbatim as single argv elements (no shell) - query-string
    # characters (& = ? <>) must survive, so do NOT sanitize them.
    cmd = ["dalfox", "url", url, "--no-color", "--silence", "--skip-bav"]
    if method and method.upper() != "GET":
        cmd += ["-X", method.upper()]
    if cookie:
        cmd += ["-C", cookie]

    return run_command(cmd, "dalfox", url, parser=_parse_dalfox, timeout=_DALFOX_TIMEOUT)
