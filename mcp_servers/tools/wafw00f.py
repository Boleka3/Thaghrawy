"""wafw00f web application firewall fingerprinting."""
from __future__ import annotations

import re
from typing import Any

from mcp_servers.tools._common import run_command, sanitize_input


def _parse_wafw00f(stdout: str) -> dict[str, Any]:
    detected = re.search(r"is behind\s+(.+?)\s*(?:\(|$)", stdout, re.IGNORECASE)
    no_waf = "No WAF detected" in stdout

    return {
        "summary": detected.group(1).strip() if detected else (
            "No WAF detected" if no_waf else "Inconclusive"
        ),
        "waf_detected": bool(detected),
        "waf_name": detected.group(1).strip() if detected else None,
    }


def wafw00f_scan(target: str) -> dict[str, Any]:
    """Detect whether a target web app is behind a WAF, and identify which
    one. Useful before fuzzing/injection attempts to anticipate blocking
    or rate-limiting."""
    target = sanitize_input(target)
    if not target:
        return {"status": "error", "error": "Target required"}

    cmd = ["wafw00f", target]
    return run_command(cmd, "wafw00f", target, parser=_parse_wafw00f)
