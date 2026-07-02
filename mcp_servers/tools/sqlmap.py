"""sqlmap SQL-injection scanner.

Builds an argv list (never a shell string) and runs it through
run_command() so it gets the same timeout / workspace-persistence /
JSON-envelope / command-logging behavior as every other tool.
"""
from __future__ import annotations

import re
from typing import Any

from mcp_servers.tools._common import run_command

_SQLMAP_TIMEOUT = 600


def _parse_sqlmap(stdout: str) -> dict[str, Any]:
    parameters = sorted(set(re.findall(r"Parameter:\s*([^\s(]+)", stdout)))
    types = sorted(set(m.strip() for m in re.findall(r"Type:\s*(.+)", stdout)))
    dbms_match = re.search(r"back-end DBMS:?\s*(.+)", stdout) or re.search(
        r"the back-end DBMS is\s*(.+)", stdout
    )
    injectable = bool(
        parameters
        or re.search(r"is vulnerable", stdout, re.IGNORECASE)
        or re.search(r"injection point", stdout, re.IGNORECASE)
    )
    return {
        "summary": (
            f"Injectable: {len(parameters)} parameter(s)"
            if injectable
            else "No SQL injection detected"
        ),
        "injectable": injectable,
        "parameters": parameters,
        "injection_types": types,
        "dbms": dbms_match.group(1).strip() if dbms_match else None,
    }


def sqlmap_scan(url: str, batch: bool = True) -> dict[str, Any]:
    """Run sqlmap against a target URL to test for SQL injection.

    Args:
        url: The target URL (include the parameter to test, e.g. ?id=1).
        batch: Run non-interactively, accepting sqlmap's default answers.
    """
    if not url:
        return {"status": "error", "error": "URL required"}

    # URL is passed as a single argv element (no shell), so query-string
    # characters like & = ? must be preserved verbatim - do NOT sanitize.
    cmd = ["sqlmap", "-u", url]
    if batch:
        cmd.append("--batch")
    cmd.append("--random-agent")

    return run_command(cmd, "sqlmap", url, parser=_parse_sqlmap, timeout=_SQLMAP_TIMEOUT)
