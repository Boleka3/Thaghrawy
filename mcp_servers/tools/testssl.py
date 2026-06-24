"""testssl.sh TLS/SSL configuration and vulnerability scanner."""
from __future__ import annotations

import re
from typing import Any

from mcp_servers.tools._common import run_command, sanitize_input

_VULN_FLAGS = (
    "heartbleed", "ccs_injection", "robot", "secure_renego", "secure_client_renego",
    "crime", "breach", "poodle_ssl", "freak", "drown", "logjam", "beast", "lucky13", "rc4",
)


def _parse_testssl(stdout: str) -> dict[str, Any]:
    protocols = {}
    for line in stdout.splitlines():
        match = re.match(r"^\s*(SSLv2|SSLv3|TLS1|TLS1_1|TLS1_2|TLS1_3)\s+(.+)$", line.strip())
        if match:
            protocols[match.group(1)] = match.group(2).strip()

    vulnerabilities = []
    for vuln in _VULN_FLAGS:
        match = re.search(rf"^\s*{vuln}\b.*$", stdout, re.IGNORECASE | re.MULTILINE)
        if match and "not vulnerable" not in match.group(0).lower():
            vulnerabilities.append(match.group(0).strip())

    return {
        "summary": f"{len(vulnerabilities)} potential TLS vulnerabilities flagged",
        "protocols": protocols,
        "vulnerabilities": vulnerabilities,
    }


def testssl_scan(target: str, fast: bool = True) -> dict[str, Any]:
    """Audit a host's TLS/SSL configuration: supported protocols, cipher
    strength, certificate issues, and known vulnerabilities (Heartbleed,
    POODLE, FREAK, DROWN, etc.)."""
    target = sanitize_input(target)
    if not target:
        return {"status": "error", "error": "Target required"}

    cmd = ["testssl.sh", "--color", "0"]
    if fast:
        cmd.append("--fast")
    cmd.append(target)

    return run_command(cmd, "testssl", target, parser=_parse_testssl, timeout=300)
