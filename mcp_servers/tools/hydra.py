"""Hydra credential brute-forcer.

Builds an argv list and runs through run_command(). Recovered credentials
are returned for the agent to act on but are NOT echoed into any persisted
filename; the raw scan log is written by run_command() as usual.
"""
from __future__ import annotations

import re
from typing import Any

from mcp_servers.tools._common import run_command, sanitize_input

_HYDRA_TIMEOUT = 300

# [80][http-get] host: 10.0.0.5   login: admin   password: secret
_CRED_RE = re.compile(
    r"\[\d+\]\[\S+\]\s+host:\s+(\S+)\s+login:\s+(\S+)\s+password:\s+(\S+)"
)


def _parse_hydra(stdout: str) -> dict[str, Any]:
    creds = [
        {"host": host, "login": login, "password": password}
        for host, login, password in _CRED_RE.findall(stdout)
    ]
    return {
        "summary": f"Recovered {len(creds)} credential pair(s)",
        "credentials_found": len(creds),
        "credentials": creds,
    }


def hydra_bruteforce(
    target: str, service: str, user: str, wordlist: str
) -> dict[str, Any]:
    """Brute-force credentials for a network service with Hydra.

    Args:
        target: Target IP or hostname (scheme/port/path are stripped).
        service: Service name (e.g. ssh, ftp, http-get).
        user: Username to test.
        wordlist: Path to the password wordlist.
    """
    if not (target and service and user and wordlist):
        return {"status": "error", "error": "target, service, user, and wordlist are required"}

    clean_target = re.sub(r"^https?://", "", target).split("/")[0].split(":")[0]
    clean_target = sanitize_input(clean_target)
    cmd = [
        "hydra",
        "-l", sanitize_input(user),
        "-P", wordlist,
        clean_target,
        sanitize_input(service),
    ]
    return run_command(cmd, "hydra", clean_target, parser=_parse_hydra, timeout=_HYDRA_TIMEOUT)
