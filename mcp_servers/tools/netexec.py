"""netexec (formerly CrackMapExec) - SMB credential validation, share
enumeration, and lateral-movement reconnaissance across one or more hosts.
Maps to the kill chain's "Actions on Objectives" phase: once a foothold and
a credential are obtained, this is how you check what else that credential
reaches before going any further."""
from __future__ import annotations

import re
from typing import Any

from mcp_servers.tools._common import run_command, sanitize_input


def _parse_netexec(stdout: str) -> dict[str, Any]:
    facts = [line.strip() for line in stdout.splitlines() if "[+]" in line or "[*]" in line]
    auth_success = [line for line in facts if "[+]" in line and ":" in line]
    shares = re.findall(r"^\s*(\S+)\s+(READ|WRITE|READ,WRITE)\b", stdout, re.MULTILINE)

    return {
        "summary": f"{len(facts)} fact(s), {len(auth_success)} successful auth(s), {len(shares)} accessible share(s)",
        "facts": facts[:40],
        "accessible_shares": [{"name": s[0], "permissions": s[1]} for s in shares],
    }


def netexec_scan(
    target: str,
    username: str = "",
    password: str = "",
    enumerate_shares: bool = False,
) -> dict[str, Any]:
    """Validate SMB credentials against a host (or check for a null/guest
    session if no credentials given), and optionally enumerate accessible
    shares. Only run this with credentials you are authorized to test."""
    target = sanitize_input(target)
    if not target:
        return {"status": "error", "error": "Target required"}

    cmd = ["netexec", "smb", target]
    if username:
        cmd.extend(["-u", sanitize_input(username), "-p", password])
    if enumerate_shares:
        cmd.append("--shares")

    return run_command(cmd, "netexec", target, parser=_parse_netexec, timeout=120)
