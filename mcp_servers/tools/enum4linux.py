"""enum4linux-ng / enum4linux - SMB/Windows domain enumeration (shares,
users, groups, OS info, password policy). Out of scope for pure web
targets, but relevant once a network/AD segment is in scope."""
from __future__ import annotations

import re
from typing import Any

from mcp_servers.tools._common import run_command, sanitize_input


def _parse_enum4linux(stdout: str) -> dict[str, Any]:
    facts = [line.strip("[+] ").strip() for line in stdout.splitlines() if line.strip().startswith("[+]")]
    shares = re.findall(r"^\s*(\S+)\s+(Disk|IPC|Printer)\b", stdout, re.MULTILINE)

    return {
        "summary": f"{len(facts)} fact(s), {len(shares)} share(s) found",
        "facts": facts[:40],
        "shares": [{"name": s[0], "type": s[1]} for s in shares],
    }


def enum4linux_scan(target: str) -> dict[str, Any]:
    """Enumerate SMB shares, users, groups, OS info, and password policy
    on a Windows/Samba host."""
    target = sanitize_input(target)
    if not target:
        return {"status": "error", "error": "Target required"}

    cmd = ["enum4linux", "-a", target]
    return run_command(cmd, "enum4linux", target, parser=_parse_enum4linux, timeout=180)
