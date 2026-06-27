"""gobuster directory/DNS/vhost brute-forcing."""
from __future__ import annotations

import os
import re
from typing import Any, Optional

from mcp_servers.tools._common import run_command, sanitize_input

VALID_MODES = ("dir", "dns", "vhost")

_WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    os.path.expanduser("~/wordlists/common.txt"),
]


def _resolve_wordlist(requested: str) -> tuple[str, str | None]:
    if os.path.isfile(requested):
        return requested, None
    for candidate in _WORDLIST_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate, None
    tried = [requested] + _WORDLIST_CANDIDATES
    return "", f"No wordlist found. Tried: {', '.join(tried)}"


def _parse_gobuster(mode: str):
    def parser(stdout: str) -> dict[str, Any]:
        found = []
        for line in stdout.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            if mode == "dir":
                match = re.search(r"^(/\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?", line)
                if match:
                    found.append({
                        "path": match.group(1),
                        "status": int(match.group(2)),
                        "size": int(match.group(3)) if match.group(3) else None,
                    })
            else:
                found.append({"result": line})

        if mode == "dir":
            interesting = [e for e in found if e.get("status") in (200, 301, 302, 403)]
            return {
                "summary": f"Found {len(found)} paths ({len(interesting)} interesting)",
                "total_found": len(found),
                "interesting_findings": interesting[:50],
            }
        return {
            "summary": f"Found {len(found)} results",
            "total_found": len(found),
            "results": found[:50],
        }
    return parser


def gobuster_scan(
    mode: str,
    target: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    threads: int = 10,
    status_codes: str = "200,204,301,302,307,401,403",
    extensions: Optional[str] = None,
) -> dict[str, Any]:
    if mode not in VALID_MODES:
        return {"status": "error", "error": f"mode must be one of {VALID_MODES}"}
    target = sanitize_input(target)
    if not target:
        return {"status": "error", "error": "Target required"}

    resolved, err = _resolve_wordlist(wordlist)
    if err:
        return {"status": "error", "error": err}

    cmd = ["gobuster", mode]
    cmd += ["-u", target] if mode in ("dir", "vhost") else ["-d", target]
    cmd += ["-w", resolved, "-t", str(threads), "-q", "--no-color"]

    if mode == "dir":
        cmd += ["-s", sanitize_input(status_codes)]
        if extensions:
            cmd += ["-x", sanitize_input(extensions)]

    return run_command(cmd, "gobuster", target, parser=_parse_gobuster(mode))
