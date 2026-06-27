"""ffuf web content/parameter fuzzing. URL must contain the FUZZ keyword."""
from __future__ import annotations

import json
import os
from typing import Any, Optional

from mcp_servers.tools._common import run_command, sanitize_input

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


def _parse_ffuf(stdout: str) -> dict[str, Any]:
    results = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        results.append(
            {
                "url": entry.get("url"),
                "status": entry.get("status"),
                "length": entry.get("length"),
                "words": entry.get("words"),
                "lines": entry.get("lines"),
                "redirect": entry.get("redirectlocation"),
            }
        )
    return {
        "summary": f"Found {len(results)} matches",
        "match_count": len(results),
        "matches": results[:100],
    }


def ffuf_fuzz(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    method: str = "GET",
    headers: Optional[list[str]] = None,
    match_codes: str = "200,204,301,302,307,401,403,405,500",
    filter_codes: Optional[str] = None,
    filter_size: Optional[str] = None,
    threads: int = 40,
) -> dict[str, Any]:
    url = sanitize_input(url)
    if not url:
        return {"status": "error", "error": "URL required"}
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"

    resolved, err = _resolve_wordlist(wordlist)
    if err:
        return {"status": "error", "error": err}

    cmd = [
        "ffuf", "-u", url, "-w", resolved, "-X", sanitize_input(method) or "GET",
        "-mc", sanitize_input(match_codes), "-t", str(threads), "-json", "-s",
    ]
    for header in headers or []:
        cmd.extend(["-H", header])
    if filter_codes:
        cmd.extend(["-fc", sanitize_input(filter_codes)])
    if filter_size:
        cmd.extend(["-fs", sanitize_input(filter_size)])

    return run_command(cmd, "ffuf", url, parser=_parse_ffuf)
