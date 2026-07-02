"""httpx live-host probing. Accepts either a workspace file of domains
(`file`) or an inline list of domains (`domains`) - the latter avoids the
file-path handoff bug observed in real engagement data where a relative
path from a prior tool call couldn't be resolved by httpx -l."""
from __future__ import annotations

import os
import re
import shutil
from typing import Any, Optional

from mcp_servers.tools._common import (
    WORKSPACE_DIR,
    run_command,
    sanitize_input,
    safe_filename,
    save_to_workspace,
)


def _parse_httpx(stdout: str) -> dict[str, Any]:
    hosts = [line.strip() for line in stdout.strip().split("\n") if line.strip()]
    return {
        "summary": f"Found {len(hosts)} alive hosts",
        "alive_count": len(hosts),
        "hosts": hosts[:100],
    }


def _looks_like_workspace_file(value: str) -> bool:
    """True if `value` resolves to an existing file (as given, or by basename
    inside the workspace) - i.e. the caller meant `file`, not a domain."""
    return os.path.isfile(value) or os.path.isfile(
        os.path.join(WORKSPACE_DIR, os.path.basename(value))
    )


def httpx_scan(file: Optional[str] = None, domains: Optional[list[str]] = None) -> dict[str, Any]:
    # The LLM often passes `domains` as a raw string (a comma/space list, or even
    # a workspace file path) instead of a JSON array. Left as-is, "\n".join() over
    # a string joins individual CHARACTERS into a garbage host file and every probe
    # fails. Normalize into a clean list, or reroute a file path to `file`.
    if isinstance(domains, str):
        s = domains.strip()
        if s and not file and _looks_like_workspace_file(s):
            file, domains = s, None
        else:
            domains = re.split(r"[\s,]+", s) if s else None
    if domains:
        flat: list[str] = []
        for d in domains:
            flat.extend(re.split(r"[\s,]+", d.strip()))
        domains = [d for d in flat if d]

    if domains:
        list_filename = safe_filename("inline_domains", "httpx_input")
        file = save_to_workspace(list_filename, "\n".join(domains))
    else:
        file = sanitize_input(file or "")
        if not file:
            return {"status": "error", "error": "Provide either 'file' or 'domains'"}
        if not os.path.isabs(file):
            file = os.path.join(WORKSPACE_DIR, os.path.basename(file))
        if not os.path.isfile(file):
            return {"status": "error", "error": f"Input file not found: {file}"}

    # On Kali/Docker the ProjectDiscovery binary is installed as `httpx-toolkit`
    # so it doesn't collide with the Python `httpx` HTTP-client CLI that ships in
    # our venv (which has no `-l` and would error). Prefer it; fall back to
    # `httpx` for bare-metal installs where the PD binary keeps that name (the
    # _common.py PATH ordering puts ~/go/bin + /usr/local/bin ahead of the venv).
    binary = shutil.which("httpx-toolkit") or "httpx"
    cmd = [binary, "-l", file, "-sc", "-title", "-tech-detect", "-silent"]
    return run_command(cmd, "httpx", file, parser=_parse_httpx)
