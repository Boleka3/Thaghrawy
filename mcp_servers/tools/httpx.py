"""httpx live-host probing. Accepts either a workspace file of domains
(`file`) or an inline list of domains (`domains`) - the latter avoids the
file-path handoff bug observed in real engagement data where a relative
path from a prior tool call couldn't be resolved by httpx -l."""
from __future__ import annotations

import os
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


def httpx_scan(file: Optional[str] = None, domains: Optional[list[str]] = None) -> dict[str, Any]:
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
