"""masscan - fast async port scanner for large IP ranges. Use nmap_scan
for service/version detection once masscan has narrowed down open ports."""
from __future__ import annotations

import re
from typing import Any

from mcp_servers.tools._common import run_command, sanitize_input


def _parse_masscan(stdout: str) -> dict[str, Any]:
    ports = []
    for line in stdout.splitlines():
        match = re.search(r"Ports:\s*(\d+)/open/(tcp|udp)", line)
        if match:
            ports.append({"port": int(match.group(1)), "protocol": match.group(2)})

    return {
        "summary": f"Found {len(ports)} open port(s)",
        "open_ports": ports,
    }


def masscan_scan(target: str, ports: str = "1-1000", rate: int = 1000) -> dict[str, Any]:
    """Fast port scan of a host/CIDR range. `ports` accepts ranges/lists
    (e.g. '1-65535' or '80,443,8080'). `rate` is packets/sec - keep it
    conservative against shared/production infrastructure."""
    target = sanitize_input(target)
    if not target:
        return {"status": "error", "error": "Target required"}

    cmd = [
        "masscan", target,
        "-p", sanitize_input(ports),
        "--rate", str(rate),
        "-oG", "-",
    ]
    return run_command(cmd, "masscan", target, parser=_parse_masscan, timeout=300)
