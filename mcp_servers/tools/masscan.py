"""masscan - fast async port scanner for large IP ranges. Use nmap_scan
for service/version detection once masscan has narrowed down open ports."""
from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any

from mcp_servers.tools._common import run_command, sanitize_input, strip_url


def _resolve_target(target: str) -> str:
    """masscan takes IPs/CIDRs only - it does no DNS resolution and rejects a
    hostname with 'unknown command-line parameter'. Resolve a bare hostname to
    its IP; pass IPs/CIDRs through untouched (and fall back to the original on
    resolution failure so the caller still gets a meaningful masscan error)."""
    try:
        ipaddress.ip_network(target, strict=False)
        return target  # already an IP or CIDR
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)
    except OSError:
        return target


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


def masscan_scan(
    target: str, ports: str = "1-1000", rate: int = 1000, top_ports: str = ""
) -> dict[str, Any]:
    """Fast port scan of a host/CIDR range. `ports` accepts ranges/lists
    (e.g. '1-65535' or '80,443,8080'). `rate` is packets/sec - keep it
    conservative against shared/production infrastructure. masscan has no
    top-ports concept; `top_ports` is accepted only as an alias for `ports`
    (harmonizing with naabu_scan) and folded into it when supplied."""
    target = strip_url(sanitize_input(target))
    if not target:
        return {"status": "error", "error": "Target required"}

    if top_ports and ports == "1-1000":
        ports = top_ports

    target = _resolve_target(target)
    cmd = [
        "masscan", target,
        "-p", sanitize_input(ports),
        "--rate", str(rate),
        "-oG", "-",
    ]
    return run_command(cmd, "masscan", target, parser=_parse_masscan, timeout=300)
