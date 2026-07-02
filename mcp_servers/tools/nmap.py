"""nmap port/service scanner."""
from __future__ import annotations

import re
from typing import Any

from mcp_servers.tools._common import run_command, sanitize_input, strip_url


def _parse_nmap(stdout: str) -> dict[str, Any]:
    ports = []
    for line in stdout.splitlines():
        match = re.match(r"^(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)(.*)$", line.strip())
        if match:
            ports.append({
                "port": int(match.group(1)),
                "protocol": match.group(2),
                "state": match.group(3),
                "service": match.group(4),
                "version": match.group(5).strip(),
            })

    os_match = re.search(r"Running:\s*(.+)", stdout) or re.search(r"OS details:\s*(.+)", stdout)

    return {
        "summary": f"Found {len(ports)} ports",
        "open_ports": [p for p in ports if p["state"] == "open"],
        "total_ports_reported": len(ports),
        "os_guess": os_match.group(1).strip() if os_match else None,
    }


def nmap_scan(
    target: str,
    ports: str = "",
    scan_type: str = "default",
    service_detection: bool = True,
    top_ports: str = "",
) -> dict[str, Any]:
    """Scan a host/range for open ports and services. `scan_type`:
    'default' (top 1000 TCP), 'quick' (-F fast scan), 'full' (-p- all 65535),
    or 'udp' (-sU, slower, top UDP ports). `ports` is an explicit list/range
    ('22,80,443' or '1-1000'); `top_ports` is the COUNT of most-common ports to
    scan (e.g. '100' -> nmap --top-ports 100)."""
    target = strip_url(sanitize_input(target))
    if not target:
        return {"status": "error", "error": "Target required"}

    # `top_ports` should be a count (nmap --top-ports N), but the model sometimes
    # passes an explicit port list there (generalizing from naabu). Route a comma
    # list to -p; a bare integer to --top-ports. An explicit `ports` wins.
    top_ports = sanitize_input(top_ports)
    if top_ports and not ports:
        if "," in top_ports or "-" in top_ports:
            ports = top_ports
            top_ports = ""

    cmd = ["nmap", "-Pn"]
    if scan_type == "quick":
        cmd.append("-F")
    elif scan_type == "full":
        cmd.append("-p-")
    elif scan_type == "udp":
        cmd.append("-sU")
    if ports:
        cmd.extend(["-p", sanitize_input(ports)])
    elif top_ports:
        cmd.extend(["--top-ports", top_ports])
    if service_detection:
        cmd.append("-sV")
    cmd.append(target)

    timeout = 600 if scan_type in ("full", "udp") else None
    return run_command(cmd, "nmap", target, parser=_parse_nmap, timeout=timeout)
