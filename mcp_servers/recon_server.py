"""Recon MCP server.

Registers each recon tool with FastMCP. All scan tools delegate to
mcp_servers/tools/<tool>.py for testable, framework-free logic; this file
is just MCP registration plus the few tools that don't warrant their own
module.
"""
import json
import os
import re
from datetime import datetime
from typing import Optional

from mcp.server.fastmcp import FastMCP

from mcp_servers.tools._common import WORKSPACE_DIR, run_command, sanitize_input
from mcp_servers.tools.amass import amass_scan as _amass_scan
from mcp_servers.tools.subfinder import subfinder_scan as _subfinder_scan
from mcp_servers.tools.httpx import httpx_scan as _httpx_scan
from mcp_servers.tools.ffuf import ffuf_fuzz as _ffuf_fuzz
from mcp_servers.tools.gobuster import gobuster_scan as _gobuster_scan
from mcp_servers.tools.katana import katana_crawl as _katana_crawl
from mcp_servers.tools.nuclei import nuclei_scan as _nuclei_scan
from mcp_servers.tools.whois import whois_lookup as _whois_lookup

mcp = FastMCP("recon")


# ══════════════════════════════════════════════
#   TOOLS BACKED BY mcp/tools/*.py MODULES
# ══════════════════════════════════════════════


@mcp.tool()
async def amass_scan(domain: str, mode: str = "passive", brute: bool = False) -> str:
    """Enumerate subdomains using OWASP Amass (passive/active, optional brute-force)."""
    return json.dumps(_amass_scan(domain, mode, brute), indent=2)


@mcp.tool()
async def subfinder_scan(domain: str) -> str:
    """Enumerate subdomains using Subfinder. Saves a usable subdomain list
    file for httpx_scan's `file` parameter."""
    return json.dumps(_subfinder_scan(domain), indent=2)


@mcp.tool()
async def httpx_scan(file: Optional[str] = None, domains: Optional[list[str]] = None) -> str:
    """Probe domains for live HTTP/HTTPS servers. Pass either `file`
    (a workspace filename from subfinder_scan) or `domains` (inline list)."""
    return json.dumps(_httpx_scan(file, domains), indent=2)


@mcp.tool()
async def ffuf_fuzz(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    method: str = "GET",
    headers: Optional[list[str]] = None,
    match_codes: str = "200,204,301,302,307,401,403,405,500",
    filter_codes: Optional[str] = None,
    filter_size: Optional[str] = None,
    threads: int = 40,
) -> str:
    """Fuzz directories/files/params with ffuf. URL must contain FUZZ
    (it is appended automatically if missing)."""
    return json.dumps(
        _ffuf_fuzz(url, wordlist, method, headers, match_codes, filter_codes, filter_size, threads),
        indent=2,
    )


@mcp.tool()
async def gobuster_scan(
    mode: str,
    target: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    threads: int = 10,
    status_codes: str = "200,204,301,302,307,401,403",
    extensions: Optional[str] = None,
) -> str:
    """Run gobuster: 'dir' (path brute-force), 'dns' (subdomains), or 'vhost'."""
    return json.dumps(
        _gobuster_scan(mode, target, wordlist, threads, status_codes, extensions), indent=2
    )


@mcp.tool()
async def katana_crawl(target: str, depth: int = 3, js_crawl: bool = True) -> str:
    """Crawl a target with katana, categorizing discovered URLs into JS/API/forms/other."""
    return json.dumps(_katana_crawl(target, depth, js_crawl), indent=2)


@mcp.tool()
async def nuclei_scan(target: str, templates: str = "", severity: str = "", tags: str = "") -> str:
    """Run nuclei vulnerability templates against a target."""
    return json.dumps(_nuclei_scan(target, templates, severity, tags), indent=2)


@mcp.tool()
async def whois_lookup(domain: str) -> str:
    """Look up domain registration details (registrar, dates, name servers, status)."""
    return json.dumps(_whois_lookup(domain), indent=2)


# ══════════════════════════════════════════════
#   ADDITIONAL TOOLS (kept inline - not in the
#   original target tool list, but valuable)
# ══════════════════════════════════════════════


def _parse_whatweb(stdout: str) -> dict:
    technologies = []
    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("http"):
            continue
        if ":" in line:
            technologies.append(line)
    return {"summary": f"Detected {len(technologies)} technology entries", "technologies": technologies[:30]}


@mcp.tool()
async def web_tech_detect(target: str) -> str:
    """Identify web technologies using WhatWeb."""
    target = sanitize_input(target)
    if not target:
        return json.dumps({"status": "error", "error": "Target required"})
    cmd = ["whatweb", "--color=never", target, "-v"]
    return json.dumps(run_command(cmd, "whatweb", target, parser=_parse_whatweb), indent=2)


def _parse_assetfinder(stdout: str) -> dict:
    assets = sorted({line.strip() for line in stdout.strip().split("\n") if line.strip()})
    return {"summary": f"Found {len(assets)} unique assets", "asset_count": len(assets), "assets": assets}


@mcp.tool()
async def assetfinder_scan(domain: str) -> str:
    """Discover related domains/subdomains using Assetfinder."""
    domain = sanitize_input(domain)
    if not domain:
        return json.dumps({"status": "error", "error": "Domain required"})
    cmd = ["assetfinder", "--subs-only", domain]
    return json.dumps(run_command(cmd, "assetfinder", domain, parser=_parse_assetfinder), indent=2)


def _parse_naabu(stdout: str) -> dict:
    open_ports = []
    for line in stdout.strip().split("\n"):
        line = line.strip()
        match = re.search(r"([^:]+):(\d+)", line)
        if match:
            open_ports.append({"host": match.group(1), "port": int(match.group(2))})
    ports_only = sorted({p["port"] for p in open_ports})
    return {
        "summary": f"Found {len(ports_only)} open ports on {len({p['host'] for p in open_ports})} host(s)",
        "open_port_count": len(ports_only),
        "ports": ports_only,
        "details": open_ports[:100],
    }


@mcp.tool()
async def naabu_scan(target: str, ports: str = "", top_ports: str = "100") -> str:
    """Fast port scan with naabu."""
    target = sanitize_input(target)
    if not target:
        return json.dumps({"status": "error", "error": "Target required"})
    cmd = ["naabu", "-host", target, "-silent", "-nc"]
    cmd += ["-p", sanitize_input(ports)] if ports else ["-top-ports", top_ports]
    return json.dumps(run_command(cmd, "naabu", target, parser=_parse_naabu), indent=2)


def _parse_dnsx(stdout: str) -> dict:
    records = [line.strip() for line in stdout.strip().split("\n") if line.strip()]
    return {"summary": f"Resolved {len(records)} DNS records", "record_count": len(records), "records": records[:100]}


@mcp.tool()
async def dnsx_scan(target: str = "", list_file: str = "", wordlist: str = "", record_type: str = "a") -> str:
    """DNS enumeration/resolution with dnsx."""
    cmd = ["dnsx", "-silent", "-nc"]
    if list_file:
        cmd.extend(["-l", sanitize_input(list_file)])
    elif target:
        cmd.extend(["-d", sanitize_input(target)])
    else:
        return json.dumps({"status": "error", "error": "Target or list_file required"})
    if wordlist:
        cmd.extend(["-w", sanitize_input(wordlist)])
    if record_type:
        cmd.append(f"-{sanitize_input(record_type)}")
    return json.dumps(run_command(cmd, "dnsx", target or list_file, parser=_parse_dnsx), indent=2)


# ══════════════════════════════════════════════
#   WORKSPACE UTILITY TOOLS
# ══════════════════════════════════════════════


@mcp.tool()
async def list_workspace() -> str:
    """List all files saved to the recon workspace by previous tool runs."""
    try:
        files = []
        for entry in sorted(os.listdir(WORKSPACE_DIR)):
            filepath = os.path.join(WORKSPACE_DIR, entry)
            if os.path.isfile(filepath):
                stat = os.stat(filepath)
                files.append({
                    "filename": entry,
                    "size_bytes": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                })
        payload = {"status": "success", "workspace": WORKSPACE_DIR, "file_count": len(files), "files": files}
        return json.dumps(payload, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)})


@mcp.tool()
async def read_file(filename: str, max_lines: int = 100) -> str:
    """Read a file from the recon workspace (use max_lines to conserve tokens)."""
    filename = sanitize_input(filename)
    if not filename:
        return json.dumps({"status": "error", "error": "Filename required"})

    filepath = os.path.join(WORKSPACE_DIR, filename)
    real_path = os.path.realpath(filepath)
    real_workspace = os.path.realpath(WORKSPACE_DIR)
    if not real_path.startswith(real_workspace):
        return json.dumps({"status": "error", "error": "Access denied: path traversal detected"})
    if not os.path.isfile(filepath):
        return json.dumps({"status": "error", "error": f"File not found: {filename}"})

    with open(filepath, "r") as f:
        lines = f.readlines()
    total_lines = len(lines)
    returned_lines = lines[:max_lines]
    return json.dumps({
        "status": "success",
        "filename": filename,
        "total_lines": total_lines,
        "returned_lines": len(returned_lines),
        "truncated": total_lines > max_lines,
        "content": "".join(returned_lines),
    }, indent=2)


@mcp.tool()
async def grep_workspace(pattern: str, filename: str = "") -> str:
    """Search for a regex pattern across workspace files without loading them entirely."""
    pattern = sanitize_input(pattern)
    if not pattern:
        return json.dumps({"status": "error", "error": "Search pattern required"})

    real_workspace = os.path.realpath(WORKSPACE_DIR)
    files_to_search = []
    if filename:
        filename = sanitize_input(filename)
        filepath = os.path.join(WORKSPACE_DIR, filename)
        real_path = os.path.realpath(filepath)
        if not real_path.startswith(real_workspace):
            return json.dumps({"status": "error", "error": "Access denied: path traversal detected"})
        if not os.path.isfile(filepath):
            return json.dumps({"status": "error", "error": f"File not found: {filename}"})
        files_to_search = [filepath]
    else:
        for entry in os.listdir(WORKSPACE_DIR):
            fpath = os.path.join(WORKSPACE_DIR, entry)
            if os.path.isfile(fpath):
                files_to_search.append(fpath)

    matches = []
    for fpath in files_to_search:
        try:
            with open(fpath, "r") as f:
                for line_num, line in enumerate(f, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        matches.append({"file": os.path.basename(fpath), "line": line_num, "content": line.strip()})
        except (UnicodeDecodeError, PermissionError):
            continue

    total_matches = len(matches)
    capped = matches[:50]
    return json.dumps({
        "status": "success",
        "pattern": pattern,
        "total_matches": total_matches,
        "returned_matches": len(capped),
        "truncated": total_matches > 50,
        "matches": capped,
    }, indent=2)


if __name__ == "__main__":
    mcp.run()
