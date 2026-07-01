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

from mcp_servers.tools._common import (
    WORKSPACE_DIR,
    run_command,
    safe_filename,
    sanitize_input,
    save_to_workspace,
    strip_url,
)
from mcp_servers.tools.amass import amass_scan as _amass_scan
from mcp_servers.tools.subfinder import subfinder_scan as _subfinder_scan
from mcp_servers.tools.httpx import httpx_scan as _httpx_scan
from mcp_servers.tools.ffuf import ffuf_fuzz as _ffuf_fuzz
from mcp_servers.tools.gobuster import gobuster_scan as _gobuster_scan
from mcp_servers.tools.katana import katana_crawl as _katana_crawl
from mcp_servers.tools.nuclei import nuclei_scan as _nuclei_scan
from mcp_servers.tools.whois import whois_lookup as _whois_lookup
from mcp_servers.tools.nmap import nmap_scan as _nmap_scan
from mcp_servers.tools.wpscan import wpscan_scan as _wpscan_scan
from mcp_servers.tools.testssl import testssl_scan as _testssl_scan
from mcp_servers.tools.wafw00f import wafw00f_scan as _wafw00f_scan
from mcp_servers.tools.searchsploit import searchsploit_lookup as _searchsploit_lookup
from mcp_servers.tools.arjun import arjun_scan as _arjun_scan
from mcp_servers.tools.masscan import masscan_scan as _masscan_scan
from mcp_servers.tools.enum4linux import enum4linux_scan as _enum4linux_scan
from mcp_servers.tools.upload_test import upload_test as _upload_test
from mcp_servers.tools.ssrf import ssrf_test as _ssrf_test

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


@mcp.tool()
async def nmap_scan(
    target: str,
    ports: str = "",
    scan_type: str = "default",
    service_detection: bool = True,
) -> str:
    """Scan for open ports/services with nmap. scan_type: 'default' (top
    1000 TCP), 'quick' (-F), 'full' (-p-), or 'udp'."""
    return json.dumps(_nmap_scan(target, ports, scan_type, service_detection), indent=2)


@mcp.tool()
async def wpscan_scan(target: str, enumerate: str = "vp,vt,u") -> str:
    """Scan a WordPress site for core/plugin/theme vulnerabilities and
    enumerate users."""
    return json.dumps(_wpscan_scan(target, enumerate), indent=2)


@mcp.tool()
async def testssl_scan(target: str, fast: bool = True) -> str:
    """Audit TLS/SSL configuration: protocols, ciphers, cert issues, and
    known vulnerabilities (Heartbleed, POODLE, FREAK, DROWN, etc.)."""
    return json.dumps(_testssl_scan(target, fast), indent=2)


@mcp.tool()
async def wafw00f_scan(target: str) -> str:
    """Detect whether a target is behind a WAF, and identify which one."""
    return json.dumps(_wafw00f_scan(target), indent=2)


@mcp.tool()
async def searchsploit_lookup(query: str) -> str:
    """Search the local Exploit-DB mirror for known public exploits
    matching a software name/version."""
    return json.dumps(_searchsploit_lookup(query), indent=2)


@mcp.tool()
async def arjun_scan(url: str, method: str = "GET", threads: int = 10) -> str:
    """Discover hidden HTTP GET/POST/JSON parameters on an endpoint."""
    return json.dumps(_arjun_scan(url, method, threads), indent=2)


@mcp.tool()
async def masscan_scan(target: str, ports: str = "1-1000", rate: int = 1000) -> str:
    """Fast async port scan of a host/CIDR range. Pair with nmap_scan for
    service/version detection on the ports it finds."""
    return json.dumps(_masscan_scan(target, ports, rate), indent=2)


@mcp.tool()
async def enum4linux_scan(target: str) -> str:
    """Enumerate SMB shares, users, groups, OS info, and password policy
    on a Windows/Samba host."""
    return json.dumps(_enum4linux_scan(target), indent=2)


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


_NAABU_VALID_TOP = {"full", "100", "1000"}


@mcp.tool()
async def naabu_scan(target: str, ports: str = "", top_ports: str = "100") -> str:
    """Fast port scan with naabu. Pass an explicit port list/range via `ports`
    (e.g. '80,443,8080' or '1-1000'); `top_ports` is naabu's preset and only
    accepts 'full', '100', or '1000'. A comma port list mistakenly passed as
    `top_ports` is routed to `-p` so it still scans instead of erroring."""
    target = strip_url(sanitize_input(target))
    if not target:
        return json.dumps({"status": "error", "error": "Target required"})
    cmd = ["naabu", "-host", target, "-silent", "-nc"]
    if ports:
        cmd += ["-p", sanitize_input(ports)]
    elif top_ports in _NAABU_VALID_TOP:
        cmd += ["-top-ports", top_ports]
    else:  # a custom/comma port list slipped into top_ports - treat it as -p
        cmd += ["-p", sanitize_input(top_ports)]
    return json.dumps(run_command(cmd, "naabu", target, parser=_parse_naabu), indent=2)


def _parse_dnsx(stdout: str) -> dict:
    records = [line.strip() for line in stdout.strip().split("\n") if line.strip()]
    return {"summary": f"Resolved {len(records)} DNS records", "record_count": len(records), "records": records[:100]}


@mcp.tool()
async def dnsx_scan(target: str = "", list_file: str = "", wordlist: str = "", record_type: str = "a") -> str:
    """DNS enumeration/resolution with dnsx.

    Default (no wordlist) resolves the given host(s): dnsx's `-d` flag is
    bruteforce mode and *requires* `-w`, so plain resolution goes through `-l`
    instead. Supplying a `wordlist` switches to subdomain bruteforce (`-d`+`-w`).
    """
    cmd = ["dnsx", "-silent", "-nc"]
    if wordlist:
        # Bruteforce mode: -d takes the base domain, -w the wordlist.
        if not target:
            return json.dumps({"status": "error", "error": "target required for wordlist bruteforce"})
        cmd.extend(["-d", sanitize_input(target), "-w", sanitize_input(wordlist)])
    elif list_file:
        cmd.extend(["-l", sanitize_input(list_file)])
    elif target:
        # Resolve the host(s) via a list file - dnsx `-l` takes a file/stdin,
        # not comma input, so write the target(s) out (mirrors httpx_scan).
        list_path = save_to_workspace(safe_filename("resolve", "dnsx_input"), sanitize_input(target))
        cmd.extend(["-l", list_path])
    else:
        return json.dumps({"status": "error", "error": "Target or list_file required"})
    if record_type:
        cmd.append(f"-{sanitize_input(record_type)}")
    return json.dumps(run_command(cmd, "dnsx", target or list_file, parser=_parse_dnsx), indent=2)


# ══════════════════════════════════════════════
#   WORKSPACE UTILITY TOOLS
# ══════════════════════════════════════════════


def _within_workspace(real_path: str, real_workspace: str) -> bool:
    """True if real_path is inside real_workspace. Uses os.path.commonpath
    rather than str.startswith, so a sibling like '<workspace>_evil' can't slip
    past the prefix check."""
    try:
        return os.path.commonpath([real_path, real_workspace]) == real_workspace
    except ValueError:
        return False  # e.g. different drives, or mixed absolute/relative


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
    if not _within_workspace(real_path, real_workspace):
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
        if not _within_workspace(real_path, real_workspace):
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


@mcp.tool()
def upload_test(url: str, field: str = "file") -> dict:
    """Test a file upload endpoint for dangerous file type acceptance (Delivery phase)."""
    return _upload_test(url, field)


@mcp.tool()
def ssrf_test(url: str, param: str, method: str = "GET") -> dict:
    """Test a URL parameter for Server-Side Request Forgery (C2/Delivery phase)."""
    return _ssrf_test(url, param, method)


if __name__ == "__main__":
    mcp.run()
