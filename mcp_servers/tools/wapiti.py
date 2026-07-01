"""wapiti - broad web-application vulnerability scanner covering several OWASP
Top-10 web classes (XSS, SQLi, command execution, file handling, SSRF, CRLF).

Builds an argv list (never a shell string) and runs it through run_command()
for consistent timeout / workspace / envelope / logging behavior. wapiti writes
a structured JSON report to the workspace; the wrapper parses that report into a
per-category vulnerability count so the agent gets a compact summary.
"""
from __future__ import annotations

import json
import os
from typing import Any

from mcp_servers.tools._common import WORKSPACE_DIR, run_command, safe_filename

_WAPITI_TIMEOUT = 900
# Cap wapiti's own crawl+attack time so one scan can't dominate the engagement.
_WAPITI_MAX_SCAN_TIME = 180


def _parse_wapiti_report(report_path: str) -> dict[str, Any]:
    """Parse a wapiti JSON report into per-category counts. wapiti's report
    shape is {"vulnerabilities": {"<Category>": [ {..}, .. ], ...}, ...}."""
    with open(report_path) as fh:
        report = json.load(fh)

    vulns = report.get("vulnerabilities", {}) or {}
    by_category = {cat: len(items) for cat, items in vulns.items() if items}
    total = sum(by_category.values())
    return {
        "summary": f"wapiti found {total} vulnerability instance(s) across {len(by_category)} categor(y/ies)",
        "vulnerability_count": total,
        "by_category": by_category,
        "categories": sorted(by_category),
    }


def wapiti_scan(
    url: str, modules: str = "xss,sql,exec,file,ssrf", scope: str = "folder"
) -> dict[str, Any]:
    """Run a broad OWASP web vulnerability sweep with wapiti.

    Args:
        url: Target base URL.
        modules: Comma-separated attack modules (xss, sql, exec, file, ssrf, ...).
        scope: Crawl scope - 'url', 'page', 'folder', or 'domain'.
    """
    if not url:
        return {"status": "error", "error": "URL required"}

    report_path = os.path.join(WORKSPACE_DIR, safe_filename(url, "wapiti", ext="json"))
    # URL passes verbatim (no shell); query characters must survive.
    cmd = [
        "wapiti", "-u", url,
        "-m", modules,
        "--scope", scope,
        "--flush-session",
        "--max-scan-time", str(_WAPITI_MAX_SCAN_TIME),
        "-f", "json", "-o", report_path,
    ]
    result = run_command(cmd, "wapiti", url, timeout=_WAPITI_TIMEOUT)

    # Augment the envelope with the parsed JSON report when wapiti produced one
    # (run_command's stdout capture alone doesn't carry the structured findings).
    if os.path.isfile(report_path):
        try:
            result.update(_parse_wapiti_report(report_path))
        except (OSError, ValueError) as exc:
            result["parse_error"] = str(exc)
    return result
