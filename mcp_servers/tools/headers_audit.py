"""OWASP A05 Security Misconfiguration — HTTP security headers auditor.
Checks for the presence and quality of security headers in HTTP responses."""
from __future__ import annotations

from typing import Any

import httpx

from mcp_servers.tools._common import safe_filename, sanitize_input, save_to_workspace

_HEADER_CHECKS: list[tuple[str, str, str, str]] = [
    ("strict-transport-security",      "HSTS",         "high",   "Missing HTTP Strict-Transport-Security header"),
    ("content-security-policy",         "CSP",          "high",   "Missing Content-Security-Policy header — XSS mitigation"),
    ("x-frame-options",                "X-Frame-Options", "high", "Missing X-Frame-Options — clickjacking risk"),
    ("x-content-type-options",         "X-Content-Type-Options", "medium",
     "Missing X-Content-Type-Options — MIME-sniffing risk"),
    ("referrer-policy",                "Referrer-Policy", "medium",
     "Missing Referrer-Policy — referrer leakage"),
    ("permissions-policy",             "Permissions-Policy", "medium",
     "Missing Permissions-Policy — no feature control"),
    ("cross-origin-opener-policy",     "COOP",         "low",    "Missing Cross-Origin-Opener-Policy"),
    ("cross-origin-embedder-policy",   "COEP",         "low",    "Missing Cross-Origin-Embedder-Policy"),
    ("cross-origin-resource-policy",   "CORP",         "low",    "Missing Cross-Origin-Resource-Policy"),
]


def _score(findings: list[dict[str, Any]]) -> int:
    """Score 0-100 based on present vs missing headers."""
    critical_missing = sum(1 for f in findings if f.get("severity") == "high")
    medium_missing = sum(1 for f in findings if f.get("severity") == "medium")
    total = len(_HEADER_CHECKS)
    present = total - critical_missing - medium_missing
    return max(0, int((present / total) * 100))


def headers_audit(url: str, follow_redirects: bool = True) -> dict[str, Any]:
    """Audit HTTP security headers of a URL.

    Checks for HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
    Referrer-Policy, Permissions-Policy, COOP, COEP, CORP.

    Returns a score 0-100 and per-header findings.
    """
    url = sanitize_input(url)
    if not url:
        return {"status": "error", "error": "url required"}

    try:
        resp = httpx.get(url, follow_redirects=follow_redirects, timeout=15)
    except httpx.HTTPError as exc:
        return {"status": "error", "error": f"Request failed: {exc}"}

    raw_headers = {k.lower(): v for k, v in resp.headers.items()}

    findings: list[dict[str, Any]] = []
    for header_lower, display_name, severity, message in _HEADER_CHECKS:
        value = raw_headers.get(header_lower, "")
        if not value:
            findings.append({
                "header": display_name,
                "present": False,
                "severity": severity,
                "message": message,
            })
        else:
            findings.append({
                "header": display_name,
                "present": True,
                "severity": "info",
                "value": value[:200],
            })

    score = _score(findings)
    lines = [f"{f['header']}: {'✓' if f['present'] else '✗'} ({f['severity']})" for f in findings]
    log_path = save_to_workspace(safe_filename(url, "headers_audit"), "\n".join(lines))

    return {
        "status": "success",
        "tool": "headers_audit",
        "target": url,
        "score": score,
        "summary": f"Security headers score: {score}/100 ({len([f for f in findings if f['present']])}/{len(findings)} headers present)",
        "findings": findings,
        "full_output_file": log_path,
    }
