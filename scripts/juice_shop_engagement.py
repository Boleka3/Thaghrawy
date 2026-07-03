"""Full Juice Shop engagement — runs all OWASP tools, saves findings, generates reports."""
from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

# Ensure we can import from the project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engagements.manager import EngagementManager  # noqa: E402
from memory.store import MemoryStore  # noqa: E402
from memory.schemas import Finding  # noqa: E402
from core.tools import (  # noqa: E402
    persist_finding,
    generate_engagement_reports,
)
from mcp_servers.tools.headers_audit import headers_audit  # noqa: E402
from mcp_servers.tools.csrf_check import csrf_check  # noqa: E402
from mcp_servers.tools.jwt_analyze import jwt_analyze  # noqa: E402
from mcp_servers.tools.xxe_test import xxe_test  # noqa: E402
from mcp_servers.tools.nuclei import nuclei_scan  # noqa: E402
import httpx  # noqa: E402

TARGET = "http://localhost:3000"
TARGET_NAME = "juice-shop"
PROMPT_HEURISTIC = "http://chall.ctf.example.com:3000"


def now() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def finding_id() -> str:
    return str(uuid.uuid4())


def save_finding(memory, manager, eid: str, **kwargs: Any) -> str:
    """Build a Finding dict and persist it, returning the id."""
    kwargs.setdefault("date", now())
    kwargs.setdefault("id", finding_id())
    kwargs.setdefault("engagement_id", eid)
    f_obj = Finding(**kwargs)
    persist_finding(memory, f_obj, manager)
    print(f"  \u2713 Finding saved: [{f_obj.severity}] {f_obj.title}  (id={f_obj.id[:8]}...)")
    return f_obj.id


def _print_reports(reports: dict) -> None:
    print(f"  Technical report:  {reports.get('technical', {}).get('markdown', 'N/A')}")
    print(f"  Technical PDF:     {reports.get('technical', {}).get('pdf', 'N/A')}")
    print(f"  Executive report:  {reports.get('executive', {}).get('markdown', 'N/A')}")
    print(f"  Executive PDF:     {reports.get('executive', {}).get('pdf', 'N/A')}")


def _preview_report(path: str, label: str, max_lines: int = 80) -> None:
    if not path or not os.path.isfile(path):
        return
    with open(path) as f:
        content = f.read()
    print(f"\n{'=' * 60}")
    print(f"  {label}")
    print(f"{'=' * 60}\n")
    lines = content.split("\n")
    for line in lines[:max_lines]:
        print(line)
    if len(lines) > max_lines:
        print(f"\n... ({len(lines) - max_lines} more lines)")


print("=" * 60)
print("  JUICE SHOP ENGAGEMENT")
print("=" * 60)

# Step 1: Create engagement
print("\n[1/5] Creating engagement...")
manager = EngagementManager()
engagement = manager.create(
    name=f"pentest-{TARGET_NAME}",
    target=TARGET,
    scope=TARGET,
    analysis_mode="full_analysis",
)
eid = engagement.id
print(f"  Engagement ID: {eid}")
print(f"  Target: {engagement.target}")

# Step 2: Initialize memory
print("\n[2/5] Initializing memory...")
memory = MemoryStore()

# Step 3: Run all OWASP tools against Juice Shop
print("\n[3/5] Running OWASP scans...")

# --- headers_audit ---
print("\n  --- headers_audit ---")
ha = headers_audit(TARGET)
print(f"  Score: {ha['score']}/100")
missing_high = [f for f in ha["findings"] if not f["present"] and f["severity"] == "high"]
missing_medium = [f for f in ha["findings"] if not f["present"] and f["severity"] == "medium"]
present_headers = [f for f in ha["findings"] if f["present"]]
print(f"  Missing (high): {len(missing_high)}  (medium): {len(missing_medium)}  present: {len(present_headers)}")

if missing_high:
    save_finding(
        memory, manager, eid,
        title="Missing HTTP Security Headers (HSTS, CSP, XFO)",
        severity="high",
        vuln_type="Security Misconfiguration",
        description=(
            f"Juice Shop is missing {len(missing_high)} critical security headers: "
            f"{', '.join(f['header'] for f in missing_high)}. "
            "Without HSTS, HTTPS enforcement is vulnerable to downgrade attacks. "
            "Without CSP, XSS mitigations are weakened. Without XFO, clickjacking is possible."
        ),
        reproduction_steps=(
            f"Run: headers_audit(url='{TARGET}')\n"
            f"Missing headers:\n" + "\n".join(f"  - {f['header']}" for f in missing_high)
        ),
        technique_used="headers_audit",
        target=TARGET,
        tags=["security-misconfiguration", "hsts", "csp", "xfo",
              "clickjacking", "auto-ingested"],
        cvss_score=6.5,
        affected_component=TARGET,
        business_impact=(
            "Users are exposed to downgrade attacks, XSS-based data theft, "
            "and UI redressing attacks."
        ),
        remediation=(
            "Add Strict-Transport-Security, Content-Security-Policy, "
            "and X-Frame-Options headers to all HTTP responses."
        ),
    )

if missing_medium:
    save_finding(
        memory, manager, eid,
        title="Missing Medium-Severity Security Headers",
        severity="medium",
        vuln_type="Security Misconfiguration",
        description=(
            f"Missing {len(missing_medium)} medium-severity headers: "
            f"{', '.join(f['header'] for f in missing_medium)}."
        ),
        reproduction_steps=f"Run: headers_audit(url='{TARGET}')",
        technique_used="headers_audit",
        target=TARGET,
        tags=["security-misconfiguration", "headers", "auto-ingested"],
        cvss_score=4.0,
        affected_component=TARGET,
        business_impact=(
            "Reduced defense-in-depth increases risk of information disclosure "
            "via referrer leakage and MIME confusion."
        ),
        remediation=(
            "Add X-Content-Type-Options: nosniff, Referrer-Policy, "
            "and Permissions-Policy headers."
        ),
    )

# --- csrf_check ---
print("\n  --- csrf_check ---")
cc = csrf_check(TARGET)
print(f"  Forms: {cc['forms_found']}  POST: {cc['post_forms']}  CSRF: {cc['has_csrf_protection']}")

cc_login = csrf_check(f"{TARGET}/rest/user/login")
print(f"  Login endpoint - Forms: {cc_login['forms_found']}  CSRF: {cc_login['has_csrf_protection']}")

# --- jwt_analyze ---
print("\n  --- jwt_analyze ---")
resp = httpx.post(
    f"{TARGET}/rest/user/login",
    json={"email": "tester@test.com", "password": "test123"},
    timeout=15,
)
if resp.status_code == 200:
    token = resp.json().get("authentication", {}).get("token", "")
    if token:
        ja = jwt_analyze(token)
        print(f"  Algorithm: {ja['header']['alg']}")
        print(f"  Findings: {ja['summary']}")
        for f_item in ja["findings"]:
            print(f"    [{f_item['severity']}] {f_item['issue']}: "
                  f"{f_item['detail'][:80]}")

        missing_exp = [f_item for f_item in ja["findings"]
                       if f_item["issue"] == "no_expiration"]
        if missing_exp and ja["header"]["alg"] not in ("RS256", "RS384", "RS512"):
            save_finding(
                memory, manager, eid,
                title="JWT Token Missing Expiration Claim",
                severity="high",
                vuln_type="Identification & Authentication Failures",
                description=(
                    f"JWT token uses {ja['header']['alg']} algorithm but lacks "
                    "an `exp` (expiration) claim. The token never expires, "
                    "increasing the window for token theft or reuse."
                ),
                reproduction_steps=(
                    "1. Login to Juice Shop\n"
                    "2. Extract JWT from response\n"
                    "3. Run: jwt_analyze(token='<token>')\n"
                    "4. Observe: no_expiration finding"
                ),
                technique_used="jwt_analyze",
                target=TARGET,
                tags=["jwt", "authentication", "expiration", "auto-ingested"],
                cvss_score=5.3,
                affected_component="/rest/user/login",
                business_impact=(
                    "Stolen or leaked tokens remain valid indefinitely, "
                    "enabling long-term account takeover."
                ),
                remediation=(
                    "Add an `exp` (expiration) claim with a reasonable TTL "
                    "(e.g. 1 hour) to all issued JWT tokens."
                ),
            )
        if ja["header"]["alg"] == "none":
            save_finding(
                memory, manager, eid,
                title="JWT Token Uses 'none' Algorithm",
                severity="critical",
                vuln_type="Identification & Authentication Failures",
                description=(
                    "JWT token has algorithm set to 'none', meaning it has "
                    "no cryptographic signature."
                ),
                reproduction_steps="Run: jwt_analyze(token) -> alg:none finding",
                technique_used="jwt_analyze",
                target=TARGET,
                tags=["jwt", "authentication", "alg-none", "auto-ingested"],
                cvss_score=9.1,
                affected_component="/rest/user/login",
                business_impact=(
                    "Any user can forge tokens with arbitrary claims, "
                    "gaining admin access."
                ),
                remediation=(
                    "Reject tokens with 'alg: none'. "
                    "Use RS256 or HS256 with a strong secret."
                ),
            )
    else:
        print("  No JWT token obtained")
else:
    print(f"  Login failed: {resp.status_code}")

# --- xxe_test ---
print("\n  --- xxe_test ---")
xt = xxe_test(f"{TARGET}/api/", method="POST")
print(f"  Vulnerable: {xt['vulnerable_count']}/{len(xt['results'])} payloads flagged")
for r in xt["results"]:
    if r.get("vulnerable"):
        print(f"    ! {r['payload_label']}: code={r.get('http_code')}")

if xt["vulnerable_count"] > 0:
    save_finding(
        memory, manager, eid,
        title="Information Disclosure via XML Processing Error",
        severity="medium",
        vuln_type="Security Misconfiguration",
        description=(
            f"The endpoint {TARGET}/api/ reflects error messages "
            f"when sent XML content. {xt['vulnerable_count']}/"
            f"{len(xt['results'])} payloads caused verbose error "
            "responses that may leak internal server information."
        ),
        reproduction_steps=(
            "Run: xxe_test(url='" + TARGET + "/api/', method='POST')"
        ),
        technique_used="xxe_test",
        target=TARGET,
        tags=["xxe", "information-disclosure", "error-handling",
              "auto-ingested"],
        cvss_score=3.7,
        affected_component="/api/",
        business_impact=(
            "Verbose error responses may leak internal paths, "
            "library versions, or database details to attackers."
        ),
        remediation=(
            "Configure the server to return generic error messages "
            "and log details server-side only."
        ),
    )

# --- nuclei ---
print("\n  --- nuclei_scan ---")
ns = nuclei_scan(TARGET, tags="misconfig,exposure")
print(f"  Nuclei results: {'see full_output_file' if ns.get('findings') else 'no findings'}")
if ns.get("findings"):
    for f_item in ns["findings"][:5]:
        info = f_item.get("info", {})
        print(f"    {f_item.get('name', '?')} ({f_item.get('severity', '?')})")
        save_finding(
            memory, manager, eid,
            title=f_item.get("name", f"Juice Shop: {info.get('name', 'Unknown')}"),
            severity=f_item.get("severity", "info"),
            vuln_type="Vulnerable Component",
            description=info.get("description", ""),
            reproduction_steps=(
                "Run: nuclei_scan(target='" + TARGET
                + "', tags='misconfig,exposure')"
            ),
            technique_used="nuclei_scan",
            target=TARGET,
            tags=["nuclei", "cve", "auto-ingested"],
            affected_component=f_item.get("matched-at", TARGET),
        )

# Step 4: Generate reports
print("\n[4/5] Generating reports...")
reports = generate_engagement_reports(memory, eid)
_print_reports(reports)

# Step 5: Display report content
print("\n[5/5] Report previews:")
_preview_report(
    reports.get("technical", {}).get("markdown", ""),
    "TECHNICAL REPORT", 100,
)
_preview_report(
    reports.get("executive", {}).get("markdown", ""),
    "EXECUTIVE REPORT", 80,
)

print(f"\n{'=' * 60}")
print("  ENGAGEMENT COMPLETE")
print(f"{'=' * 60}")
