"""Turn structured scanner output into Finding drafts.

Findings currently depend entirely on the LLM choosing to call save_finding.
That's fragile with a weak model. These pure helpers bridge the gap: they read a
scanner result dict (nuclei's per-vuln list, sqlmap's verdict, dalfox's POCs,
wapiti's categories, nikto's high-precision misconfig lines) and produce Finding
objects directly.

`vuln_type` is normalized to the benchmark's ground-truth category vocabulary
(benchmarks/ground_truth.py) so an auto-ingested finding actually scores against
the Detection-Rate metric and doesn't inflate the false-positive rate. This is
NOT gaming the metric - classification is conservative keyword matching, and
anything unrecognized becomes "Security Misconfiguration" (a real category and
the dominant class of enumeration findings).

Used two ways: PentestAgent.enumerate() auto-ingests during the autonomous
enumeration phase, and the human-driven "promote result -> finding" flow reuses
finding_from_tool_result() to pre-fill a draft the operator reviews.

Also detects flag/secret patterns (picoCTF{...}, CTF{...}) in ANY tool output
via flag_findings_from_output(), which is appended to every finding_from_tool_result
call — so flags from shell, http_request, or any tool get surfaced as draft findings.
"""
from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import config
from memory.schemas import Finding

logger = logging.getLogger(__name__)

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

# Ordered (substring -> ground-truth category) rules. First match wins, so more
# specific patterns must precede general ones. Category strings are chosen to
# substring-match GROUND_TRUTH entries in benchmarks/ground_truth.py.
_CATEGORY_RULES: list[tuple[tuple[str, ...], str]] = [
    (("sql injection", "sqli", "sql-injection"), "SQL Injection"),
    (("cross site scripting", "cross-site scripting", "xss"), "XSS"),
    (("command injection", "command execution", "command exec", "rce", "os command"), "Command Injection"),
    (("csrf", "cross-site request forgery"), "CSRF"),
    (("local file inclusion", "remote file inclusion", "file inclusion", "lfi", "rfi",
      "path traversal", "directory traversal"), "File Inclusion"),
    (("file upload", "unrestricted upload"), "File Upload"),
    (("ssrf", "server-side request forgery"), "Injection"),
    (("cve-", "outdated", "vulnerable version", "version disclosure", "end-of-life", "eol"), "Vulnerable Components"),
    (("tls", "ssl", "certificate", "cipher", "heartbleed", "poodle"), "Sensitive Data Exposure"),
    (("default cred", "weak password", "brute", "login"), "Brute Force"),
]

# Fallback category for the many benign enumeration hits (missing headers,
# directory listing, exposed panels, info leaks, cookie flags, CORS, …).
_DEFAULT_CATEGORY = "Security Misconfiguration"


def normalize_vuln_type(hint: str) -> str:
    """Classify a free-text scanner hint into a ground-truth category phrase.

    Matches each needle at a word boundary so a short token can't match inside a
    larger word (e.g. 'rce' must not fire on 'cross-origin-resou[rce]-policy')."""
    low = (hint or "").lower()
    for needles, category in _CATEGORY_RULES:
        if any(re.search(r"\b" + re.escape(n), low) for n in needles):
            return category
    return _DEFAULT_CATEGORY


def _severity(raw: Optional[str], default: str = "info") -> str:
    sev = (raw or "").strip().lower()
    return sev if sev in _VALID_SEVERITIES else default


def _mk(
    *,
    engagement_id: str,
    target: str,
    title: str,
    vuln_type: str,
    severity: str,
    description: str,
    reproduction_steps: str,
    technique_used: str,
    affected_component: Optional[str] = None,
    tags: Optional[list[str]] = None,
) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        title=title[:200],
        severity=severity,
        vuln_type=vuln_type,
        description=description,
        reproduction_steps=reproduction_steps,
        technique_used=technique_used,
        target=target,
        engagement_id=engagement_id,
        date=datetime.now(timezone.utc).date().isoformat(),
        tags=tags or [vuln_type, "auto-ingested"],
        affected_component=affected_component,
    )


def _from_nuclei(result: dict[str, Any], engagement_id: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for item in result.get("findings", []) or []:
        template = str(item.get("template", "")).strip()
        matched = str(item.get("matched", "")).strip() or target
        vuln_type = normalize_vuln_type(f"{template} {matched}")
        findings.append(_mk(
            engagement_id=engagement_id, target=target,
            title=f"nuclei: {template}" if template else "nuclei match",
            vuln_type=vuln_type,
            severity=_severity(item.get("severity")),
            description=f"nuclei template '{template}' matched at {matched}.",
            reproduction_steps=f"Run: nuclei -u {target}\nObserve template '{template}' match at {matched}.",
            technique_used="nuclei_scan",
            affected_component=matched,
        ))
    return findings


# Nikto emits unstructured text lines and is prone to false positives (e.g. a
# JAMon .jsp hit on a Node app). Only auto-ingest lines matching high-precision
# misconfiguration patterns; leave everything else for the human to promote.
_NIKTO_SAFE_PATTERNS = (
    "x-frame-options", "x-content-type-options", "content-security-policy",
    "strict-transport-security", "header is not", "not set", "not present",
    "directory indexing", "server leaks", "cookie", "clickjacking",
)


def _from_nikto(result: dict[str, Any], engagement_id: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in result.get("findings", []) or []:
        low = str(line).lower()
        if not any(p in low for p in _NIKTO_SAFE_PATTERNS):
            continue  # skip ambiguous / FP-prone lines
        findings.append(_mk(
            engagement_id=engagement_id, target=target,
            title=f"nikto: {str(line)[:80]}",
            vuln_type=_DEFAULT_CATEGORY,
            severity="low",
            description=str(line),
            reproduction_steps=f"Run: nikto -h {target}\nObserve: {line}",
            technique_used="nikto_scan",
        ))
    return findings


def _from_wapiti(result: dict[str, Any], engagement_id: str, target: str) -> list[Finding]:
    findings: list[Finding] = []
    for category, count in (result.get("by_category") or {}).items():
        if not count:
            continue
        vuln_type = normalize_vuln_type(category)
        findings.append(_mk(
            engagement_id=engagement_id, target=target,
            title=f"wapiti: {category} ({count})",
            vuln_type=vuln_type,
            severity="medium",
            description=f"wapiti reported {count} '{category}' instance(s) on {target}.",
            reproduction_steps=f"Run: wapiti -u {target}\nReview the '{category}' section of the report.",
            technique_used="wapiti_scan",
        ))
    return findings


def _from_sqlmap(result: dict[str, Any], engagement_id: str, target: str) -> list[Finding]:
    if not result.get("injectable"):
        return []
    params = ", ".join(result.get("parameters", []) or []) or "the tested parameter"
    dbms = result.get("dbms") or "unknown DBMS"
    return [_mk(
        engagement_id=engagement_id, target=target,
        title=f"SQL Injection in {params}",
        vuln_type="SQL Injection",
        severity="high",
        description=f"sqlmap confirmed SQL injection ({dbms}) via {params}.",
        reproduction_steps=f"Run: sqlmap -u {target} --batch\nObserve injectable parameter(s): {params}.",
        technique_used="sqlmap_scan",
    )]


def _from_dalfox(result: dict[str, Any], engagement_id: str, target: str) -> list[Finding]:
    if not result.get("xss_found"):
        return []
    params = ", ".join(result.get("reflected_params", []) or []) or "a reflected parameter"
    return [_mk(
        engagement_id=engagement_id, target=target,
        title=f"Reflected XSS via {params}",
        vuln_type="XSS",
        severity="high",
        description=f"dalfox produced {result.get('poc_count', 0)} XSS PoC(s) on {target}.",
        reproduction_steps=f"Run: dalfox url {target}\nReview the reported POC line(s) for {params}.",
        technique_used="dalfox_scan",
    )]


# Built-in flag patterns: picoCTF{...}, CTF{...}, flag{...}
_FLAG_PATTERNS: list[re.Pattern] = [
    re.compile(r"picoCTF\{[^}]{1,256}\}"),
    re.compile(r"(?i)\b(?:flag|ctf)\{[^}]{1,256}\}"),
]


def _coerce_to_string(result: Any) -> str:
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        try:
            return json.dumps(result)
        except (ValueError, TypeError):
            return str(result)
    return str(result)


def flag_findings_from_output(
    tool_name: str,
    result: Any,
    engagement_id: str,
    target: str,
) -> list[Finding]:
    """Scan any tool output for captured flag/secret patterns. Returns one
    Finding per unique match, vuln_type='Sensitive Data Exposure'."""
    text = _coerce_to_string(result)
    if not text:
        return []

    patterns = list(_FLAG_PATTERNS)
    if config.FLAG_REGEX:
        try:
            patterns.append(re.compile(config.FLAG_REGEX))
        except re.error as exc:
            logger.warning("Invalid FLAG_REGEX pattern (%s): %s", config.FLAG_REGEX, exc)

    seen: set[str] = set()
    findings: list[Finding] = []
    for pat in patterns:
        for m in pat.finditer(text):
            match = m.group(0)
            if match in seen:
                continue
            seen.add(match)
            findings.append(_mk(
                engagement_id=engagement_id,
                target=target,
                title=f"Secret/flag captured: {match[:80]}",
                vuln_type="Sensitive Data Exposure",
                severity="high",
                description=f"Flag/secret pattern matched in {tool_name} output: {match}",
                reproduction_steps=f"Rerun {tool_name} and observe the match in its output.",
                technique_used=tool_name,
                tags=["flag", "auto-ingested"],
            ))
    return findings


_EXTRACTORS = {
    "nuclei_scan": _from_nuclei,
    "nikto_scan": _from_nikto,
    "wapiti_scan": _from_wapiti,
    "sqlmap_scan": _from_sqlmap,
    "dalfox_scan": _from_dalfox,
}


def finding_from_tool_result(
    tool_name: str,
    result: Any,
    engagement_id: str,
    target: str,
) -> list[Finding]:
    """Derive Finding drafts from a scanner's result. Accepts either a dict or the
    JSON string the MCP tool wrappers return. Returns [] for tools with no
    structured vuln output or when the scan found nothing.

    Also appends flag/secret detections from ANY tool output (shell, http_request,
    etc.) via flag_findings_from_output, so captured flags are always surfaced."""
    findings: list[Finding] = []
    extractor = _EXTRACTORS.get(tool_name)
    if extractor is not None:
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except (ValueError, TypeError) as exc:
                logger.debug("Tool result not JSON for %s: %s", tool_name, exc)
        if isinstance(result, dict) and result.get("status") != "error":
            try:
                findings.extend(extractor(result, engagement_id, target))
            except Exception as exc:
                logger.warning("%s extractor failed: %s", tool_name, exc)
    # Flag/secret detection on any tool output (including shell, http_request, etc.)
    try:
        findings.extend(flag_findings_from_output(tool_name, result, engagement_id, target))
    except Exception as exc:
        logger.warning("flag_findings_from_output failed for %s: %s", tool_name, exc)
    return findings
