"""OWASP A01 Broken Access Control — CSRF protection checker.
Crawls a page, extracts forms, checks for anti-CSRF tokens."""
from __future__ import annotations

import re
from typing import Any

import httpx

from mcp_servers.tools._common import safe_filename, sanitize_input, save_to_workspace

_CSRF_TOKEN_NAMES: list[re.Pattern] = [
    re.compile(r"csrf", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"authenticity_token", re.IGNORECASE),
    re.compile(r"_method", re.IGNORECASE),
]

# Framework-specific CSRF token field names
_KNOWN_CSRF_FIELDS: list[str] = [
    "csrfmiddlewaretoken",
    "__RequestVerificationToken",
    "authenticity_token",
    "_token",
    "csrf_token",
    "csrf-token",
    "xsrf-token",
    "xsrf_token",
    "csrfkey",
    "sesskey",
    "cc_csrf",
    "csrf_test_name",
    "YII_CSRF_TOKEN",
    "ci_csrf_token",
]


def _has_csrf_token(html: str) -> bool:
    """Check if HTML contains any known CSRF protection indicator."""
    # Check hidden input fields with CSRF-related names
    input_pattern = re.compile(r'<input[^>]*?(?:name|id)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
    for match in input_pattern.finditer(html):
        field_name = match.group(1).lower()
        if field_name in _KNOWN_CSRF_FIELDS:
            return True
        for pattern in _CSRF_TOKEN_NAMES:
            if pattern.search(field_name):
                return True
    # Check for meta tags with CSRF tokens
    meta_pattern = re.compile(r'<meta[^>]*?(?:name|content)\s*=\s*["\']([^"\']*csrf[^"\']*)["\']', re.IGNORECASE)
    if meta_pattern.search(html):
        return True
    # Check for JavaScript-embedded CSRF tokens
    js_pattern = re.compile(r'csrf[_-]token["\']?\s*[:=]\s*["\']', re.IGNORECASE)
    if js_pattern.search(html):
        return True
    return False


def csrf_check(url: str, follow_redirects: bool = True) -> dict[str, Any]:
    """Check a URL for CSRF protection on forms.

    Fetches the page, parses all HTML forms, and checks for
    anti-CSRF tokens (csrfmiddlewaretoken, __RequestVerificationToken,
    authenticity_token, etc).

    Returns findings per detected form or a summary.
    """
    url = sanitize_input(url)
    if not url:
        return {"status": "error", "error": "url required"}

    try:
        resp = httpx.get(url, follow_redirects=follow_redirects, timeout=15)
    except httpx.HTTPError as exc:
        return {"status": "error", "error": f"Request failed: {exc}"}

    html = resp.text
    forms_found = []
    form_pattern = re.compile(r'<form[^>]*?action=["\']([^"\']*)["\'][^>]*?>', re.IGNORECASE)
    for match in form_pattern.finditer(html):
        action = match.group(1) or url
        forms_found.append(action)

    methods = re.findall(r'<form[^>]*?method=["\'](get|post)["\']', html, re.IGNORECASE)
    post_forms = sum(1 for m in methods if m.lower() == "post")

    has_csrf = _has_csrf_token(html)

    result_lines = [
        f"URL: {url}",
        f"Forms detected: {len(forms_found)} (POST: {post_forms})",
        f"CSRF protection: {'PRESENT' if has_csrf else 'ABSENT'}",
    ]
    if post_forms > 0 and not has_csrf:
        result_lines.append("WARNING: {post_forms} POST form(s) without CSRF protection")
    log_path = save_to_workspace(safe_filename(url, "csrf_check"), "\n".join(result_lines))

    return {
        "status": "success",
        "tool": "csrf_check",
        "target": url,
        "forms_found": len(forms_found),
        "post_forms": post_forms,
        "has_csrf_protection": has_csrf,
        "summary": (
            f"CSRF protection {'detected' if has_csrf else 'NOT DETECTED'} "
            f"({len(forms_found)} forms, {post_forms} POST)"
        ),
        "form_actions": forms_found[:20],
        "full_output_file": log_path,
        "severity": "high" if post_forms > 0 and not has_csrf else "info",
    }
