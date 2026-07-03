"""OWASP A07 Identification & Authentication Failures — JWT token analyzer.
Decodes and inspects JWT tokens for common security weaknesses."""
from __future__ import annotations

import base64
import json
import re
from typing import Any

from mcp_servers.tools._common import safe_filename, sanitize_input, save_to_workspace

_WEAK_SECRETS: list[str] = [
    "secret", "password", "123456", "admin", "key", "changeme",
    "supersecret", "pass", "test", "secret123", "abc123", "P@ssw0rd",
]


def _b64url_decode(data: str) -> str:
    data = data.strip()
    data += "=" * (4 - len(data) % 4)
    try:
        return base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")
    except Exception:
        try:
            return base64.b64decode(data).decode("utf-8", errors="replace")
        except Exception:
            return ""


def _decode_jwt(token: str) -> dict[str, Any]:
    parts = token.strip().split(".")
    if len(parts) != 3:
        return {"valid_format": False, "error": "Not a valid JWT (expected 3 dot-separated parts)"}

    header_raw = _b64url_decode(parts[0])
    payload_raw = _b64url_decode(parts[1])
    signature = parts[2]

    header = {}
    payload = {}
    try:
        header = json.loads(header_raw) if header_raw else {}
    except json.JSONDecodeError:
        pass
    try:
        payload = json.loads(payload_raw) if payload_raw else {}
    except json.JSONDecodeError:
        pass

    return {
        "valid_format": True,
        "header": header,
        "payload": payload,
        "signature_present": len(signature) > 0,
        "signature_length": len(signature),
    }


def _analyze_weaknesses(decoded: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    header = decoded.get("header", {})
    payload = decoded.get("payload", {})

    alg = header.get("alg", "").upper()

    if alg == "NONE":
        findings.append({
            "issue": "alg:none", "severity": "critical",
            "detail": "Algorithm is 'none' — token has no cryptographic signature",
        })

    if alg == "HS256" and not decoded.get("signature_length", 0):
        findings.append({
            "issue": "empty_signature", "severity": "critical",
            "detail": "HS256 algorithm with empty signature — token can be forged",
        })

    typ = header.get("typ", "")
    if typ == "JWT":
        findings.append({
            "issue": "typ_overridden", "severity": "low",
            "detail": "typ header is set (typically ignored by libraries)",
        })

    kid = header.get("kid", "")
    if kid:
        findings.append({
            "issue": "kid_present", "severity": "medium",
            "detail": "Key ID present — potential for SQLi/SSRF if arbitrary",
        })

    if "exp" not in payload:
        findings.append({
            "issue": "no_expiration", "severity": "high",
            "detail": "Token has no expiration (exp claim)",
        })
    if "nbf" not in payload:
        findings.append({
            "issue": "no_not_before", "severity": "low",
            "detail": "Token has no not-before (nbf claim)",
        })
    if "iss" not in payload:
        findings.append({
            "issue": "no_issuer", "severity": "low",
            "detail": "Token has no issuer (iss claim)",
        })

    if "sub" in payload and not isinstance(payload["sub"], str):
        findings.append({
            "issue": "non_string_sub", "severity": "medium",
            "detail": "Subject (sub) is not a string — potential type confusion",
        })

    return findings


def jwt_analyze(token: str) -> dict[str, Any]:
    """Analyze a JWT token for security weaknesses.

    Decodes the token (without verification), inspects algorithm usage,
    claims present, and checks for common security issues like alg:none,
    missing expiration, empty signatures, etc.

    Does NOT verify signature validity (requires the secret/private key).
    """
    token = sanitize_input(token)
    if not token:
        return {"status": "error", "error": "token required"}

    decoded = _decode_jwt(token)

    if not decoded.get("valid_format"):
        return {
            "status": "error",
            "tool": "jwt_analyze",
            "error": decoded.get("error", "Invalid token format"),
        }

    findings = _analyze_weaknesses(decoded)

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: severity_order.get(f.get("severity", "low"), 99))

    lines = [
        f"Algorithm: {decoded['header'].get('alg', '?')}",
        f"Type: {decoded['header'].get('typ', '')}",
        f"Issuer: {decoded['payload'].get('iss', 'N/A')}",
        f"Subject: {decoded['payload'].get('sub', 'N/A')}",
        f"Expiration: {decoded['payload'].get('exp', 'NONE')}",
        "",
        f"Issues ({len(findings)}):",
    ]
    for f in findings:
        lines.append(f"  [{f['severity']}] {f['issue']}: {f['detail']}")

    log_path = save_to_workspace(safe_filename(token[:16], "jwt_analyze"), "\n".join(lines))

    critical = [f for f in findings if f["severity"] == "critical"]
    high = [f for f in findings if f["severity"] == "high"]

    return {
        "status": "success",
        "tool": "jwt_analyze",
        "header": decoded["header"],
        "payload": decoded["payload"],
        "findings": findings,
        "summary": (
            f"{len(critical)} critical, {len(high)} high, {len(findings)} total findings"
        ),
        "severity": "critical" if critical else ("high" if high else "low"),
        "full_output_file": log_path,
    }
