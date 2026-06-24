"""whois domain registration lookup.

The original Thaghrawy implementation was broken (missing `import re`,
referenced an undefined `output` variable, and copy-pasted an "Amass
failed" error message). Rewritten from scratch here.
"""
from __future__ import annotations

import re
from typing import Any

from mcp_servers.tools._common import run_command, sanitize_input

_FIELDS = {
    "registrar": r"Registrar:\s*(.+)",
    "creation_date": r"Creation Date:\s*(.+)",
    "expiration_date": r"Registry Expiry Date:\s*(.+)",
    "updated_date": r"Updated Date:\s*(.+)",
    "name_servers": r"Name Server:\s*(.+)",
    "status": r"Domain Status:\s*(.+)",
}


def _parse_whois(stdout: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for field, pattern in _FIELDS.items():
        matches = re.findall(pattern, stdout, re.IGNORECASE)
        if not matches:
            continue
        cleaned = [m.strip() for m in matches]
        parsed[field] = cleaned if field == "name_servers" else cleaned[0]

    return {
        "summary": f"Retrieved whois record ({len(parsed)} fields parsed)",
        "fields": parsed,
    }


def whois_lookup(domain: str) -> dict[str, Any]:
    domain = sanitize_input(domain)
    if not domain:
        return {"status": "error", "error": "Domain required"}

    cmd = ["whois", domain]
    return run_command(cmd, "whois", domain, parser=_parse_whois)
