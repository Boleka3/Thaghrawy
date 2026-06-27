"""Kill Chain — Actions on Objectives: search workspace files for credential patterns."""
from __future__ import annotations

import os
import re
from typing import Any

from mcp_servers.tools._common import WORKSPACE_DIR, safe_filename, save_to_workspace

_PATTERNS: list[tuple[str, str]] = [
    ("password_kv",      r'(?i)pass(?:word|wd)?\s*[=:]\s*\S+'),
    ("username_kv",      r'(?i)user(?:name)?\s*[=:]\s*\S+'),
    ("api_key",          r'(?i)api[_-]?key\s*[=:]\s*[A-Za-z0-9_\-]{16,}'),
    ("bearer_token",     r'(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*'),
    ("basic_auth_url",   r'https?://[^:@/\s]+:[^@/\s]+@'),
    ("jwt_token",        r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
    ("private_key_header", r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    ("aws_access_key",   r'AKIA[0-9A-Z]{16}'),
    ("connection_string", r'(?i)(?:mysql|postgresql|mongodb|redis|mssql)://[^\s"\']+'),
    ("hash_ntlm",        r'[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}'),
    ("hash_bcrypt",      r'\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}'),
]


def credential_search(directory: str = WORKSPACE_DIR) -> dict[str, Any]:
    """
    Scan all files in the recon workspace (or a given directory) for credential
    patterns: passwords, API keys, tokens, private keys, connection strings, hashes.
    Returns a list of matches with file, line number, pattern type, and matched snippet.

    Args:
        directory: Directory to scan (defaults to the engagement workspace)
    """
    if not os.path.isdir(directory):
        return {"status": "error", "error": f"Directory not found: {directory}"}

    compiled = [(name, re.compile(pattern)) for name, pattern in _PATTERNS]
    matches: list[dict[str, Any]] = []
    files_scanned = 0

    for fname in os.listdir(directory):
        fpath = os.path.join(directory, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            with open(fpath, "r", errors="replace") as f:
                for lineno, line in enumerate(f, 1):
                    for pname, rx in compiled:
                        m = rx.search(line)
                        if m:
                            snippet = m.group(0)[:120]
                            matches.append({
                                "file": fname,
                                "line": lineno,
                                "pattern": pname,
                                "match": snippet,
                            })
            files_scanned += 1
        except Exception:
            continue

    out = "\n".join(f"{m['file']}:{m['line']} [{m['pattern']}] {m['match']}" for m in matches)
    log_path = save_to_workspace(safe_filename("workspace", "credential_search"), out or "No matches found")

    return {
        "status": "success",
        "tool": "credential_search",
        "directory": directory,
        "files_scanned": files_scanned,
        "summary": f"Found {len(matches)} credential pattern matches across {files_scanned} files",
        "matches": matches[:100],
        "full_output_file": log_path,
    }
